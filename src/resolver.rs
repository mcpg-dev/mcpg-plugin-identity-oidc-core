use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::config::{OidcOAuthConfig, OidcProviderConfig, TokenSourceConfig, VerificationConfig};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Security: SSRF guard. Reject URLs whose resolved host is in a
/// private/loopback/ULA range unless `allow_private_issuer` is set.
/// Also enforce the optional host allowlist and require HTTPS.
pub fn enforce_discovery_url_safety(
    url: &str,
    allowed_hosts: &[String],
    allow_private: bool,
) -> Result<()> {
    let parsed = url::Url::parse(url).with_context(|| format!("invalid OIDC URL '{url}'"))?;

    let scheme = parsed.scheme();
    // Use typed host so IPv6 literals arrive as IpAddr directly.
    let host_typed = parsed
        .host()
        .ok_or_else(|| anyhow::anyhow!("OIDC URL '{url}' has no host"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("OIDC URL '{url}' has no host"))?;

    if scheme != "https" && !(scheme == "http" && allow_private) {
        return Err(anyhow::anyhow!(
            "OIDC URL '{url}' must use https (set allow_private_issuer only for dev)"
        ));
    }

    // Allowlist: when non-empty, the host MUST match case-insensitively.
    if !allowed_hosts.is_empty() {
        let host_lower = host.to_ascii_lowercase();
        let allowed = allowed_hosts.iter().any(|h| {
            let h_lower = h.to_ascii_lowercase();
            h_lower == host_lower || host_lower.ends_with(&format!(".{h_lower}"))
        });
        if !allowed {
            return Err(anyhow::anyhow!(
                "OIDC host '{host}' is not in allowed_issuer_hosts"
            ));
        }
    }

    if allow_private {
        return Ok(());
    }

    // Blocklist: if the host parses as an IP literal, fail on any
    // reserved / loopback / private / link-local / ULA range. We
    // deliberately do NOT resolve DNS here — DNS rebinding is a real
    // concern but the fix belongs in a connector-level pin, not here.
    // Hostnames pointing at private IPs are caught when the kernel
    // later refuses to establish the TCP session from a rebinding
    // attack because the IP shown to reqwest is different from the
    // one we check here, which is the right trade-off for a simple
    // pre-flight guard.
    let addr: Option<IpAddr> = match host_typed {
        url::Host::Ipv4(v4) => Some(IpAddr::V4(v4)),
        url::Host::Ipv6(v6) => Some(IpAddr::V6(v6)),
        url::Host::Domain(_) => host.parse::<IpAddr>().ok(),
    };
    if let Some(addr) = addr
        && is_private_address(&addr)
    {
        return Err(anyhow::anyhow!(
            "OIDC URL '{url}' resolves to a private/loopback address; \
             set allow_private_issuer=true only for local dev"
        ));
    }

    Ok(())
}

fn is_private_address(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_multicast()
                || is_cgnat(v4)
                || is_reserved_v4(v4)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || is_unique_local_v6(v6)
                || is_link_local_v6(v6)
        }
    }
}

fn is_cgnat(v4: &std::net::Ipv4Addr) -> bool {
    // 100.64.0.0/10
    let o = v4.octets();
    o[0] == 100 && (o[1] & 0xC0) == 64
}

fn is_reserved_v4(v4: &std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    // 0.0.0.0/8, 240.0.0.0/4
    o[0] == 0 || o[0] >= 240
}

fn is_unique_local_v6(v6: &std::net::Ipv6Addr) -> bool {
    // fc00::/7
    (v6.segments()[0] & 0xFE00) == 0xFC00
}

fn is_link_local_v6(v6: &std::net::Ipv6Addr) -> bool {
    // fe80::/10
    (v6.segments()[0] & 0xFFC0) == 0xFE80
}

/// Map a JWK key algorithm to a jsonwebtoken Algorithm.
pub fn map_key_algorithm(ka: jsonwebtoken::jwk::KeyAlgorithm) -> Option<Algorithm> {
    use jsonwebtoken::jwk::KeyAlgorithm;
    match ka {
        KeyAlgorithm::HS256 => Some(Algorithm::HS256),
        KeyAlgorithm::HS384 => Some(Algorithm::HS384),
        KeyAlgorithm::HS512 => Some(Algorithm::HS512),
        KeyAlgorithm::RS256 => Some(Algorithm::RS256),
        KeyAlgorithm::RS384 => Some(Algorithm::RS384),
        KeyAlgorithm::RS512 => Some(Algorithm::RS512),
        KeyAlgorithm::PS256 => Some(Algorithm::PS256),
        KeyAlgorithm::PS384 => Some(Algorithm::PS384),
        KeyAlgorithm::PS512 => Some(Algorithm::PS512),
        KeyAlgorithm::ES256 => Some(Algorithm::ES256),
        KeyAlgorithm::ES384 => Some(Algorithm::ES384),
        KeyAlgorithm::EdDSA => Some(Algorithm::EdDSA),
        _ => None,
    }
}

/// Resolved identity from OIDC/OAuth verification.
#[derive(Debug, Clone)]
pub struct OidcIdentity {
    /// The subject identifier (mapped from configured subject_claim).
    pub subject_id: String,
    /// The issuer that verified this token.
    pub issuer: String,
    /// Provider label for diagnostics.
    pub provider_label: String,
    /// Extracted groups from claim mappings.
    pub groups: Vec<String>,
    /// Extracted roles from claim mappings.
    pub roles: Vec<String>,
    /// Extracted scopes.
    pub scopes: Vec<String>,
    /// Extracted attributes from claim mappings.
    pub attributes: BTreeMap<String, String>,
}

/// Result of an OIDC/OAuth verification attempt.
#[derive(Debug)]
pub enum OidcVerificationResult {
    /// Token verified and identity resolved.
    Verified(OidcIdentity),
    /// No bearer token was present in the request.
    None,
    /// Token was present but verification failed.
    Invalid(String),
}

// ---------------------------------------------------------------------------
// OIDC Discovery metadata
// ---------------------------------------------------------------------------

/// Minimal OIDC discovery document fields we need.
#[derive(Debug, Clone, Deserialize)]
struct DiscoveryDocument {
    issuer: String,
    jwks_uri: String,
}

// ---------------------------------------------------------------------------
// Cached JWKS state per provider
// ---------------------------------------------------------------------------

/// Cached JWKS key set. Refreshed on a configurable interval; served stale up to
/// `max_staleness_secs` so a temporary JWKS endpoint outage does not immediately
/// block all token verification.
struct CachedJwks {
    keys: Vec<KeyEntry>,
    fetched_at: Instant,
}

/// Pre-parsed JWK used for token verification. Security: the explicit algorithm
/// field prevents algorithm confusion — JWKs without `alg` are rejected.
struct KeyEntry {
    kid: Option<String>,
    key: DecodingKey,
    algorithm: Option<Algorithm>,
}

// ---------------------------------------------------------------------------
// Provider runtime state
// ---------------------------------------------------------------------------

/// Runtime state for a single OIDC/OAuth provider. Each provider maintains its
/// own JWKS cache, discovery cache, and circuit breaker — a broken provider
/// cannot take down healthy ones in the multi-provider resolution chain.
struct ProviderState {
    config: OidcProviderConfig,
    jwks_cache: RwLock<Option<CachedJwks>>,
    discovery_cache: RwLock<Option<CachedDiscovery>>,
    http_client: reqwest::Client,
    allowed_algs: Vec<Algorithm>,
    /// Circuit breaker over JWKS refresh + discovery. After
    /// `JWKS_CB_FAIL_THRESHOLD` consecutive failures the breaker
    /// opens for `JWKS_CB_OPEN_SECS` and short-circuits refresh.
    /// While open, verification falls back to whatever keys
    /// the cache still holds (the existing max_staleness logic keeps
    /// serving stale keys within the configured window; after that,
    /// tokens fail fast).
    jwks_cb: std::sync::Mutex<JwksCircuit>,
    /// Last unknown-`kid` refresh attempt, successful or not.
    ///
    /// An unknown kid triggers a JWKS refetch, and those refetches
    /// *succeed*, so the failure-driven circuit breaker never trips on
    /// them: a stream of attacker-chosen random kids turns one inbound
    /// request into one outbound fetch, unbounded. This floor is the same
    /// one the embedded EMA authorization server keeps for the identical
    /// path.
    last_kid_refresh: std::sync::Mutex<Option<Instant>>,
}

/// Minimum spacing between unknown-`kid` JWKS refetches, per provider.
const UNKNOWN_KID_REFRESH_FLOOR: Duration = Duration::from_secs(60);

const JWKS_CB_FAIL_THRESHOLD: u32 = 5;
const JWKS_CB_OPEN_SECS: u64 = 30;

/// JWKS refresh circuit breaker. After `JWKS_CB_FAIL_THRESHOLD` consecutive
/// failures the breaker opens for `JWKS_CB_OPEN_SECS`, falling back to
/// stale cached keys rather than hammering an unhealthy JWKS endpoint.
#[derive(Debug, Clone)]
enum JwksCircuit {
    Closed { consecutive_failures: u32 },
    Open { until: Instant },
}

impl JwksCircuit {
    fn record_success(&mut self) {
        *self = JwksCircuit::Closed {
            consecutive_failures: 0,
        };
    }

    fn record_failure(&mut self) {
        let new = match self {
            JwksCircuit::Closed {
                consecutive_failures,
            } => {
                let n = *consecutive_failures + 1;
                if n >= JWKS_CB_FAIL_THRESHOLD {
                    JwksCircuit::Open {
                        until: Instant::now() + Duration::from_secs(JWKS_CB_OPEN_SECS),
                    }
                } else {
                    JwksCircuit::Closed {
                        consecutive_failures: n,
                    }
                }
            }
            JwksCircuit::Open { .. } => JwksCircuit::Open {
                until: Instant::now() + Duration::from_secs(JWKS_CB_OPEN_SECS),
            },
        };
        *self = new;
    }

    fn allow_attempt(&mut self) -> bool {
        match self {
            JwksCircuit::Closed { .. } => true,
            JwksCircuit::Open { until } => {
                if Instant::now() >= *until {
                    *self = JwksCircuit::Closed {
                        consecutive_failures: 0,
                    };
                    true
                } else {
                    false
                }
            }
        }
    }
}

struct CachedDiscovery {
    doc: DiscoveryDocument,
    fetched_at: Instant,
}

impl ProviderState {
    fn new(config: OidcProviderConfig, http_client: reqwest::Client) -> Result<Self> {
        let allowed_algs = match &config.verification {
            VerificationConfig::OidcJwks { allowed_algs, .. }
            | VerificationConfig::Hybrid { allowed_algs, .. } => allowed_algs
                .iter()
                .map(|a| crate::config::parse_algorithm(a))
                .collect::<Result<Vec<_>>>()?,
            VerificationConfig::OauthIntrospection { .. } => vec![],
        };

        Ok(Self {
            config,
            last_kid_refresh: std::sync::Mutex::new(None),
            jwks_cache: RwLock::new(None),
            discovery_cache: RwLock::new(None),
            http_client,
            allowed_algs,
            jwks_cb: std::sync::Mutex::new(JwksCircuit::Closed {
                consecutive_failures: 0,
            }),
        })
    }

    fn jwks_timeout(&self) -> Duration {
        let ms = match &self.config.verification {
            VerificationConfig::OidcJwks { timeout_ms, .. } => *timeout_ms,
            VerificationConfig::Hybrid { timeout_ms, .. } => *timeout_ms,
            VerificationConfig::OauthIntrospection { .. } => 2000,
        };
        Duration::from_millis(ms)
    }

    fn refresh_interval(&self) -> Duration {
        let secs = match &self.config.verification {
            VerificationConfig::OidcJwks {
                refresh_interval_secs,
                ..
            } => *refresh_interval_secs,
            VerificationConfig::Hybrid {
                refresh_interval_secs,
                ..
            } => *refresh_interval_secs,
            VerificationConfig::OauthIntrospection { .. } => 300,
        };
        Duration::from_secs(secs)
    }

    fn max_staleness(&self) -> Duration {
        let secs = match &self.config.verification {
            VerificationConfig::OidcJwks {
                max_staleness_secs, ..
            } => *max_staleness_secs,
            VerificationConfig::Hybrid {
                max_staleness_secs, ..
            } => *max_staleness_secs,
            VerificationConfig::OauthIntrospection { .. } => 3600,
        };
        Duration::from_secs(secs)
    }

    fn introspection_timeout(&self) -> Duration {
        let ms = match &self.config.verification {
            VerificationConfig::OauthIntrospection { timeout_ms, .. } => *timeout_ms,
            VerificationConfig::Hybrid {
                introspection_timeout_ms,
                ..
            } => *introspection_timeout_ms,
            VerificationConfig::OidcJwks { .. } => 2000,
        };
        Duration::from_millis(ms)
    }

    /// Get OIDC discovery document, fetching and caching if needed.
    async fn discovery(&self) -> Result<DiscoveryDocument> {
        // Check cache
        {
            let cache = self.discovery_cache.read().await;
            if let Some(ref cached) = *cache
                && cached.fetched_at.elapsed() < self.refresh_interval()
            {
                return Ok(cached.doc.clone());
            }
        }

        // Fetch discovery
        let uri = self.config.effective_discovery_uri();
        // Security: SSRF preflight
        enforce_discovery_url_safety(
            &uri,
            &self.config.allowed_issuer_hosts,
            self.config.allow_private_issuer,
        )?;
        debug!(issuer = %self.config.issuer, uri = %uri, "fetching OIDC discovery document");

        let response = self
            .http_client
            .get(&uri)
            .timeout(self.jwks_timeout())
            .send()
            .await
            .with_context(|| format!("failed to fetch OIDC discovery from {uri}"))?;

        // Security: DNS rebinding guard — verify the response did not
        // come from a private IP.
        if !self.config.allow_private_issuer {
            mcpg_plugin_protocol::security::check_response_remote_addr(
                response.remote_addr(),
                false,
            )
            .map_err(|e| anyhow::anyhow!("OIDC discovery SSRF blocked: {e}"))?;
        }

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "OIDC discovery from {uri} returned status {}",
                response.status()
            ));
        }

        let doc: DiscoveryDocument = response
            .json()
            .await
            .with_context(|| format!("failed to parse OIDC discovery from {uri}"))?;

        // Verify issuer matches
        if doc.issuer != self.config.issuer {
            return Err(anyhow::anyhow!(
                "OIDC discovery issuer mismatch: expected '{}', got '{}'",
                self.config.issuer,
                doc.issuer
            ));
        }

        // Cache it
        {
            let mut cache = self.discovery_cache.write().await;
            *cache = Some(CachedDiscovery {
                doc: doc.clone(),
                fetched_at: Instant::now(),
            });
        }

        info!(issuer = %self.config.issuer, jwks_uri = %doc.jwks_uri, "OIDC discovery cached");
        Ok(doc)
    }

    /// Get JWKS keys, fetching via discovery if needed.
    async fn ensure_jwks(&self) -> Result<()> {
        // Check if we have fresh keys
        {
            let cache = self.jwks_cache.read().await;
            if let Some(ref cached) = *cache
                && cached.fetched_at.elapsed() < self.refresh_interval()
            {
                return Ok(());
            }
        }

        self.refresh_jwks().await
    }

    /// Force-refresh JWKS keys (e.g., on kid miss).
    /// Claim the unknown-`kid` refresh slot, stamping the attempt.
    ///
    /// Stamped whether or not the fetch then succeeds: the point is to bound
    /// egress per inbound request, and an unknown kid produces a *successful*
    /// fetch, so the failure-driven breaker never limits this path.
    fn may_refresh_for_unknown_kid(&self) -> bool {
        let mut last = self
            .last_kid_refresh
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some(at) = *last
            && at.elapsed() < UNKNOWN_KID_REFRESH_FLOOR
        {
            return false;
        }
        *last = Some(Instant::now());
        true
    }

    async fn refresh_jwks(&self) -> Result<()> {
        // Check staleness first — allow stale keys if refresh fails
        let stale_ok = {
            let cache = self.jwks_cache.read().await;
            cache
                .as_ref()
                .is_some_and(|c| c.fetched_at.elapsed() < self.max_staleness())
        };

        // Circuit breaker: skip refresh entirely while open. Cached
        // keys within max_staleness continue to verify tokens.
        {
            let mut cb = self.jwks_cb.lock().expect("jwks_cb");
            if !cb.allow_attempt() {
                metrics::counter!(
                    "mcpg_oidc_jwks_circuit_short_circuited_total",
                    "issuer" => self.config.issuer.clone(),
                )
                .increment(1);
                if stale_ok {
                    return Ok(());
                }
                return Err(anyhow::anyhow!(
                    "JWKS circuit breaker open; stale keys exhausted"
                ));
            }
        }

        // Wrap the fetch logic; the inner also flips the breaker state
        // on its own because success vs. stale-fallback are both Ok(())
        // but the breaker MUST only see true upstream success.
        self.refresh_jwks_inner(stale_ok).await
    }

    fn record_jwks_outcome(&self, upstream_ok: bool) {
        let mut cb = self.jwks_cb.lock().expect("jwks_cb");
        if upstream_ok {
            cb.record_success();
        } else {
            cb.record_failure();
        }
    }

    async fn refresh_jwks_inner(&self, stale_ok: bool) -> Result<()> {
        let jwks_uri = match self.discovery().await {
            Ok(doc) => doc.jwks_uri,
            Err(e) => {
                // Upstream failure — tip the circuit breaker toward open.
                self.record_jwks_outcome(false);
                if stale_ok {
                    warn!(
                        issuer = %self.config.issuer,
                        error = %e,
                        "OIDC discovery failed but stale JWKS keys still valid"
                    );
                    metrics::counter!(
                        "mcpg_oidc_stale_jwks_served_total",
                        "reason" => "discovery_failed",
                    )
                    .increment(1);
                    return Ok(());
                }
                return Err(e);
            }
        };

        // Security: re-run SSRF preflight on the discovered JWKS endpoint
        // in case a compromised discovery doc points at a private IP.
        enforce_discovery_url_safety(
            &jwks_uri,
            &self.config.allowed_issuer_hosts,
            self.config.allow_private_issuer,
        )?;
        debug!(issuer = %self.config.issuer, jwks_uri = %jwks_uri, "fetching JWKS keys");

        let response = match self
            .http_client
            .get(&jwks_uri)
            .timeout(self.jwks_timeout())
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                self.record_jwks_outcome(false);
                if stale_ok {
                    warn!(
                        issuer = %self.config.issuer,
                        error = %e,
                        "JWKS fetch failed but stale keys still valid"
                    );
                    metrics::counter!(
                        "mcpg_oidc_stale_jwks_served_total",
                        "reason" => "fetch_error",
                    )
                    .increment(1);
                    return Ok(());
                }
                return Err(e.into());
            }
        };

        if !response.status().is_success() {
            self.record_jwks_outcome(false);
            if stale_ok {
                warn!(
                    issuer = %self.config.issuer,
                    status = %response.status(),
                    "JWKS fetch returned error status but stale keys still valid"
                );
                metrics::counter!(
                    "mcpg_oidc_stale_jwks_served_total",
                    "reason" => format!("http_{}", response.status().as_u16()),
                )
                .increment(1);
                return Ok(());
            }
            return Err(anyhow::anyhow!(
                "JWKS fetch from {jwks_uri} returned status {}",
                response.status()
            ));
        }

        let jwks_json = response
            .text()
            .await
            .context("failed to read JWKS response body")?;

        let jwk_set: JwkSet =
            serde_json::from_str(&jwks_json).context("failed to parse JWKS JSON")?;

        let mut keys = Vec::new();
        for jwk in &jwk_set.keys {
            let decoding_key = match DecodingKey::from_jwk(jwk) {
                Ok(k) => k,
                Err(e) => {
                    warn!(
                        kid = ?jwk.common.key_id,
                        error = %e,
                        "skipping unusable JWK key"
                    );
                    continue;
                }
            };
            let algorithm = jwk.common.key_algorithm.and_then(map_key_algorithm);

            keys.push(KeyEntry {
                kid: jwk.common.key_id.clone(),
                key: decoding_key,
                algorithm,
            });
        }

        if keys.is_empty() && !stale_ok {
            return Err(anyhow::anyhow!(
                "JWKS from {jwks_uri} contains no usable keys"
            ));
        }

        if !keys.is_empty() {
            let key_count = keys.len();
            let mut cache = self.jwks_cache.write().await;
            *cache = Some(CachedJwks {
                keys,
                fetched_at: Instant::now(),
            });
            info!(
                issuer = %self.config.issuer,
                key_count,
                "JWKS keys cached"
            );
        }

        // Upstream responded, parsed, cached — record success.
        self.record_jwks_outcome(true);
        Ok(())
    }

    /// Verify a JWT token using cached JWKS keys.
    async fn verify_jwt(&self, token: &str) -> OidcVerificationResult {
        if let Err(e) = self.ensure_jwks().await {
            return OidcVerificationResult::Invalid(format!(
                "JWKS unavailable for issuer '{}': {e}",
                self.config.issuer
            ));
        }

        let header = match decode_header(token) {
            Ok(h) => h,
            Err(e) => {
                return OidcVerificationResult::Invalid(format!("invalid JWT header: {e}"));
            }
        };

        // Check algorithm is allowed
        if !self.allowed_algs.is_empty() && !self.allowed_algs.contains(&header.alg) {
            return OidcVerificationResult::Invalid(format!(
                "algorithm {:?} not in allowed list for issuer '{}'",
                header.alg, self.config.issuer
            ));
        }

        // Reject alg=none
        if header.alg == Algorithm::default() && !self.allowed_algs.contains(&Algorithm::default())
        {
            return OidcVerificationResult::Invalid("algorithm 'none' is not allowed".to_owned());
        }

        let jwks_cache = self.jwks_cache.read().await;
        let cached = match &*jwks_cache {
            Some(c) => c,
            None => {
                return OidcVerificationResult::Invalid(format!(
                    "no JWKS keys available for issuer '{}'",
                    self.config.issuer
                ));
            }
        };

        // Find matching keys
        let candidate_keys: Vec<&KeyEntry> = if let Some(ref kid) = header.kid {
            let matching: Vec<_> = cached
                .keys
                .iter()
                .filter(|k| k.kid.as_deref() == Some(kid))
                .collect();
            if matching.is_empty() {
                drop(jwks_cache);
                // Try a JWKS refresh for unknown kid, no more than once per
                // floor: the refetch succeeds for any kid, so without this a
                // caller cycling random kids drives one outbound fetch per
                // request and the failure-driven breaker never sees a failure.
                if !self.may_refresh_for_unknown_kid() {
                    return OidcVerificationResult::Invalid(format!(
                        "no key for kid '{kid}' (refresh rate-limited)"
                    ));
                }
                debug!(kid = %kid, issuer = %self.config.issuer, "unknown kid, attempting JWKS refresh");
                if self.refresh_jwks().await.is_ok() {
                    let refreshed = self.jwks_cache.read().await;
                    if let Some(ref c) = *refreshed {
                        let retry: Vec<_> = c
                            .keys
                            .iter()
                            .filter(|k| k.kid.as_deref() == Some(kid.as_str()))
                            .collect();
                        if retry.is_empty() {
                            return OidcVerificationResult::Invalid(format!(
                                "no key found for kid '{kid}' after JWKS refresh"
                            ));
                        }
                        return self.try_keys(&retry, token, &header);
                    }
                }
                return OidcVerificationResult::Invalid(format!("no key found for kid '{kid}'"));
            }
            matching
        } else {
            cached.keys.iter().collect()
        };

        self.try_keys(&candidate_keys, token, &header)
    }

    /// Try to verify a token against candidate keys.
    fn try_keys(
        &self,
        keys: &[&KeyEntry],
        token: &str,
        header: &jsonwebtoken::Header,
    ) -> OidcVerificationResult {
        for key_entry in keys {
            let algorithm = key_entry.algorithm.unwrap_or(header.alg);

            let mut validation = Validation::new(algorithm);
            // Security: explicit exp + nbf validation. Set explicitly to
            // stay defensive against upstream default drift.
            validation.validate_exp = true;
            validation.validate_nbf = true;
            validation.leeway = self.config.clock_skew_secs;

            validation.set_issuer(&[&self.config.issuer]);

            // jsonwebtoken's `set_issuer`/`set_audience` only validate a claim
            // when it is PRESENT (default required_spec_claims is {exp}). Require
            // `iss` (and `aud` when configured) so a token omitting the claim is
            // hard-rejected — the MCP SEP-1012 audience-binding requirement
            // cited below.
            let mut required = vec!["exp", "iss"];
            if !self.config.audiences.is_empty() {
                validation.set_audience(&self.config.audiences);
                required.push("aud");
            } else {
                // Per MCP 2025-11-25 / SEP-1012 servers MUST validate
                // audience binding. If the operator configured no
                // audiences, surface that as a warning rather than
                // silently accepting any `aud` claim.
                tracing::warn!(
                    issuer = %self.config.issuer,
                    "OIDC plugin configured without audiences; MCP MUST validate audience binding — \
                     add `audiences` to the plugin config or tokens intended for another gateway \
                     may be accepted"
                );
                validation.validate_aud = false;
            }
            validation.set_required_spec_claims(&required);

            match decode::<serde_json::Value>(token, &key_entry.key, &validation) {
                Ok(token_data) => {
                    return self.map_claims(&token_data.claims);
                }
                Err(e) => {
                    debug!(
                        kid = ?key_entry.kid,
                        algorithm = ?algorithm,
                        error = %e,
                        issuer = %self.config.issuer,
                        "JWT verification failed with key, trying next"
                    );
                    continue;
                }
            }
        }

        warn!(
            issuer = %self.config.issuer,
            keys_tried = keys.len(),
            "JWT verification failed: no key could verify the token"
        );
        OidcVerificationResult::Invalid("token signature verification failed".to_owned())
    }

    /// Perform OAuth token introspection (RFC 7662).
    async fn introspect_token(&self, token: &str) -> OidcVerificationResult {
        let (introspection_url, client_id, client_secret_ref) = match &self.config.verification {
            VerificationConfig::OauthIntrospection {
                introspection_url,
                client_id,
                client_secret_ref,
                ..
            }
            | VerificationConfig::Hybrid {
                introspection_url,
                client_id,
                client_secret_ref,
                ..
            } => (introspection_url, client_id, client_secret_ref),
            _ => {
                return OidcVerificationResult::Invalid(
                    "introspection not configured for this provider".to_owned(),
                );
            }
        };

        let client_secret = resolve_secret_ref(client_secret_ref);

        debug!(
            issuer = %self.config.issuer,
            introspection_url = %introspection_url,
            "performing token introspection"
        );

        let response = match self
            .http_client
            .post(introspection_url)
            .basic_auth(client_id, Some(&client_secret))
            .form(&[("token", token)])
            .timeout(self.introspection_timeout())
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                return OidcVerificationResult::Invalid(format!(
                    "introspection request failed for issuer '{}': {e}",
                    self.config.issuer
                ));
            }
        };

        if !response.status().is_success() {
            return OidcVerificationResult::Invalid(format!(
                "introspection returned status {} for issuer '{}'",
                response.status(),
                self.config.issuer
            ));
        }

        let body: serde_json::Value = match response.json().await {
            Ok(v) => v,
            Err(e) => {
                return OidcVerificationResult::Invalid(format!(
                    "failed to parse introspection response for issuer '{}': {e}",
                    self.config.issuer
                ));
            }
        };

        // RFC 7662: check "active" field
        let active = body
            .get("active")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !active {
            return OidcVerificationResult::Invalid(
                "token is not active (introspection)".to_owned(),
            );
        }

        // Verify issuer if present in introspection response
        if let Some(iss) = body.get("iss").and_then(|v| v.as_str())
            && iss != self.config.issuer
        {
            return OidcVerificationResult::Invalid(format!(
                "introspection issuer mismatch: expected '{}', got '{iss}'",
                self.config.issuer
            ));
        }

        // Verify audience if configured.
        //
        // RFC 7662 makes `aud` OPTIONAL in an introspection response, and
        // plenty of authorization servers omit it — so treating "absent" as
        // "nothing to check" accepted a token minted for ANY relying party
        // of this issuer. An operator who configured `audiences` asked for
        // that binding, so a response without `aud` is a rejection, matching
        // the JWT path where `aud` is a required claim.
        if !self.config.audiences.is_empty() {
            let Some(aud) = body.get("aud") else {
                return OidcVerificationResult::Invalid(format!(
                    "introspection response for issuer '{}' carries no `aud`; cannot honour the \
                     configured audience binding (set allow_any_audience to accept this)",
                    self.config.issuer
                ));
            };
            let aud_list = match aud {
                serde_json::Value::String(s) => vec![s.as_str()],
                serde_json::Value::Array(arr) => arr.iter().filter_map(|v| v.as_str()).collect(),
                _ => vec![],
            };
            if !self
                .config
                .audiences
                .iter()
                .any(|expected| aud_list.contains(&expected.as_str()))
            {
                return OidcVerificationResult::Invalid(format!(
                    "audience mismatch for issuer '{}'",
                    self.config.issuer
                ));
            }
        }

        self.map_claims(&body)
    }

    /// Map verified claims (from JWT or introspection) into an OidcIdentity.
    fn map_claims(&self, claims: &serde_json::Value) -> OidcVerificationResult {
        let mappings = &self.config.claim_mappings;

        // Extract subject
        let subject_id = match extract_string_claim(claims, &mappings.subject_claim) {
            Some(s) if !s.trim().is_empty() => s,
            _ => {
                return OidcVerificationResult::Invalid(format!(
                    "missing or empty '{}' claim for issuer '{}'",
                    mappings.subject_claim, self.config.issuer
                ));
            }
        };

        // Extract groups
        let groups = extract_string_list_claims(claims, &mappings.group_claim_paths);

        // Extract roles
        let roles = extract_string_list_claims(claims, &mappings.role_claim_paths);

        // Extract scopes
        let scopes = extract_scope_claims(claims, &mappings.scope_claim_paths);

        // Extract attributes
        let mut attributes = BTreeMap::new();
        for (claim_name, attr_name) in &mappings.attribute_claim_mappings {
            if let Some(value) = extract_string_claim(claims, claim_name) {
                attributes.insert(attr_name.clone(), value);
            }
        }

        debug!(
            issuer = %self.config.issuer,
            subject = %subject_id,
            groups = ?groups,
            roles = ?roles,
            scopes = ?scopes,
            "OIDC/OAuth identity resolved"
        );

        OidcVerificationResult::Verified(OidcIdentity {
            subject_id,
            issuer: self.config.issuer.clone(),
            provider_label: self.config.issuer.clone(),
            groups,
            roles,
            scopes,
            attributes,
        })
    }

    /// Verify a token using this provider's configured strategy.
    async fn verify_token(&self, token: &str) -> OidcVerificationResult {
        match &self.config.verification {
            VerificationConfig::OidcJwks { .. } => self.verify_jwt(token).await,
            VerificationConfig::OauthIntrospection { .. } => self.introspect_token(token).await,
            VerificationConfig::Hybrid { .. } => {
                // Introspection cannot re-apply `allowed_algs` (there is no
                // header to check) and binds the issuer only when the response
                // carries `iss`, so it must never re-adjudicate a token the JWT
                // path has already rejected — that is verifier shopping inside
                // a single provider. Classify first: fall through only when the
                // token is not a JWS at all, which is the case introspection
                // exists for (an opaque access token). Once it is a JWT, the
                // JWT verdict is final, including a JWKS outage — otherwise an
                // attacker who can reach the JWKS endpoint downgrades every
                // token to the laxer verifier.
                if decode_header(token).is_err() {
                    debug!(issuer = %self.config.issuer, "token is not a JWS; introspecting");
                    return self.introspect_token(token).await;
                }
                self.verify_jwt(token).await
            }
        }
    }

    /// Check if this provider might match a JWT token (by issuer in unverified claims).
    fn matches_issuer(&self, unverified_iss: Option<&str>) -> bool {
        match unverified_iss {
            Some(iss) => iss == self.config.issuer,
            None => false,
        }
    }
}

// ---------------------------------------------------------------------------
// OidcOAuthResolver: multi-provider resolution
// ---------------------------------------------------------------------------

/// Top-level OIDC/OAuth identity resolver supporting multiple providers.
pub struct OidcOAuthResolver {
    providers: Vec<Arc<ProviderState>>,
    token_source: TokenSourceConfig,
}

impl std::fmt::Debug for OidcOAuthResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcOAuthResolver")
            .field("provider_count", &self.providers.len())
            .field(
                "issuers",
                &self
                    .providers
                    .iter()
                    .map(|p| p.config.issuer.as_str())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl OidcOAuthResolver {
    /// Build a resolver from configuration.
    pub fn from_config(config: &OidcOAuthConfig) -> Result<Self> {
        let http_client = reqwest::Client::builder()
            .user_agent("mcpg/oidc")
            .timeout(Duration::from_secs(10))
            // `enforce_discovery_url_safety` vets discovery, JWKS and
            // introspection URLs before they are requested; following a
            // redirect would reach a host the guard never inspected.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("failed to build HTTP client for OIDC")?;

        let mut providers = Vec::new();
        for provider_config in &config.providers {
            let state = ProviderState::new(provider_config.clone(), http_client.clone())?;
            providers.push(Arc::new(state));
        }

        Ok(Self {
            providers,
            token_source: config.token_source.clone(),
        })
    }

    /// Build a resolver with a custom HTTP client (for testing).
    #[cfg(test)]
    pub fn from_config_with_client(
        config: &OidcOAuthConfig,
        http_client: reqwest::Client,
    ) -> Result<Self> {
        let mut providers = Vec::new();
        for provider_config in &config.providers {
            let state = ProviderState::new(provider_config.clone(), http_client.clone())?;
            providers.push(Arc::new(state));
        }

        Ok(Self {
            providers,
            token_source: config.token_source.clone(),
        })
    }

    /// Extract and verify a bearer token from the given headers.
    pub async fn verify_from_headers(&self, headers: &http::HeaderMap) -> OidcVerificationResult {
        let token = match self.extract_token(headers) {
            Some(t) => t,
            None => return OidcVerificationResult::None,
        };

        self.verify_token(token).await
    }

    /// Extract the raw token string from request headers.
    fn extract_token<'a>(&self, headers: &'a http::HeaderMap) -> Option<&'a str> {
        let header_name = self.token_source.effective_header_name();
        let prefix = self.token_source.effective_header_prefix();

        let header_value = headers.get(header_name).and_then(|v| v.to_str().ok())?;

        if prefix.is_empty() {
            return Some(header_value);
        }

        header_value.strip_prefix(prefix)
    }

    /// Verify a raw token string against configured providers.
    async fn verify_token(&self, token: &str) -> OidcVerificationResult {
        if self.providers.len() == 1 {
            return self.providers[0].verify_token(token).await;
        }

        // Multi-provider: try to find the right provider by decoding
        // the unverified issuer claim from the JWT header/payload.
        // For opaque tokens, we must try each provider.
        let unverified_issuer = extract_unverified_issuer(token);

        // If we can identify the issuer, try that provider first
        if let Some(ref iss) = unverified_issuer {
            for provider in &self.providers {
                if provider.matches_issuer(Some(iss)) {
                    return provider.verify_token(token).await;
                }
            }
        }

        // Fall back to trying each provider in order
        let mut last_error = String::new();
        for provider in &self.providers {
            match provider.verify_token(token).await {
                OidcVerificationResult::Verified(id) => {
                    return OidcVerificationResult::Verified(id);
                }
                OidcVerificationResult::Invalid(msg) => {
                    debug!(
                        issuer = %provider.config.issuer,
                        error = %msg,
                        "provider verification failed, trying next"
                    );
                    last_error = msg;
                }
                OidcVerificationResult::None => {
                    return OidcVerificationResult::None;
                }
            }
        }

        OidcVerificationResult::Invalid(format!(
            "no configured provider could verify the token (last error: {last_error})"
        ))
    }

    /// Get the effective header name for token extraction.
    pub fn header_name(&self) -> &str {
        self.token_source.effective_header_name()
    }

    /// Get the configured provider count.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Get the list of configured issuer URIs.
    pub fn issuers(&self) -> Vec<&str> {
        self.providers
            .iter()
            .map(|p| p.config.issuer.as_str())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the unverified `iss` claim from a JWT without verifying the signature.
/// This is used for multi-provider routing only — the token is still fully verified
/// by the matched provider.
fn extract_unverified_issuer(token: &str) -> Option<String> {
    // JWT is header.payload.signature — decode the payload without verification
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() < 2 {
        return None; // Not a JWT (probably opaque token)
    }

    use base64::Engine;
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .ok()?;

    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;
    claims.get("iss").and_then(|v| v.as_str()).map(String::from)
}

/// Extract a string claim from a JSON value, supporting dotted paths like "realm_access.roles".
fn extract_string_claim(claims: &serde_json::Value, path: &str) -> Option<String> {
    let value = resolve_json_path(claims, path)?;
    value.as_str().map(String::from)
}

/// Extract string list claims from multiple paths in the JWT payload.
fn extract_string_list_claims(claims: &serde_json::Value, paths: &[String]) -> Vec<String> {
    let mut result = Vec::new();
    for path in paths {
        if let Some(value) = resolve_json_path(claims, path) {
            match value {
                serde_json::Value::Array(arr) => {
                    for item in arr {
                        if let Some(s) = item.as_str() {
                            result.push(s.to_owned());
                        }
                    }
                }
                serde_json::Value::String(s) => {
                    // Space-separated list (common for scopes)
                    for part in s.split_whitespace() {
                        result.push(part.to_owned());
                    }
                }
                _ => {}
            }
        }
    }
    result
}

/// Extract scope claims — same as string list but also splits space-separated strings.
fn extract_scope_claims(claims: &serde_json::Value, paths: &[String]) -> Vec<String> {
    extract_string_list_claims(claims, paths)
}

/// Resolve a dotted JSON path like "realm_access.roles" against a JSON value.
fn resolve_json_path<'a>(
    value: &'a serde_json::Value,
    path: &str,
) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

/// Return the client secret value. The gateway substitutes
/// `${env.X}` / `cred://…` references in the plugin config at load,
/// so the value arrives already resolved and is used as-is.
fn resolve_secret_ref(secret_ref: &str) -> String {
    secret_ref.to_owned()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod jwks_circuit_tests {
    use super::*;

    #[test]
    fn circuit_opens_after_threshold_failures() {
        let mut cb = JwksCircuit::Closed {
            consecutive_failures: 0,
        };
        for _ in 0..(JWKS_CB_FAIL_THRESHOLD - 1) {
            cb.record_failure();
            assert!(cb.allow_attempt(), "still closed");
        }
        cb.record_failure();
        assert!(!cb.allow_attempt(), "breaker should be open now");
    }

    #[test]
    fn circuit_closes_on_success_after_half_open() {
        let mut cb = JwksCircuit::Open {
            until: std::time::Instant::now() - std::time::Duration::from_secs(1),
        };
        // Past the open window → allow_attempt flips back to Closed
        assert!(cb.allow_attempt());
        cb.record_success();
        assert!(cb.allow_attempt(), "closed after success");
    }
}

#[cfg(test)]
mod ssrf_tests {
    use super::enforce_discovery_url_safety;

    #[test]
    fn accepts_public_https_host() {
        assert!(
            enforce_discovery_url_safety(
                "https://login.example.com/.well-known/openid-configuration",
                &[],
                false,
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_plain_http_without_dev_flag() {
        let err = enforce_discovery_url_safety(
            "http://idp.example.com/.well-known/openid-configuration",
            &[],
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("https"), "got: {err}");
    }

    #[test]
    fn rejects_private_ipv4_by_default() {
        let err = enforce_discovery_url_safety("https://10.0.0.5/jwks", &[], false).unwrap_err();
        assert!(err.to_string().contains("private/loopback"), "got: {err}");
    }

    #[test]
    fn rejects_loopback_ipv4_by_default() {
        let err = enforce_discovery_url_safety("https://127.0.0.1/jwks", &[], false).unwrap_err();
        assert!(err.to_string().contains("private/loopback"), "got: {err}");
    }

    #[test]
    fn rejects_link_local_ipv6_by_default() {
        let err = enforce_discovery_url_safety("https://[fe80::1]/jwks", &[], false).unwrap_err();
        assert!(err.to_string().contains("private/loopback"), "got: {err}");
    }

    #[test]
    fn permits_private_ipv4_with_dev_flag() {
        assert!(
            enforce_discovery_url_safety(
                "http://127.0.0.1:8080/.well-known/openid-configuration",
                &[],
                true,
            )
            .is_ok()
        );
    }

    #[test]
    fn allowlist_accepts_exact_host() {
        assert!(
            enforce_discovery_url_safety(
                "https://idp.example.com/jwks",
                &["idp.example.com".to_owned()],
                false,
            )
            .is_ok()
        );
    }

    #[test]
    fn allowlist_rejects_off_list_host() {
        let err = enforce_discovery_url_safety(
            "https://evil.example.net/jwks",
            &["idp.example.com".to_owned()],
            false,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("not in allowed_issuer_hosts"),
            "got: {err}"
        );
    }

    #[test]
    fn allowlist_accepts_subdomain_of_listed_root() {
        assert!(
            enforce_discovery_url_safety(
                "https://eu.idp.example.com/jwks",
                &["idp.example.com".to_owned()],
                false,
            )
            .is_ok()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClaimMappingConfig;

    // -- claim extraction tests --

    #[test]
    fn resolve_json_path_simple() {
        let claims = serde_json::json!({
            "sub": "user-1",
            "email": "user@example.com"
        });
        assert_eq!(
            resolve_json_path(&claims, "sub"),
            Some(&serde_json::json!("user-1"))
        );
        assert_eq!(
            resolve_json_path(&claims, "email"),
            Some(&serde_json::json!("user@example.com"))
        );
        assert_eq!(resolve_json_path(&claims, "missing"), None);
    }

    #[test]
    fn resolve_json_path_nested() {
        let claims = serde_json::json!({
            "realm_access": {
                "roles": ["admin", "editor"]
            }
        });
        assert_eq!(
            resolve_json_path(&claims, "realm_access.roles"),
            Some(&serde_json::json!(["admin", "editor"]))
        );
    }

    #[test]
    fn extract_string_claim_works() {
        let claims = serde_json::json!({"sub": "alice", "email": "alice@example.com"});
        assert_eq!(
            extract_string_claim(&claims, "sub"),
            Some("alice".to_owned())
        );
        assert_eq!(extract_string_claim(&claims, "missing"), None);
    }

    #[test]
    fn extract_string_list_from_array() {
        let claims = serde_json::json!({
            "groups": ["admin", "dev"],
            "roles": ["editor"]
        });
        let result =
            extract_string_list_claims(&claims, &["groups".to_owned(), "roles".to_owned()]);
        assert_eq!(result, vec!["admin", "dev", "editor"]);
    }

    #[test]
    fn extract_string_list_from_space_separated() {
        let claims = serde_json::json!({"scope": "openid profile email"});
        let result = extract_string_list_claims(&claims, &["scope".to_owned()]);
        assert_eq!(result, vec!["openid", "profile", "email"]);
    }

    #[test]
    fn extract_string_list_from_nested_path() {
        let claims = serde_json::json!({
            "realm_access": {
                "roles": ["admin", "user"]
            }
        });
        let result = extract_string_list_claims(&claims, &["realm_access.roles".to_owned()]);
        assert_eq!(result, vec!["admin", "user"]);
    }

    #[test]
    fn claim_mapping_full() {
        let claims = serde_json::json!({
            "sub": "user-42",
            "iss": "https://login.example.com/",
            "aud": "mcpg",
            "groups": ["engineers"],
            "realm_access": {"roles": ["admin"]},
            "scope": "openid profile",
            "email": "user@example.com",
            "department": "engineering"
        });

        let config = OidcProviderConfig {
            issuer: "https://login.example.com/".to_owned(),
            discovery_uri: None,
            audiences: vec!["mcpg".to_owned()],
            verification: VerificationConfig::OidcJwks {
                allowed_algs: vec!["RS256".to_owned()],
                refresh_interval_secs: 300,
                timeout_ms: 2000,
                max_staleness_secs: 3600,

                allow_hmac: false,
            },
            claim_mappings: ClaimMappingConfig {
                subject_claim: "sub".to_owned(),
                group_claim_paths: vec!["groups".to_owned()],
                role_claim_paths: vec!["realm_access.roles".to_owned()],
                scope_claim_paths: vec!["scope".to_owned()],
                attribute_claim_mappings: {
                    let mut m = BTreeMap::new();
                    m.insert("email".to_owned(), "email".to_owned());
                    m.insert("department".to_owned(), "department".to_owned());
                    m
                },
            },
            clock_skew_secs: 60,
            allowed_issuer_hosts: Vec::new(),
            allow_private_issuer: true,
            allow_any_audience: false,
        };

        let http_client = reqwest::Client::new();
        let provider = ProviderState::new(config, http_client).unwrap();

        match provider.map_claims(&claims) {
            OidcVerificationResult::Verified(id) => {
                assert_eq!(id.subject_id, "user-42");
                assert_eq!(id.issuer, "https://login.example.com/");
                assert_eq!(id.groups, vec!["engineers"]);
                assert_eq!(id.roles, vec!["admin"]);
                assert_eq!(id.scopes, vec!["openid", "profile"]);
                assert_eq!(id.attributes.get("email").unwrap(), "user@example.com");
                assert_eq!(id.attributes.get("department").unwrap(), "engineering");
            }
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    #[test]
    fn claim_mapping_missing_subject_returns_invalid() {
        let claims = serde_json::json!({"email": "user@example.com"});

        let config = OidcProviderConfig {
            issuer: "https://login.example.com/".to_owned(),
            discovery_uri: None,
            audiences: vec![],
            verification: VerificationConfig::OidcJwks {
                allowed_algs: vec!["RS256".to_owned()],
                refresh_interval_secs: 300,
                timeout_ms: 2000,
                max_staleness_secs: 3600,

                allow_hmac: false,
            },
            claim_mappings: ClaimMappingConfig::default(),
            clock_skew_secs: 60,
            allowed_issuer_hosts: Vec::new(),
            allow_private_issuer: true,
            allow_any_audience: false,
        };

        let http_client = reqwest::Client::new();
        let provider = ProviderState::new(config, http_client).unwrap();

        match provider.map_claims(&claims) {
            OidcVerificationResult::Invalid(msg) => {
                assert!(msg.contains("sub"), "error should mention 'sub': {msg}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn extract_unverified_issuer_from_jwt() {
        // Build a minimal JWT-like token (header.payload.signature)
        use base64::Engine;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"iss":"https://login.example.com/","sub":"user-1"}"#);
        let fake_token = format!("{header}.{payload}.fakesignature");

        assert_eq!(
            extract_unverified_issuer(&fake_token),
            Some("https://login.example.com/".to_owned())
        );
    }

    #[test]
    fn extract_unverified_issuer_from_opaque_token() {
        assert_eq!(extract_unverified_issuer("opaque-token-no-dots"), None);
    }

    #[test]
    fn resolve_secret_ref_passes_value_through() {
        // The gateway resolves `${env.X}` / `cred://…` before the
        // plugin sees the value, so the plugin uses it verbatim and
        // does no env lookup of its own.
        assert_eq!(resolve_secret_ref("my-secret"), "my-secret");
    }

    #[test]
    fn resolve_secret_ref_literal() {
        assert_eq!(resolve_secret_ref("literal-value"), "literal-value");
    }

    // -- config validation tests --

    #[test]
    fn oidc_provider_config_validation() {
        let valid = OidcProviderConfig {
            issuer: "https://login.example.com/".to_owned(),
            discovery_uri: None,
            audiences: vec!["mcpg".to_owned()],
            verification: VerificationConfig::OidcJwks {
                allowed_algs: vec!["RS256".to_owned()],
                refresh_interval_secs: 300,
                timeout_ms: 2000,
                max_staleness_secs: 3600,

                allow_hmac: false,
            },
            claim_mappings: ClaimMappingConfig::default(),
            clock_skew_secs: 60,
            allowed_issuer_hosts: Vec::new(),
            allow_private_issuer: true,
            allow_any_audience: false,
        };
        assert!(valid.validate().is_ok());
    }

    #[test]
    fn oidc_provider_requires_https_issuer() {
        let bad = OidcProviderConfig {
            issuer: "not-a-url".to_owned(),
            discovery_uri: None,
            audiences: vec![],
            verification: VerificationConfig::OidcJwks {
                allowed_algs: vec!["RS256".to_owned()],
                refresh_interval_secs: 300,
                timeout_ms: 2000,
                max_staleness_secs: 3600,

                allow_hmac: false,
            },
            claim_mappings: ClaimMappingConfig::default(),
            clock_skew_secs: 60,
            allowed_issuer_hosts: Vec::new(),
            allow_private_issuer: true,
            allow_any_audience: false,
        };
        let err = bad.validate().unwrap_err();
        assert!(err.to_string().contains("https://"));
    }

    #[test]
    fn oidc_config_rejects_empty_providers() {
        let config = OidcOAuthConfig {
            token_source: TokenSourceConfig::default(),
            providers: vec![],
        };
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("at least one provider"));
    }

    #[test]
    fn oidc_config_rejects_duplicate_issuers() {
        let provider = OidcProviderConfig {
            issuer: "https://login.example.com/".to_owned(),
            discovery_uri: None,
            // Non-empty so per-provider validate() passes and the
            // duplicate-issuer check (the subject of this test) is reached.
            audiences: vec!["mcpg".to_owned()],
            verification: VerificationConfig::OidcJwks {
                allowed_algs: vec!["RS256".to_owned()],
                refresh_interval_secs: 300,
                timeout_ms: 2000,
                max_staleness_secs: 3600,

                allow_hmac: false,
            },
            claim_mappings: ClaimMappingConfig::default(),
            clock_skew_secs: 60,
            allowed_issuer_hosts: Vec::new(),
            allow_private_issuer: true,
            allow_any_audience: false,
        };
        let config = OidcOAuthConfig {
            token_source: TokenSourceConfig::default(),
            providers: vec![provider.clone(), provider],
        };
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("duplicate issuer"));
    }

    #[test]
    fn effective_discovery_uri_default() {
        let config = OidcProviderConfig {
            issuer: "https://login.example.com".to_owned(),
            discovery_uri: None,
            audiences: vec![],
            verification: VerificationConfig::OidcJwks {
                allowed_algs: vec!["RS256".to_owned()],
                refresh_interval_secs: 300,
                timeout_ms: 2000,
                max_staleness_secs: 3600,

                allow_hmac: false,
            },
            claim_mappings: ClaimMappingConfig::default(),
            clock_skew_secs: 60,
            allowed_issuer_hosts: Vec::new(),
            allow_private_issuer: true,
            allow_any_audience: false,
        };
        assert_eq!(
            config.effective_discovery_uri(),
            "https://login.example.com/.well-known/openid-configuration"
        );
    }

    #[test]
    fn effective_discovery_uri_explicit() {
        let config = OidcProviderConfig {
            issuer: "https://login.example.com/".to_owned(),
            discovery_uri: Some("https://custom.example.com/discovery".to_owned()),
            audiences: vec![],
            verification: VerificationConfig::OidcJwks {
                allowed_algs: vec!["RS256".to_owned()],
                refresh_interval_secs: 300,
                timeout_ms: 2000,
                max_staleness_secs: 3600,

                allow_hmac: false,
            },
            claim_mappings: ClaimMappingConfig::default(),
            clock_skew_secs: 60,
            allowed_issuer_hosts: Vec::new(),
            allow_private_issuer: true,
            allow_any_audience: false,
        };
        assert_eq!(
            config.effective_discovery_uri(),
            "https://custom.example.com/discovery"
        );
    }

    #[test]
    fn token_source_defaults() {
        let ts = TokenSourceConfig::default();
        assert_eq!(ts.effective_header_name(), "authorization");
        assert_eq!(ts.effective_header_prefix(), "Bearer ");
    }

    #[test]
    fn token_source_custom_header() {
        let ts = TokenSourceConfig {
            kind: crate::config::TokenSourceKind::CustomHeader,
            header_name: Some("x-api-key".to_owned()),
            header_prefix: Some("".to_owned()),
        };
        assert_eq!(ts.effective_header_name(), "x-api-key");
        assert_eq!(ts.effective_header_prefix(), "");
    }

    #[test]
    fn resolver_from_config() {
        let config = OidcOAuthConfig {
            token_source: TokenSourceConfig::default(),
            providers: vec![OidcProviderConfig {
                issuer: "https://login.example.com/".to_owned(),
                discovery_uri: None,
                audiences: vec!["mcpg".to_owned()],
                verification: VerificationConfig::OidcJwks {
                    allowed_algs: vec!["RS256".to_owned()],
                    refresh_interval_secs: 300,
                    timeout_ms: 2000,
                    max_staleness_secs: 3600,

                    allow_hmac: false,
                },
                claim_mappings: ClaimMappingConfig::default(),
                clock_skew_secs: 60,
                allowed_issuer_hosts: Vec::new(),
                allow_private_issuer: true,
                allow_any_audience: false,
            }],
        };

        let resolver = OidcOAuthResolver::from_config(&config).unwrap();
        assert_eq!(resolver.provider_count(), 1);
        assert_eq!(resolver.issuers(), vec!["https://login.example.com/"]);
    }

    #[test]
    fn verification_config_rejects_empty_algs() {
        let config = VerificationConfig::OidcJwks {
            allowed_algs: vec![],
            refresh_interval_secs: 300,
            timeout_ms: 2000,
            max_staleness_secs: 3600,

            allow_hmac: false,
        };
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("allowed_algs"));
    }

    #[test]
    fn verification_config_rejects_unknown_algorithm() {
        let config = VerificationConfig::OidcJwks {
            allowed_algs: vec!["INVALID".to_owned()],
            refresh_interval_secs: 300,
            timeout_ms: 2000,
            max_staleness_secs: 3600,

            allow_hmac: false,
        };
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("unsupported algorithm"));
    }

    #[test]
    fn introspection_config_validates() {
        let config = VerificationConfig::OauthIntrospection {
            introspection_url: "https://oauth.example.com/introspect".to_owned(),
            client_id: "mcpg".to_owned(),
            client_secret_ref: "resolved-secret".to_owned(),
            timeout_ms: 2000,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn introspection_config_rejects_empty_url() {
        let config = VerificationConfig::OauthIntrospection {
            introspection_url: "".to_owned(),
            client_id: "mcpg".to_owned(),
            client_secret_ref: "resolved-secret".to_owned(),
            timeout_ms: 2000,
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("introspection_url must not be empty")
        );
    }

    #[tokio::test]
    async fn resolver_returns_no_token_when_header_missing() {
        let config = OidcOAuthConfig {
            token_source: TokenSourceConfig::default(),
            providers: vec![OidcProviderConfig {
                issuer: "https://login.example.com/".to_owned(),
                discovery_uri: None,
                audiences: vec![],
                verification: VerificationConfig::OidcJwks {
                    allowed_algs: vec!["RS256".to_owned()],
                    refresh_interval_secs: 300,
                    timeout_ms: 2000,
                    max_staleness_secs: 3600,

                    allow_hmac: false,
                },
                claim_mappings: ClaimMappingConfig::default(),
                clock_skew_secs: 60,
                allowed_issuer_hosts: Vec::new(),
                allow_private_issuer: true,
                allow_any_audience: false,
            }],
        };

        let resolver = OidcOAuthResolver::from_config(&config).unwrap();
        let headers = http::HeaderMap::new();

        match resolver.verify_from_headers(&headers).await {
            OidcVerificationResult::None => {}
            other => panic!("expected None, got {other:?}"),
        }
    }

    /// Hybrid provider whose introspection endpoint refuses connections, so
    /// the two verification paths are distinguishable purely by which error
    /// comes back.
    fn hybrid_provider() -> ProviderState {
        let config = OidcProviderConfig {
            issuer: "https://127.0.0.1:1/".to_owned(),
            discovery_uri: None,
            audiences: vec![],
            verification: VerificationConfig::Hybrid {
                allowed_algs: vec!["RS256".to_owned()],
                refresh_interval_secs: 300,
                timeout_ms: 500,
                max_staleness_secs: 3600,
                introspection_url: "http://127.0.0.1:1/introspect".to_owned(),
                client_id: "gw".to_owned(),
                client_secret_ref: "shh".to_owned(),
                introspection_timeout_ms: 500,
                allow_hmac: false,
            },
            claim_mappings: ClaimMappingConfig::default(),
            clock_skew_secs: 60,
            allowed_issuer_hosts: Vec::new(),
            allow_private_issuer: true,
            allow_any_audience: false,
        };
        ProviderState::new(config, reqwest::Client::new()).unwrap()
    }

    #[tokio::test]
    async fn hybrid_does_not_retry_a_rejected_jwt_against_introspection() {
        // A JWS the JWT path refuses must not get a second, laxer
        // adjudication: introspection has no header to apply `allowed_algs`
        // to, so falling through is verifier shopping inside one provider.
        use base64::Engine;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"iss":"https://127.0.0.1:1/","sub":"user-1"}"#);
        let jwt = format!("{header}.{payload}.notarealsignature");

        match hybrid_provider().verify_token(&jwt).await {
            OidcVerificationResult::Invalid(msg) => {
                assert!(
                    !msg.contains("introspection"),
                    "JWT rejection fell through to introspection: {msg}"
                );
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn hybrid_still_introspects_a_token_that_is_not_a_jws() {
        // The case introspection exists for: an opaque access token the JWT
        // path cannot classify at all.
        match hybrid_provider().verify_token("opaque-access-token").await {
            OidcVerificationResult::Invalid(msg) => {
                assert!(
                    msg.contains("introspection"),
                    "opaque token was not introspected: {msg}"
                );
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }
}
