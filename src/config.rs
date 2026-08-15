//! OIDC/OAuth identity plugin configuration types.
//!
//! These are standalone config types that mirror the gateway's config,
//! enabling this crate to be used independently. The gateway provides
//! a conversion bridge so the existing YAML config still works.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Top-level OIDC config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OidcOAuthConfig {
    /// How to extract the bearer token from the request.
    #[serde(default)]
    pub token_source: TokenSourceConfig,
    /// One or more identity providers. At least one is required.
    pub providers: Vec<OidcProviderConfig>,
}

impl OidcOAuthConfig {
    pub fn validate(&self) -> Result<()> {
        if self.providers.is_empty() {
            return Err(anyhow::anyhow!(
                "oidc_oauth.providers must have at least one provider"
            ));
        }
        for (i, provider) in self.providers.iter().enumerate() {
            provider
                .validate()
                .with_context(|| format!("oidc_oauth.providers[{i}]"))?;
        }
        let mut issuers = std::collections::HashSet::new();
        for provider in &self.providers {
            if !issuers.insert(&provider.issuer) {
                return Err(anyhow::anyhow!(
                    "oidc_oauth.providers: duplicate issuer '{}'",
                    provider.issuer
                ));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Token source
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TokenSourceConfig {
    #[serde(default = "default_token_source_kind")]
    pub kind: TokenSourceKind,
    #[serde(default)]
    pub header_name: Option<String>,
    #[serde(default)]
    pub header_prefix: Option<String>,
}

impl Default for TokenSourceConfig {
    fn default() -> Self {
        Self {
            kind: TokenSourceKind::AuthorizationBearer,
            header_name: None,
            header_prefix: None,
        }
    }
}

impl TokenSourceConfig {
    pub fn effective_header_name(&self) -> &str {
        match self.kind {
            TokenSourceKind::AuthorizationBearer => "authorization",
            TokenSourceKind::CustomHeader => self.header_name.as_deref().unwrap_or("authorization"),
        }
    }

    pub fn effective_header_prefix(&self) -> &str {
        if let Some(ref prefix) = self.header_prefix {
            return prefix;
        }
        match self.kind {
            TokenSourceKind::AuthorizationBearer => "Bearer ",
            TokenSourceKind::CustomHeader => "",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TokenSourceKind {
    AuthorizationBearer,
    CustomHeader,
}

fn default_token_source_kind() -> TokenSourceKind {
    TokenSourceKind::AuthorizationBearer
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OidcProviderConfig {
    pub issuer: String,
    #[serde(default)]
    pub discovery_uri: Option<String>,
    #[serde(default)]
    pub audiences: Vec<String>,
    pub verification: VerificationConfig,
    #[serde(default)]
    pub claim_mappings: ClaimMappingConfig,
    #[serde(default = "default_clock_skew_secs")]
    pub clock_skew_secs: u64,
    /// Optional hostname allowlist for OIDC discovery and JWKS fetches.
    /// Empty means only the private-range blocklist applies.
    #[serde(default)]
    pub allowed_issuer_hosts: Vec<String>,
    /// Dev escape hatch: permit private/loopback ranges in OIDC URLs.
    /// Production MUST leave this false.
    #[serde(default)]
    pub allow_private_issuer: bool,
    /// Explicit opt-in to SKIP audience (`aud`) validation. When false
    /// (the default) an empty `audiences` is a hard config error at boot —
    /// otherwise a mistyped `audiences` key would silently disable
    /// audience binding and accept tokens minted for any gateway. Production
    /// MUST leave this false and set `audiences`; only the rare provider that
    /// genuinely issues no `aud` claim should opt in.
    #[serde(default)]
    pub allow_any_audience: bool,
}

impl OidcProviderConfig {
    pub fn effective_discovery_uri(&self) -> String {
        if let Some(ref uri) = self.discovery_uri {
            return uri.clone();
        }
        let base = self.issuer.trim_end_matches('/');
        format!("{base}/.well-known/openid-configuration")
    }

    pub fn validate(&self) -> Result<()> {
        if self.issuer.trim().is_empty() {
            return Err(anyhow::anyhow!("issuer must not be empty"));
        }
        if !self.issuer.starts_with("https://") && !self.issuer.starts_with("http://") {
            return Err(anyhow::anyhow!(
                "issuer '{}' must start with https:// or http://",
                self.issuer
            ));
        }
        if let Some(ref uri) = self.discovery_uri
            && !uri.starts_with("https://")
            && !uri.starts_with("http://")
        {
            return Err(anyhow::anyhow!(
                "discovery_uri must start with https:// or http://"
            ));
        }
        if self.clock_skew_secs > MAX_CLOCK_SKEW_SECS {
            return Err(anyhow::anyhow!(
                "clock_skew_secs {} exceeds the maximum {}s — a larger leeway is a token \
                 replay window, not clock-drift tolerance",
                self.clock_skew_secs,
                MAX_CLOCK_SKEW_SECS
            ));
        }
        // Servers MUST validate audience binding. An empty
        // `audiences` silently disables `aud` validation (accepting tokens
        // minted for any gateway) — almost always a mistyped key. Refuse at
        // boot unless the operator explicitly opted out via
        // `allow_any_audience`, mirroring the `allow_private_issuer` escape
        // hatch. With `deny_unknown_fields` on the config struct a misspelled
        // `audiences` key now also hard-fails parse, so both failure modes
        // are caught fail-fast.
        if self.audiences.is_empty() && !self.allow_any_audience {
            return Err(anyhow::anyhow!(
                "audiences is empty — refusing to skip `aud` validation (a token minted \
                 for another gateway would be accepted). Set `audiences`, or for the rare \
                 provider that issues no audience claim opt in explicitly with \
                 `allow_any_audience: true`"
            ));
        }
        self.verification.validate()?;
        Ok(())
    }
}

/// Token exp/nbf leeway in SECONDS (consumed as jsonwebtoken `leeway`).
/// 60s absorbs normal clock drift; a large value silently widens the
/// replay window for a leaked short-lived token.
fn default_clock_skew_secs() -> u64 {
    60
}

/// Hard upper bound on `clock_skew_secs`. Beyond a few minutes the leeway
/// stops being clock-drift tolerance and becomes a replay window.
const MAX_CLOCK_SKEW_SECS: u64 = 300;

/// Hard upper bound on `max_staleness_secs`. Serving a stale JWKS is a
/// deliberate availability trade; past a day it stops covering an IdP
/// outage and becomes a window in which a revoked signing key still
/// verifies tokens.
const MAX_JWKS_STALENESS_SECS: u64 = 86_400;

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VerificationConfig {
    OidcJwks {
        #[serde(default = "default_allowed_algs")]
        allowed_algs: Vec<String>,
        #[serde(default = "default_jwks_refresh_interval_secs")]
        refresh_interval_secs: u64,
        #[serde(default = "default_jwks_timeout_ms")]
        timeout_ms: u64,
        #[serde(default = "default_jwks_max_staleness_secs")]
        max_staleness_secs: u64,
        /// Security: HMAC algorithms share a secret across the trust
        /// boundary and are unsuitable for most OIDC deployments.
        /// Operators must explicitly opt in.
        #[serde(default)]
        allow_hmac: bool,
    },
    OauthIntrospection {
        introspection_url: String,
        client_id: String,
        client_secret_ref: String,
        #[serde(default = "default_introspection_timeout_ms")]
        timeout_ms: u64,
    },
    /// JWTs are verified against the JWKS; opaque tokens are introspected.
    ///
    /// The two paths are selected by the token's *shape*, not by whether the
    /// first one accepted it. Introspection has no header to apply
    /// `allowed_algs` to, so a token that is a JWS is adjudicated by the JWT
    /// path and that verdict stands — a rejection there is never retried
    /// against the authorization server.
    Hybrid {
        #[serde(default = "default_allowed_algs")]
        allowed_algs: Vec<String>,
        #[serde(default = "default_jwks_refresh_interval_secs")]
        refresh_interval_secs: u64,
        #[serde(default = "default_jwks_timeout_ms")]
        timeout_ms: u64,
        #[serde(default = "default_jwks_max_staleness_secs")]
        max_staleness_secs: u64,
        introspection_url: String,
        client_id: String,
        client_secret_ref: String,
        #[serde(default = "default_introspection_timeout_ms")]
        introspection_timeout_ms: u64,
        /// See `OidcJwks.allow_hmac`.
        #[serde(default)]
        allow_hmac: bool,
    },
}

impl VerificationConfig {
    pub fn validate(&self) -> Result<()> {
        fn check_algs(algs: &[String], allow_hmac: bool) -> Result<()> {
            if algs.is_empty() {
                return Err(anyhow::anyhow!(
                    "verification.allowed_algs must not be empty"
                ));
            }
            for alg in algs {
                parse_algorithm(alg)?;
                if is_hmac_alg(alg) && !allow_hmac {
                    return Err(anyhow::anyhow!(
                        "verification.allowed_algs contains HMAC algorithm '{alg}'; \
                         set verification.allow_hmac=true only if your IdP only signs with HS*"
                    ));
                }
            }
            Ok(())
        }

        fn check_staleness(secs: u64) -> Result<()> {
            if secs > MAX_JWKS_STALENESS_SECS {
                return Err(anyhow::anyhow!(
                    "verification.max_staleness_secs {} exceeds the maximum {}s — past a day \
                     a stale JWKS stops covering an IdP outage and becomes a window in which \
                     a revoked signing key still verifies tokens",
                    secs,
                    MAX_JWKS_STALENESS_SECS
                ));
            }
            Ok(())
        }

        match self {
            VerificationConfig::OidcJwks {
                allowed_algs,
                allow_hmac,
                max_staleness_secs,
                ..
            } => {
                check_algs(allowed_algs, *allow_hmac)?;
                check_staleness(*max_staleness_secs)?;
            }
            VerificationConfig::OauthIntrospection {
                introspection_url,
                client_id,
                client_secret_ref,
                ..
            } => {
                if introspection_url.trim().is_empty() {
                    return Err(anyhow::anyhow!(
                        "verification.introspection_url must not be empty"
                    ));
                }
                if !introspection_url.starts_with("https://")
                    && !introspection_url.starts_with("http://")
                {
                    return Err(anyhow::anyhow!(
                        "verification.introspection_url must start with https:// or http:///"
                    ));
                }
                if client_id.trim().is_empty() {
                    return Err(anyhow::anyhow!("verification.client_id must not be empty"));
                }
                if client_secret_ref.trim().is_empty() {
                    return Err(anyhow::anyhow!(
                        "verification.client_secret_ref must not be empty"
                    ));
                }
            }
            VerificationConfig::Hybrid {
                allowed_algs,
                introspection_url,
                client_id,
                client_secret_ref,
                allow_hmac,
                max_staleness_secs,
                ..
            } => {
                check_algs(allowed_algs, *allow_hmac)?;
                check_staleness(*max_staleness_secs)?;
                if introspection_url.trim().is_empty() {
                    return Err(anyhow::anyhow!(
                        "verification.introspection_url must not be empty"
                    ));
                }
                if client_id.trim().is_empty() {
                    return Err(anyhow::anyhow!("verification.client_id must not be empty"));
                }
                if client_secret_ref.trim().is_empty() {
                    return Err(anyhow::anyhow!(
                        "verification.client_secret_ref must not be empty"
                    ));
                }
            }
        }
        Ok(())
    }
}

fn default_allowed_algs() -> Vec<String> {
    vec!["RS256".to_owned()]
}

/// Returns true for HMAC symmetric algorithms (HS256/HS384/HS512).
pub fn is_hmac_alg(name: &str) -> bool {
    matches!(name, "HS256" | "HS384" | "HS512")
}
/// How often the JWKS/discovery cache is proactively refreshed, in
/// SECONDS. This is the only proactive freshness bound, so it is also
/// the floor on how long a key the IdP has revoked keeps verifying
/// tokens.
fn default_jwks_refresh_interval_secs() -> u64 {
    300
}
fn default_jwks_timeout_ms() -> u64 {
    2000
}
/// How long a stale JWKS may still be served when refresh fails, in
/// SECONDS. Spanning a short IdP outage is worth more than failing
/// closed; spanning a key rotation is not.
fn default_jwks_max_staleness_secs() -> u64 {
    3600
}
fn default_introspection_timeout_ms() -> u64 {
    2000
}

/// Parse an algorithm name string into a jsonwebtoken Algorithm.
pub fn parse_algorithm(name: &str) -> Result<jsonwebtoken::Algorithm> {
    match name {
        "RS256" => Ok(jsonwebtoken::Algorithm::RS256),
        "RS384" => Ok(jsonwebtoken::Algorithm::RS384),
        "RS512" => Ok(jsonwebtoken::Algorithm::RS512),
        "PS256" => Ok(jsonwebtoken::Algorithm::PS256),
        "PS384" => Ok(jsonwebtoken::Algorithm::PS384),
        "PS512" => Ok(jsonwebtoken::Algorithm::PS512),
        "ES256" => Ok(jsonwebtoken::Algorithm::ES256),
        "ES384" => Ok(jsonwebtoken::Algorithm::ES384),
        "EdDSA" => Ok(jsonwebtoken::Algorithm::EdDSA),
        "HS256" => Ok(jsonwebtoken::Algorithm::HS256),
        "HS384" => Ok(jsonwebtoken::Algorithm::HS384),
        "HS512" => Ok(jsonwebtoken::Algorithm::HS512),
        other => Err(anyhow::anyhow!("unsupported algorithm: '{other}'")),
    }
}

// ---------------------------------------------------------------------------
// Claim mappings
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimMappingConfig {
    #[serde(default = "default_subject_claim")]
    pub subject_claim: String,
    #[serde(default)]
    pub group_claim_paths: Vec<String>,
    #[serde(default)]
    pub role_claim_paths: Vec<String>,
    #[serde(default = "default_scope_claim_paths")]
    pub scope_claim_paths: Vec<String>,
    #[serde(default)]
    pub attribute_claim_mappings: BTreeMap<String, String>,
}

impl Default for ClaimMappingConfig {
    fn default() -> Self {
        Self {
            subject_claim: default_subject_claim(),
            group_claim_paths: vec![],
            role_claim_paths: vec![],
            scope_claim_paths: default_scope_claim_paths(),
            attribute_claim_mappings: BTreeMap::new(),
        }
    }
}

fn default_subject_claim() -> String {
    "sub".to_owned()
}
fn default_scope_claim_paths() -> Vec<String> {
    vec!["scope".to_owned(), "scp".to_owned()]
}

#[cfg(test)]
mod clock_skew_tests {
    use super::*;

    fn provider(clock_skew_secs: u64) -> OidcProviderConfig {
        OidcProviderConfig {
            issuer: "https://login.example.com/".to_owned(),
            discovery_uri: None,
            audiences: vec!["mcpg".to_owned()],
            verification: VerificationConfig::OidcJwks {
                allowed_algs: vec!["RS256".to_owned()],
                refresh_interval_secs: default_jwks_refresh_interval_secs(),
                timeout_ms: default_jwks_timeout_ms(),
                max_staleness_secs: default_jwks_max_staleness_secs(),
                allow_hmac: false,
            },
            claim_mappings: ClaimMappingConfig::default(),
            clock_skew_secs,
            allowed_issuer_hosts: Vec::new(),
            allow_private_issuer: true,
            allow_any_audience: false,
        }
    }

    /// The default leeway is 60 SECONDS, not milliseconds — a larger
    /// value consumed as seconds would yield a ~16.7h replay window.
    #[test]
    fn default_clock_skew_is_60_seconds() {
        assert_eq!(default_clock_skew_secs(), 60);
    }

    /// An over-large leeway is a replay window; validate must reject it.
    #[test]
    fn rejects_excessive_clock_skew() {
        let err = provider(60_000).validate().unwrap_err().to_string();
        assert!(err.contains("clock_skew_secs"), "got: {err}");
        provider(60).validate().unwrap();
        provider(MAX_CLOCK_SKEW_SECS).validate().unwrap();
    }

    /// Both JWKS windows are SECONDS. A millisecond magnitude here is a
    /// 1000x amplification: 300_000 would refresh every 3.5 days and
    /// 3_600_000 would serve a revoked signing key for 41.7 days.
    #[test]
    fn jwks_window_defaults_are_seconds() {
        assert_eq!(default_jwks_refresh_interval_secs(), 300);
        assert_eq!(default_jwks_max_staleness_secs(), 3_600);
    }

    /// The stale-serve window is bounded, so a unit slip or a careless
    /// value cannot reopen a multi-week revocation gap.
    #[test]
    fn rejects_excessive_jwks_staleness() {
        let staleness = |secs| VerificationConfig::OidcJwks {
            allowed_algs: default_allowed_algs(),
            refresh_interval_secs: default_jwks_refresh_interval_secs(),
            timeout_ms: default_jwks_timeout_ms(),
            max_staleness_secs: secs,
            allow_hmac: false,
        };
        let err = staleness(3_600_000).validate().unwrap_err().to_string();
        assert!(err.contains("max_staleness_secs"), "got: {err}");
        staleness(MAX_JWKS_STALENESS_SECS).validate().unwrap();
        staleness(default_jwks_max_staleness_secs())
            .validate()
            .unwrap();
    }
}

#[cfg(test)]
mod hmac_opt_in_tests {
    use super::*;

    fn oidc_jwks(allowed_algs: Vec<String>, allow_hmac: bool) -> VerificationConfig {
        VerificationConfig::OidcJwks {
            allowed_algs,
            refresh_interval_secs: default_jwks_refresh_interval_secs(),
            timeout_ms: default_jwks_timeout_ms(),
            max_staleness_secs: default_jwks_max_staleness_secs(),
            allow_hmac,
        }
    }

    /// HS256 allowed but allow_hmac false — validation MUST fail.
    #[test]
    fn rejects_hmac_without_opt_in() {
        let cfg = oidc_jwks(vec!["HS256".to_owned()], false);
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("HMAC"), "got: {err}");
    }

    /// allow_hmac=true lets HS256 through.
    #[test]
    fn accepts_hmac_with_opt_in() {
        let cfg = oidc_jwks(vec!["HS256".to_owned()], true);
        cfg.validate().unwrap();
    }

    /// RS256-only configurations are unaffected by the flag.
    #[test]
    fn rs256_only_unaffected_by_flag() {
        oidc_jwks(vec!["RS256".to_owned()], false)
            .validate()
            .unwrap();
        oidc_jwks(vec!["RS256".to_owned()], true)
            .validate()
            .unwrap();
    }
}

#[cfg(test)]
mod deny_unknown_and_audience_tests {
    use super::*;

    const VALID_PROVIDER_JSON: &str = r#"{
        "issuer": "https://login.example.com/",
        "audiences": ["mcpg"],
        "verification": { "kind": "oidc_jwks", "allowed_algs": ["RS256"] }
    }"#;

    /// A well-formed provider config still parses (guards the negatives below).
    #[test]
    fn valid_provider_config_parses() {
        let cfg: OidcProviderConfig = serde_json::from_str(VALID_PROVIDER_JSON).unwrap();
        assert_eq!(cfg.audiences, vec!["mcpg".to_owned()]);
        cfg.validate().unwrap();
    }

    /// SECURITY: a mistyped `audiences` key (here `audiance`) is now a hard
    /// parse error (deny_unknown_fields), not a silently-empty audience list.
    #[test]
    fn misspelled_audiences_key_is_rejected_at_parse() {
        let json = r#"{
            "issuer": "https://login.example.com/",
            "audiance": ["mcpg"],
            "verification": { "kind": "oidc_jwks", "allowed_algs": ["RS256"] }
        }"#;
        let err = serde_json::from_str::<OidcProviderConfig>(json).unwrap_err();
        assert!(
            err.to_string().contains("audiance") || err.to_string().contains("unknown field"),
            "expected unknown-field parse error, got: {err}"
        );
    }

    /// A stray key in the verification (tagged) enum is rejected too.
    #[test]
    fn unknown_key_in_verification_enum_is_rejected() {
        let json = r#"{
            "issuer": "https://login.example.com/",
            "audiences": ["mcpg"],
            "verification": { "kind": "oidc_jwks", "allowed_algs": ["RS256"], "bogus": 1 }
        }"#;
        assert!(serde_json::from_str::<OidcProviderConfig>(json).is_err());
    }

    /// Empty audiences without the explicit opt-in is a hard
    /// validation error (otherwise `aud` validation is silently skipped).
    #[test]
    fn empty_audiences_without_opt_in_fails_validate() {
        let mut cfg: OidcProviderConfig = serde_json::from_str(VALID_PROVIDER_JSON).unwrap();
        cfg.audiences = Vec::new();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("audiences"), "got: {err}");
    }

    /// The explicit opt-in lets a no-audience provider through.
    #[test]
    fn empty_audiences_with_opt_in_validates() {
        let mut cfg: OidcProviderConfig = serde_json::from_str(VALID_PROVIDER_JSON).unwrap();
        cfg.audiences = Vec::new();
        cfg.allow_any_audience = true;
        cfg.validate().unwrap();
    }
}
