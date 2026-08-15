//! OIDC/OAuth verification for MCPG — the library half.
//!
//! Discovery-document and JWKS caching, JWT verification, RFC 7662
//! introspection, hybrid mode, and claim extraction, plus the config
//! types those are driven by.
//!
//! This is deliberately NOT a plugin. The gateway links it directly: its
//! own config schema re-exports these types, config validation calls
//! `resolver::enforce_discovery_url_safety` (the SSRF guard) at load time,
//! and the authorization-server surface builds on the resolver. The plugin
//! ABI wrapper that turns this into `dev.mcpg.identity.oidc` lives in the
//! sibling `mcpg-plugin-identity-oidc` crate, which ships as a cdylib.

pub mod config;
pub mod resolver;

pub use config::{
    ClaimMappingConfig, OidcOAuthConfig, OidcProviderConfig, TokenSourceConfig, VerificationConfig,
    parse_algorithm,
};
pub use resolver::{OidcIdentity, OidcOAuthResolver, OidcVerificationResult};
