# mcpg-plugin-identity-oidc-core

OIDC/OAuth verification library for MCPG: provider discovery, JWKS caching,
JWT and token-introspection verification, and the configuration types the
gateway validates against. This is the shared core behind the OIDC identity
plugin — a plain Rust library, not a loadable plugin itself.

## Building and testing

```sh
cargo build
cargo test
```
