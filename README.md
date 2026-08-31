# Lenso Passkey Auth Plugin

`lenso-auth-passkey-plugin` adds passwordless WebAuthn passkeys to a Lenso App
without taking ownership of canonical identities or App sessions.

The repository contains:

- `lenso-capability-passkey-auth`, the portable `lenso.auth.passkey@1` role;
- `lenso-auth-passkey-plugin`, a linked Rust implementation backed by an owned
  PostgreSQL schema and `webauthn-rs` verification.

The Plugin requires a bound Identity Directory to recheck subject status, a
Credential Issuer to create the normal App session after authentication, and
Secrets to resolve its database URL and idempotency-receipt encryption key.
Browser HTTP routes, cookies, JavaScript calls to `navigator.credentials`, and
account-recovery policy remain separate Adapter/product concerns.

See [the Plugin card](docs/plugin-card.md) for the ownership boundary and
[the release process](docs/release-process.md) for validation and publication.

## Local validation

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
lenso-contract-codegen check crates/lenso-capability-passkey-auth/capability.json \
  --rust crates/lenso-capability-passkey-auth/src/generated.rs
LENSO_PACKAGE_ALLOW_DIRTY=1 \
  ./scripts/check-public-packages.sh
./scripts/check-repository-boundary.sh
```

Set `LENSO_POSTGRES_TEST_URL` and run ignored tests serially for the PostgreSQL
acceptance suite.
