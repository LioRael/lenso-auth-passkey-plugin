# Release process

This repository has two public Rust crates:

1. `lenso-capability-passkey-auth`
2. `lenso-auth-passkey-plugin`

Publication is manual-only from a clean, reviewed `main` checkout through
`.github/workflows/release-plz.yml`. A push to `main` may refresh the
Release-plz PR, but merging that PR does not publish.

## Trusted publishing and first releases

Trusted Publishing cannot allocate a new crates.io name. After all local and CI
gates pass on reviewed `main`, use a temporary crates.io token restricted to
new-package publication to allocate the two `0.1.0` names in dependency order,
then revoke it immediately. Never store it in Cargo credentials, GitHub
secrets, workflow logs, or shell history.

Configure a crates.io Trusted Publisher for both crates with:

- owner: `LioRael`
- repository: `lenso-auth-passkey-plugin`
- workflow: `release-plz.yml`
- environment: unset

The workflow has no Cargo registry token fallback. Live publication obtains a
short-lived crates.io credential through GitHub OIDC and requires `main`,
`live=true`, and the literal confirmation `publish`.

## Local gates

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
LENSO_PACKAGE_ALLOW_DIRTY=1 \
  ./scripts/check-public-packages.sh
./scripts/check-repository-boundary.sh
```

The package check fully verifies the Capability archive. It then creates the
Plugin archive using the unpublished Capability as a temporary bootstrap,
regenerates the archive-local lockfile against the Capability's normalized
package manifest, and checks, tests, and lints that consumer dependency graph.
Publish the Capability first; once its declared version is available in the
registry, the unpatched Plugin package verification must also pass before
publishing the Plugin.

Run PostgreSQL acceptance before publication:

```sh
LENSO_POSTGRES_TEST_URL=postgres://... \
  cargo test --locked --workspace -- --include-ignored --test-threads=1
```

The Capability Descriptor/Schemas and Rust projection must be fresh. The
PostgreSQL suite must prove caller-scoped command keys and one-time challenge
consumption. The software authenticator test must prove real registration,
authentication, and strict-origin rejection through `webauthn-rs`.
