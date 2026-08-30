# Agent instructions

This repository owns only the portable Passkey Capability and its removable
PostgreSQL implementation. Read `CONTEXT.md`, local ADRs, and
`docs/release-process.md` before architecture or release work.

Use source-first Capability authoring: change `src/contract.rs`, intentionally
refresh the Descriptor/Schemas with `LENSO_UPDATE_CONTRACT_SNAPSHOT=1`, then
regenerate `src/generated.rs` with `lenso-contract-codegen`. Generated files
must never be edited by hand.

Keep browser HTTP routes, cookie policy, canonical identities, App sessions,
account recovery, Organization, and RBAC outside this repository. Every
registration or management operation requires both an allowed caller Instance
and a verified user Actor assertion. Authentication operations require an
allowed ingress caller and never infer ambient Auth authority.

Run Cargo through
`/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo`. Use concise
imperative Conventional Commit subjects under 72 characters.
