# Lenso Passkey Auth context

## Outcome

An already-authenticated user can register, inspect, and revoke WebAuthn
passkeys. A trusted ingress Adapter can run a passwordless ceremony for a
known canonical subject and receive the App's normal opaque session credential.

## Ownership

- `lenso.auth.passkey@1` owns the portable ceremony and management contract.
- `lenso-auth-passkey-plugin` owns RP-bound WebAuthn credentials, server-side
  ceremony state, one-time challenges, labels, counters, revisions,
  and caller-scoped command receipts in its PostgreSQL schema.
- Identity Directory owns canonical subjects and active/disabled status.
- Credential Issuer owns App sessions and session credentials.
- An ingress Adapter owns HTTP, origin routing, cookies, browser JavaScript,
  CSRF, and credential transport.

## Invariants

- RP ID and exact origins are immutable configuration for a Plugin generation.
- `webauthn-rs` verifies registration and authentication responses; this
  repository does not implement WebAuthn cryptography.
- Ceremony state never crosses the Capability boundary and is consumed once,
  including after an invalid finish attempt.
- Registration/list/revoke require a valid user Actor assertion whose subject
  matches the requested subject, plus a configured management caller.
- Begin/finish authentication require a configured authentication caller.
- Directory status is rechecked before registration and session issuance.
- Optimistic revisions protect credential-set mutation. Caller-scoped
  idempotency receipts reject key reuse with a different intent.
- Runtime/storage failures never become anonymous success.

## Known seam

`lenso.auth.credential-issuer@1` version 1.1 has no idempotency key on `issue`.
The Plugin therefore moves a verified authentication command to an `issuing`
state before the external call. A crash in that narrow window is fail-closed:
the command remains in progress and is not automatically retried, avoiding an
unbounded duplicate-session claim. Production recovery needs an idempotent
Credential Issuer operation or a durable workflow coordinator.
