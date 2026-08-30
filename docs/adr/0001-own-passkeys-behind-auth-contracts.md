# ADR 0001: Own passkeys behind shared Auth contracts

- Status: accepted
- Date: 2026-08-30
- Upstream: Lenso ADR 0039 and ADR 0064

## Context

WebAuthn requires RP/origin validation, server-side ceremony state, durable
public-key credentials, signature counters, and one-time challenge handling.
Putting those facts in Account Auth would make passwordless login impossible to
remove independently and would give the account directory ownership of a
browser authentication protocol.

The existing `lenso.identity.directory@1` and
`lenso.auth.credential-issuer@1` roles already separate canonical subject
status from session issuance. Target Plugins can verify Auth Actor assertions
without receiving Auth signing authority.

## Decision

Create `lenso.auth.passkey@1` with begin/finish registration, begin/finish
authentication, list, and revoke request Operations. The linked PostgreSQL
Plugin owns passkey credentials, exact RP/origin policy, server-only serialized
`webauthn-rs` ceremony state, single-use expiry, signature counters, optimistic
revisions, and caller-scoped idempotency receipts.

Registration, listing, and revocation require both an allowed management caller
and a verified user Actor assertion matching the subject. Authentication
requires an explicitly allowed ingress caller. Directory status is rechecked
before credential registration and before session issuance. Credential Issuer
creates the ordinary App session after WebAuthn succeeds.

Use the safe `webauthn-rs` Passkey API. The two narrowly named `danger` features
are enabled only to persist ceremony state on the server and inspect the
credential object for durable public-key/counter columns. Neither serialized
state nor credential internals cross the Capability boundary.

## Consequences

- Removing the Plugin removes passkey login without deleting identities or
  sessions owned elsewhere.
- Browser routes, cookies, CSRF, and `navigator.credentials` remain Adapter
  work.
- Exact origins are configured; wildcard subdomains and arbitrary ports remain
  disabled.
- Credential Issuer 1.1 lacks idempotent issue. A verified command is marked
  `issuing` before that cross-Plugin call and ambiguous failure stays
  fail-closed. An idempotent issuer or workflow coordinator is required before
  claiming automated recovery from that crash window.
