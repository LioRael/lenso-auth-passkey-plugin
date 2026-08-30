# Passkey Auth Plugin card

## Outcome

An authenticated user can add, inspect, and revoke passkeys. A trusted ingress
can authenticate a known canonical subject with WebAuthn and return the App's
normal opaque session credential.

## Package and slot

- Package: `lenso-auth-passkey-plugin`
- Plugin id: `lenso.auth.passkey`
- Root slot: `auth-methods`
- Capability: `lenso.auth.passkey@1`

## Provides

- `begin_registration` and `finish_registration`
- `begin_authentication` and `finish_authentication`
- `list_passkeys` and `revoke_passkey`

All are portable request Operations. The browser's WebAuthn request/response is
a validated raw JSON value; opaque server ceremony state never leaves the
Plugin.

## Requires

- `lenso.identity.directory@1/read_status` for active/disabled subject checks
- `lenso.auth.credential-issuer@1/issue` for App session issuance
- `lenso.secrets@1/resolve` for the PostgreSQL URL and receipt-encryption key
- a verified user Actor assertion for every registration/management request
- immutable management and authentication caller allowlists

## Owned facts and lifecycle

The Plugin owns a PostgreSQL schema containing stable WebAuthn user handles,
credential IDs, COSE public keys, complete serializable Passkey values,
signature counters, labels, last-use/revocation timestamps, credential-set and
credential revisions, one-time expiring ceremonies, and caller-scoped command
receipts. Successful receipt payloads are AES-256-GCM encrypted and bound to
caller, operation, and idempotency key.

`activate` resolves secrets and verifies an already-installed exact schema. It
does not migrate. Explicit `PasskeyOperator::setup/upgrade` workflows own
migrations. `deactivate` drops active cryptographic material and closes the
owned pool. There are no background tasks.

## Final authorization

Registration/list/revoke accept only a configured management caller and an
Ed25519-verified `user` Actor assertion whose subject exactly equals the
request. Begin/finish authentication accept only a configured ingress caller;
rejected or unknown subjects use the same invalid-credentials outcome.

## Deletion boundary

Removing the Plugin Instance, bindings, and owned schema removes passkey
behavior and state. Identity Directory subjects and Credential Issuer sessions
remain. Kernel has no passkey branch or ambient provider lookup.

## Deliberate limits

- v1 is subject-first authentication. Discoverable usernameless authentication
  needs a separate privacy-reviewed contract because it changes subject lookup
  and enumeration semantics.
- Attestation allowlists and enterprise device policy are not claimed. v1 uses
  the safe passkey API with user verification and no attestation trust list.
- Credential Issuer 1.1 has no idempotency input. Ambiguous failure after a
  verified assertion remains `operation_in_progress` and requires operator
  investigation; the Plugin does not automatically create a second session.
  Incomplete `reserved`, `verifying`, and `issuing` receipts are therefore
  never removed by automatic retention cleanup.
- HTTP endpoints, browser JavaScript, cookies, recovery, and UI contribution
  are separate Plugins/Adapters.
