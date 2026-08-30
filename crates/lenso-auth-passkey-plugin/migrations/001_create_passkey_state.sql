CREATE TABLE passkey_subjects (
    subject_id TEXT PRIMARY KEY,
    webauthn_user_id UUID NOT NULL UNIQUE,
    revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (char_length(subject_id) BETWEEN 1 AND 256)
);

CREATE TABLE passkeys (
    passkey_id TEXT PRIMARY KEY,
    subject_id TEXT NOT NULL REFERENCES passkey_subjects(subject_id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE,
    public_key JSONB NOT NULL,
    passkey JSONB NOT NULL,
    label TEXT NOT NULL,
    sign_count BIGINT NOT NULL CHECK (sign_count >= 0),
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    CHECK (char_length(passkey_id) BETWEEN 1 AND 128),
    CHECK (char_length(label) BETWEEN 1 AND 128)
);

CREATE INDEX passkeys_subject_active_idx
    ON passkeys (subject_id, created_at, passkey_id)
    WHERE revoked_at IS NULL;

CREATE TABLE passkey_challenges (
    challenge_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('registration', 'authentication')),
    caller_instance TEXT NOT NULL,
    subject_id TEXT NOT NULL REFERENCES passkey_subjects(subject_id) ON DELETE CASCADE,
    expected_revision BIGINT NOT NULL CHECK (expected_revision >= 0),
    state JSONB NOT NULL,
    public_options JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    consumed_by_operation TEXT,
    consumed_by_idempotency_key TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (char_length(challenge_id) BETWEEN 1 AND 128),
    CHECK (char_length(caller_instance) BETWEEN 1 AND 128),
    CHECK (
        (consumed_at IS NULL AND consumed_by_operation IS NULL AND consumed_by_idempotency_key IS NULL)
        OR
        (consumed_at IS NOT NULL AND consumed_by_operation IS NOT NULL AND consumed_by_idempotency_key IS NOT NULL)
    )
);

CREATE INDEX passkey_challenges_expiry_idx ON passkey_challenges (expires_at);

CREATE TABLE passkey_commands (
    caller_instance TEXT NOT NULL,
    operation TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    intent_hash BYTEA NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('reserved', 'verifying', 'issuing', 'completed_success', 'completed_error')
    ),
    response_nonce BYTEA,
    response_ciphertext BYTEA,
    error_code TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (caller_instance, operation, idempotency_key),
    CHECK (char_length(caller_instance) BETWEEN 1 AND 128),
    CHECK (char_length(operation) BETWEEN 1 AND 64),
    CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    CHECK (octet_length(intent_hash) = 32),
    CHECK (
        (status = 'completed_success' AND response_nonce IS NOT NULL AND response_ciphertext IS NOT NULL AND error_code IS NULL AND completed_at IS NOT NULL)
        OR
        (status = 'completed_error' AND response_nonce IS NULL AND response_ciphertext IS NULL AND error_code IS NOT NULL AND completed_at IS NOT NULL)
        OR
        (status IN ('reserved', 'verifying', 'issuing') AND response_nonce IS NULL AND response_ciphertext IS NULL AND error_code IS NULL AND completed_at IS NULL)
    )
);

CREATE INDEX passkey_commands_retention_idx ON passkey_commands (completed_at, created_at);
