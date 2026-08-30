use lenso_postgres_kit::OwnedPostgres;
use serde_json::Value;
use sqlx::{Postgres, Row, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::PasskeyPluginError;

#[derive(Debug)]
pub(crate) enum CommandClaim {
    Claimed,
    CompletedSuccess { nonce: Vec<u8>, ciphertext: Vec<u8> },
    CompletedError(String),
    Conflict,
    InProgress,
}

#[derive(Debug)]
pub(crate) struct SubjectRow {
    pub user_id: Uuid,
    pub revision: i64,
}

#[derive(Debug)]
pub(crate) struct PasskeyRow {
    pub passkey_id: String,
    pub credential_id: Vec<u8>,
    pub passkey: Value,
    pub label: String,
    pub sign_count: i64,
    pub revision: i64,
    pub created_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
    pub revoked_at: Option<OffsetDateTime>,
}

#[derive(Debug)]
pub(crate) struct ChallengeRow {
    pub caller_instance: String,
    pub subject: String,
    pub expected_revision: i64,
    pub state: Value,
    pub expires_at: OffsetDateTime,
    pub consumed_at: Option<OffsetDateTime>,
}

pub(crate) async fn prune(
    postgres: &OwnedPostgres,
    receipt_ttl_seconds: i64,
) -> Result<(), PasskeyPluginError> {
    sqlx::query("DELETE FROM passkey_challenges WHERE expires_at < now() - interval '1 day'")
        .execute(postgres.pool())
        .await
        .map_err(db("prune passkey challenges"))?;
    sqlx::query(
        "DELETE FROM passkey_commands WHERE completed_at IS NOT NULL AND completed_at < now() - make_interval(secs => $1)",
    )
    .bind(receipt_ttl_seconds)
    .execute(postgres.pool())
    .await
    .map_err(db("prune passkey command receipts"))?;
    Ok(())
}

pub(crate) async fn claim_command(
    postgres: &OwnedPostgres,
    caller: &str,
    operation: &str,
    idempotency_key: &str,
    intent_hash: &[u8; 32],
) -> Result<CommandClaim, PasskeyPluginError> {
    let inserted = sqlx::query(
        "INSERT INTO passkey_commands (caller_instance,operation,idempotency_key,intent_hash,status) VALUES ($1,$2,$3,$4,'reserved') ON CONFLICT DO NOTHING",
    )
    .bind(caller)
    .bind(operation)
    .bind(idempotency_key)
    .bind(intent_hash.as_slice())
    .execute(postgres.pool())
    .await
    .map_err(db("reserve passkey command"))?
    .rows_affected()
        == 1;
    if inserted {
        return Ok(CommandClaim::Claimed);
    }
    let row = sqlx::query(
        "SELECT intent_hash,status,response_nonce,response_ciphertext,error_code FROM passkey_commands WHERE caller_instance=$1 AND operation=$2 AND idempotency_key=$3",
    )
    .bind(caller)
    .bind(operation)
    .bind(idempotency_key)
    .fetch_one(postgres.pool())
    .await
    .map_err(db("load passkey command"))?;
    let existing: Vec<u8> = row
        .try_get("intent_hash")
        .map_err(db("decode passkey command intent"))?;
    if existing.as_slice() != intent_hash {
        return Ok(CommandClaim::Conflict);
    }
    let status: String = row
        .try_get("status")
        .map_err(db("decode passkey command status"))?;
    match status.as_str() {
        "completed_success" => Ok(CommandClaim::CompletedSuccess {
            nonce: row
                .try_get("response_nonce")
                .map_err(db("decode passkey response nonce"))?,
            ciphertext: row
                .try_get("response_ciphertext")
                .map_err(db("decode passkey response ciphertext"))?,
        }),
        "completed_error" => Ok(CommandClaim::CompletedError(
            row.try_get("error_code")
                .map_err(db("decode passkey command error"))?,
        )),
        _ => Ok(CommandClaim::InProgress),
    }
}

pub(crate) async fn complete_command_success(
    transaction: &mut Transaction<'_, Postgres>,
    caller: &str,
    operation: &str,
    idempotency_key: &str,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<(), PasskeyPluginError> {
    let changed = sqlx::query(
        "UPDATE passkey_commands SET status='completed_success',response_nonce=$4,response_ciphertext=$5,completed_at=now(),updated_at=now() WHERE caller_instance=$1 AND operation=$2 AND idempotency_key=$3 AND status IN ('reserved','verifying','issuing')",
    )
    .bind(caller)
    .bind(operation)
    .bind(idempotency_key)
    .bind(nonce)
    .bind(ciphertext)
    .execute(&mut **transaction)
    .await
    .map_err(db("complete passkey command"))?
    .rows_affected();
    if changed != 1 {
        return Err(PasskeyPluginError::Invariant(
            "passkey command was not completable",
        ));
    }
    Ok(())
}

pub(crate) async fn complete_command_error(
    postgres: &OwnedPostgres,
    caller: &str,
    operation: &str,
    idempotency_key: &str,
    error_code: &str,
) -> Result<(), PasskeyPluginError> {
    let changed = sqlx::query(
        "UPDATE passkey_commands SET status='completed_error',error_code=$4,completed_at=now(),updated_at=now() WHERE caller_instance=$1 AND operation=$2 AND idempotency_key=$3 AND status IN ('reserved','verifying','issuing')",
    )
    .bind(caller)
    .bind(operation)
    .bind(idempotency_key)
    .bind(error_code)
    .execute(postgres.pool())
    .await
    .map_err(db("complete failed passkey command"))?
    .rows_affected();
    if changed != 1 {
        return Err(PasskeyPluginError::Invariant(
            "passkey command error was not completable",
        ));
    }
    Ok(())
}

pub(crate) async fn set_command_status(
    postgres: &OwnedPostgres,
    caller: &str,
    operation: &str,
    idempotency_key: &str,
    from: &str,
    to: &str,
) -> Result<bool, PasskeyPluginError> {
    Ok(sqlx::query(
        "UPDATE passkey_commands SET status=$5,updated_at=now() WHERE caller_instance=$1 AND operation=$2 AND idempotency_key=$3 AND status=$4",
    )
    .bind(caller)
    .bind(operation)
    .bind(idempotency_key)
    .bind(from)
    .bind(to)
    .execute(postgres.pool())
    .await
    .map_err(db("advance passkey command"))?
    .rows_affected()
        == 1)
}

pub(crate) async fn ensure_subject(
    transaction: &mut Transaction<'_, Postgres>,
    subject: &str,
    proposed_user_id: Uuid,
) -> Result<SubjectRow, PasskeyPluginError> {
    sqlx::query(
        "INSERT INTO passkey_subjects (subject_id,webauthn_user_id) VALUES ($1,$2) ON CONFLICT (subject_id) DO NOTHING",
    )
    .bind(subject)
    .bind(proposed_user_id)
    .execute(&mut **transaction)
    .await
    .map_err(db("ensure passkey subject"))?;
    lock_subject(transaction, subject).await
}

pub(crate) async fn lock_subject(
    transaction: &mut Transaction<'_, Postgres>,
    subject: &str,
) -> Result<SubjectRow, PasskeyPluginError> {
    let row = sqlx::query(
        "SELECT webauthn_user_id,revision FROM passkey_subjects WHERE subject_id=$1 FOR UPDATE",
    )
    .bind(subject)
    .fetch_one(&mut **transaction)
    .await
    .map_err(db("lock passkey subject"))?;
    Ok(SubjectRow {
        user_id: row
            .try_get("webauthn_user_id")
            .map_err(db("decode WebAuthn user id"))?,
        revision: row
            .try_get("revision")
            .map_err(db("decode passkey subject revision"))?,
    })
}

pub(crate) async fn lock_subject_optional(
    transaction: &mut Transaction<'_, Postgres>,
    subject: &str,
) -> Result<Option<SubjectRow>, PasskeyPluginError> {
    let row = sqlx::query(
        "SELECT webauthn_user_id,revision FROM passkey_subjects WHERE subject_id=$1 FOR UPDATE",
    )
    .bind(subject)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(db("lock optional passkey subject"))?;
    row.map(|row| {
        Ok(SubjectRow {
            user_id: row
                .try_get("webauthn_user_id")
                .map_err(db("decode WebAuthn user id"))?,
            revision: row
                .try_get("revision")
                .map_err(db("decode passkey subject revision"))?,
        })
    })
    .transpose()
}

pub(crate) async fn load_subject(
    postgres: &OwnedPostgres,
    subject: &str,
) -> Result<Option<SubjectRow>, PasskeyPluginError> {
    let row =
        sqlx::query("SELECT webauthn_user_id,revision FROM passkey_subjects WHERE subject_id=$1")
            .bind(subject)
            .fetch_optional(postgres.pool())
            .await
            .map_err(db("load passkey subject"))?;
    row.map(|row| {
        Ok(SubjectRow {
            user_id: row
                .try_get("webauthn_user_id")
                .map_err(db("decode WebAuthn user id"))?,
            revision: row
                .try_get("revision")
                .map_err(db("decode passkey subject revision"))?,
        })
    })
    .transpose()
}

pub(crate) async fn load_passkeys(
    postgres: &OwnedPostgres,
    subject: &str,
    include_revoked: bool,
) -> Result<Vec<PasskeyRow>, PasskeyPluginError> {
    let rows = sqlx::query(
        "SELECT passkey_id,credential_id,passkey,label,sign_count,revision,created_at,last_used_at,revoked_at FROM passkeys WHERE subject_id=$1 AND ($2 OR revoked_at IS NULL) ORDER BY created_at,passkey_id",
    )
    .bind(subject)
    .bind(include_revoked)
    .fetch_all(postgres.pool())
    .await
    .map_err(db("load passkeys"))?;
    rows.iter().map(decode_passkey).collect()
}

pub(crate) async fn load_passkeys_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    subject: &str,
) -> Result<Vec<PasskeyRow>, PasskeyPluginError> {
    let rows = sqlx::query(
        "SELECT passkey_id,credential_id,passkey,label,sign_count,revision,created_at,last_used_at,revoked_at FROM passkeys WHERE subject_id=$1 AND revoked_at IS NULL ORDER BY created_at,passkey_id FOR UPDATE",
    )
    .bind(subject)
    .fetch_all(&mut **transaction)
    .await
    .map_err(db("lock active passkeys"))?;
    rows.iter().map(decode_passkey).collect()
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn insert_challenge(
    transaction: &mut Transaction<'_, Postgres>,
    challenge_id: &str,
    kind: &str,
    caller: &str,
    subject: &str,
    expected_revision: i64,
    state: &Value,
    public_options: &Value,
    expires_at: OffsetDateTime,
) -> Result<(), PasskeyPluginError> {
    sqlx::query(
        "INSERT INTO passkey_challenges (challenge_id,kind,caller_instance,subject_id,expected_revision,state,public_options,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(challenge_id)
    .bind(kind)
    .bind(caller)
    .bind(subject)
    .bind(expected_revision)
    .bind(state)
    .bind(public_options)
    .bind(expires_at)
    .execute(&mut **transaction)
    .await
    .map_err(db("store passkey challenge"))?;
    Ok(())
}

pub(crate) async fn consume_challenge(
    postgres: &OwnedPostgres,
    challenge_id: &str,
    kind: &str,
    caller: &str,
    operation: &str,
    idempotency_key: &str,
) -> Result<Option<ChallengeRow>, PasskeyPluginError> {
    let mut transaction = postgres
        .pool()
        .begin()
        .await
        .map_err(db("begin passkey challenge consumption"))?;
    let row = sqlx::query(
        "SELECT caller_instance,subject_id,expected_revision,state,expires_at,consumed_at FROM passkey_challenges WHERE challenge_id=$1 AND kind=$2 FOR UPDATE",
    )
    .bind(challenge_id)
    .bind(kind)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(db("lock passkey challenge"))?;
    let Some(row) = row else {
        transaction
            .commit()
            .await
            .map_err(db("commit missing challenge lookup"))?;
        return Ok(None);
    };
    let challenge = ChallengeRow {
        caller_instance: row
            .try_get("caller_instance")
            .map_err(db("decode challenge caller"))?,
        subject: row
            .try_get("subject_id")
            .map_err(db("decode challenge subject"))?,
        expected_revision: row
            .try_get("expected_revision")
            .map_err(db("decode challenge revision"))?,
        state: row.try_get("state").map_err(db("decode challenge state"))?,
        expires_at: row
            .try_get("expires_at")
            .map_err(db("decode challenge expiry"))?,
        consumed_at: row
            .try_get("consumed_at")
            .map_err(db("decode challenge consumption"))?,
    };
    if challenge.caller_instance != caller || challenge.consumed_at.is_some() {
        transaction
            .commit()
            .await
            .map_err(db("commit used challenge lookup"))?;
        return Ok(Some(challenge));
    }
    sqlx::query(
        "UPDATE passkey_challenges SET consumed_at=now(),consumed_by_operation=$2,consumed_by_idempotency_key=$3 WHERE challenge_id=$1",
    )
    .bind(challenge_id)
    .bind(operation)
    .bind(idempotency_key)
    .execute(&mut *transaction)
    .await
    .map_err(db("consume passkey challenge"))?;
    transaction
        .commit()
        .await
        .map_err(db("commit passkey challenge consumption"))?;
    Ok(Some(challenge))
}

fn decode_passkey(row: &sqlx::postgres::PgRow) -> Result<PasskeyRow, PasskeyPluginError> {
    Ok(PasskeyRow {
        passkey_id: row.try_get("passkey_id").map_err(db("decode passkey id"))?,
        credential_id: row
            .try_get("credential_id")
            .map_err(db("decode passkey credential id"))?,
        passkey: row.try_get("passkey").map_err(db("decode passkey value"))?,
        label: row.try_get("label").map_err(db("decode passkey label"))?,
        sign_count: row
            .try_get("sign_count")
            .map_err(db("decode passkey sign count"))?,
        revision: row
            .try_get("revision")
            .map_err(db("decode passkey revision"))?,
        created_at: row
            .try_get("created_at")
            .map_err(db("decode passkey creation time"))?,
        last_used_at: row
            .try_get("last_used_at")
            .map_err(db("decode passkey last use"))?,
        revoked_at: row
            .try_get("revoked_at")
            .map_err(db("decode passkey revocation"))?,
    })
}

pub(crate) fn db(operation: &'static str) -> impl FnOnce(sqlx::Error) -> PasskeyPluginError {
    move |source| PasskeyPluginError::Database { operation, source }
}
