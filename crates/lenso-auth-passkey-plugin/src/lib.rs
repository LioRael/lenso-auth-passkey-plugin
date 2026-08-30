//! PostgreSQL-backed `WebAuthn` passkey Plugin.

mod operator;
mod schema;
mod storage;

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fmt,
    rc::Rc,
    time::Duration as StdDuration,
};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use lenso::{ActivateContext, DeactivateContext, Lifecycle, Port, provides};
use lenso_auth_sdk::{
    ActorAssertion, ActorAssertionVerifier, ActorProjectionError, FixedClock, TypedActor,
};
use lenso_capability_credential_issuer as credential_issuer;
use lenso_capability_credential_issuer::{
    CredentialIssuerIssueInvocationError, IssueError, IssueRequest,
};
use lenso_capability_identity_directory as directory;
use lenso_capability_identity_directory::{
    DirectoryClient, DirectoryReadStatusInvocationError, ReadStatusRequest,
    ReadStatusResponseStatus,
};
use lenso_capability_passkey_auth as passkey;
use lenso_capability_passkey_auth::{
    BEGIN_AUTHENTICATION_OPERATION, BEGIN_REGISTRATION_OPERATION, BeginAuthenticationError,
    BeginAuthenticationRequest, BeginAuthenticationResponse, BeginRegistrationError,
    BeginRegistrationRequest, BeginRegistrationResponse, FINISH_AUTHENTICATION_OPERATION,
    FINISH_REGISTRATION_OPERATION, FinishAuthenticationError, FinishAuthenticationRequest,
    FinishAuthenticationResponse, FinishRegistrationError, FinishRegistrationRequest,
    FinishRegistrationResponse, LIST_PASSKEYS_OPERATION, ListPasskeysError, ListPasskeysRequest,
    ListPasskeysResponse, PasskeyBeginAuthentication, PasskeyBeginRegistration,
    PasskeyFinishAuthentication, PasskeyFinishRegistration, PasskeyListPasskeys, PasskeyProvider,
    PasskeyRevokePasskey, PasskeySummary, REVOKE_PASSKEY_OPERATION, RawJson, RevokePasskeyError,
    RevokePasskeyRequest, RevokePasskeyResponse,
};
use lenso_capability_secrets as secrets;
use lenso_capability_secrets::{ResolveRequest, SecretsInvocationError};
use lenso_kernel::{InvocationContext, NativeRequestFuture, RuntimeFailure};
use lenso_postgres_kit::OwnedPostgres;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use sqlx::Row;
use thiserror::Error;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{
    AuthenticationResult, Credential, CredentialID, Passkey, PasskeyAuthentication,
    PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential, Webauthn,
    WebauthnBuilder,
};
use zeroize::Zeroizing;

use crate::{
    schema::schema_plan,
    storage::{CommandClaim, PasskeyRow},
};

pub use operator::{PasskeyOperator, PasskeyOperatorError};

const DEPENDENCY_TIMEOUT: StdDuration = StdDuration::from_secs(10);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyAuthConfig {
    schema: String,
    database_url_secret: String,
    receipt_encryption_key_secret: String,
    rp_id: String,
    rp_name: String,
    allowed_origins: Vec<String>,
    auth_issuer: String,
    auth_public_key: String,
    management_callers: Vec<String>,
    authentication_callers: Vec<String>,
    audience: Vec<String>,
    challenge_ttl_seconds: u64,
    session_ttl_seconds: u64,
    receipt_ttl_seconds: u64,
    max_passkeys_per_subject: u32,
}

impl PasskeyAuthConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        schema: impl Into<String>,
        database_url_secret: impl Into<String>,
        receipt_encryption_key_secret: impl Into<String>,
        rp_id: impl Into<String>,
        rp_name: impl Into<String>,
        allowed_origins: Vec<String>,
        auth_issuer: impl Into<String>,
        auth_public_key: impl Into<String>,
        management_callers: Vec<String>,
        authentication_callers: Vec<String>,
        audience: Vec<String>,
        challenge_ttl_seconds: u64,
        session_ttl_seconds: u64,
        receipt_ttl_seconds: u64,
        max_passkeys_per_subject: u32,
    ) -> Result<Self, PasskeyConfigError> {
        let value = Self {
            schema: schema.into(),
            database_url_secret: database_url_secret.into(),
            receipt_encryption_key_secret: receipt_encryption_key_secret.into(),
            rp_id: rp_id.into(),
            rp_name: rp_name.into(),
            allowed_origins,
            auth_issuer: auth_issuer.into(),
            auth_public_key: auth_public_key.into(),
            management_callers,
            authentication_callers,
            audience,
            challenge_ttl_seconds,
            session_ttl_seconds,
            receipt_ttl_seconds,
            max_passkeys_per_subject,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), PasskeyConfigError> {
        schema_plan(self.schema.clone()).map_err(|_| PasskeyConfigError::InvalidSchema)?;
        if !valid_secret_reference(&self.database_url_secret)
            || !valid_secret_reference(&self.receipt_encryption_key_secret)
            || self.database_url_secret == self.receipt_encryption_key_secret
        {
            return Err(PasskeyConfigError::InvalidSecretReferences);
        }
        if !valid_name(&self.auth_issuer) {
            return Err(PasskeyConfigError::InvalidAuthAuthority);
        }
        ActorAssertionVerifier::from_public_key_base64(
            self.auth_issuer.clone(),
            &self.auth_public_key,
        )
        .map_err(|_| PasskeyConfigError::InvalidAuthAuthority)?;
        if self.rp_id.is_empty()
            || self.rp_id.len() > 253
            || self.rp_name.trim().is_empty()
            || self.rp_name.len() > 128
            || self.allowed_origins.is_empty()
            || self.allowed_origins.len() > 16
        {
            return Err(PasskeyConfigError::InvalidRelyingParty);
        }
        let origins = self.parsed_origins()?;
        let mut builder = WebauthnBuilder::new(&self.rp_id, &origins[0])
            .map_err(|_| PasskeyConfigError::InvalidRelyingParty)?
            .rp_name(&self.rp_name)
            .timeout(StdDuration::from_secs(self.challenge_ttl_seconds));
        for origin in &origins[1..] {
            builder = builder.append_allowed_origin(origin);
        }
        builder
            .build()
            .map_err(|_| PasskeyConfigError::InvalidRelyingParty)?;
        for values in [&self.management_callers, &self.authentication_callers] {
            validate_authority_set(values, 128)?;
        }
        validate_authority_set(&self.audience, 256)?;
        if !(60..=900).contains(&self.challenge_ttl_seconds)
            || !(1..=2_592_000).contains(&self.session_ttl_seconds)
            || !(300..=604_800).contains(&self.receipt_ttl_seconds)
            || self.receipt_ttl_seconds <= self.challenge_ttl_seconds
            || !(1..=64).contains(&self.max_passkeys_per_subject)
        {
            return Err(PasskeyConfigError::InvalidLimits);
        }
        Ok(())
    }

    fn parsed_origins(&self) -> Result<Vec<Url>, PasskeyConfigError> {
        let mut seen = BTreeSet::new();
        self.allowed_origins
            .iter()
            .map(|raw| {
                let origin = Url::parse(raw).map_err(|_| PasskeyConfigError::InvalidOrigin)?;
                let domain = origin.domain().ok_or(PasskeyConfigError::InvalidOrigin)?;
                let localhost = domain == "localhost";
                if (origin.scheme() != "https" && !(localhost && origin.scheme() == "http"))
                    || (!localhost && origin.port().is_some())
                    || origin.username() != ""
                    || origin.password().is_some()
                    || origin.path() != "/"
                    || origin.query().is_some()
                    || origin.fragment().is_some()
                    || !(domain == self.rp_id || domain.ends_with(&format!(".{}", self.rp_id)))
                    || !seen.insert(origin.as_str().to_owned())
                {
                    return Err(PasskeyConfigError::InvalidOrigin);
                }
                Ok(origin)
            })
            .collect()
    }

    fn webauthn(&self) -> Result<Webauthn, PasskeyConfigError> {
        let origins = self.parsed_origins()?;
        let mut builder = WebauthnBuilder::new(&self.rp_id, &origins[0])
            .map_err(|_| PasskeyConfigError::InvalidRelyingParty)?
            .rp_name(&self.rp_name)
            .timeout(StdDuration::from_secs(self.challenge_ttl_seconds));
        for origin in &origins[1..] {
            builder = builder.append_allowed_origin(origin);
        }
        builder
            .build()
            .map_err(|_| PasskeyConfigError::InvalidRelyingParty)
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PasskeyConfigError {
    #[error("invalid owned PostgreSQL schema")]
    InvalidSchema,
    #[error("database and receipt encryption require distinct valid secret references")]
    InvalidSecretReferences,
    #[error("invalid Auth assertion authority")]
    InvalidAuthAuthority,
    #[error("invalid WebAuthn relying party")]
    InvalidRelyingParty,
    #[error("invalid exact WebAuthn origin")]
    InvalidOrigin,
    #[error("invalid or duplicate caller/audience authority")]
    InvalidAuthoritySet,
    #[error("invalid challenge, session, receipt, or passkey limit")]
    InvalidLimits,
}

fn validate_config(config: &PasskeyAuthConfig) -> Result<(), RuntimeFailure> {
    config
        .validate()
        .map_err(|error| RuntimeFailure::InvalidResolvedPlan {
            detail: error.to_string(),
        })
}

#[derive(Clone)]
struct ReceiptCipher(Zeroizing<[u8; 32]>);

impl ReceiptCipher {
    fn derive(secret: &[u8]) -> Self {
        let digest = Sha256::digest(secret);
        let mut key = [0_u8; 32];
        key.copy_from_slice(&digest);
        Self(Zeroizing::new(key))
    }

    fn encrypt<T: Serialize>(
        &self,
        value: &T,
        aad: &[u8],
    ) -> Result<([u8; 12], Vec<u8>), PasskeyPluginError> {
        let bytes = serde_json::to_vec(value).map_err(PasskeyPluginError::SerializeReceipt)?;
        let mut nonce = [0_u8; 12];
        getrandom::fill(&mut nonce).map_err(PasskeyPluginError::Random)?;
        let cipher = Aes256Gcm::new_from_slice(self.0.as_ref())
            .map_err(|_| PasskeyPluginError::Invariant("invalid receipt encryption key"))?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: &bytes, aad })
            .map_err(|_| PasskeyPluginError::ReceiptEncryption)?;
        Ok((nonce, ciphertext))
    }

    fn decrypt<T: DeserializeOwned>(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<T, PasskeyPluginError> {
        let nonce: [u8; 12] = nonce
            .try_into()
            .map_err(|_| PasskeyPluginError::ReceiptDecryption)?;
        let cipher = Aes256Gcm::new_from_slice(self.0.as_ref())
            .map_err(|_| PasskeyPluginError::Invariant("invalid receipt encryption key"))?;
        let bytes = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| PasskeyPluginError::ReceiptDecryption)?;
        serde_json::from_slice(&bytes).map_err(PasskeyPluginError::DeserializeReceipt)
    }
}

impl fmt::Debug for ReceiptCipher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReceiptCipher(<redacted>)")
    }
}

struct ActivePasskey {
    postgres: OwnedPostgres,
    config: PasskeyAuthConfig,
    webauthn: Webauthn,
    actor_verifier: ActorAssertionVerifier,
    receipt_cipher: ReceiptCipher,
}

impl fmt::Debug for ActivePasskey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActivePasskey")
            .field("schema", &self.postgres.schema())
            .field("rp_id", &self.config.rp_id)
            .finish_non_exhaustive()
    }
}

#[lenso::plugin(
    lifecycle,
    configuration_schema = "configuration.schema.json",
    validate = validate_config
)]
#[derive(Clone)]
struct PasskeyAuthPlugin {
    #[config]
    config: PasskeyAuthConfig,
    secrets: Port<secrets::SecretsClient>,
    directory: Port<directory::DirectoryClient>,
    issuer: Port<credential_issuer::CredentialIssuerClient>,
    postgres: Rc<RefCell<Option<OwnedPostgres>>>,
    active: Rc<RefCell<Option<Rc<ActivePasskey>>>>,
}

impl fmt::Debug for PasskeyAuthPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PasskeyAuthPlugin")
            .field("active", &self.active.borrow().is_some())
            .finish_non_exhaustive()
    }
}

impl PasskeyAuthPlugin {
    fn active(&self) -> Result<Rc<ActivePasskey>, RuntimeFailure> {
        self.active
            .borrow()
            .clone()
            .ok_or_else(|| failure("Passkey Auth is not active"))
    }
}

#[derive(Debug)]
struct UserActor {
    subject: String,
}

impl TypedActor for UserActor {
    fn from_assertion(assertion: &ActorAssertion) -> Result<Self, ActorProjectionError> {
        if assertion.actor_kind() != "user" {
            return Err(ActorProjectionError::UnexpectedActorKind {
                expected: "user".to_owned(),
                actual: assertion.actor_kind().to_owned(),
            });
        }
        Ok(Self {
            subject: assertion.subject().to_owned(),
        })
    }
}

#[derive(Debug, Error)]
pub enum PasskeyPluginError {
    #[error("{operation}: {source}")]
    Database {
        operation: &'static str,
        #[source]
        source: sqlx::Error,
    },
    #[error("failed to generate secure random bytes: {0}")]
    Random(getrandom::Error),
    #[error("failed to serialize idempotency receipt: {0}")]
    SerializeReceipt(serde_json::Error),
    #[error("failed to deserialize idempotency receipt: {0}")]
    DeserializeReceipt(serde_json::Error),
    #[error("failed to encrypt idempotency receipt")]
    ReceiptEncryption,
    #[error("failed to decrypt idempotency receipt")]
    ReceiptDecryption,
    #[error("Plugin invariant failed: {0}")]
    Invariant(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectoryStatus {
    Active,
    Disabled,
    Missing,
}

#[provides(passkey::Passkey)]
impl PasskeyProvider for PasskeyAuthPlugin {
    #[allow(clippy::too_many_lines)]
    fn begin_registration(
        &self,
        context: InvocationContext,
        request: BeginRegistrationRequest,
    ) -> NativeRequestFuture<PasskeyBeginRegistration> {
        let active = self.active();
        let directory = self.directory.clone();
        Box::pin(async move {
            let active = active?;
            let Some(caller) = management_caller(
                &active,
                &context,
                BEGIN_REGISTRATION_OPERATION,
                &request.subject,
            ) else {
                return Ok(Err(BeginRegistrationError::Forbidden));
            };
            let Some(expected_revision) = valid_begin_registration(&request) else {
                return Ok(Err(BeginRegistrationError::InvalidRequest));
            };
            storage::prune(
                &active.postgres,
                i64::try_from(active.config.receipt_ttl_seconds).expect("validated"),
            )
            .await
            .map_err(runtime)?;
            let intent = intent_hash(&request).map_err(runtime)?;
            let aad = receipt_aad(
                &caller,
                BEGIN_REGISTRATION_OPERATION,
                &request.idempotency_key,
            );
            match storage::claim_command(
                &active.postgres,
                &caller,
                BEGIN_REGISTRATION_OPERATION,
                &request.idempotency_key,
                &intent,
            )
            .await
            .map_err(runtime)?
            {
                CommandClaim::Claimed => {}
                CommandClaim::CompletedSuccess { nonce, ciphertext } => {
                    return Ok(Ok(active
                        .receipt_cipher
                        .decrypt(&nonce, &ciphertext, &aad)
                        .map_err(runtime)?));
                }
                CommandClaim::CompletedError(code) => {
                    return Ok(Err(begin_registration_error(&code).map_err(runtime)?));
                }
                CommandClaim::Conflict => {
                    return Ok(Err(BeginRegistrationError::IdempotencyConflict));
                }
                CommandClaim::InProgress => {
                    return Ok(Err(BeginRegistrationError::OperationInProgress));
                }
            }
            if directory_status(&directory, context.clone(), &request.subject).await?
                != DirectoryStatus::Active
            {
                storage::complete_command_error(
                    &active.postgres,
                    &caller,
                    BEGIN_REGISTRATION_OPERATION,
                    &request.idempotency_key,
                    "disabled",
                )
                .await
                .map_err(runtime)?;
                return Ok(Err(BeginRegistrationError::Disabled));
            }
            let mut transaction = active
                .postgres
                .pool()
                .begin()
                .await
                .map_err(storage::db("begin registration challenge transaction"))
                .map_err(runtime)?;
            let subject =
                storage::ensure_subject(&mut transaction, &request.subject, Uuid::new_v4())
                    .await
                    .map_err(runtime)?;
            if subject.revision != expected_revision {
                transaction
                    .rollback()
                    .await
                    .map_err(storage::db("rollback registration revision conflict"))
                    .map_err(runtime)?;
                storage::complete_command_error(
                    &active.postgres,
                    &caller,
                    BEGIN_REGISTRATION_OPERATION,
                    &request.idempotency_key,
                    "revision_conflict",
                )
                .await
                .map_err(runtime)?;
                return Ok(Err(BeginRegistrationError::RevisionConflict));
            }
            let stored = storage::load_passkeys_for_update(&mut transaction, &request.subject)
                .await
                .map_err(runtime)?;
            if stored.len()
                >= usize::try_from(active.config.max_passkeys_per_subject).expect("validated")
            {
                transaction
                    .rollback()
                    .await
                    .map_err(storage::db("rollback passkey limit"))
                    .map_err(runtime)?;
                storage::complete_command_error(
                    &active.postgres,
                    &caller,
                    BEGIN_REGISTRATION_OPERATION,
                    &request.idempotency_key,
                    "too_many_passkeys",
                )
                .await
                .map_err(runtime)?;
                return Ok(Err(BeginRegistrationError::TooManyPasskeys));
            }
            let exclude = stored
                .iter()
                .map(decode_passkey)
                .collect::<Result<Vec<_>, _>>()?
                .iter()
                .map(|credential| credential.cred_id().clone())
                .collect::<Vec<CredentialID>>();
            let (options, state) = active
                .webauthn
                .start_passkey_registration(
                    subject.user_id,
                    &request.user_name,
                    &request.display_name,
                    (!exclude.is_empty()).then_some(exclude),
                )
                .map_err(|error| {
                    failure(format!("failed to start WebAuthn registration: {error}"))
                })?;
            let challenge_id = random_id("pkr_").map_err(runtime)?;
            let expires_at = OffsetDateTime::now_utc()
                + Duration::seconds(
                    i64::try_from(active.config.challenge_ttl_seconds).expect("validated"),
                );
            let options_value = serde_json::to_value(&options).map_err(serialization_failure)?;
            let state_value = serde_json::to_value(&state).map_err(serialization_failure)?;
            let response = BeginRegistrationResponse {
                challenge_id: challenge_id.clone(),
                public_key_json: RawJson::new(options_value.to_string())
                    .map_err(serialization_failure)?,
                expires_at: format_time(expires_at)?,
                revision: subject.revision.to_string(),
            };
            let (nonce, ciphertext) = active
                .receipt_cipher
                .encrypt(&response, &aad)
                .map_err(runtime)?;
            storage::insert_challenge(
                &mut transaction,
                &challenge_id,
                "registration",
                &caller,
                &request.subject,
                subject.revision,
                &state_value,
                &options_value,
                expires_at,
            )
            .await
            .map_err(runtime)?;
            storage::complete_command_success(
                &mut transaction,
                &caller,
                BEGIN_REGISTRATION_OPERATION,
                &request.idempotency_key,
                &nonce,
                &ciphertext,
            )
            .await
            .map_err(runtime)?;
            transaction
                .commit()
                .await
                .map_err(storage::db("commit registration challenge"))
                .map_err(runtime)?;
            Ok(Ok(response))
        })
    }

    #[allow(clippy::too_many_lines)]
    fn begin_authentication(
        &self,
        context: InvocationContext,
        request: BeginAuthenticationRequest,
    ) -> NativeRequestFuture<PasskeyBeginAuthentication> {
        let active = self.active();
        let directory = self.directory.clone();
        Box::pin(async move {
            let active = active?;
            let Some(caller) = allowed_caller(&active.config.authentication_callers, &context)
            else {
                return Ok(Err(BeginAuthenticationError::Forbidden));
            };
            if !valid_subject(&request.subject) || !valid_idempotency_key(&request.idempotency_key)
            {
                return Ok(Err(BeginAuthenticationError::InvalidRequest));
            }
            storage::prune(
                &active.postgres,
                i64::try_from(active.config.receipt_ttl_seconds).expect("validated"),
            )
            .await
            .map_err(runtime)?;
            let intent = intent_hash(&request).map_err(runtime)?;
            let aad = receipt_aad(
                &caller,
                BEGIN_AUTHENTICATION_OPERATION,
                &request.idempotency_key,
            );
            match storage::claim_command(
                &active.postgres,
                &caller,
                BEGIN_AUTHENTICATION_OPERATION,
                &request.idempotency_key,
                &intent,
            )
            .await
            .map_err(runtime)?
            {
                CommandClaim::Claimed => {}
                CommandClaim::CompletedSuccess { nonce, ciphertext } => {
                    return Ok(Ok(active
                        .receipt_cipher
                        .decrypt(&nonce, &ciphertext, &aad)
                        .map_err(runtime)?));
                }
                CommandClaim::CompletedError(code) => {
                    return Ok(Err(begin_authentication_error(&code).map_err(runtime)?));
                }
                CommandClaim::Conflict => {
                    return Ok(Err(BeginAuthenticationError::IdempotencyConflict));
                }
                CommandClaim::InProgress => {
                    return Ok(Err(BeginAuthenticationError::OperationInProgress));
                }
            }
            if directory_status(&directory, context, &request.subject).await?
                != DirectoryStatus::Active
            {
                storage::complete_command_error(
                    &active.postgres,
                    &caller,
                    BEGIN_AUTHENTICATION_OPERATION,
                    &request.idempotency_key,
                    "invalid_credentials",
                )
                .await
                .map_err(runtime)?;
                return Ok(Err(BeginAuthenticationError::InvalidCredentials));
            }
            let mut transaction = active
                .postgres
                .pool()
                .begin()
                .await
                .map_err(storage::db("begin authentication challenge transaction"))
                .map_err(runtime)?;
            let Some(subject) = storage::lock_subject_optional(&mut transaction, &request.subject)
                .await
                .map_err(runtime)?
            else {
                transaction
                    .rollback()
                    .await
                    .map_err(storage::db("rollback missing passkey subject"))
                    .map_err(runtime)?;
                storage::complete_command_error(
                    &active.postgres,
                    &caller,
                    BEGIN_AUTHENTICATION_OPERATION,
                    &request.idempotency_key,
                    "invalid_credentials",
                )
                .await
                .map_err(runtime)?;
                return Ok(Err(BeginAuthenticationError::InvalidCredentials));
            };
            let credentials = storage::load_passkeys_for_update(&mut transaction, &request.subject)
                .await
                .map_err(runtime)?
                .iter()
                .map(decode_passkey)
                .collect::<Result<Vec<_>, _>>()?;
            if credentials.is_empty() {
                transaction
                    .rollback()
                    .await
                    .map_err(storage::db("rollback missing passkeys"))
                    .map_err(runtime)?;
                storage::complete_command_error(
                    &active.postgres,
                    &caller,
                    BEGIN_AUTHENTICATION_OPERATION,
                    &request.idempotency_key,
                    "invalid_credentials",
                )
                .await
                .map_err(runtime)?;
                return Ok(Err(BeginAuthenticationError::InvalidCredentials));
            }
            let (options, state) = active
                .webauthn
                .start_passkey_authentication(&credentials)
                .map_err(|error| {
                    failure(format!("failed to start WebAuthn authentication: {error}"))
                })?;
            let challenge_id = random_id("pka_").map_err(runtime)?;
            let expires_at = OffsetDateTime::now_utc()
                + Duration::seconds(
                    i64::try_from(active.config.challenge_ttl_seconds).expect("validated"),
                );
            let options_value = serde_json::to_value(&options).map_err(serialization_failure)?;
            let state_value = serde_json::to_value(&state).map_err(serialization_failure)?;
            let response = BeginAuthenticationResponse {
                challenge_id: challenge_id.clone(),
                public_key_json: RawJson::new(options_value.to_string())
                    .map_err(serialization_failure)?,
                expires_at: format_time(expires_at)?,
                revision: subject.revision.to_string(),
            };
            let (nonce, ciphertext) = active
                .receipt_cipher
                .encrypt(&response, &aad)
                .map_err(runtime)?;
            storage::insert_challenge(
                &mut transaction,
                &challenge_id,
                "authentication",
                &caller,
                &request.subject,
                subject.revision,
                &state_value,
                &options_value,
                expires_at,
            )
            .await
            .map_err(runtime)?;
            storage::complete_command_success(
                &mut transaction,
                &caller,
                BEGIN_AUTHENTICATION_OPERATION,
                &request.idempotency_key,
                &nonce,
                &ciphertext,
            )
            .await
            .map_err(runtime)?;
            transaction
                .commit()
                .await
                .map_err(storage::db("commit authentication challenge"))
                .map_err(runtime)?;
            Ok(Ok(response))
        })
    }

    #[allow(clippy::too_many_lines)]
    fn finish_registration(
        &self,
        context: InvocationContext,
        request: FinishRegistrationRequest,
    ) -> NativeRequestFuture<PasskeyFinishRegistration> {
        let active = self.active();
        let directory = self.directory.clone();
        Box::pin(async move {
            let active = active?;
            let Some(caller) = management_caller(
                &active,
                &context,
                FINISH_REGISTRATION_OPERATION,
                &request.subject,
            ) else {
                return Ok(Err(FinishRegistrationError::Forbidden));
            };
            let Some(expected_revision) = valid_finish_registration(&request) else {
                return Ok(Err(FinishRegistrationError::InvalidRequest));
            };
            let intent = intent_hash(&request).map_err(runtime)?;
            let aad = receipt_aad(
                &caller,
                FINISH_REGISTRATION_OPERATION,
                &request.idempotency_key,
            );
            match storage::claim_command(
                &active.postgres,
                &caller,
                FINISH_REGISTRATION_OPERATION,
                &request.idempotency_key,
                &intent,
            )
            .await
            .map_err(runtime)?
            {
                CommandClaim::Claimed => {}
                CommandClaim::CompletedSuccess { nonce, ciphertext } => {
                    return Ok(Ok(active
                        .receipt_cipher
                        .decrypt(&nonce, &ciphertext, &aad)
                        .map_err(runtime)?));
                }
                CommandClaim::CompletedError(code) => {
                    return Ok(Err(finish_registration_error(&code).map_err(runtime)?));
                }
                CommandClaim::Conflict => {
                    return Ok(Err(FinishRegistrationError::IdempotencyConflict));
                }
                CommandClaim::InProgress => {
                    return Ok(Err(FinishRegistrationError::OperationInProgress));
                }
            }
            if !storage::set_command_status(
                &active.postgres,
                &caller,
                FINISH_REGISTRATION_OPERATION,
                &request.idempotency_key,
                "reserved",
                "verifying",
            )
            .await
            .map_err(runtime)?
            {
                return Ok(Err(FinishRegistrationError::OperationInProgress));
            }
            let Some(challenge) = storage::consume_challenge(
                &active.postgres,
                &request.challenge_id,
                "registration",
                &caller,
                FINISH_REGISTRATION_OPERATION,
                &request.idempotency_key,
            )
            .await
            .map_err(runtime)?
            else {
                record_error(
                    &active,
                    &caller,
                    FINISH_REGISTRATION_OPERATION,
                    &request.idempotency_key,
                    "invalid_request",
                )
                .await?;
                return Ok(Err(FinishRegistrationError::InvalidRequest));
            };
            let challenge_error = if challenge.caller_instance != caller
                || challenge.subject != request.subject
                || challenge.expected_revision != expected_revision
            {
                Some((FinishRegistrationError::InvalidRequest, "invalid_request"))
            } else if challenge.consumed_at.is_some() {
                Some((FinishRegistrationError::ChallengeUsed, "challenge_used"))
            } else if OffsetDateTime::now_utc() >= challenge.expires_at {
                Some((
                    FinishRegistrationError::ChallengeExpired,
                    "challenge_expired",
                ))
            } else {
                None
            };
            if let Some((error, code)) = challenge_error {
                record_error(
                    &active,
                    &caller,
                    FINISH_REGISTRATION_OPERATION,
                    &request.idempotency_key,
                    code,
                )
                .await?;
                return Ok(Err(error));
            }
            if directory_status(&directory, context, &request.subject).await?
                != DirectoryStatus::Active
            {
                record_error(
                    &active,
                    &caller,
                    FINISH_REGISTRATION_OPERATION,
                    &request.idempotency_key,
                    "disabled",
                )
                .await?;
                return Ok(Err(FinishRegistrationError::Disabled));
            }
            let state: PasskeyRegistration =
                serde_json::from_value(challenge.state).map_err(serialization_failure)?;
            let Ok(registration): Result<RegisterPublicKeyCredential, _> =
                serde_json::from_str(request.credential_json.as_str())
            else {
                record_error(
                    &active,
                    &caller,
                    FINISH_REGISTRATION_OPERATION,
                    &request.idempotency_key,
                    "invalid_credential",
                )
                .await?;
                return Ok(Err(FinishRegistrationError::InvalidCredential));
            };
            let Ok(verified) = active
                .webauthn
                .finish_passkey_registration(&registration, &state)
            else {
                record_error(
                    &active,
                    &caller,
                    FINISH_REGISTRATION_OPERATION,
                    &request.idempotency_key,
                    "invalid_credential",
                )
                .await?;
                return Ok(Err(FinishRegistrationError::InvalidCredential));
            };
            let credential: Credential = verified.clone().into();
            let credential_id = verified.cred_id().as_ref().to_vec();
            let credential_id_wire = URL_SAFE_NO_PAD.encode(&credential_id);
            let public_key =
                serde_json::to_value(verified.get_public_key()).map_err(serialization_failure)?;
            let passkey_value = serde_json::to_value(&verified).map_err(serialization_failure)?;
            let passkey_id = random_id("pk_").map_err(runtime)?;
            let mut transaction = active
                .postgres
                .pool()
                .begin()
                .await
                .map_err(storage::db("begin passkey registration transaction"))
                .map_err(runtime)?;
            let subject = storage::lock_subject(&mut transaction, &request.subject)
                .await
                .map_err(runtime)?;
            if subject.revision != expected_revision {
                transaction
                    .rollback()
                    .await
                    .map_err(storage::db(
                        "rollback finish registration revision conflict",
                    ))
                    .map_err(runtime)?;
                record_error(
                    &active,
                    &caller,
                    FINISH_REGISTRATION_OPERATION,
                    &request.idempotency_key,
                    "revision_conflict",
                )
                .await?;
                return Ok(Err(FinishRegistrationError::RevisionConflict));
            }
            let inserted = sqlx::query(
                "INSERT INTO passkeys (passkey_id,subject_id,credential_id,public_key,passkey,label,sign_count) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (credential_id) DO NOTHING RETURNING revision,created_at",
            )
            .bind(&passkey_id)
            .bind(&request.subject)
            .bind(&credential_id)
            .bind(&public_key)
            .bind(&passkey_value)
            .bind(request.label.trim())
            .bind(i64::from(credential.counter))
            .fetch_optional(&mut *transaction)
            .await
            .map_err(storage::db("insert verified passkey"))
            .map_err(runtime)?;
            let Some(inserted) = inserted else {
                transaction
                    .rollback()
                    .await
                    .map_err(storage::db("rollback duplicate passkey"))
                    .map_err(runtime)?;
                record_error(
                    &active,
                    &caller,
                    FINISH_REGISTRATION_OPERATION,
                    &request.idempotency_key,
                    "credential_exists",
                )
                .await?;
                return Ok(Err(FinishRegistrationError::CredentialExists));
            };
            let passkey_revision: i64 = inserted
                .try_get("revision")
                .map_err(storage::db("decode registered passkey revision"))
                .map_err(runtime)?;
            let created_at: OffsetDateTime = inserted
                .try_get("created_at")
                .map_err(storage::db("decode registered passkey time"))
                .map_err(runtime)?;
            let collection_revision: i64 = sqlx::query_scalar(
                "UPDATE passkey_subjects SET revision=revision+1,updated_at=now() WHERE subject_id=$1 RETURNING revision",
            )
            .bind(&request.subject)
            .fetch_one(&mut *transaction)
            .await
            .map_err(storage::db("advance passkey collection revision"))
            .map_err(runtime)?;
            let response = FinishRegistrationResponse {
                passkey: PasskeySummary {
                    passkey_id,
                    label: request.label.trim().to_owned(),
                    credential_id: credential_id_wire,
                    sign_count: credential.counter.to_string(),
                    revision: passkey_revision.to_string(),
                    created_at: format_time(created_at)?,
                    last_used_at: None,
                    revoked_at: None,
                },
                revision: collection_revision.to_string(),
            };
            let (nonce, ciphertext) = active
                .receipt_cipher
                .encrypt(&response, &aad)
                .map_err(runtime)?;
            storage::complete_command_success(
                &mut transaction,
                &caller,
                FINISH_REGISTRATION_OPERATION,
                &request.idempotency_key,
                &nonce,
                &ciphertext,
            )
            .await
            .map_err(runtime)?;
            transaction
                .commit()
                .await
                .map_err(storage::db("commit passkey registration"))
                .map_err(runtime)?;
            Ok(Ok(response))
        })
    }

    #[allow(clippy::too_many_lines)]
    fn finish_authentication(
        &self,
        context: InvocationContext,
        request: FinishAuthenticationRequest,
    ) -> NativeRequestFuture<PasskeyFinishAuthentication> {
        let active = self.active();
        let directory = self.directory.clone();
        let issuer_client = self.issuer.clone();
        Box::pin(async move {
            let active = active?;
            let Some(caller) = allowed_caller(&active.config.authentication_callers, &context)
            else {
                return Ok(Err(FinishAuthenticationError::Forbidden));
            };
            if !valid_idempotency_key(&request.idempotency_key)
                || !valid_token(&request.challenge_id, 128)
                || request.credential_json.as_str().len() > 65_536
            {
                return Ok(Err(FinishAuthenticationError::InvalidRequest));
            }
            let intent = intent_hash(&request).map_err(runtime)?;
            let aad = receipt_aad(
                &caller,
                FINISH_AUTHENTICATION_OPERATION,
                &request.idempotency_key,
            );
            match storage::claim_command(
                &active.postgres,
                &caller,
                FINISH_AUTHENTICATION_OPERATION,
                &request.idempotency_key,
                &intent,
            )
            .await
            .map_err(runtime)?
            {
                CommandClaim::Claimed => {}
                CommandClaim::CompletedSuccess { nonce, ciphertext } => {
                    return Ok(Ok(active
                        .receipt_cipher
                        .decrypt(&nonce, &ciphertext, &aad)
                        .map_err(runtime)?));
                }
                CommandClaim::CompletedError(code) => {
                    return Ok(Err(finish_authentication_error(&code).map_err(runtime)?));
                }
                CommandClaim::Conflict => {
                    return Ok(Err(FinishAuthenticationError::IdempotencyConflict));
                }
                CommandClaim::InProgress => {
                    return Ok(Err(FinishAuthenticationError::OperationInProgress));
                }
            }
            if !storage::set_command_status(
                &active.postgres,
                &caller,
                FINISH_AUTHENTICATION_OPERATION,
                &request.idempotency_key,
                "reserved",
                "verifying",
            )
            .await
            .map_err(runtime)?
            {
                return Ok(Err(FinishAuthenticationError::OperationInProgress));
            }
            let Some(challenge) = storage::consume_challenge(
                &active.postgres,
                &request.challenge_id,
                "authentication",
                &caller,
                FINISH_AUTHENTICATION_OPERATION,
                &request.idempotency_key,
            )
            .await
            .map_err(runtime)?
            else {
                record_error(
                    &active,
                    &caller,
                    FINISH_AUTHENTICATION_OPERATION,
                    &request.idempotency_key,
                    "invalid_request",
                )
                .await?;
                return Ok(Err(FinishAuthenticationError::InvalidRequest));
            };
            let challenge_error = if challenge.caller_instance != caller {
                Some((FinishAuthenticationError::InvalidRequest, "invalid_request"))
            } else if challenge.consumed_at.is_some() {
                Some((FinishAuthenticationError::ChallengeUsed, "challenge_used"))
            } else if OffsetDateTime::now_utc() >= challenge.expires_at {
                Some((
                    FinishAuthenticationError::ChallengeExpired,
                    "challenge_expired",
                ))
            } else {
                None
            };
            if let Some((error, code)) = challenge_error {
                record_error(
                    &active,
                    &caller,
                    FINISH_AUTHENTICATION_OPERATION,
                    &request.idempotency_key,
                    code,
                )
                .await?;
                return Ok(Err(error));
            }
            let state: PasskeyAuthentication =
                serde_json::from_value(challenge.state).map_err(serialization_failure)?;
            let Ok(authentication): Result<PublicKeyCredential, _> =
                serde_json::from_str(request.credential_json.as_str())
            else {
                record_error(
                    &active,
                    &caller,
                    FINISH_AUTHENTICATION_OPERATION,
                    &request.idempotency_key,
                    "invalid_credentials",
                )
                .await?;
                return Ok(Err(FinishAuthenticationError::InvalidCredentials));
            };
            let Ok(result) = active
                .webauthn
                .finish_passkey_authentication(&authentication, &state)
            else {
                record_error(
                    &active,
                    &caller,
                    FINISH_AUTHENTICATION_OPERATION,
                    &request.idempotency_key,
                    "invalid_credentials",
                )
                .await?;
                return Ok(Err(FinishAuthenticationError::InvalidCredentials));
            };
            if directory_status(&directory, context.clone(), &challenge.subject).await?
                != DirectoryStatus::Active
            {
                record_error(
                    &active,
                    &caller,
                    FINISH_AUTHENTICATION_OPERATION,
                    &request.idempotency_key,
                    "disabled",
                )
                .await?;
                return Ok(Err(FinishAuthenticationError::Disabled));
            }
            let Some((passkey_id, collection_revision)) = update_authenticated_passkey(
                &active,
                &caller,
                &request.idempotency_key,
                &challenge.subject,
                &result,
            )
            .await?
            else {
                record_error(
                    &active,
                    &caller,
                    FINISH_AUTHENTICATION_OPERATION,
                    &request.idempotency_key,
                    "invalid_credentials",
                )
                .await?;
                return Ok(Err(FinishAuthenticationError::InvalidCredentials));
            };
            let expires_at = OffsetDateTime::now_utc()
                + Duration::seconds(
                    i64::try_from(active.config.session_ttl_seconds).expect("validated"),
                );
            let session = match issuer_client
                .issue_with_context(
                    context,
                    IssueRequest {
                        subject: challenge.subject.clone(),
                        actor_kind: "user".to_owned(),
                        assurance: "passkey".to_owned(),
                        audience: active.config.audience.clone(),
                        claims: BTreeMap::new(),
                        expires_at: format_time(expires_at)?,
                    },
                )
                .await
            {
                Ok(session) => session,
                Err(CredentialIssuerIssueInvocationError::Domain(IssueError::Disabled)) => {
                    record_error(
                        &active,
                        &caller,
                        FINISH_AUTHENTICATION_OPERATION,
                        &request.idempotency_key,
                        "disabled",
                    )
                    .await?;
                    return Ok(Err(FinishAuthenticationError::Disabled));
                }
                Err(CredentialIssuerIssueInvocationError::Domain(error)) => {
                    return Err(failure(format!(
                        "Credential Issuer rejected verified passkey authentication: {error:?}"
                    )));
                }
                Err(CredentialIssuerIssueInvocationError::Runtime(error)) => return Err(error),
            };
            let response = FinishAuthenticationResponse {
                subject: challenge.subject,
                passkey_id,
                revision: collection_revision.to_string(),
                session_id: session.session_id,
                credential: session.credential,
                expires_at: session.expires_at,
            };
            let (nonce, ciphertext) = active
                .receipt_cipher
                .encrypt(&response, &aad)
                .map_err(runtime)?;
            let mut transaction = active
                .postgres
                .pool()
                .begin()
                .await
                .map_err(storage::db("begin authentication receipt transaction"))
                .map_err(runtime)?;
            storage::complete_command_success(
                &mut transaction,
                &caller,
                FINISH_AUTHENTICATION_OPERATION,
                &request.idempotency_key,
                &nonce,
                &ciphertext,
            )
            .await
            .map_err(runtime)?;
            transaction
                .commit()
                .await
                .map_err(storage::db("commit authentication receipt"))
                .map_err(runtime)?;
            Ok(Ok(response))
        })
    }

    fn list_passkeys(
        &self,
        context: InvocationContext,
        request: ListPasskeysRequest,
    ) -> NativeRequestFuture<PasskeyListPasskeys> {
        let active = self.active();
        let directory = self.directory.clone();
        Box::pin(async move {
            let active = active?;
            if management_caller(&active, &context, LIST_PASSKEYS_OPERATION, &request.subject)
                .is_none()
            {
                return Ok(Err(ListPasskeysError::Forbidden));
            }
            if !valid_subject(&request.subject) {
                return Ok(Err(ListPasskeysError::InvalidRequest));
            }
            if directory_status(&directory, context, &request.subject).await?
                != DirectoryStatus::Active
            {
                return Ok(Err(ListPasskeysError::Disabled));
            }
            let subject = storage::load_subject(&active.postgres, &request.subject)
                .await
                .map_err(runtime)?;
            let passkeys = if subject.is_some() {
                storage::load_passkeys(&active.postgres, &request.subject, request.include_revoked)
                    .await
                    .map_err(runtime)?
                    .iter()
                    .map(passkey_summary)
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                Vec::new()
            };
            Ok(Ok(ListPasskeysResponse {
                revision: subject
                    .map_or_else(|| "0".to_owned(), |value| value.revision.to_string()),
                passkeys,
            }))
        })
    }

    #[allow(clippy::too_many_lines)]
    fn revoke_passkey(
        &self,
        context: InvocationContext,
        request: RevokePasskeyRequest,
    ) -> NativeRequestFuture<PasskeyRevokePasskey> {
        let active = self.active();
        let directory = self.directory.clone();
        Box::pin(async move {
            let active = active?;
            let Some(caller) = management_caller(
                &active,
                &context,
                REVOKE_PASSKEY_OPERATION,
                &request.subject,
            ) else {
                return Ok(Err(RevokePasskeyError::Forbidden));
            };
            let Some(expected_revision) = valid_revoke(&request) else {
                return Ok(Err(RevokePasskeyError::InvalidRequest));
            };
            let intent = intent_hash(&request).map_err(runtime)?;
            let aad = receipt_aad(&caller, REVOKE_PASSKEY_OPERATION, &request.idempotency_key);
            match storage::claim_command(
                &active.postgres,
                &caller,
                REVOKE_PASSKEY_OPERATION,
                &request.idempotency_key,
                &intent,
            )
            .await
            .map_err(runtime)?
            {
                CommandClaim::Claimed => {}
                CommandClaim::CompletedSuccess { nonce, ciphertext } => {
                    return Ok(Ok(active
                        .receipt_cipher
                        .decrypt(&nonce, &ciphertext, &aad)
                        .map_err(runtime)?));
                }
                CommandClaim::CompletedError(code) => {
                    return Ok(Err(revoke_error(&code).map_err(runtime)?));
                }
                CommandClaim::Conflict => {
                    return Ok(Err(RevokePasskeyError::IdempotencyConflict));
                }
                CommandClaim::InProgress => {
                    return Ok(Err(RevokePasskeyError::OperationInProgress));
                }
            }
            if directory_status(&directory, context, &request.subject).await?
                != DirectoryStatus::Active
            {
                record_error(
                    &active,
                    &caller,
                    REVOKE_PASSKEY_OPERATION,
                    &request.idempotency_key,
                    "disabled",
                )
                .await?;
                return Ok(Err(RevokePasskeyError::Disabled));
            }
            let mut transaction = active
                .postgres
                .pool()
                .begin()
                .await
                .map_err(storage::db("begin passkey revocation transaction"))
                .map_err(runtime)?;
            let Some(subject) = storage::lock_subject_optional(&mut transaction, &request.subject)
                .await
                .map_err(runtime)?
            else {
                transaction
                    .rollback()
                    .await
                    .map_err(storage::db("rollback missing revocation subject"))
                    .map_err(runtime)?;
                record_error(
                    &active,
                    &caller,
                    REVOKE_PASSKEY_OPERATION,
                    &request.idempotency_key,
                    "passkey_not_found",
                )
                .await?;
                return Ok(Err(RevokePasskeyError::PasskeyNotFound));
            };
            if subject.revision != expected_revision {
                transaction
                    .rollback()
                    .await
                    .map_err(storage::db("rollback revocation revision conflict"))
                    .map_err(runtime)?;
                record_error(
                    &active,
                    &caller,
                    REVOKE_PASSKEY_OPERATION,
                    &request.idempotency_key,
                    "revision_conflict",
                )
                .await?;
                return Ok(Err(RevokePasskeyError::RevisionConflict));
            }
            let row = sqlx::query(
                "SELECT revision,revoked_at FROM passkeys WHERE passkey_id=$1 AND subject_id=$2 FOR UPDATE",
            )
            .bind(&request.passkey_id)
            .bind(&request.subject)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(storage::db("lock passkey for revocation"))
            .map_err(runtime)?;
            let Some(row) = row else {
                transaction
                    .rollback()
                    .await
                    .map_err(storage::db("rollback missing passkey revocation"))
                    .map_err(runtime)?;
                record_error(
                    &active,
                    &caller,
                    REVOKE_PASSKEY_OPERATION,
                    &request.idempotency_key,
                    "passkey_not_found",
                )
                .await?;
                return Ok(Err(RevokePasskeyError::PasskeyNotFound));
            };
            let mut passkey_revision: i64 = row
                .try_get("revision")
                .map_err(storage::db("decode revoked passkey revision"))
                .map_err(runtime)?;
            let revoked_at: Option<OffsetDateTime> = row
                .try_get("revoked_at")
                .map_err(storage::db("decode passkey revocation time"))
                .map_err(runtime)?;
            let (revoked, collection_revision) = if revoked_at.is_none() {
                passkey_revision = sqlx::query_scalar(
                    "UPDATE passkeys SET revoked_at=now(),revision=revision+1 WHERE passkey_id=$1 RETURNING revision",
                )
                .bind(&request.passkey_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(storage::db("revoke passkey"))
                .map_err(runtime)?;
                let revision: i64 = sqlx::query_scalar(
                    "UPDATE passkey_subjects SET revision=revision+1,updated_at=now() WHERE subject_id=$1 RETURNING revision",
                )
                .bind(&request.subject)
                .fetch_one(&mut *transaction)
                .await
                .map_err(storage::db("advance revoked passkey collection revision"))
                .map_err(runtime)?;
                (true, revision)
            } else {
                (false, subject.revision)
            };
            let response = RevokePasskeyResponse {
                passkey_id: request.passkey_id,
                revoked,
                revision: collection_revision.to_string(),
                passkey_revision: passkey_revision.to_string(),
            };
            let (nonce, ciphertext) = active
                .receipt_cipher
                .encrypt(&response, &aad)
                .map_err(runtime)?;
            storage::complete_command_success(
                &mut transaction,
                &caller,
                REVOKE_PASSKEY_OPERATION,
                &request.idempotency_key,
                &nonce,
                &ciphertext,
            )
            .await
            .map_err(runtime)?;
            transaction
                .commit()
                .await
                .map_err(storage::db("commit passkey revocation"))
                .map_err(runtime)?;
            Ok(Ok(response))
        })
    }
}

async fn update_authenticated_passkey(
    active: &ActivePasskey,
    caller: &str,
    idempotency_key: &str,
    subject: &str,
    result: &AuthenticationResult,
) -> Result<Option<(String, i64)>, RuntimeFailure> {
    let mut transaction = active
        .postgres
        .pool()
        .begin()
        .await
        .map_err(storage::db("begin authenticated passkey update"))
        .map_err(runtime)?;
    let Some(subject_row) = storage::lock_subject_optional(&mut transaction, subject)
        .await
        .map_err(runtime)?
    else {
        transaction
            .rollback()
            .await
            .map_err(storage::db("rollback missing authenticated subject"))
            .map_err(runtime)?;
        return Ok(None);
    };
    let rows = storage::load_passkeys_for_update(&mut transaction, subject)
        .await
        .map_err(runtime)?;
    let result_id = result.cred_id().as_ref();
    let Some(row) = rows
        .into_iter()
        .find(|row| row.credential_id.as_slice() == result_id)
    else {
        transaction
            .rollback()
            .await
            .map_err(storage::db("rollback unknown authenticated passkey"))
            .map_err(runtime)?;
        return Ok(None);
    };
    let result_counter = i64::from(result.counter());
    if result_counter > 0 && row.sign_count > 0 && result_counter <= row.sign_count {
        transaction
            .rollback()
            .await
            .map_err(storage::db("rollback stale passkey counter"))
            .map_err(runtime)?;
        return Ok(None);
    }
    let mut passkey = decode_passkey(&row)?;
    if passkey.update_credential(result).is_none() {
        transaction
            .rollback()
            .await
            .map_err(storage::db("rollback mismatched passkey update"))
            .map_err(runtime)?;
        return Ok(None);
    }
    let passkey_value = serde_json::to_value(&passkey).map_err(serialization_failure)?;
    sqlx::query(
        "UPDATE passkeys SET passkey=$2,sign_count=GREATEST(sign_count,$3),revision=revision+1,last_used_at=now() WHERE passkey_id=$1",
    )
    .bind(&row.passkey_id)
    .bind(&passkey_value)
    .bind(result_counter)
    .execute(&mut *transaction)
    .await
    .map_err(storage::db("update authenticated passkey"))
    .map_err(runtime)?;
    let revision: i64 = sqlx::query_scalar(
        "UPDATE passkey_subjects SET revision=revision+1,updated_at=now() WHERE subject_id=$1 RETURNING revision",
    )
    .bind(subject)
    .fetch_one(&mut *transaction)
    .await
    .map_err(storage::db("advance authenticated passkey collection revision"))
    .map_err(runtime)?;
    let advanced = sqlx::query(
        "UPDATE passkey_commands SET status='issuing',updated_at=now() WHERE caller_instance=$1 AND operation=$2 AND idempotency_key=$3 AND status='verifying'",
    )
    .bind(caller)
    .bind(FINISH_AUTHENTICATION_OPERATION)
    .bind(idempotency_key)
    .execute(&mut *transaction)
    .await
    .map_err(storage::db("mark verified passkey authentication issuing"))
    .map_err(runtime)?
    .rows_affected();
    if advanced != 1 {
        transaction
            .rollback()
            .await
            .map_err(storage::db("rollback stale authentication command"))
            .map_err(runtime)?;
        return Err(failure("passkey authentication command did not advance"));
    }
    transaction
        .commit()
        .await
        .map_err(storage::db("commit authenticated passkey update"))
        .map_err(runtime)?;
    let _ = subject_row;
    Ok(Some((row.passkey_id, revision)))
}

fn management_caller(
    active: &ActivePasskey,
    context: &InvocationContext,
    operation: &str,
    subject: &str,
) -> Option<String> {
    let caller = allowed_caller(&active.config.management_callers, context)?;
    let actor = active
        .actor_verifier
        .project_context::<UserActor>(
            context,
            passkey::CAPABILITY_ID,
            operation,
            &FixedClock::new(OffsetDateTime::now_utc()),
        )
        .ok()?;
    (actor.subject == subject).then_some(caller)
}

fn allowed_caller(callers: &[String], context: &InvocationContext) -> Option<String> {
    context
        .caller_instance()
        .filter(|caller| callers.iter().any(|allowed| allowed == caller))
        .map(str::to_owned)
}

async fn directory_status(
    directory: &DirectoryClient,
    context: InvocationContext,
    subject: &str,
) -> Result<DirectoryStatus, RuntimeFailure> {
    match directory
        .read_status_with_context(
            context,
            ReadStatusRequest {
                subject: subject.to_owned(),
            },
        )
        .await
    {
        Ok(response) if response.subject != subject => Err(failure(
            "Identity Directory returned another subject for passkey status",
        )),
        Ok(response) => Ok(match response.status {
            ReadStatusResponseStatus::Active => DirectoryStatus::Active,
            ReadStatusResponseStatus::Disabled => DirectoryStatus::Disabled,
        }),
        Err(DirectoryReadStatusInvocationError::Domain(
            directory::ReadStatusError::NotFound | directory::ReadStatusError::InvalidSubject,
        )) => Ok(DirectoryStatus::Missing),
        Err(DirectoryReadStatusInvocationError::Domain(error)) => Err(failure(format!(
            "Identity Directory returned an unknown passkey status error: {error:?}"
        ))),
        Err(DirectoryReadStatusInvocationError::Runtime(error)) => Err(error),
    }
}

async fn record_error(
    active: &ActivePasskey,
    caller: &str,
    operation: &str,
    idempotency_key: &str,
    code: &str,
) -> Result<(), RuntimeFailure> {
    storage::complete_command_error(&active.postgres, caller, operation, idempotency_key, code)
        .await
        .map_err(runtime)
}

fn decode_passkey(row: &PasskeyRow) -> Result<Passkey, RuntimeFailure> {
    serde_json::from_value(row.passkey.clone()).map_err(serialization_failure)
}

fn passkey_summary(row: &PasskeyRow) -> Result<PasskeySummary, RuntimeFailure> {
    Ok(PasskeySummary {
        passkey_id: row.passkey_id.clone(),
        label: row.label.clone(),
        credential_id: URL_SAFE_NO_PAD.encode(&row.credential_id),
        sign_count: row.sign_count.to_string(),
        revision: row.revision.to_string(),
        created_at: format_time(row.created_at)?,
        last_used_at: row.last_used_at.map(format_time).transpose()?,
        revoked_at: row.revoked_at.map(format_time).transpose()?,
    })
}

fn valid_begin_registration(request: &BeginRegistrationRequest) -> Option<i64> {
    let revision = parse_revision(&request.expected_revision)?;
    (valid_idempotency_key(&request.idempotency_key)
        && valid_subject(&request.subject)
        && valid_human_name(&request.user_name, 256)
        && valid_human_name(&request.display_name, 256))
    .then_some(revision)
}

fn valid_finish_registration(request: &FinishRegistrationRequest) -> Option<i64> {
    let revision = parse_revision(&request.expected_revision)?;
    (valid_idempotency_key(&request.idempotency_key)
        && valid_token(&request.challenge_id, 128)
        && valid_subject(&request.subject)
        && valid_human_name(&request.label, 128)
        && request.credential_json.as_str().len() <= 65_536)
        .then_some(revision)
}

fn valid_revoke(request: &RevokePasskeyRequest) -> Option<i64> {
    let revision = parse_revision(&request.expected_revision)?;
    (valid_idempotency_key(&request.idempotency_key)
        && valid_subject(&request.subject)
        && valid_token(&request.passkey_id, 128))
    .then_some(revision)
}

fn valid_subject(value: &str) -> bool {
    valid_token(value, 256)
}

fn valid_idempotency_key(value: &str) -> bool {
    valid_token(value, 128)
}

fn valid_token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_human_name(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

fn valid_name(value: &str) -> bool {
    valid_token(value, 128)
}

fn validate_authority_set(
    values: &[String],
    max_value_length: usize,
) -> Result<(), PasskeyConfigError> {
    if values.is_empty()
        || values.len() > 64
        || values
            .iter()
            .any(|value| !valid_token(value, max_value_length))
        || values.iter().collect::<BTreeSet<_>>().len() != values.len()
    {
        return Err(PasskeyConfigError::InvalidAuthoritySet);
    }
    Ok(())
}

fn valid_secret_reference(value: &str) -> bool {
    valid_token(value, 256)
}

fn parse_revision(value: &str) -> Option<i64> {
    value
        .parse::<i64>()
        .ok()
        .filter(|revision| *revision >= 0 && revision.to_string() == value)
}

fn intent_hash<T: Serialize>(value: &T) -> Result<[u8; 32], PasskeyPluginError> {
    let bytes = serde_json::to_vec(value).map_err(PasskeyPluginError::SerializeReceipt)?;
    let digest = Sha256::digest(bytes);
    let mut result = [0_u8; 32];
    result.copy_from_slice(&digest);
    Ok(result)
}

fn receipt_aad(caller: &str, operation: &str, idempotency_key: &str) -> Vec<u8> {
    format!("{caller}\0{operation}\0{idempotency_key}").into_bytes()
}

fn random_id(prefix: &str) -> Result<String, PasskeyPluginError> {
    let mut bytes = [0_u8; 24];
    getrandom::fill(&mut bytes).map_err(PasskeyPluginError::Random)?;
    Ok(format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes)))
}

fn format_time(value: OffsetDateTime) -> Result<String, RuntimeFailure> {
    value
        .format(&Rfc3339)
        .map_err(|error| failure(format!("failed to format passkey timestamp: {error}")))
}

fn serialization_failure(error: impl fmt::Display) -> RuntimeFailure {
    failure(format!("invalid internal WebAuthn representation: {error}"))
}

#[allow(clippy::needless_pass_by_value)]
fn runtime(error: PasskeyPluginError) -> RuntimeFailure {
    failure(error.to_string())
}

fn failure(detail: impl Into<String>) -> RuntimeFailure {
    RuntimeFailure::PluginFailure {
        detail: detail.into(),
    }
}

fn begin_registration_error(code: &str) -> Result<BeginRegistrationError, PasskeyPluginError> {
    match code {
        "disabled" => Ok(BeginRegistrationError::Disabled),
        "revision_conflict" => Ok(BeginRegistrationError::RevisionConflict),
        "too_many_passkeys" => Ok(BeginRegistrationError::TooManyPasskeys),
        _ => Err(PasskeyPluginError::Invariant(
            "unknown begin-registration receipt error",
        )),
    }
}

fn begin_authentication_error(code: &str) -> Result<BeginAuthenticationError, PasskeyPluginError> {
    match code {
        "invalid_credentials" => Ok(BeginAuthenticationError::InvalidCredentials),
        _ => Err(PasskeyPluginError::Invariant(
            "unknown begin-authentication receipt error",
        )),
    }
}

fn finish_registration_error(code: &str) -> Result<FinishRegistrationError, PasskeyPluginError> {
    match code {
        "invalid_request" => Ok(FinishRegistrationError::InvalidRequest),
        "disabled" => Ok(FinishRegistrationError::Disabled),
        "challenge_expired" => Ok(FinishRegistrationError::ChallengeExpired),
        "challenge_used" => Ok(FinishRegistrationError::ChallengeUsed),
        "invalid_credential" => Ok(FinishRegistrationError::InvalidCredential),
        "credential_exists" => Ok(FinishRegistrationError::CredentialExists),
        "revision_conflict" => Ok(FinishRegistrationError::RevisionConflict),
        _ => Err(PasskeyPluginError::Invariant(
            "unknown finish-registration receipt error",
        )),
    }
}

fn finish_authentication_error(
    code: &str,
) -> Result<FinishAuthenticationError, PasskeyPluginError> {
    match code {
        "invalid_request" => Ok(FinishAuthenticationError::InvalidRequest),
        "invalid_credentials" => Ok(FinishAuthenticationError::InvalidCredentials),
        "challenge_expired" => Ok(FinishAuthenticationError::ChallengeExpired),
        "challenge_used" => Ok(FinishAuthenticationError::ChallengeUsed),
        "disabled" => Ok(FinishAuthenticationError::Disabled),
        _ => Err(PasskeyPluginError::Invariant(
            "unknown finish-authentication receipt error",
        )),
    }
}

fn revoke_error(code: &str) -> Result<RevokePasskeyError, PasskeyPluginError> {
    match code {
        "disabled" => Ok(RevokePasskeyError::Disabled),
        "passkey_not_found" => Ok(RevokePasskeyError::PasskeyNotFound),
        "revision_conflict" => Ok(RevokePasskeyError::RevisionConflict),
        _ => Err(PasskeyPluginError::Invariant(
            "unknown revoke-passkey receipt error",
        )),
    }
}

impl Lifecycle for PasskeyAuthPlugin {
    async fn activate(&self, context: ActivateContext) -> Result<(), RuntimeFailure> {
        let config = self.config.clone();
        let dependencies = context.dependencies().clone();
        let cancellation = context.cancellation();
        let database_context =
            dependencies.invocation_context_after(DEPENDENCY_TIMEOUT, cancellation.clone())?;
        let database_url = self
            .secrets
            .resolve_with_context(
                database_context,
                ResolveRequest {
                    reference: config.database_url_secret.clone(),
                },
            )
            .await
            .map(|value| Zeroizing::new(value.value))
            .map_err(|error| match error {
                SecretsInvocationError::Domain(_) => {
                    failure("passkey database secret was rejected")
                }
                SecretsInvocationError::Runtime(error) => error,
            })?;
        let encryption_context =
            dependencies.invocation_context_after(DEPENDENCY_TIMEOUT, cancellation)?;
        let encryption_secret = self
            .secrets
            .resolve_with_context(
                encryption_context,
                ResolveRequest {
                    reference: config.receipt_encryption_key_secret.clone(),
                },
            )
            .await
            .map(|value| Zeroizing::new(value.value))
            .map_err(|error| match error {
                SecretsInvocationError::Domain(_) => {
                    failure("passkey receipt encryption secret was rejected")
                }
                SecretsInvocationError::Runtime(error) => error,
            })?;
        if encryption_secret.len() < 32 {
            return Err(failure(
                "passkey receipt encryption secret must contain at least 32 bytes",
            ));
        }
        let postgres = OwnedPostgres::prepare(
            &database_url,
            schema_plan(config.schema.clone()).map_err(|error| {
                RuntimeFailure::InvalidResolvedPlan {
                    detail: error.to_string(),
                }
            })?,
        )
        .await
        .map_err(|error| failure(error.to_string()))?;
        let webauthn = config
            .webauthn()
            .map_err(|error| RuntimeFailure::InvalidResolvedPlan {
                detail: error.to_string(),
            })?;
        let actor_verifier = ActorAssertionVerifier::from_public_key_base64(
            config.auth_issuer.clone(),
            &config.auth_public_key,
        )
        .map_err(|_| RuntimeFailure::InvalidResolvedPlan {
            detail: "invalid passkey Auth verification key".to_owned(),
        })?;
        let receipt_cipher = ReceiptCipher::derive(encryption_secret.as_bytes());
        self.postgres.replace(Some(postgres.clone()));
        self.active.replace(Some(Rc::new(ActivePasskey {
            postgres,
            config,
            webauthn,
            actor_verifier,
            receipt_cipher,
        })));
        Ok(())
    }

    async fn deactivate(&self, _context: DeactivateContext) -> Result<(), RuntimeFailure> {
        self.active.borrow_mut().take();
        let postgres = self.postgres.borrow_mut().take();
        if let Some(postgres) = postgres {
            postgres.pool().close().await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lenso_auth_sdk::ActorAssertionIssuer;
    use sqlx::{AssertSqlSafe, Executor};
    use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};

    fn config() -> PasskeyAuthConfig {
        let public_key =
            ActorAssertionIssuer::new("auth.users", b"test signing secret").public_key_base64();
        PasskeyAuthConfig::new(
            "passkey_auth",
            "database-url",
            "receipt-key",
            "example.com",
            "Example",
            vec!["https://login.example.com/".to_owned()],
            "auth.users",
            public_key,
            vec!["account-settings".to_owned()],
            vec!["web-ingress".to_owned()],
            vec!["app".to_owned()],
            300,
            86_400,
            3_600,
            16,
        )
        .expect("valid test config")
    }

    #[test]
    fn relying_party_rejects_non_https_remote_origin() {
        let mut value = config();
        value.allowed_origins = vec!["http://login.example.com/".to_owned()];
        assert_eq!(value.validate(), Err(PasskeyConfigError::InvalidOrigin));
    }

    #[test]
    fn relying_party_rejects_remote_non_default_port() {
        let mut value = config();
        value.allowed_origins = vec!["https://login.example.com:8443/".to_owned()];
        assert_eq!(value.validate(), Err(PasskeyConfigError::InvalidOrigin));
    }

    #[test]
    fn caller_limits_match_the_owned_schema() {
        let mut value = config();
        value.authentication_callers = vec!["a".repeat(129)];
        assert_eq!(
            value.validate(),
            Err(PasskeyConfigError::InvalidAuthoritySet)
        );
    }

    #[test]
    fn receipt_encryption_is_bound_to_command_identity() {
        let cipher = ReceiptCipher::derive(b"at least thirty-two bytes of secret material");
        let response = RevokePasskeyResponse {
            passkey_id: "pk_one".to_owned(),
            revoked: true,
            revision: "2".to_owned(),
            passkey_revision: "2".to_owned(),
        };
        let (nonce, ciphertext) = cipher
            .encrypt(&response, b"caller\0revoke\0one")
            .expect("encrypt receipt");
        let decoded: RevokePasskeyResponse = cipher
            .decrypt(&nonce, &ciphertext, b"caller\0revoke\0one")
            .expect("decrypt receipt");
        assert_eq!(decoded, response);
        assert!(
            cipher
                .decrypt::<RevokePasskeyResponse>(&nonce, &ciphertext, b"caller\0revoke\0different")
                .is_err()
        );
    }

    #[test]
    fn webauthn_library_verifies_registration_authentication_and_origin() {
        let config = config();
        let webauthn = config.webauthn().expect("valid WebAuthn policy");
        let origin = Url::parse("https://login.example.com/").expect("origin");
        let (creation, registration_state) = webauthn
            .start_passkey_registration(Uuid::new_v4(), "ada", "Ada", None)
            .expect("begin registration");
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let registration = authenticator
            .do_registration(origin.clone(), creation)
            .expect("software authenticator registration");
        let credential = webauthn
            .finish_passkey_registration(&registration, &registration_state)
            .expect("verify registration");
        let (request, authentication_state) = webauthn
            .start_passkey_authentication(std::slice::from_ref(&credential))
            .expect("begin authentication");
        let authentication = authenticator
            .do_authentication(origin, request)
            .expect("software authenticator authentication");
        let result = webauthn
            .finish_passkey_authentication(&authentication, &authentication_state)
            .expect("verify authentication");
        assert_eq!(result.cred_id(), credential.cred_id());

        let (creation, registration_state) = webauthn
            .start_passkey_registration(Uuid::new_v4(), "grace", "Grace", None)
            .expect("begin registration with strict origin");
        let wrong_origin = Url::parse("https://other.example.com/").expect("wrong origin");
        let registration = authenticator
            .do_registration(wrong_origin, creation)
            .expect("authenticator creates wrong-origin response");
        assert!(
            webauthn
                .finish_passkey_registration(&registration, &registration_state)
                .is_err()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires LENSO_POSTGRES_TEST_URL"]
    #[allow(clippy::too_many_lines)]
    async fn postgres_enforces_caller_scoped_receipts_and_single_use_challenges() {
        let database_url =
            std::env::var("LENSO_POSTGRES_TEST_URL").expect("LENSO_POSTGRES_TEST_URL is required");
        let schema = format!("passkey_test_{}", Uuid::new_v4().simple());
        PasskeyOperator::setup(&database_url, &schema)
            .await
            .expect("setup passkey schema");
        let postgres = OwnedPostgres::prepare(
            &database_url,
            schema_plan(schema.clone()).expect("schema plan"),
        )
        .await
        .expect("prepare passkey schema");
        let intent = intent_hash(&BeginAuthenticationRequest {
            idempotency_key: "begin-1".to_owned(),
            subject: "usr_ada".to_owned(),
        })
        .expect("intent hash");
        assert!(matches!(
            storage::claim_command(
                &postgres,
                "web-ingress",
                BEGIN_AUTHENTICATION_OPERATION,
                "begin-1",
                &intent
            )
            .await
            .expect("first command"),
            CommandClaim::Claimed
        ));
        assert!(matches!(
            storage::claim_command(
                &postgres,
                "web-ingress",
                BEGIN_AUTHENTICATION_OPERATION,
                "begin-1",
                &intent
            )
            .await
            .expect("same caller replay"),
            CommandClaim::InProgress
        ));
        let other_intent = [9_u8; 32];
        assert!(matches!(
            storage::claim_command(
                &postgres,
                "web-ingress",
                BEGIN_AUTHENTICATION_OPERATION,
                "begin-1",
                &other_intent
            )
            .await
            .expect("conflicting replay"),
            CommandClaim::Conflict
        ));
        assert!(matches!(
            storage::claim_command(
                &postgres,
                "other-ingress",
                BEGIN_AUTHENTICATION_OPERATION,
                "begin-1",
                &intent
            )
            .await
            .expect("other caller command"),
            CommandClaim::Claimed
        ));

        let mut transaction = postgres.pool().begin().await.expect("transaction");
        storage::ensure_subject(&mut transaction, "usr_ada", Uuid::new_v4())
            .await
            .expect("subject");
        storage::insert_challenge(
            &mut transaction,
            "pka_test",
            "authentication",
            "web-ingress",
            "usr_ada",
            0,
            &serde_json::json!({"state": "server-only"}),
            &serde_json::json!({"publicKey": {}}),
            OffsetDateTime::now_utc() + Duration::minutes(5),
        )
        .await
        .expect("challenge");
        transaction.commit().await.expect("commit challenge");
        let first = storage::consume_challenge(
            &postgres,
            "pka_test",
            "authentication",
            "web-ingress",
            FINISH_AUTHENTICATION_OPERATION,
            "finish-1",
        )
        .await
        .expect("first consumption")
        .expect("challenge exists");
        assert!(first.consumed_at.is_none());
        let replay = storage::consume_challenge(
            &postgres,
            "pka_test",
            "authentication",
            "web-ingress",
            FINISH_AUTHENTICATION_OPERATION,
            "finish-2",
        )
        .await
        .expect("replay consumption")
        .expect("challenge exists");
        assert!(replay.consumed_at.is_some());
        storage::prune(&postgres, 3_600)
            .await
            .expect("prune completed receipts and expired challenges");

        postgres.pool().close().await;
        let cleanup = sqlx::PgPool::connect(&database_url)
            .await
            .expect("cleanup pool");
        cleanup
            .execute(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
            .await
            .expect("drop test schema");
        cleanup.close().await;
    }
}
