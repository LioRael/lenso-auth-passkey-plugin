//! Authoritative source for the Passkey Capability contract.

use lenso_contract_authoring as lenso;

#[derive(serde::Deserialize)]
pub struct Nullable<T>(Option<T>);

impl<T: lenso::JsonSchema> lenso::JsonSchema for Nullable<T> {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        format!("Nullable_{}", T::schema_name()).into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        format!("Nullable<{}>", T::schema_id()).into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        <Option<T> as lenso::JsonSchema>::json_schema(generator)
    }
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct PasskeySummary {
    pub passkey_id: String,
    pub label: String,
    pub credential_id: String,
    pub sign_count: String,
    pub revision: String,
    #[schemars(extend("format" = "date-time"))]
    pub created_at: String,
    #[schemars(extend("format" = "date-time"))]
    pub last_used_at: Nullable<String>,
    #[schemars(extend("format" = "date-time"))]
    pub revoked_at: Nullable<String>,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct BeginRegistrationRequest {
    pub idempotency_key: String,
    pub subject: String,
    pub user_name: String,
    pub display_name: String,
    pub expected_revision: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct BeginRegistrationResponse {
    pub challenge_id: String,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub public_key_json: String,
    #[schemars(extend("format" = "date-time"))]
    pub expires_at: String,
    pub revision: String,
}

#[derive(lenso::DomainError)]
pub enum BeginRegistrationError {
    Forbidden,
    InvalidRequest,
    Disabled,
    RevisionConflict,
    IdempotencyConflict,
    OperationInProgress,
    TooManyPasskeys,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct FinishRegistrationRequest {
    pub idempotency_key: String,
    pub challenge_id: String,
    pub subject: String,
    pub expected_revision: String,
    pub label: String,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub credential_json: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct FinishRegistrationResponse {
    pub passkey: PasskeySummary,
    pub revision: String,
}

#[derive(lenso::DomainError)]
pub enum FinishRegistrationError {
    Forbidden,
    InvalidRequest,
    Disabled,
    ChallengeExpired,
    ChallengeUsed,
    InvalidCredential,
    CredentialExists,
    RevisionConflict,
    IdempotencyConflict,
    OperationInProgress,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct BeginAuthenticationRequest {
    pub idempotency_key: String,
    pub subject: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct BeginAuthenticationResponse {
    pub challenge_id: String,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub public_key_json: String,
    #[schemars(extend("format" = "date-time"))]
    pub expires_at: String,
    pub revision: String,
}

#[derive(lenso::DomainError)]
pub enum BeginAuthenticationError {
    Forbidden,
    InvalidRequest,
    InvalidCredentials,
    IdempotencyConflict,
    OperationInProgress,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct FinishAuthenticationRequest {
    pub idempotency_key: String,
    pub challenge_id: String,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub credential_json: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct FinishAuthenticationResponse {
    pub subject: String,
    pub passkey_id: String,
    pub revision: String,
    pub session_id: String,
    #[schemars(extend("x-lenso-sensitive" = true))]
    pub credential: String,
    #[schemars(extend("format" = "date-time"))]
    pub expires_at: String,
}

#[derive(lenso::DomainError)]
pub enum FinishAuthenticationError {
    Forbidden,
    InvalidRequest,
    InvalidCredentials,
    ChallengeExpired,
    ChallengeUsed,
    Disabled,
    IdempotencyConflict,
    OperationInProgress,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ListPasskeysRequest {
    pub subject: String,
    pub include_revoked: bool,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ListPasskeysResponse {
    pub revision: String,
    pub passkeys: Vec<PasskeySummary>,
}

#[derive(lenso::DomainError)]
pub enum ListPasskeysError {
    Forbidden,
    InvalidRequest,
    Disabled,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct RevokePasskeyRequest {
    pub idempotency_key: String,
    pub subject: String,
    pub passkey_id: String,
    pub expected_revision: String,
}

#[derive(lenso::JsonSchema, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct RevokePasskeyResponse {
    pub passkey_id: String,
    pub revoked: bool,
    pub revision: String,
    pub passkey_revision: String,
}

#[derive(lenso::DomainError)]
pub enum RevokePasskeyError {
    Forbidden,
    InvalidRequest,
    Disabled,
    PasskeyNotFound,
    RevisionConflict,
    IdempotencyConflict,
    OperationInProgress,
}

#[lenso::capability(
    id = "lenso.auth.passkey",
    major = 1,
    version = "1.0.0",
    portable = true,
    cross_lane_transfer = true
)]
pub trait Passkey {
    async fn begin_registration(
        &self,
        context: lenso::Ctx<'_>,
        request: BeginRegistrationRequest,
    ) -> Result<BeginRegistrationResponse, BeginRegistrationError>;

    async fn finish_registration(
        &self,
        context: lenso::Ctx<'_>,
        request: FinishRegistrationRequest,
    ) -> Result<FinishRegistrationResponse, FinishRegistrationError>;

    async fn begin_authentication(
        &self,
        context: lenso::Ctx<'_>,
        request: BeginAuthenticationRequest,
    ) -> Result<BeginAuthenticationResponse, BeginAuthenticationError>;

    async fn finish_authentication(
        &self,
        context: lenso::Ctx<'_>,
        request: FinishAuthenticationRequest,
    ) -> Result<FinishAuthenticationResponse, FinishAuthenticationError>;

    async fn list_passkeys(
        &self,
        context: lenso::Ctx<'_>,
        request: ListPasskeysRequest,
    ) -> Result<ListPasskeysResponse, ListPasskeysError>;

    async fn revoke_passkey(
        &self,
        context: lenso::Ctx<'_>,
        request: RevokePasskeyRequest,
    ) -> Result<RevokePasskeyResponse, RevokePasskeyError>;
}
