use lenso_postgres_kit::{Migration, PlanError, SchemaPlan, sql_migrations};

const MIGRATIONS: &[Migration] = sql_migrations![(
    1,
    "create-passkey-state",
    "migrations/001_create_passkey_state.sql",
)];

pub(crate) fn schema_plan(schema: impl Into<std::sync::Arc<str>>) -> Result<SchemaPlan, PlanError> {
    SchemaPlan::new(schema, MIGRATIONS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_owns_one_time_challenges_counters_and_caller_scoped_receipts() {
        let sql = MIGRATIONS[0].sql();
        assert!(sql.contains("credential_id BYTEA NOT NULL UNIQUE"));
        assert!(sql.contains("sign_count BIGINT NOT NULL"));
        assert!(sql.contains("consumed_at TIMESTAMPTZ"));
        assert!(sql.contains("PRIMARY KEY (caller_instance, operation, idempotency_key)"));
        assert!(sql.contains("status IN ('reserved', 'verifying', 'issuing'"));
    }

    #[test]
    fn invalid_schema_is_rejected() {
        assert!(schema_plan("public; DROP SCHEMA public").is_err());
    }
}
