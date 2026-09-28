-- Run as the migration owner after migrations, in the application's database.
-- Provision beacon_runtime as a LOGIN role with a unique password via your secret manager.
-- This role must not inherit any owner/admin role. Dedicated database, public schema assumed.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO beacon_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON users, products, cases, sessions, evidence, notifications, oidc_states, rate_limits TO beacon_runtime;
GRANT SELECT, INSERT ON audit_events TO beacon_runtime;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO beacon_runtime;
GRANT SELECT ON migration_ledger, schema_version, deployment_secrets TO beacon_runtime;
GRANT UPDATE (oidc_issuer) ON deployment_secrets TO beacon_runtime;
