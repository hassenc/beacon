# Deployment

The supported deployment path is documented in [deployment configuration](docs/deployment/README.md), [the production Compose starting point](deploy/compose.production.yaml), and [the operator runbook](docs/operations/runbook.md).

Production requires a separately provisioned PostgreSQL service, migration-owner credential, restricted runtime credential, HTTPS proxy, explicit security.txt expiry, SMTP with certificate-verified STARTTLS, protected secret files, backups, and named response/escalation/backup owners. The application does not provision DNS, TLS, SMTP, identity providers or human coverage.

Use synthetic data until the release gates and the witnessed recovery/response rehearsal are complete.
