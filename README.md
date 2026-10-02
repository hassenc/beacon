# Beacon Community

**A self-hosted security response portal for product manufacturers.**

Receive private vulnerability reports, coordinate investigation, preserve evidence and audit records, and track explicitly activated CRA reporting deadlines.

**Current version: 0.1.0-beta.1, synthetic evaluation source.** Hardening and operations tooling are implemented and locally tested, but production acceptance remains open. Use synthetic data until the deployment gates are satisfied.

Product and guide site: [Beacon Community](https://beacon.grislabs.com/) (marketing deployment in progress).

## Try locally

Requires Docker Compose and Python 3.

```sh
git clone https://github.com/hassenc/beacon.git
cd beacon
./scripts/setup.sh
docker compose up --build -d
```

Open [localhost:8787](http://localhost:8787). The generated team sign-in email and password are in the ignored `.env` file. There is no baked-in default password. Optionally seed an empty evaluation database:

```sh
docker compose exec beacon /beacon seed-demo
```

Stop with `docker compose down`. The database volume persists. Keep the encryption key safe: a backup without its matching key cannot recover encrypted records. Do not use `down -v` unless deliberately deleting the local database.

See the [synthetic evaluation walkthrough](docs/evaluation-walkthrough.md) for
the reporter → triage → response → export path. For non-sensitive evaluation
feedback, open a [public issue](https://github.com/hassenc/beacon/issues) with
synthetic or redacted information only. Do not use public issues for
vulnerabilities or private reporter data; follow [SECURITY.md](SECURITY.md).

## Included

- Anonymous or identified reports, encrypted evidence, hash-only recovery tokens and private reporter conversations.
- Owner, Triage, Engineer and Viewer permissions; explicit assignment and watchers; strict internal/external message separation.
- TOTP with replay protection and recovery codes; OIDC with explicit subject binding and assurance checks; password changes, offboarding and session/token revocation.
- Search across authorized metadata, 50-case pagination, product/version records, multiple affected-product entries, CVE/CWE/CVSS fields, duplicates and references.
- Human-confirmed CRA activation, versioned deadline policies, awareness corrections, filing records and a reviewed selective export.
- Transactional encrypted email queue, TLS SMTP, retries and deadline notifications.
- Separate encrypted evidence storage, envelope keys, offline key rotation, legal holds and controlled case purge.
- Audit-chain verification, full case archives, explicit checksummed migrations and tested local backup/restore.
- Production backup/restore wrappers with authenticated archives, off-host metadata and isolated recovery checks; optional customer-managed dependency-free health/queue/backup/disk monitoring examples with deduplicated alerts.
- English/French pages, server-rendered forms, no frontend package dependencies, no telemetry or LLM integration.

## Boundaries

Beacon does not determine legal applicability or file reports with ENISA. Review any exported report and selected evidence before external sharing. Full case archives contain private internal context.

The audit chain requires independently retained checkpoints to detect privileged rewriting. Encryption does not hide searchable metadata. SMTP delivery is at-least-once, so crash recovery can result in duplicate mail.

The 10,001-case test verifies search and pagination, not the complete capacity target. The small-pilot intake envelope is four concurrent multipart requests capped at 7 MiB each; PostgreSQL evidence storage has not been qualified for 500 GB or sustained production concurrency. Browser submission, accessibility, native-language review, independent security assessment, a fresh Linux installation and real SMTP/IdP deployment drills remain release gates.

## Development and verification

Requires Go 1.26.8; `go.mod` pins the toolchain.

```sh
docker compose up -d db
./scripts/run-local.sh
./scripts/test.sh
python3 scripts/localize.py --check
python3 scripts/smoke.py
./scripts/backup.sh
./scripts/restore-check.sh
python3 scripts/test_monitor.py
scripts/test-production-tools.sh
scripts/test-production-recovery.sh
```

The smoke test creates a synthetic case. Integration tests create temporary PostgreSQL schemas and leave existing evaluation cases intact. Without `BEACON_TEST_DATABASE_URL`, plain `go test ./...` skips database tests; `scripts/test.sh` configures it from the local `.env` and runs the full suite. The restore check uses a separate temporary database. `scripts/test-production-recovery.sh` is an optional disposable PostgreSQL qualification, not a production deployment or required customer monitoring service.

The checked-in backup and monitor systemd units are opt-in self-hosting
examples. They are not enabled by Beacon installation and do not define a
mandatory Beacon-hosted alerting service; each deployment operator chooses its
storage, monitoring route and recipients.

## Documentation

- [Privacy and data handling](PRIVACY.md), [architecture](ARCHITECTURE.md), [deployment](DEPLOYMENT.md), [backup and restore](BACKUP_RESTORE.md), and [deferred scope](NOT_NOW.md)
- [Architecture and code map](docs/architecture/README.md)
- [Deployment configuration](docs/deployment/README.md) and [operator runbook](docs/operations/runbook.md)
- [Backup and restore](docs/backup/README.md)
- [Customer operations template](docs/operations/customer-operations-template.md)
- [Synthetic evaluation walkthrough](docs/evaluation-walkthrough.md)
- [v0.1.0-beta.1 evaluation release notes](docs/releases/v0.1.0-beta.1.md)
- [Threat model](THREAT_MODEL.md) and [security policy](SECURITY.md)
- [Contribution guide](CONTRIBUTING.md) and [governance](GOVERNANCE.md)
- [Third-party notices](THIRD_PARTY_NOTICES.md)
- [Authorization matrix](docs/security/authorization.md)

## License

Apache-2.0. No paid feature gates in the security workflow. No association with or endorsement by ENISA is implied.
