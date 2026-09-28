# Architecture

Beacon is a single Go executable with PostgreSQL, embedded server-rendered HTML/CSS and no required JavaScript, frontend package tree or telemetry service.

The [code map](docs/architecture/README.md) is the canonical module guide. The [threat model](THREAT_MODEL.md) describes trust boundaries and limitations. Cases and audit events are committed transactionally; case mutations and audit appends share a database serialization lock. Per-case encrypted payloads and detached encrypted evidence are protected by the deployment key.

The service is intentionally not a multi-tenant SaaS, legal classifier, ENISA filing client, malware scanner, attachment previewer or 24/7 response service. Capacity beyond the documented pilot envelope requires measurement before architectural change.
