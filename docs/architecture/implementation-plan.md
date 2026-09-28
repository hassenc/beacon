> Historical implementation notes. The code and operator documentation are the authoritative sources for the current implementation.

# Specification review and implementation plan

## Assessment

The product boundary is good. The P0 list is too broad for the first implementation and mixes an initial functional milestone with production-release criteria. Preserve the original document as the destination; label this implementation **0.1.0-alpha.1**, not the completed production v0.1.

## Required corrections

1. **CRA workflow:** human-confirmed classification and awareness only. Both initial deadlines use awareness; submitting early warning must not move the 72-hour deadline. Keep the policy version on each case. A vulnerability final stage waits for a corrective-measure timestamp; an incident final stage waits for the notification timestamp. Do not treat a month as 30 days. The documented engine uses UTC calendar-month addition, clamped to month end; legal review of boundary conventions is a release gate. ENISA confirms the initial SRP has no API. [ENISA FAQ](https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/frequently-asked-questions).
2. **Intermediate reports:** CRA Article 14(6) permits CSIRT-requested intermediate reports. The earlier draft incorrectly imported NIS2 ongoing-incident progress/final-report triggers; those are not CRA rules. Beta records intermediate filings without changing statutory clocks. It does not declare legal compliance. [CRA Article 14](https://eur-lex.europa.eu/legal-content/EN/TXT/PDF/?uri=OJ%3AL_202402847).
3. **Security.txt:** use the actual hosted location as Canonical. Set an explicit persisted expiration; never silently roll it forward on every request. The standard requires Contact and a single Expires value. An optional PGP link must point to a real configured key. [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116.html).
4. **Audit integrity:** a hash chain alone cannot detect a privileged attacker rewriting the whole chain or truncating its tail. Serialize chain appends with database locking, commit events with mutations, and compare externally retained checkpoints. Do not describe the database as immutable against its administrator.
5. **Reporter boundaries:** construct an explicit public projection. Never serialize an internal case and rely on UI hiding. Public status must be mapped separately; tokens are one-case secrets, hashed at rest, submitted in forms, and exchanged for short-lived server-side sessions.
6. **RBAC:** define a matrix, including list/search/export/download. Engineers get explicitly assigned cases; owner/triage manage all; viewer is read-only. Assignment and regulatory decisions require owner/triage. Test the backend boundaries.
7. **Storage:** transactionally persist report, attachments and event. Bound request sizes, file sizes, list sizes and rate-limiter memory. Treat all files as opaque downloads. Initial bounded attachments are stored with their case in PostgreSQL; move to separate encrypted object storage before the 500 GB target.
8. **Encryption/search:** specify exactly what remains visible. Initial AES-GCM encryption protects report text, reporter identity, messages and attachments at rest; metadata (title/product/status/owner/deadlines) remains searchable. Initial key management is one external master key, not per-object envelope encryption. Key rotation is a release-gate follow-up.
9. **Reliable operations:** SMTP needs a transactional outbox with retry/idempotency, health visibility and tests. A deadline dashboard alone does not provide after-hours coverage.
10. **Privacy and lifecycle:** add retention, token revocation/rotation, user offboarding, legal holds and controlled deletion with an audit-preserving policy. No claim of complete GDPR compliance.

## Architecture chosen

Go modular monolith, PostgreSQL, embedded server-rendered HTML/CSS, no JavaScript required for forms. This uses the specification's lightweight frontend alternative: React is not necessary for the first workflow. No Node runtime, telemetry, third-party fonts, CAPTCHA, or application LLM calls. Browser requests stay on the deployment except when the user explicitly opens the SRP.

Use small application modules for domain/deadline rules, storage/audit, encryption/authentication and HTTP presentation. Cases are versioned JSON aggregates in PostgreSQL for the alpha; users, sessions, products and audit events have separate tables. Row locks prevent lost updates, and a global transaction lock orders audit commits. Normalize case search and attachment storage before load targets are claimed. Migrations are forward-only and schema-versioned.

## Milestones and acceptance gates

| Milestone | Deliverable | Acceptance |
|---|---|---|
| M1 — initial application (this build) | Public report, token recovery, internal sign-in, queue/detail, assignment/status/severity, internal and reporter messages, products, bounded evidence files, audit verification, JSON/ZIP export, explicit CRA clocks and recorded filings, security.txt, Docker | End-to-end report→acknowledge→communicate→close; authorization matrix; CSRF; at-rest secrecy; concurrency; deadline boundaries; restart and restore tests |
| M2 — identity and response reliability | OIDC, local TOTP, account lifecycle, token rotation/revocation, SMTP outbox and escalation worker | Identity-provider integration tests; email contains no case details; retries do not duplicate work; expiry and revocation tests |
| M3 — complete response model | Multiple affected products/versions, duplicate linkage, watchers, assessment fields, awareness corrections with reasons, full incident lifecycle, selective CRA packet | Versioned deadline-policy upgrades preserve existing cases; complete regulatory review; packet review prevents internal-note disclosure |
| M4 — operational release | Full EN/FR strings, encryption/key rotation, separate attachment storage, retention, migration/restore automation, accessibility/load review | Fresh VM deployment and recovery; independent security review; supported migration path; performance evidence |
| M5 — public v0.1 | Signed container and sources, SBOM/provenance, dependency scans, maintainers' security policy and pilot feedback | No known unresolved exploitable Critical/High findings; five partners complete drills; published release checklist |

M1 is a real persisted application for local evaluation with synthetic data. It is not permission to route live vulnerability reports through an unaudited alpha. The remaining milestones are explicit work, not hidden placeholders in the UI.

## Indicative effort

Planning estimate for one experienced full-time engineer: M1 1–2 weeks to review and stabilize, M2 2–3 weeks, M3 2–3 weeks, M4/M5 3–5 weeks plus external review scheduling. These are estimates, not delivery commitments; interview findings may reduce or change scope. Reserve sustained maintenance capacity after release.

## Commercial work alongside development

Run interviews and paid setup/drill experiments during M1/M2. Avoid building multi-tenancy until partners demonstrate repeatable multi-client operations. Keep all security-critical product features in Community. The release gate is evidence of safe operation; the business gate is customer commitment and paid delivery economics.
