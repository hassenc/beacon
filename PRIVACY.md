# Privacy and data handling

Beacon is self-hosted. Reports, reporter identity, messages, evidence, user accounts and the audit chain stay in the configured PostgreSQL deployment unless an operator deliberately exports or backs up them.

Case report text, reporter identity, messages and evidence are encrypted with the deployment key. Searchable case metadata, including title, product, version, status, owner, deadlines, timestamps and administrative filing notes, remains visible to the database service. Database dumps also contain metadata, password hashes and encrypted fields; use the supported authenticated encrypted backup path.

Beacon sends only minimal notification mail: a case reference, a deployment link and an instruction to sign in. SMTP acceptance is not proof that a person read the message. Beacon has no telemetry, trackers, hosted service dependency or automatic third-party vulnerability lookup.

Operators choose the retention schedule, legal-hold process, access roster, backup custody and deletion policy. Purging a terminal case removes live case content, evidence, reporter sessions and notifications while retaining an audit record of the purge. Backups and exports are separate copies and require their own retention controls. This document is operational guidance, not a complete jurisdiction-specific privacy notice or legal advice.
