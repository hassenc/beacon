# Changelog

## 0.1.0-beta.1 — unreleased

- Bind all case-action authorization and attribution to the transaction's current actor; add stale-role and uncapped-export regression coverage.
- Bind privileged writes and MFA proof consumption to the authenticated identity generation; add stale-password-change, stale-enrollment and active-demotion regression coverage.
- Load session-bound actor identity in one consistent query so an in-flight identity reset cannot upgrade an old session before a privileged write.
- Fix the synthetic loopback smoke drill's over-escaped export-revision matcher; the full HTTP rehearsal now completes through evidence export.
- Replace the backup V1 terminator with authenticated V2 archive identity, ordered frames and final length; stage complete decryption before restore and repair historical notification cancellations in migration 004.
- Wire trusted proxy CIDRs into production Compose, bound public POSTs to a four-request/7 MiB pilot envelope, and expose failed/stale notification queue alerts.
- Add TOTP with replay protection, recovery codes, OIDC, password changes, offboarding and session/token revocation.
- Add an encrypted SMTP outbox with retries, leases, deadline thresholds and delivery review.
- Add checksummed migrations, alpha payload conversion, separate encrypted evidence and offline envelope-key rotation.
- Add assessment fields, affected-product associations, watchers, version records, duplicate links, awareness corrections, reviewed CRA packets and retention holds/purge.
- Search authorized metadata across the entire case collection; paginate results and persist request throttles.
- Add English/French templates, production configuration examples, operator runbooks, CI pinning, dependency/secret checks and candidate artifact tooling.
- Preserve prerelease status pending the documented acceptance gates.

## 0.1.0-alpha.1 — local evaluation

Initial report intake, scoped reporter conversations, case triage, evidence, audit chain, manual CRA clocks and backup/restore tooling.
