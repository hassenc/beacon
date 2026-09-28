# Threat model — beta

## Assets and boundaries

Unpublished report content, evidence, reporter identity, internal conversation, response metadata, regulatory timeline, credentials and the external encryption key. Trust boundaries separate unauthenticated reporters, one-case reporter sessions, internal users, the Go server, PostgreSQL and the database administrator.

## Controls implemented

| Threat | Control |
|---|---|
| Reporter accesses internal data | Separate public projection; scoped sessions; backend checks for lists, detail, export and files |
| Stored script / malicious HTML upload | Go html/template escaping, CSP, no script execution or preview, attachment content-disposition and nosniff |
| Password compromise through DB read | Argon2id hashes with per-password salts; bounded authentication concurrency |
| Token compromise through DB read | Random 256-bit recovery/session secrets; SHA-256 storage; tokens exchanged through POST, not URLs |
| Cross-site request forgery | Signed double-submit CSRF cookie, constant-time comparison, Origin validation, SameSite Strict; secure host cookies with HTTPS |
| Database content disclosure | AES-256-GCM for payload and evidence; object ID as associated data; external master key |
| Audit modification | Atomic mutation/event transaction, serialized chain appends, update/delete/truncate rejection trigger, verifier |
| Lost updates | Row locking, revision preconditions and transaction commit |
| Upload exhaustion | 7 MiB request cap, 5 MB/file, 10 MB/case, four concurrent multipart admissions and 1 MiB parser memory; no archive extraction |

## Residual risk and explicit exclusions

This has not undergone independent security review. Database/application administrator or host compromise can bypass the audit trigger, recompute a chain, read the master key, or decrypt data. External checkpoints are necessary to detect historical rewrites. A hash chain by itself is not notarization or nonrepudiation.

Implemented hardening includes per-case/file envelope keys, offline atomic key rotation, OIDC/TOTP, account and reporter-session revocation, PostgreSQL rate limits, retention holds and controlled purge. Production runtime credentials cannot own tables or hold administrative role attributes. The grant script denies audit rewrites.

Residual operational risks include proxy-level client attribution, global storage quotas, sustained load, backup retention, and host compromise. Rate windows persist across replicas; forwarded client attribution requires an explicitly configured immediate proxy CIDR. The small-pilot upload envelope is four concurrent 7 MiB multipart requests against a 32 MiB `/tmp` budget; sustained attackers can still degrade service. Evidence remains in PostgreSQL and the 500 GB target is not qualified.

Application-level encryption does not hide titles, ownership, product/version data, user email addresses, timestamps or administrative filing notes. SMTP notifications require configuration and monitoring; queued mail is not proof of human escalation. Availability, on-call response and legal classification are not supplied by software timers.

Configured SMTP and OIDC providers receive mail and authentication traffic. Otherwise core case processing has no mandatory external service. Dependency fetching and development tools use the network during builds. The SRP link opens only when the user chooses it.

## Federation and notification boundaries

OIDC uses browser-bound single-use state, PKCE, nonce, signature/audience/expiry checks and a configured assurance value. Provisioned subjects bind to a deployment issuer. Test provider-specific MFA semantics before production. TOTP codes are rejected on reuse; single-use recovery codes are stored as hashes.

Outbox recipients are encrypted and access is rechecked before sending. Messages contain only a reference and login link. SMTP crashes can cause duplicate delivery; stable Message-ID is not an exactly-once guarantee. A disabled account may already have received previous emails.
