# Code map

Beacon is a single Go executable with embedded server-rendered HTML/CSS and PostgreSQL. Core forms require no JavaScript. There are no frontend packages, trackers or mandatory cloud services.

| Module | Responsibility |
|---|---|
| `domain.go`, `policy.json` | Roles, case model, status transitions, versioned CRA deadlines |
| `store.go`, `migration.go` | Transaction boundaries, audit chain, sessions, checksummed migrations |
| `crypto.go`, `evidence.go` | Password hashing, envelope encryption, separate evidence storage, key rotation |
| `identity.go`, `oidc.go` | TOTP/recovery, lifecycle controls, federation and browser-bound login |
| `notifications.go` | Encrypted transactional outbox, deadline scheduling, leased delivery and retries |
| `workflow.go`, `products.go`, `queue.go` | Assessment, affected products, registry, privacy controls, bounded search |
| `http.go` | Routes, authorization, CSRF, request limits and HTML rendering |
| `i18n.go`, `web/fr.json` | Language selection and French catalog; generated French templates |
| `cmd/beacon` | Startup, explicit migrations, verification and maintenance CLI |

Sensitive case payloads and evidence use independent random keys wrapped by a deployment key. Case metadata remains searchable plaintext; keep sensitive investigative details in internal notes. Evidence stays in PostgreSQL transactionally but is detached from case reads. This design has not been qualified for 500 GB.

All durable case mutations and audit appends share a transaction. Revisions prevent silent case overwrite. Audit writes are serialized with a database advisory lock. The audit chain needs independently retained checkpoints to detect privileged rewriting.

OIDC binds a provisioned subject to one deployment issuer and verifies signature, audience, expiry, nonce, browser state, PKCE and configured assurance. No account is linked merely because an email address matches.

For translations, update English templates and `web/fr.json`, run `python3 scripts/localize.py`, and commit generated `.fr.html` files. Translation happens on static template literals before user content is rendered; it never rewrites report text. Diagnostic errors and regulatory export field names may remain English. Obtain native-language and accessibility review before claiming complete localization acceptance.
