# Authorization matrix

Authorization is case-based. Product ownership is descriptive metadata and does not grant access to a case.

| Capability | Owner | Triage | Engineer | Viewer |
|---|---:|---:|---:|---:|
| List/search all cases | yes | yes | assigned/watched only | yes |
| Read case and files | yes | yes | assigned/watched only | yes |
| Add internal note | yes | yes | assigned/watched only | no |
| Send reporter-visible reply | yes | yes | no | no |
| Change status/severity/assignment | yes | yes | limited case write; severity/assignment manager-only | no |
| Manage products, watchers and CRA decisions | yes | yes | no | no |
| Manage users and OIDC bindings | yes | no | no | no |
| Export full case or CRA packet | yes | yes | no | no |
| Purge terminal case | yes | no | no | no |
| View global audit and delivery queue | yes | yes | no | no |

Every privileged write reloads the actor and relevant case under the transaction serialization boundary. Disabled users, stale identity generations, removed assignments and removed watchers cannot complete an in-flight write.
