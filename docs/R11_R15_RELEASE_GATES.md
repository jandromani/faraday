# R11 enterprise release gate — expanded after R12/R13/R14/R15

**Release provenance must be conditional on ALL relevant internal assurance checks, not just original R1.**

The protected `master` ruleset presently requires `security (3.11/3.12/3.13)`.
Those checks now **explicitly fail if any upstream job fails/skips/cancels**:
Node/Docker/Vault/MCP baseline, official HTTPS Keycloak+Vault Authority,
real PostgreSQL-fenced MCP gateway, R12 SCRAM least-privilege native driver,
R13 expiring leader leases, R14 signed delegation non-amplification,
and R15 hostile input/SQL/TLS abuse matrix.

`R1 attest-candidate` also **needs all these reusable workflows**. A single
failed job must stop package attestation and release. Evidence: inspect the
actual SHA's workflow graph and all upstream job outcomes before accepting
any signed Developer Preview.

Direct GitHub ruleset administration has not been changed: a repository
administrator should add stable individual contexts and a real second
reviewer without deadlocking a sole-maintainer workflow.

**Still not an enterprise certificate:** tests are self-authored and largely
use disposable services. Real human delegated OBO, independent pentest,
five external unassisted installs, one authorized operational pilot,
geographically independent HA and real downstream reconciliation are open.
