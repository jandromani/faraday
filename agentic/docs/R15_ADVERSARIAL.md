# R15 — Adversarial abuse matrix

Tests deliberately mutate the **protected synthetic backend request**
500 times with attacker-controlled tool/resource/action/operation ID,
gateway owner/epoch and payment-like arguments. Every malformed request
must be denied **before any database call**. An additional set attacks
native PostgreSQL SQL selection and bind values, control/execute role
separation, and production TLS guardrails. Existing FARADAY fuzz tests
run in the same dedicated CI gate.

This is an internal, self-authored negative campaign. It is **not** an
independent penetration test, proof of freedom from SQL injection, full
multi-tenant isolation or assurance against all MITM attacks. Report
actual failures and do not relax parameters to force a green CI.

Before external R15/R16 acceptance require:
- External red-team scope, exact commit, attack trace artifacts and severity;
- Strict egress and ingress tests in independently hosted namespaces;
- Supply-chain SBOM vulnerability scanning and reproducible release identity;
- Rotation and compromise of agent, issuer and backend credentials;
- Cross-tenant authorization and receipt substitution/rollback attacks;
- Real network splits, partial backend effect and unknown-result reconciliation.
