# FARADAY v0.96 — Operator Security & Evaluation

**Status: experimental synthetic Secure Pilot, not enterprise production.**
E17 quotas, E18 signed approvals, E19 incident response and E26 mutation testing have meaningful partial implementations, not the entire original epics.

## Dual approval (E18)
Independent Ed25519 signatures bind the **exact capability**, agent, resource, action, tool, canonical argument hash and expiry. Quorum 2 and optional role diversity are checked BEFORE spending a capability and BEFORE any backend side effect. The agent and gateway NEVER receive approver private keys in the Docker test. The Docker fixture generates synthetic finance/security approvers, not verified human employees.

Quorum verification rejects aliases that share the same Ed25519 public key. Distinct keys alone do not prove distinct people or organizational roles.

Operator CLI, after manually inspecting the request:
```sh
faraday approval sign --request request.json --approver finance --private-key private/finance.pem --out finance-approval.json
faraday approval sign --request request.json --approver security --private-key private/security.pem --out security-approval.json
faraday approval verify --request request.json --bundle bundle.json --keys trusted-keys.json --quorum 2
```
A request holds capability, agent, tool, resource, action, args. The signed JSON objects are passed as a Base64URL-encoded array in the `X-Faraday-Approvals` MCP header. Their private keys remain out of the agent and gateway. There is no enterprise approval UI/SSO yet.

## Sentinel (E19)
Persistent SQLite stop, denial-triggered temporary quarantine, pseudonymized metadata and a local hash-linked ledger.
```sh
faraday sentinel status --db /absolute/path/to/gateway-state/sentinel.sqlite
faraday sentinel stop --db /absolute/path/to/gateway-state/sentinel.sqlite
faraday sentinel resume --db /absolute/path/to/gateway-state/sentinel.sqlite
faraday sentinel verify --db /absolute/path/to/gateway-state/sentinel.sqlite
```
The hash chain detects some modifications, **not truncation/re-hashing by a privileged DB editor**. Quarantining by network address can impact clients behind the same NAT. No SIEM, cluster-wide revocation, external evidence anchoring or HA.
Stop/resume and the corresponding control event are committed together; an audit write failure rolls back the state change.

## Budgets (E17)
A transactionally enforced per-agent call budget is stored in local SQLite; it is consumed after cryptographic authorization but before backend execution. Unknown/exhausted budgets fail closed. Failures may burn quota, intentionally favouring safety over availability. **Not a global/distributed token or CPU limiter.**
The last successful consumption time is persisted per agent; a clock earlier than that time is rejected. This does not prevent a forward clock jump or provide trusted time, tenant isolation or distributed accounting.

## Adversarial mutation tests (E26)
`npm run security:fuzz` runs 320 mutated capability signatures, 320 mutated approval signatures and 120 signed-argument substitutions. Canonical Base64URL signature encoding is enforced after a fuzz test revealed ambiguous trailing character encodings. These are reproducible mutation checks, not formal security proofs or coverage-guided fuzzing/chaos.

## Docker boundary
`npm run pilot:docker` runs an isolated synthetic backend and a gateway, with a dummy agent on a separate network; anonymous and approval-less requests are denied, an approved execution is signed independently by gateway and backend, replay is denied, and agent-to-backend direct network access is denied. Docker isolation is a **property of this test topology**, not universal prevention of all bypasses.

## Residual blockers
E17–E19 and E26 remain **partially done** at their enterprise scope: corporate identities, a real human approval service, distributed ledger and policy, SIEM integration, resource-level gateway, signed evidence anchoring, prolonged fuzzing/chaos, external audit, and real deployment pilots are pending.
