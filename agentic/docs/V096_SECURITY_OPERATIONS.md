# FARADAY v0.96 — Operator Security & Evaluation

**Status: experimental synthetic Secure Pilot, not enterprise production.**
E17 quotas, E18 signed approvals, E19 incident response and E26 mutation testing have meaningful partial implementations, not the entire original epics.

## Dual approval (E18)
Independent Ed25519 signatures bind the **exact capability**, agent, resource, action, tool, canonical argument hash and expiry. Quorum 2 and optional role diversity are checked BEFORE spending a capability and BEFORE any backend side effect. The agent and gateway NEVER receive approver private keys in the Docker test. The Docker fixture generates synthetic finance/security approvers, not verified human employees.

Quorum verification rejects aliases that share the same Ed25519 public key. The gateway also rejects an approval made with the requesting agent's registered key. Distinct keys alone do not prove distinct people or organizational roles.

For configured approvals, the gateway stores the verified signed bundle and its claims digest under the operation ID in the journal, atomically with the reservation. Storage failure prevents backend execution, but the capability and budget may already be consumed. `ExecutionJournal.getApprovalEvidence(operationId)` retrieves the bundle; journal backups include it. Verification later also requires independently retained trusted approver keys, policy, capability and request context. Expiry is checked at execution time, not proven by a trusted timestamp. The journal and its unencrypted backups are mutable by a privileged operator, and the digest is not bound into the signed receipt or independently anchored. The bundle identifies configured key aliases, not authenticated people.

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
faraday sentinel alerts --db /absolute/path/to/gateway-state/sentinel.sqlite
faraday sentinel deliver --db /absolute/path/to/gateway-state/sentinel.sqlite --url https://alerts.example.org/events
faraday sentinel recover --db /absolute/path/to/gateway-state/sentinel.sqlite --head REVIEWED_CHAIN_HEAD --operator responder --reason reviewed
```
The hash chain detects some modifications, **not truncation/re-hashing by a privileged DB editor**. Quarantining by network address can impact clients behind the same NAT. No SIEM, cluster-wide revocation, external evidence anchoring or HA.
Stop/resume and the corresponding control event are committed together; an audit write failure rolls back the state change.

A denial threshold creates a quarantine event and an outbox entry in the same transaction as the denial and quarantine. Control events are also queued. `alerts` reads up to 100 pending entries; `deliver` explicitly POSTs up to 100 in order to the operator-selected HTTPS URL, without redirects or built-in authentication. No delivery happens automatically. A 2xx marks an entry delivered locally; errors leave it pending and cause a nonzero CLI exit. An accepted POST can be repeated after a crash, local acknowledgement failure or concurrent delivery: the receiver must deduplicate on `event.event_hash`. A 2xx does not prove durable ingestion or incident handling. The payload includes the pseudonymized source and event reason; do not put secrets or sensitive personal data in reasons or URLs. HTTPS delivery was tested with an injected simulated transport, not a real SIEM or external service. Earlier events are not backfilled into the outbox.

For a reviewed local recovery, inspect `status` and the chain, then pass the reviewed `chain.head`, an operator alias and a short reason to `recover`. It atomically verifies the current chain/head, clears the global stop, appends the recovery event and queues an alert. The alias is pseudonymized, not authenticated; this does not remove source quarantines or establish independent oversight. The legacy `resume` command and `stop(false)` API remain available without this review, so this is not enforced separation of duties.

Invalid clocks or clocks earlier than the last event fail closed during quarantine checks and recording. Forward jumps, unrecorded quarantine expiry, in-flight operations, retention and clock authenticity remain outside this control. Tests share one local SQLite file between processes; they do not establish safe network-filesystem use or coordination between nodes. Outbox and chain are mutable local state, not signed or immutable evidence.

## Budgets (E17)
A transactionally enforced per-agent call budget is stored in local SQLite; it is consumed after cryptographic authorization but before backend execution. Unknown/exhausted budgets fail closed. Failures may burn quota, intentionally favouring safety over availability. **Not a global/distributed token or CPU limiter.**
Optionally configure a shared organization call limit in the gateway JSON:
```json
{
	"budgetDb": "/absolute/path/to/budget.sqlite",
	"budgets": {"agent-a": {"maxCalls": 100, "windowMs": 60000}, "agent-b": {"maxCalls": 100, "windowMs": 60000}},
	"organizationBudgets": {"org-a": {"maxCalls": 150, "windowMs": 60000}},
	"agentOrganizations": {"agent-a": "org-a", "agent-b": "org-a"}
}
```
When organization limits are configured every budgeted agent must map to a configured organization. Agent and organization counters update together or roll back together; accepted calls return their remaining counts through `LocalBudget.consume`. A configured budget without `budgetDb` prevents the gateway from starting. Tests use multiple processes sharing one local SQLite file, not multiple nodes.

The last successful consumption time is persisted per agent and organization; an earlier clock is rejected. This does not prevent a forward clock jump or provide trusted time. Organization membership and limits are static operator configuration, not verified tenant identity or isolation; all processes must use consistent mappings and window policies. Changing window lengths against existing counters is not a supported policy migration. There is no distributed accounting, CPU/memory/token measurement or alert delivery. Capability, budget and journal use separate stores, so a later denial can consume a capability or quota without a backend call.

## Adversarial mutation tests (E26)
`npm run security:fuzz` runs 320 mutated capability signatures, 320 mutated approval signatures and 120 signed-argument substitutions. Canonical Base64URL signature encoding is enforced after a fuzz test revealed ambiguous trailing character encodings. These are reproducible mutation checks, not formal security proofs or coverage-guided fuzzing/chaos.

## Docker boundary
`npm run pilot:docker` runs an isolated synthetic backend and a gateway, with a dummy agent on a separate network; anonymous and approval-less requests are denied, an approved execution is signed independently by gateway and backend, replay is denied, and agent-to-backend direct network access is denied. Docker isolation is a **property of this test topology**, not universal prevention of all bypasses.

## Residual blockers
E17–E19 and E26 remain **partially done** at their enterprise scope: corporate identities, a real human approval service, distributed ledger and policy, SIEM integration, resource-level gateway, signed evidence anchoring, prolonged fuzzing/chaos, external audit, and real deployment pilots are pending.
