# R7: Real MCP gateway → trusted backend → PostgreSQL fenced synthetic effect

## What changes

The secure-pilot HTTP gateway now accepts an **opt-in immutable process fencing
lease** `fencingLease: {owner,epoch}` from an operator-controlled source. It
forwards that epoch *only after* evaluating signed agent execution intent,
Authority and exact tool scope. The backend can be configured with
`gatewaySecrets` (independent per-owner credentials) and refuses to start
without a PostgreSQL-fenced store. Owner identity derives from the backend
credential, **never** from a request field alone.

`PostgresFencedSyntheticStore` uses an injected SQL transport to apply the
effect under a single PostgreSQL statement that locks the current epoch
and enforces a globally unique idempotency key. It does not write any
separate SQLite synthetic effect. Backend signed attestations bind to the
persisted PostgreSQL record, which a receipt verifier checks independently.

## Acceptance

CI starts real official PostgreSQL, two independent gateway Authority
fixtures, separate SQLite execution journals, a single protected HTTP backend
with gateway-specific secrets, and a shared PostgreSQL store. It checks:
- Legitimate signed MCP call via owner A applies one synthetic operation;
- Independent backend attestation and signed gateway receipt verify;
- Replay is denied and direct backend without credentials is rejected;
- After an operator promotes B, A retains a locally valid signed capability
  but cannot write an effect (fenced by PostgreSQL, gateway reports uncertain);
- B applies a new effect with independent Authority and credential;
- Eight privileged parallel HTTP retries of the same operation result in
  exactly one committed PostgreSQL effect; stale epoch, mismatched owner,
  mismatched credential and direct calls are rejected;
- Failed/uncertain operations are not retried blindly by FARADAY.

## Critically out of scope

The only persistent effects are **synthetic** ledger rows. The example SQL
transport runs through an isolated Docker/psql test harness; production must
supply an authenticated, least-privileged PostgreSQL driver and migrate
the exact atomic business transaction, or use a downstream effect-specific
idempotency protocol with reconciliation.

Epoch takeover is operator-triggered. There is no automatic leader election,
heartbeat expiry, multi-AZ deployment, true partition injection, continuous
availability SLA, or irreversible external transfer guarantee. Backend
credential leakage remains a threat requiring Vault/rotation and network
isolation. This is **a stronger integration proof**, not 2-node enterprise HA.
