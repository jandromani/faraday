# R5 / R3: PostgreSQL fencing and process-level idempotency proof

Status: **integration reference only**, not an Enterprise-ready HA solution.

## Purpose
The existing FARADAY local SQLite journal prevents replay on a single installed instance.
This reference adds a *shared PostgreSQL fencing epoch* and a unique effect ledger, tested using
separate Node processes and a real official PostgreSQL container. It does not replace the
pilot MCP gateway, nor automatically coordinate multiple FARADAY servers.

## Trust model and atomicity
- Only a trusted control plane may grant a new leader epoch with `R5_TAKEOVER_SQL`.
  Never expose the takeover SQL or its DB credentials to untrusted agents.
- Each backend execution supplies `scope`, `owner`, numeric `epoch`, operation ID
  and the signed/independently verified payload hash.
- In `R5_APPLY_SQL`, PostgreSQL locks the active owner+epoch row with
  `SELECT ... FOR UPDATE` and performs the effect ledger insert in the SAME statement.
  A promoted epoch serializes against old-epoch commits; stale writers cannot insert.
- Unique `(scope,operation_id)` rejects duplicated effects and conflicting payloads.
  In a concurrent snapshot a second worker may temporarily observe a conflict rather
  than a duplicate; it MUST NOT repeat the effect. Reconciling by operation ID is required.
- This is a **synthetic persisted effect**. It does not make an external payment exactly-once.
  A real backend must atomically couple its business effect with the idempotency row, or
  use backend-native idempotency and reconciliation. The gateway itself must use the
  returned fencing epoch on every actual action.

## CI evidence
The GitHub workflow `FARADAY R5 Postgres Fencing Integration` launches disposable
PostgreSQL without exposed ports, creates schema, grants A epoch 1, performs and retries
one operation, promotes B, verifies A's old epoch cannot apply, runs eight workers in
parallel against the same Postgres, and promotes C after simulated restart. Count must
remain two committed synthetic effects, with no duplicate or conflicting replacement.

## Still required to close enterprise R3
1. Integrate the fence and idempotency key with actual MCP gateway and backend adapters,
   with least-privilege PostgreSQL roles.
2. Prove node crash during an external operation, backend attestation, independent
   reconciliation and no repeat of irreversible effects.
3. Add lease TTL/heartbeats, orchestrated automatic failover, health and supervisor checks.
4. Test true network partitions and split-brain with process/container failure injection.
5. Record p50/p95/p99, at least 100 samples, bounded RPO/RTO and independent evidence.

Never describe this protocol example as automatic failover, two-site HA, or R3 closure.
