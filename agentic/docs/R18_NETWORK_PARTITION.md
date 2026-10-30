# R18 — Two real Docker network partitions, stale owner recovery

The R18 CI suite launches two independent Node worker containers on a
shared **observer** bridge and a separate **database** bridge, with official
PostgreSQL 17. Only the database bridge is physically disconnected using
`docker network disconnect` and later reconnected. The observer route
remains available to inspect operation outcomes during the outage.

Every worker obtains a short database-owned lease. Node A first becomes
leader and records a synthetic effect. The database route to A is then
cut, A fails to renew, B claims a newer epoch and records another effect.
After network healing, the old A epoch must be rejected by PostgreSQL
even if A still holds its prior token. The direction is reversed to test
B losing the route and A reclaiming **a new epoch**. An idempotent repeat
of a committed effect must not add a duplicate row. The runner records
observed takeover intervals and **only synthetic effects**.

Important constraints:
- Workers have two PostgreSQL roles in the same test process for scripted
  chaos control. This arrangement is **test-only**, and NOT acceptable as
  production role separation or operator isolation.
- PostgreSQL is a single container and single failure domain. This is
  not quorum-based distributed HA or a network partition of PostgreSQL
  replicas. The worker HTTP endpoint is a synthetic harness, not the full
  protected MCP client. Do not claim SLA or external payment exactly-once.
- No production TLS cert, real IdP or multi-AZ failover is demonstrated
  in this particular test. The release gate should not treat this as a
  substitute for the R6 Keycloak+Vault signed MCP and R7 backend tests.
