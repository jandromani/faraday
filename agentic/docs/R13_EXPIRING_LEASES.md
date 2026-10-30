# R13 — Database-fenced expiring leases, multiple contenders

A trusted controller can now request `claim_lease(scope, instanceId, ttlMs)` through
the isolated PostgreSQL `faraday_controller` role. Three contenders request
ownership concurrently; only one wins while the lease is current. Renewals
from the same owner extend an unexpired lease without advancing the epoch.

The backend's `faraday_secure.apply_effect` function additionally checks the
lease expiry under the same PostgreSQL row lock as the synthetic effect.
If an owner stops heartbeats and the lease expires, it **cannot** continue
writing even before another leader claims the slot. Takeover advances a
monotonic epoch; old owners are fenced after recovery.

CI proves this on actual PostgreSQL (SCRAM authentication, two separate
roles), with withheld renewal, three contenders and 12 parallel idempotent
requests. No control-plane credential enters the gateway's executor pool.

**Not established:** actual network partition of independently hosted gateways;
automatic process discovery/election supervisor; quorum across multiple
database failure domains; no-double-effect for downstream external payments;
SLO, RPO or RTO measurements across repeated infrastructure failures.
The single DB is still a single point of failure. This is partial R13,
not enterprise HA certification.

Operational safeguards: each process should use a unique random instance
owner identifier; do not reuse a defeated instance's old credentials. Both
clock and lease expiration are calculated within PostgreSQL rather than
trusting host clocks. Migrations are administrator-only.
