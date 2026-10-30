# R12 — Native PostgreSQL with segregated SQL principals

Status: **integration candidate**; not production-certified until real CI confirms.

The former R7 integration used `docker exec ... psql` only as a test
transport. R12 introduces a real parameterized PostgreSQL adapter
`createNativePgFencedExecutor({pool})`, a separately injected leader
promotion adapter `createNativePgPromotion({pool})`, and a strict TLS pool
factory `createTlsVerifiedNativePgPool`.

## Threat boundary

- An **administrator/function owner** applies
  `sql/r12_native_postgres.sql` only after provisioning two separate
  SQL roles, `faraday_executor` and `faraday_controller`.
- Effect principal is granted EXECUTE on narrowly scoped, fixed
  `faraday_secure.apply_effect`, `lookup_effect` and `count_effects`.
  It cannot read or mutate underlying ledger/lease tables directly.
- Control principal can promote a fenced leader epoch but **cannot apply
  effects** or read the ledger.
- A SECURITY DEFINER function pins `search_path=pg_catalog`, accesses
  fully qualified tables and holds the active epoch row lock and idempotent
  insert together. The operator must protect function-ownership and
  migrations as privileged administrative tasks; no arbitrary SQL is
  accepted through the runtime adapter.
- No role or credential is available to an MCP agent. Every gateway
  backend request must still satisfy signed FARADAY Authority and
  backend-specific identity checks.

## Production TLS setup

In the production process use a nonlocal database hostname, a trusted CA
certificate and a role-specific password to create the executor pool with
`createTlsVerifiedNativePgPool`; TLS cannot be bypassed through a
`rejectUnauthorized:false` switch. The caller supplies separate control
credentials outside the backend process.

The optional `pg` dependency is **not bundled** into the existing
air-gapped FARADAY package: install the separately audited and
version-pinned `pg@8.23.1` in an explicitly approved adapter environment
before enabling the native runtime. This design preserves existing offline
install tests; operator deployment packaging remains a future gate.
No CI credential or plaintext SCRAM test password is suitable for production.

## CI acceptance and limitations

The official PostgreSQL 17 container requires SCRAM on TCP; tests create
separate roles, apply SQL with an administrator and execute the native driver
using those role credentials over disposable loopback TCP. They verify:
direct base-table access denied, executor cannot promote, controller
cannot apply, signed synthetic backend hash consistency, stale epoch denial,
16 concurrent idempotent retries and exactly one committed synthetic effect.
The test's **loopback** transport is not a production TLS deployment
attestation.

This is not HA or external payments exactly-once. Remaining: a full
deployment of actual backend using this adapter with TLS cert renewal,
pool failure injection, a control-plane cluster, site-independent
failover and observability, and an external security review.
