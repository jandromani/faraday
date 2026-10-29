# FARADAY v0.99.6 — Reference trust boundary and Vault KV v2 adapter

**Release classification:** Developer Preview, synthetic action fixture, NOT general zero trust, production Vault deployment, or third-party penetration-test report.

## E11 / E13 — attacker and network isolation

The Docker Compose reference network has these zones:

- `agent_zone`: `dummy-agent`, `rogue-agent` and `gateway`, with `internal: true`. Neither agent has a backend route or direct external egress through this fixture network.
- `backend_private`: `backend` and `gateway` only; explicitly `internal: true`.
- `gateway`: the **only** dual-zone service. It has backend credentials; the agents do not.
- `rogue-agent`: no agent signing key, capability or backend credential. The security-negative test tries both a direct backend HTTP request and gateway `tools/call` with no or forged proof. Both fail.

The effective Compose configuration is checked with `docker compose config --format json`, then `scripts/check-pilot-deployment.mjs`. Moving an agent to `backend_private`, exposing backend ports, sharing credentials, allowing privileged mode or dropping read-only mode aborts the test before containers start. These are **reference-deployment assertions**, not global runtime guarantees. The test does not simulate host root compromise, a malicious Docker daemon, network policies outside this Compose file or arbitrary MCP executables.

To reproduce in the repository root `agentic`:

```bash
npm run boundary:test
npm run pilot:docker
```

## E12 — optional Vault KV v2 protocol adapter

`createVaultKv2SecretProvider` provides a read-only `GET /v1/{mount}/data/{path}`; it requires a regular token file with mode `0600` on POSIX systems. Example trusted configuration (never put the actual token in the configuration):

```json
{
  "vaultKv2BackendSecret": {
    "baseUrl": "https://vault.internal.example.com",
    "mount": "faraday",
    "secretPath": "gateway/backend",
    "field": "backend_credential",
    "tokenFile": "/run/secrets/vault-client-token"
  }
}
```

The object is optional inside the existing gateway `FARADAY_PILOT_CONFIG`. The backend may independently use a JSON file referenced through `FARADAY_VAULT_KV2_CONFIG`. Both must be configured to retrieve the same secret value for the synthetic backend. When configured, Vault is requested at each operation; **there is no fallback** to a cached credential or local hardcoded value on failures. The provider requires HTTPS, refuses redirects, uses bounded response size/time and rejects invalid KV payloads and unsafe token-file modes. Loopback HTTP requires a *separate explicit test-only option*.

**Remaining limits:** static token file rather than Vault Agent/workload OIDC, no Vault auth provisioning, no lease renewal, no revocation propagation, no production HA, no real KV live Vault environment asserted, and backend effects are simulated. Sensitive credential bytes exist temporarily in process memory and in the HTTP request to the protected backend; no claim of HSM-level protection.

## Evidence classes

- **Unit/integration:** Vault API contract and mutation tests using a disposable loopback server; Docker topology checker mutation tests.
- **Adversarial deployment:** GitHub Actions Docker test with rogue agent and live reference network, if that CI job passes.
- **Independent:** NONE. No external tester/attestation; the evidence cannot be marketed as independent validation.

## v0.99.6 additional contract regressions

The validator now fails closed if extra services or networks are added to the reference Compose project, if the agent zone loses its internal-network flag, if Docker-socket or host-root mounts are introduced, if an adversarial agent imports another service's volumes, or if Compose secrets, host aliases or privileged device bindings bypass the declared volume/network arrangement. These are syntactic assertions on rendered Compose configuration and do not prove host or container-runtime safety.
