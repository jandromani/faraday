# FARADAY v0.95.1 — Two-party synthetic evidence and safe reconciliation

This is a **synthetic secure-pilot prototype, not an independently attested production enclave or real payment executor**. It does not close all roadmap E09–E15 requirements.

## Guarantees in the reference deployment

- The agent possesses a pinned Ed25519 private key; issuer and gateway use separate signing material. Pinned keys are **not workload attestation**.
- The gateway checks capability scope, agent proof, replay and static policy; Docker networks exclude the backend from the dummy-agent namespace. No claim is made about arbitrary real clients.
- The backend has its own Ed25519 private key to attest the synthetic operation. The gateway checks it and binds the backend attestation into its independently signed receipt. Offline verification requires both public keys.
- Missing/invalid backend evidence and other unverified backend responses produce an uncertain result rather than success or a definitive rejection. An HTTP error does not establish whether an operation occurred.
- Explicit operator-initiated read-only reconciliation queries the signed backend status; it does **not re-execute** the tool. Journal transitions are atomic and preserve original and final receipts.
- Docker reference configures unprivileged processes, dropped capabilities, read-only container filesystems and explicit pids/CPU/memory limits. These settings require runtime verification on each deployment and do not establish an independently hardened sandbox.
- Backend service credentials require HTTPS outside literal loopback by default. The synthetic Docker fixture explicitly opts into plaintext HTTP on its isolated network; this exception provides neither encryption nor a secrets broker. Gateway and backend still share a static credential.

## Run

`npm run test:all` locally; `npm run pilot:docker` in Docker-enabled CI.

## Not yet supplied

Workload-attested identity (SPIFFE/OIDC), real customer tools, dynamic revocation, KMS/HSM, secret broker, distributed HA, independent audit and conformance with external MCP clients. Do not claim enterprise production readiness.
