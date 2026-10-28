# Build 002 — Identity-bound, asymmetric FARADAY Authority

**Status: experimental. Not suitable for protecting real payments, customer data or production tools.**

## What works

| Component | Build 001 | Build 002 |
| --- | --- | --- |
| Authority signature | Shared HMAC secret in issuer and gate | Ed25519; issuer holds private key, gate pins public key |
| Agent identity | Caller-supplied string | Registered agent key + Ed25519 proof-of-possession |
| Issuer isolation | In-process class | Optional separate loopback HTTP service/process |
| Intent binding | Agent, tool and args | Same + signature with purpose, nonce, expiry |
| Execution binding | Capability bearer token | Capability fingerprint + new agent-signed execution proof |
| Token replay | SQLite atomic unique JTI | SQLite atomic unique JTI, plus issuance-intent nonce replay defense |
| Tool execution | Not implemented | Not implemented |
| Real identity attestation | Not implemented | Not implemented; SPIFFE-like identity is only a local label |
| Network enforcement | Not implemented | Not implemented |

## Try it

Python 3.11+ with package \`cryptography\`:

\`\`\`bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python scripts/demo_v2.py
\`\`\`

The demo generates ephemeral signing keys, launches a **separate issuer HTTP process** on 127.0.0.1, sends the agent's signed issuance intent, validates an issuer-signed capability with the public key in the Gate process, denies a forged execution proof and denies capability reuse.

**No real invoice is sent.** This is intentionally an authorization-only demo.

## Request lifecycle

1. **Identity registration:** a trusted administrator pins the agent public key to an exact agent ID (for demo only). No independent workload/platform attestation is performed.
2. **Signed intent:** the agent signs a canonical request with its own private key, purpose \`faraday.issue.v2\`, expiry and random nonce.
3. **Issuer:** verifies signature, applies default-deny invoice policy, rejects repeated intent nonce, returns signed capability.
4. **Execution proof:** the agent signs a second request with purpose \`faraday.execute.v2\` and the SHA-256 fingerprint of the exact issued capability.
5. **Gate:** verifies issuer public signature, agent public signature, short lifetimes, exact tool and inputs, proof/capability binding, policy and persistent one-use nonce.
6. **Result:** \`allow\` or \`deny\`; no downstream tool receives a request in this release.

## Threat model and security caveats

- **Not SPIFFE verified:** the string \`spiffe://faraday.local/agent/finance\` is a *demo identifier*, not a validly attested SPIFFE-SVID identity. Pinning a public key proves possession of its private key, not which executable holds it.
- **Issuer HTTP endpoint:** localhost-only, plaintext, development only. A production service needs workload-authenticated TLS, an identity attestor, transport authorization, private key HSM/KMS, key versioning, rotation and emergency revocation.
- **No mandatory proxy:** agents can call external APIs directly unless network and credentials make bypass impossible. Build 003 must close that gap.
- **No real tool side effects:** Gate returns a decision. This build proves neither zero bypasses nor isolation of sensitive execution.
- **Static policy:** a narrow toy invoice policy only, with a fake supplier and max EUR 200. No policy engine / approval flow / tenant separation.
- **Replay/idempotency:** sqlite is a single-node dev store. Token consumption before execution requires durable idempotency keys, retries/recovery and distributed linearizable storage in production.
- **No provenance or monitoring:** no authenticated execution receipt, distributed audit log, revocation endpoint or Sentinel response.
- **Key custody:** process isolation alone is not host isolation. The demo runs both processes under the same developer user. Protect the private issuer key from every agent and Gate process before any real deployment.

## Go/no-go criteria for Build 003

**Required to claim a meaningful safety boundary:**

- Mandatory MCP/HTTP mediation, tools unreachable via direct network/API credentials.
- Proper workload identity via SPIFFE/SPIRE or cloud workload OIDC and mTLS; validate trust domain and audience.
- Independent issuer with KMS-backed signing, rotation, revocation and approval policy.
- Adversarial bypass tests for direct tool calls, credential leakage, prompt injection, retries and confused deputy.
- Signed, privacy-preserving end-to-end execution receipts that link the approval to *what actually happened*.
- Measured latency, throughput, negative-test false-allow rate and fault recovery.

## Product position

FARADAY **is not the first to propose external agent tool authorization**. AWS AgentCore Policy and Aembit already offer strong solutions in overlapping areas. Future differentiation must be demonstrated by cross-framework/neutral deployment, mandatory mediation, cryptographic proof of execution, policy portability and independent adversarial benchmarks — not asserted as novelty.

References: [AWS AgentCore Policy](https://aws.amazon.com/bedrock/agentcore/faqs/), [Aembit](https://aembit.io/), [SPIFFE](https://spiffe.io/docs/latest/spiffe/concepts/), [MCP Authorization](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization).
