# FARADAY v0.99.5 — Local revocation, credential rotation, witnessed evidence

Status: **experimental Secure Developer Preview**. This update strengthens specific local pilots, NOT the entire original E09/E12/E14/E16 enterprise epics.

## E09 / E10 — OAuth revoke + JWKS operator rotation

- `lib/oauth-revocations.js` provides a local SQLite revocation ledger by JWT `jti`, agent `sub` or `client_id`.
- **Opt-in enforcement:** set `oauthResource.revocationDb` to an **existing** database path in `FARADAY_PILOT_CONFIG`. A missing database prevents gateway startup. When enabled, every OAuth token requires a valid `jti` (8–128 safe characters); missing `jti`, unavailable storage or revoked identity deny before the protected tool executes.
- Operator can create/revoke using `node bin/faraday-revocations.js init --db /path/revocations.sqlite` and `... revoke --db ... --kind jti|subject|client --value IDENTIFIER` in a trusted shell, before gateway startup. Only fingerprints with a random per-database salt are persisted; the command is governed by filesystem permissions, not authenticated over HTTP.
- `PinnedOAuthResource.replacePublicJwks([...])` supports **explicit, validated, atomic operator-initiated** public-key replacement. The method is not exposed remotely. Rotation of public keys in a running process requires invoking this API from a trusted operator integration; changing the JWKS file alone does **not** update an already-running process.
- Caveats: not SPIFFE, not tenant-wide global revocation, no dynamic JWKS fetch, no central IdP, no audit-resistant database, no enterprise HA. SQLite file deletion/rollback is an OS/operator responsibility. The resource still rejects any token of unsupported signing algorithm.

## E12 — backend secret refresh

- `createStrictSecretFileProvider` reads a bounded regular file with restricted permissions on each operation; no symlinks, permissive Unix modes or malformed credentials. The pilot gateway and backend process now use this provider instead of caching the secret on startup.
- An operator can replace the backing file with a valid 0600 credential in a trusted deployment; both services will use the current value on their next request. A mismatch denies the backend; a missing credential makes the operation **uncertain** in the journal and requires read-only reconciliation, never automatic replay.
- This remains a **local static credential rotation primitive**, not Vault/KMS, secret brokering, per-agent delegation or short-lived workload credentials. File-based secrets must not be mounted in agent containers.

## E14 — witnessed evidence

- `lib/evidence-checkpoint.js` validates gateway-signed receipts **and backend-signed synthetic attestations**, detects duplicate operation IDs, chains receipt digests and signs checkpoint summary with a separately provisioned **Ed25519 witness** key.
- Verification requires the gateway public key, backend public key, a witness public key supplied from a separate trust root, and an expected witness identifier. Reordered, truncated and tampered bundles fail verification against the original witness signature.
- **Important:** signing with a witness key generated in the same gateway DOES NOT establish independence. To make this meaningful, an external operator must retain the witness private key off the gateway and store the signed checkpoint in independent custody. No anchoring or independent auditor is integrated by default. Synthetic backend signatures are not proof of real-world business effects.

## Tests / release requirements

```bash
cd agentic
npm run trust:test
npm run oauth:test
npm run test:all
```

`trust-controls.yml` runs these on Linux/macOS/Windows, Node 22/24. Existing Graph/Docker network isolation and OAuth CI must remain green. The risk of fail-open from revocation availability is checked by negative tests. No externally attested enterprise close may be claimed from green CI.
