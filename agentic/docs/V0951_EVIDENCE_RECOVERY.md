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

## Witnessed checkpoints

`witnessEvidenceCheckpoint` verifies an ordered list of receipts with pinned gateway and backend public keys, then signs its chained digest with a distinct Ed25519 witness key. `verifyEvidenceCheckpoint` verifies the witness signature and every receipt. A caller can supply a previously verified `{count, root}` as `trustedPrefix` to detect truncation or changes to that prefix. An explicitly trusted replacement witness key can sign a later checkpoint containing the same prefix.

The witness function is an offline API, not an external witness service or transparency log. The operator must independently protect and distribute the witness key, verified anchor and trusted public keys. Without a trusted external anchor a valid older checkpoint can be replayed, and different keys alone do not prove independent custody. Witness timestamps are caller-supplied; there is no trusted timestamp, append-only storage, automatic key lifecycle or gateway/backend key rotation within a checkpoint. These signatures attest synthetic records, not an independently corroborated real-world effect.

## Run

`npm run test:all` locally; `npm run pilot:docker` in Docker-enabled CI.

## Signed journal backup

The operator can create an online SQLite snapshot, verify an Ed25519-signed manifest, and restore the verified bytes to a new path:

```sh
faraday recovery backup --db journal.sqlite --out backup.sqlite --private-key signer.pem
faraday recovery verify --backup-file backup.sqlite --public-key signer.pub.pem --expected-sha256 TRUSTED_HASH
faraday recovery restore --backup-file backup.sqlite --out restored.sqlite --public-key signer.pub.pem --expected-sha256 TRUSTED_HASH
faraday recovery inspect --db restored.sqlite
```

`--expected-sha256` and `--min-created-at` are optional; their trusted values must come from an independently protected record, not from the backup being checked. The signed timestamp is operator-supplied, not trusted time. The snapshot uses SQLite's online backup API, including committed WAL data. Verification checks the manifest, digest, SQLite integrity and row count, not the authenticity of each stored receipt or completeness of a business operation. Creation returns `created`, not an independent verification result.

The journal is only one part of the system. The snapshot does **not** include the Authority nonce/revocation ledger, backend database, configuration, keys or external effects. Never resume execution from a restored journal alone: stop writers and have an operator reconcile all stores and uncertain or reserved operations against independent evidence. Restore does not retry, release or execute operations. Old snapshots can omit later actions; a separately trusted digest can detect substitution only when an appropriate current digest was recorded.

Backups, manifests and temporary copies are not encrypted; use protected directories and encrypted storage. The source and destination directories must be trusted and protected from concurrent modification. File-path races and Windows ACLs are not verified; a crash may leave an incomplete backup or temporary copy. These routines do not supply automatic failover, multi-node recovery, external storage, compensation, or measured RPO/RTO.

## Not yet supplied

Workload-attested identity (SPIFFE/OIDC), real customer tools, dynamic revocation, KMS/HSM, secret broker, distributed HA, independent audit and conformance with external MCP clients. Do not claim enterprise production readiness.
