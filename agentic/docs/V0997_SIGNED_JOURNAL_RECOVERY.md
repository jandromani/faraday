# FARADAY v0.99.7 — Signed single-node recovery (E16)

**Scope:** Developer Preview. NOT high availability, encrypted storage, RPO/RTO, automatic failover or distributed exactly-once semantics.

1. Keep an Ed25519 private signing key outside the agent and use a restricted private PEM file.
2. Inspect pending operations with `faraday recovery inspect --db journal.sqlite`.
3. Execute `faraday recovery backup --db journal.sqlite --out snapshot.sqlite --private-key signer.pem` — SQLite online API, not unsafe raw WAL copying.
4. Verify using `faraday recovery verify --backup-file snapshot.sqlite --public-key signer.pub.pem` — signature, hash, integrity and row count.
5. Restore using `faraday recovery restore --backup-file snapshot.sqlite --out restored.sqlite --public-key signer.pub.pem` — only to a NEW journal location.

**Security limits:** Snapshots are not encrypted by FARADAY; store in encrypted controlled storage. A valid old snapshot may be substituted unless independently pinned to a trusted latest digest. Uncertain side effects require read-only reconciliation; the restore operation NEVER calls a tool or retries an effect. No claims of distributed recovery, offsite retention or independent attestation.

**Verification:** `npm run recovery:test` and GitHub Linux Node 22/24, macOS Node 24, Windows Node 24 CI when those runs complete.

## Optional anti-rollback operator pins

Supply an independently trusted `--expected-sha256` and/or `--min-created-at` (epoch milliseconds) to `verify` and `restore`. A matching signature alone cannot rule out substitution of an older signed snapshot. The expected digest or minimum timestamp MUST come from a separate protected record; reading them back from the backup does not provide rollback protection.
