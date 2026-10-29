# MemoryGuard Local Preview

This opt-in component is an isolated SQLite quarantine for signed documents. It is not connected automatically to the free AI advisor, an embedding index, an agent or a RAG pipeline. It makes no network or model calls.

## Document And Source Keys

The operator supplies a local JSON object mapping source aliases to pinned Ed25519 public PEM strings. A document has this exact schema:

```json
{
  "version": 1,
  "id": "reference-1",
  "source": "source-a",
  "issuedAt": 0,
  "expiresAt": 4102444800000,
  "text": "Synthetic reference document",
  "facts": [{"key": "region", "value": "eu"}]
}
```

Times are Unix milliseconds. The source signature binds the complete document, including its text, structured facts, ID and validity interval. `text` is limited to 4096 UTF-8 bytes, facts to 32 entries with unique keys, and an ingested packet to 16 KiB. A valid signature proves possession of the configured key, not the truth, safety, authorship or independence of the content.

## Operator Workflow

```sh
faraday memory sign --file document.json --private-key source-private.pem --out signed-packet.json
faraday memory ingest --db memory.sqlite --keys trusted-sources.json --file signed-packet.json
faraday memory list --db memory.sqlite --keys trusted-sources.json
faraday memory inspect --db memory.sqlite --keys trusted-sources.json --digest PACKET_DIGEST
faraday memory approve --db memory.sqlite --keys trusted-sources.json --digest PACKET_DIGEST --reviewer operator-alias
faraday memory approved --db memory.sqlite --keys trusted-sources.json
```

Every new packet enters quarantine, including validly signed packets. `list` returns up to 100 metadata records; `inspect` explicitly returns the full **untrusted** packet. An operator must inspect content and approve its exact digest. Approval rechecks the signature, source and time and atomically records the review. The reviewer alias is self-asserted, not authenticated. Conflicting structured facts with the same exact key and different values, or a duplicate source/document ID, prevent approval while the previous document remains current. Retrieval verifies signatures and reviews again, filters expired documents and rejects detectable storage corruption or conflicting approved facts.

The operator must configure the same trusted-source keys for all processes sharing the database. Removing or replacing a key causes retrieval of its previously approved, unexpired documents to fail closed. There is no distributed key revocation; an already-running process retains its configured keys. A persisted clock rejects backward movement, but a forward jump can expire documents and prevent later operation; the clock is not trusted time. There is no automatic garbage collection, manual rejection workflow, signed review, or quota for total stored packets.

## Synthetic Attack Corpus And Limits

[MemoryGuard tests](../tests/memory-guard.test.js) include signed prompt-injection text, altered documents, source substitution, wrong signing keys, unknown sources, expiration, malformed schemas, conflicting facts, failed review writes and concurrent local reviews. Signed malicious text remains quarantined **because all inputs require review**, not because an injection detector recognizes it. A reviewer can approve malicious content; exact string comparison of declared facts does not detect semantic contradictions, missing facts, indirect instructions, encoded attacks or poisoned embeddings. These fixtures are not a comprehensive RAG security evaluation.

SQLite, its WAL and input/output files can contain the complete untrusted documents and are not encrypted; Windows ACLs and path races are not verified. A privileged editor can rewrite the database and reviews, and can configure trusted keys. There is no immutable or independently anchored audit trail, authenticated user identity, isolation across tenants, mandatory retrieval mediation or proof of document origin outside the configured public key. Consumers that bypass `approved()` or place inspected quarantine content into a prompt bypass this control. Protect inputs, key configuration, database, backups and exports independently.