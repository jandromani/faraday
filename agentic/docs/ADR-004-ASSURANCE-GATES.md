# ADR-004 — Evidence levels and non-negotiable release gates

**Decision:** replace test-count-as-security scoring with hard gates. The evidence levels are:

| Type | What it establishes |
|---|---|
| `unit` | Local invariant under controlled conditions |
| `integration` | A working protocol boundary across components |
| `adversarial_deployment` | A negative/bypass test against a defined live topology |
| `independent_validation` | External evaluator's signed, separately trusted result |

The `developer` profile requires *passed* unit, integration and adversarial deployment evidence, all bound to the same actual Git commit. Any failed bypass case blocks release, even with 1,000+ passing unit tests. `gap` is never `pass`.

The `enterprise` profile additionally requires an **Ed25519-signed attestation**, with an explicitly pinned evaluator public key, bound to the same commit and evidence digest. Signature verification against caller-supplied roots cannot establish the evaluator's independence or the truth of the checks. `enterpriseEvidencePassed` reports only this limited gate; `enterpriseReady` remains false even when it passes. SSO, tenant isolation, operational evidence and independent assessment remain separate requirements. The provided CI runner does not create an independent attestation.

`npm run assurance:ci` executes the actual Node test suite, OAuth loopback integration and Docker pilot isolation checks before writing `artifacts/faraday-assurance.json`; no manually supplied checkbox can replace the actual command results. The CI job archives the evidence. Docker assertions only cover the pilot topology, not arbitrary live workloads.

**Administrator action required:** configure branch protection/rulesets requiring the new `FARADAY Architecture and Blocking Assurance` job, then lock down bypass permissions. Committing the workflow alone does **not** make it a required check. Pin workflow actions, protect external signers and periodically review the corpus.

**Scope:** security assessment quality is improved; no independent security certification has been performed.
