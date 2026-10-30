# R9/R10 — Independent FARADAY installation and security validation protocol

Status: **ready to recruit participants**, not externally validated.

## Release distribution and provenance
Release `v0.99.8-r9-preview` is published **only if** R1 passes on its exact
protected-`master` commit: full Node regression, Python security matrix,
official MCP client and offline onboarding (Linux/macOS/Windows), Vault
AppRole, hostile Docker network bypass, source inventory, package integrity,
GitHub OIDC/Sigstore attestation and hosted `gh attestation verify`.

The package remains `private: true`: no npm registry publication.
Treat a release tag as a specific snapshot. Earlier
`v0.99.7-r5-preview` does NOT contain current R6/R7 features.
The one-time R9 tag must NEVER be retargeted or overwritten.

Download archive, manifest and SPDX inventory from the release on a new
machine, compare SHA-256 against the manifest and run:

```bash
gh attestation verify faraday-agentic-0.99.8.tgz --repo jandromani/faraday
npm install --offline --ignore-scripts ./faraday-agentic-0.99.8.tgz
```

The tester must independently verify the release's **exact git SHA** and
manifest and run `faraday doctor`, an opt-in disposable fixture proxy install
and uninstall, and a signed synthetic MCP tool execution; never deploy
to real payment tooling or attach production credentials.

## Five independent installation sessions
Use a fresh environment for each session. Accept one session only when:
- Participant was **not** involved in implementation or test authoring;
- Machine, Node version, OS and the exact release digest are recorded;
- Installation, first proxy, authorization denial, authorized synthetic
  tool call, receipt verification, uninstall and restoration all have
  reproducible redacted logs;
- Stopwatch: `time-to-first-protected-tool` is measured by the tester;
- Failure modes and help needed are recorded even when a session fails.

Store only pseudonymous tester IDs, consent reference, environment metadata,
redacted SHA-256 evidence digests, result and durations. No credential,
personal document, device identifier, raw token or real customer data is
required or permitted in public evidence. Do not claim `5/5` until the
five independent human signoffs exist.

## Independent adversarial review
External reviewer must attempt: missing signature, wrong JWT `aud`,
wrong Keycloak client, stolen or revoked capability, changed args, replay,
backend direct call, stale PostgreSQL epoch, duplicate concurrent action,
secrets volume access, backend network route bypass, and interrupted result
reconciliation. Reviewer records exact code/release SHA, attack method,
expected/observed result, reproducible PoC IDs and residual severity.
Do not mark issues resolved on the strength of self-authored tests alone.

## Pilot with a real organization
Ask a consenting owner to name a **non-production** tool with a real
operational user. Pre-register success criteria, boundaries, emergency
shutdown and allowed data retention. Quantify protected calls, denied
unsafe calls, real integration effort, operator interventions, latency
p50/p95/p99 and usability. Disclose the organization only after
explicit publishing approval.

## What must remain absent from the VC score
`independent_pilot_count=0`, `signed_security_review=none`, and
`external_installations_verified=0` are the correct baseline until evidence
is submitted. A self-generated evidence template is NOT independent validation.
