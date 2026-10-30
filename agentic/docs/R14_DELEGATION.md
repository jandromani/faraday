# R14 — Cryptographically signed, non-amplifying delegation reference

An operator trust root may issue an Ed25519-signed grant binding a named
principal to a FARADAY agent and an exact tool, action and resource with
an amount ceiling and short expiry. Each subsequent agent may sign an
attenuated grant for another registered agent, with a parent hash and
lower or equal amount ceiling. A verifier uses only operator-supplied
trusted public keys, checks every signature, rejects cycles and widening,
checks expiry/chain length, and **requires** revocation checks. Replayed
execution must still be stopped by the existing Authority nonce ledger.

The CI proves signed chains, altered grants, unauthorized signers,
spliced parent chains, revoked principals/nonce, cycles, expiry and
privilege escalation are rejected.

**Major limitation:** `oidc:test-subject` in this test is a synthetic
identifier signed by an *operator* key; it is **not** a cryptographically
verified human Keycloak subject. This protocol is not actual OAuth
Token Exchange, human OBO, or production mTLS workload identity.
The application must connect the trusted issuer to a separately verified
real OIDC user identity, map the final agent to its signed execution,
enforce end-to-end revocation at each tool execution and independently
review who can issue/rotate trust roots. This module is an isolated
foundation and has NOT been enabled as a default gateway requirement.

R14 enterprise closure must not be claimed from this module alone.
