# FARADAY — Competitive reality and product hypothesis

Research snapshot: 2026-10-28. This is a strategy hypothesis, **not** a claim of invention, patentability, market leadership or validated product/market fit.

## Important finding

**External authorization for agent tool calls is not new. Neither are short-lived signed capabilities, secure workload identities, mandatory MCP gateways or independently verifiable action receipts.** FARADAY must distinguish itself through a proved integration and enforcement outcome, not the individual primitives.

| Solution | Verified public positioning | FARADAY consequence |
| --- | --- | --- |
| AWS Bedrock AgentCore Policy | Cedar-based policy enforcement for tool calls outside the agent boundary | Direct competition with Gate-only story |
| Aembit | Agent/workload identity, short-lived scoped credentials, policies and audit | Direct competition on identity and authorization |
| Microsoft Entra Agent ID | Enterprise agent identities, conditional access, governance | Competes on enterprise agent governance |
| Permit MCP Gateway | Consent, human delegation, identity and policy for MCP actions | Competes on gateway and workflow approvals |
| Pipelock | MCP/HTTP egress firewall, containment and mediator-signed action receipts | Competes on enforcement and verifiable evidence |
| Raucle | Ed25519-signed capabilities and verifiable execution receipts; formal claims | Very direct overlap with proof-of-authorization design |
| SPIFFE/SPIRE | Standardized workload identities, SVIDs and attestation | Integrate; do not replace |
| MCP authorization | OAuth/resource-bound token guidance | Interoperate and follow requirements |

Sources (product/vendor claims are not independent tests):
- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-getting-started.html
- https://aembit.io/
- https://learn.microsoft.com/entra/agent-id/
- https://docs.permit.io/permit-mcp-gateway/
- https://github.com/pipelab-org/pipelock
- https://raucle.com/
- https://spiffe.io/docs/latest/spiffe/concepts/
- https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/docs/specification/2026-07-28/basic/authorization/security-considerations.mdx

## Proposed narrow product thesis (unvalidated)

**FARADAY = provider-neutral, self-hostable execution authority for connected agent ecosystems.**

Its possible wedge is an operationally complete, independently tested **no-bypass** setup for multi-cloud/on-prem agents: authentic identity, delegated policy, mandatory mediation, isolated tools, controlled egress, atomic action idempotency, tenant boundaries, and portable evidence. That scope is broader than a cryptographic token library and overlaps existing providers; only user testing and measured superiority can establish differentiation.

## Three things to prove before calling it disruptive

1. **Mandatory:** in a contained demonstration, direct HTTP/MCP/API access to the sensitive tool is impossible from the agent namespace, including stolen downstream credentials; verified by attempted bypasses, not only allowed-path tests.
2. **Interoperable:** a single policy and receipt format works across at least three heterogeneous runtimes and tool types, including MCP and a non-MCP API.
3. **Adoptable:** onboarding complexity, p95 added latency, operational cost and recovery are measurably better for a specified regulated enterprise use case than using an existing commercial offering.

## Build 003 proposed benchmark

- Attack corpus: direct network bypass, prompt-injection attempts, malicious tool metadata, argument swaps, replay, token theft, issuer/key compromise assumptions, race conditions, revoked delegate, confused deputy and execution-after-denial.
- Metrics: falsely authorized executions **0 in a fixed published test corpus** (not a general security guarantee); median/p95 latency and throughput; missing receipt rate, tamper detection, recovery semantics.
- Compare against AWS AgentCore, Permit, Pipelock or other viable competitors using public reproducible configurations, rather than marketing estimates.

**Decision rule:** if no independent enforcement advantage, customer willingness-to-pay or defensible deployment niche emerges, reposition FARADAY as an integrator/reference architecture or stop building a competing security product.
