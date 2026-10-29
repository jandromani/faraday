# Local synthetic lab campaigns

These opt-in APIs run offline against a newly created loopback MCP gateway and a synthetic invoice backend. They generate temporary keys and SQLite files and clean up their fixture after execution. They do not call a model provider or perform payments. Run from `agentic` with Node 22.16 or later:

```sh
node --input-type=module -e "import {runMultiAgentLab,runAdaptiveLabCampaign} from './packages/lab/index.js'; console.log(JSON.stringify(await runMultiAgentLab({seed:17,fault:'lost-response'}),null,2)); console.log(JSON.stringify(await runAdaptiveLabCampaign(),null,2))"
```

`runMultiAgentLab` accepts an integer `seed` from 0 to 4294967295 and a `fault` of `none`, `quarantined-memory`, `expired-memory`, `altered-arguments`, `backend-unavailable`, or `lost-response`. The seed identifies the synthetic memory document; it does not generate a range of agent behaviors. Fault selection is explicit. The three roles and delegation messages are scripted in one process. A fixture reviewer approves the fixed benign document and deliberately leaves the selected malicious fixture quarantined; it is not a general prompt-injection detector. The finance role retrieves reviewed signed memory before calling the real local MCP HTTP gateway and its synthetic backend. One fixture agent identity signs the invocation; the messages are not cryptographic delegation. `lost-response` discards a received response at the client and retries the same capability: it is not an injected network packet loss. Backend failure closes the local fixture backend and checks the journal's uncertain state.

`runAdaptiveLabCampaign` tries altered arguments, missing proof, missing approvals and a direct request without the backend secret. It proceeds only after the previous attempt was denied without a backend effect. It then verifies a signed positive control and attempts replay. Each step reports the HTTP status and the change in the backend's synthetic operation count. Unexpected effects or successful unauthorized responses fail the campaign; unexpected responses are inconclusive. The optional `createHarness` parameter is a test seam, not isolation of an untrusted target.

This is bounded scripted adaptation, not an independent attacker, open-ended exploration, real multiagent autonomy or a security certification. The loopback servers share the local host and process trust boundary; they do not prove container or production isolation, and access with the backend credential is outside this campaign. The historical 1,000-case lab remains at 650 PASS and 350 GAP; neither campaign changes or closes those gaps.

## Mutation coverage and network fault

`node --experimental-test-coverage --test-coverage-include=lib/authority.js --test-coverage-include=lib/approvals.js --test tests/fuzz.test.js` reports coverage for the existing deterministic mutations only. One Windows Node 24.22.0 run measured 93.12% lines and 67.57% branches for those two files combined; those figures are not coverage of the entire project or a security score. The proposed CI runs this command on pushes and pull requests; no new CI result is claimed here. The corpus uses fixed mutation seeds and identifies the failing iteration, but generates fresh signing keys and does not persist exact crashing inputs. It is not coverage-guided fuzzing or automatic crash reproduction.

The pilot test `E26 socket loss after committed backend effect stays uncertain and replay does not repeat it` sends traffic through a loopback proxy that closes its downstream socket after the backend has responded. It verifies one synthetic effect, a signed uncertain journal entry and replay denial. It is not distributed chaos engineering or a general network-failure campaign.

## Concurrent synthetic gateway benchmark

```sh
node --input-type=module -e "import {runSyntheticGatewayBenchmark} from './packages/lab/index.js'; console.log(JSON.stringify(await runSyntheticGatewayBenchmark({requests:100,concurrency:8}),null,2))"
```

The bounded benchmark issues one negative altered-argument control and measures up to 200 authorized requests at concurrency 1 to 16. Credentials are generated before timing. Each latency includes HTTP response parsing; completed HTTP error responses are included, but transport failures have no latency sample. Throughput counts successful HTTP responses per measured wall-clock second. The report separately counts errors and backend effects, and compares effects with successful responses; receipts are not verified in the timed path. The negative control reports both HTTP status and backend effect count, but its single case is not a false-permit rate. CPU time and before/after RSS are for the entire Node process, including client, gateway and backend; they are not per-service or peak measurements.

One local Windows x64 Node 24.22.0 run with 100 requests and concurrency 8 observed 100 HTTP successes, 100 synthetic effects, no HTTP or transport errors, and no effect from the negative control. It measured 56.65 successes/s, p50 133.97 ms, p95 208.70 ms and p99 212.30 ms; process CPU was 922 ms user plus 734 ms system, and RSS changed from 82,808,832 to 97,751,040 bytes. This single uncalibrated run is not a performance claim, SLA, independent comparison, cost measurement or result for external MCP servers. There is no equivalent unprotected baseline or competitive scoreboard.