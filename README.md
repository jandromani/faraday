# FARADAY - Trust Fabric

FARADAY is a security research prototype for agent tool execution. The current
Node.js developer preview is **0.99.4**; the earlier Python builds remain as
standalone proof-of-concept implementations. It is not independently audited and
must not be used as a production authorization boundary.

The [agentic package](agentic/README.md) includes MCP discovery and observation,
an Authority prototype with signed capabilities and proof of possession, and a
limited MCP pilot with a synthetic backend and signed receipts. OAuth resource
validation is available in the pilot when explicitly configured; it is not a full
identity provider or proof of workload identity. The package is private and is
not published to npm.

The optional external policy filter in the pilot is an additional deny control,
not a replacement for Authority. An external gateway is not yet integrated or
certified. The synthetic Docker topology is not proof of isolation in other
deployments. The pilot never makes real payments, and an uncertain backend
result requires reconciliation rather than an automatic retry.

## Run locally

Node.js 22.16 or later is required for SQLite. The Python prototypes require
Python 3.11 or later; Build 002 also requires the dependencies in
[requirements.txt](requirements.txt).

```bash
cd agentic
npm test
npm run authority
npm run pilot
```

From the repository root, run the Python tests with:

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

Docker is required for the optional synthetic network-isolation demonstration.
The full `npm run test:all` currently contains a POSIX-specific Python command;
its availability and results depend on the platform and installed tools. On
Windows, POSIX file mode checks do not verify private-key ACLs. Set
`FARADAY_PYTHON` to an interpreter path when the Node adapter test cannot use
`python3`. Some symlink tests require permission to create symbolic links.
Proxy installation creates backups that can contain credentials. Automatic
installation is disabled on Windows because POSIX modes do not verify Windows
ACLs; dry-run and uninstall remain available. Existing backups must be reviewed
and protected using Windows ACLs by their owner.

## Evidence and limits

- [Developer preview, usage and limitations](agentic/README.md)
- [Gateway decision and integration requirements](agentic/docs/ADR-002-GATEWAY-MAKE-OR-BUY.md)
- [Assurance evidence gates](agentic/docs/ADR-004-ASSURANCE-GATES.md)
- [Roadmap status](docs/ROADMAP_STATUS.md)
- [Historical Build 002 model](docs/BUILD002.md)

External gateway enforcement, deployment-specific bypass resistance, key
management and independent validation remain open. Local test results and
synthetic evidence do not certify a deployment or establish production readiness.
