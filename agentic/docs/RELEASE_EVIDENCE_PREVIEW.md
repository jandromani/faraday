# Offline release evidence preview

`signReleaseEvidence` binds the SHA-256 hashes of an artifact and an inventory to a declared package name and version using an operator-supplied Ed25519 private key. `verifyReleaseEvidence` requires the artifact and inventory bytes, an independently trusted public key, and the expected package name and version. The signature is domain-separated and the evidence schema and signature encoding are strictly checked.

```js
import {readFileSync} from 'node:fs';
import {signReleaseEvidence,verifyReleaseEvidence} from '@faraday/agentic/release-evidence';

const artifact=readFileSync('faraday-agentic-0.99.4.tgz');
const sbom=readFileSync('inventory.spdx.json');
const evidence=signReleaseEvidence({artifact,sbom,packageName:'@faraday/agentic',packageVersion:'0.99.4',privatePem:readFileSync('release-private.pem','utf8')});
const report=verifyReleaseEvidence({artifact,sbom,evidence,publicPem:readFileSync('trusted-public.pem','utf8'),expectedPackageName:'@faraday/agentic',expectedPackageVersion:'0.99.4'});
```

The operator must protect the private key, retain and distribute the evidence alongside the exact bytes, and establish the public-key trust channel independently. No private key, archive, inventory or signature is published by this API. Verification checks the binding, not that the inventory matches the archive, that the package metadata is truthful, or that a build was trusted. It does not provide key rotation, revocation, timestamps, transparency, a trusted builder, SLSA provenance or a signed release.

`npm run release:audit` produces an inventory of files listed by `npm pack --dry-run`; it is not an inventory of resolved direct or transitive dependencies, a general secret scanner, or an audit of every file in the repository. The archive and inventory are independently supplied inputs: a signature does not establish that they describe the same build. The current package remains private and no publication is implied.