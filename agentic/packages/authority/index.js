/** FARADAY Authority public migration boundary v1. */
export {AuthorityError,AuthorityGate,AuthorityIssuer,NonceLedger,evaluatePolicy,createIntent,createExecution} from '../../lib/authority.js';
export {PinnedOAuthResource,OAuthBoundaryError} from '../../lib/mcp-oauth-resource.js';
export {signApproval,verifyApprovals} from '../../lib/approvals.js';
export {ToolPolicy} from '../../lib/security-policy.js';
export const AUTHORITY_API_VERSION='1.0.0-preview';
export {LocalOAuthRevocations} from '../../lib/oauth-revocations.js';
export {createStrictSecretFileProvider} from '../../lib/secret-file-provider.js';

export {createVaultKv2SecretProvider} from '../../lib/vault-kv2-secret-provider.js';
