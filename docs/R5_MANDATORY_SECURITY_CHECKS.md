# R5 / Mandatory branch protection without changing GitHub admin rules

The GitHub ruleset for `master` requires three existing Python contexts:
`security (3.11)`, `security (3.12)`, `security (3.13)`.
The current GitHub connector lacks an administrative write action for rulesets.

To enforce the most valuable gates immediately without weakening that ruleset,
`.github/workflows/test.yml` adds one `mandatory-security-gate` whose **success
is a prerequisite** for all three required contexts.

It runs Node regression, package audit, 15-epic scoped acceptance,
architecture tests, hostile Docker deployment, official MCP client, reversible
onboarding, and official disposable Vault AppRole privilege/revocation checks.
The existing Python jobs retain their exact names and still run after the gate.

**Critical detail:** the Python job uses `if: always()` and contains a first
step that **fails** if `needs['mandatory-security-gate'].result != 'success'`.
A skipped required job can otherwise count as successful in GitHub. This
makes an omitted/cancelled/failed dependency fail the required check instead.

This is a bridge until an administrator adds the individual named job checks
to the ruleset. It is not equivalent to verifying Github branch protection
configuration or to production enterprise certification. Any future change
to required-check names, workflow scope or job dependencies MUST be tested
against a real PR and re-audited for bypass.

Developer Preview production guarantee remains explicitly unclaimed.
