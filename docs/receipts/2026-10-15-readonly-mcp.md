# Read-only MCP integration receipt

RECEIPT-ID: 2026-10-15-readonly-mcp-two
CREATED-AT: 2026-10-15
REPO: jussray/juss-protect-me-2
BRANCH: fix/privacy-safe-evidence-20261015
CODE-CANDIDATE: 82ef32ac5fc91e65250eacc76f51327ed73fdf13
SCOPE: Model Two; independently named product, no cross-product authorization

## VERIFIED
- `mcp/protocol.mjs`, `mcp/tools.mjs`, `mcp/worker.mjs`, `mcp/protocol.test.mjs`, and `wrangler.mcp.jsonc` committed on the existing privacy branch.
- Server disabled by default; bearer token length check and Origin allowlist implemented; read-only tools with no external writes.
- 8/8 isolated MCP protocol tests; governance dry-run and evidence field screening exercised.
- No private chat transcripts, real credentials, or user data used as test fixtures.

## UNKNOWN / BLOCKED
- Node.js `npm test` and exact-head GitHub Actions not yet run.
- Cloudflare runtime / endpoint not deployed or independently inspected.
- No bearer secret provisioned by this work and no ChatGPT custom plugin registered.
- Remote ChatGPT availability depends on account / workspace capabilities.
- This is not monitoring of ChatGPT conversations or OpenAI's infrastructure.

## RISK
- Transport security requires live provider readback and runtime tests with a protected endpoint.
- Pattern-based evidence screening is not complete sensitive-data prevention.
- An MCP tool call cannot protect messages that were never routed through it.

## ROLLBACK
Revert focused MCP commits or discard this branch; do not modify `main` until exact-head verification and founder authorization. Keep `MCP_ENABLED=false` until those gates pass.

## NEXT GATE
Run exact-head Node CI and authenticated HTTP smoke tests; review security and deployment identity; only then authorize protected rollout and optional plugin registration.

## Follow-up security verification and identity gate (2026-10-15)

- PROOF: Protect Me Model Two branch code at 75cec8e1ee37a1fb4e409ba2bdcb6d7069beafa9 passed its entire recorded GitHub Actions workflow: https://github.com/jussray/juss-protect-me-2/actions/runs/38827485475.
- CONTINUITY: Feature branch reconciled 3 disjoint Shield/config main changes with two-parent merge commit; 9 ahead, 0 behind. Production main untouched.
- IMPLEMENTED: read-only MCP protocol/Worker handlers and privacy rejection tests remain disabled for production by `MCP_ENABLED=false`.
- RISK: a static, server-wide `MCP_BEARER_TOKEN` is not a user-bound OAuth access token. Do **not** claim ChatGPT plugin readiness, account ownership verification, or chat confidentiality from this implementation.
- CANDIDATE IDENTITY: Existing Founder Control Room Supabase project is active, and current Supabase documentation describes an OAuth 2.1 server suitable for MCP; its enabled state, consent UI, token issuer, audience, project suitability, and cost impact have not been verified.
- AUTH GATE: before any public endpoint, require an established OAuth 2.1 provider, PKCE authorization-code flow, user approval, resource metadata, asymmetric signed-token validation (JWKS), issuer/audience/expiry/scope checks, separate MCP product permissions, and real client revocation proof. Never authorize access from user-editable metadata or a receipt.
- PROOF GATE: test the **final exact branch head** using GitHub CI, inspect deployment identity, run an authenticated/unauthed HTTP smoke, validate tool schema discovery and client consent/revocation, then seek founder approval for deployment and plugin registration.
- ROLLBACK: this branch is isolated. Do not change production `main`, Cloudflare runtime, account access, or Supabase Auth settings as part of this receipt.
- CURRENT RECEIPT STATE: INFERRED continuity text until a receipt checker establishes a valid chain; referenced GitHub CI is independently VERIFIED for its stated commit.

## FCR-issued OAuth implementation (2026-10-15)

- SOURCE-COMMITTED: jussray/juss-protect-me-2 `77ccd629a2fc016b13d9ade000ae9a6fd53a5a0c` on `fix/privacy-safe-evidence-20261015`.
- CI VERIFIED: https://github.com/jussray/juss-protect-me-2/actions/runs/38834440493. At this SHA the existing Node suite passed; Model Two also passed its existing Playwright/Wrangler Shield smoke gates.
- AUTH DESIGN: FCR Supabase Auth acts as pinned OAuth 2.1 issuer. Resource server validates JWKS signatures (RS256/ES256), issuer, audience `authenticated`, role, subject, expiry/not-before/issued-at, and a required exact OAuth `client_id` allowlist unique to this product. A user-facing custom `mcp:read` scope is NOT assumed because Supabase's current OAuth server only supports standard OIDC scopes.
- DISCOVERY: implementation advertises OAuth protected-resource metadata via a read-only MCP Worker endpoint. Static access is not configured for OAuth deployment; prior static mode remains a guarded compatibility/test option.
- ENVIRONMENT: `MCP_ENABLED=false` remains set. OAuth runtime also rejects absent `MCP_RESOURCE_URL` or `MCP_OAUTH_CLIENT_IDS`. No user JWTs, private messages, provider secrets, or user data were copied to GitHub.
- PROVIDER STATE UNKNOWN: FCR Supabase OAuth enabled state, asymmetric signing keys, live consent UI, registered individual clients, redirect URI/PKCE verification, FCR RLS and per-client permissions, expiration/revocation after session changes, actual HTTPS endpoint, and ChatGPT custom connector availability are NOT VERIFIED.
- SECURITY STOP: do not enable dynamic client registration, configure live authorized clients, expose production MCP routes, or modify RLS without separate evidence and a verified founder decision. Existing FCR data must not be exposed to OAuth clients by broad RLS policies.
- CONTINUITY FINGERPRINT: repository=jussray/juss-protect-me-2; code_sha=77ccd629a2fc016b13d9ade000ae9a6fd53a5a0c; issuer=FCR-Supabase-project; mode=oauth-read-only; deployed=NO; risk=provider-config-unknown. This marker is not authority or a fingerprint of user data.
- ROLLBACK: feature branch only; discard/revert this commit chain. Production main and Supabase Auth are unchanged.
