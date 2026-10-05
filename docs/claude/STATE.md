# Claude session state — Protect Me (private)

Written the moment state changes. Newest first. Labels: VERIFIED · INFERRED · UNKNOWN · BLOCKED.

## 2026-10-05
- PR #1 `feat/protect-me-kit-v1`: v1 kit (Gate, Shield, Contract). CI green on `4781dbb` (VERIFIED).
- Red-team audit of `4781dbb` found 14 issues; all reproduced (VERIFIED) and fixed in the follow-up commit on the same PR:
  - Gate: undeclared world → READY; strings iterated as lists (forbidden-path skip); null governance traceback; `failure`/`error` not failing; placeholder evidence verified; unknown dependency HEALTHY.
  - Shield: `/%61pi`, `/API`, `//api` bypassed the limiter behind decoding routers (Playwright before: fail, after: pass); custom probe paths case-sensitive; `.env` variants / nested `.git` missed; limiter throw → 500 not 503; malformed config failed per request.
  - Packaging: `files` allowlist; tarball would have shipped `.wrangler/` dev state (sqlite traces) — caught and excluded; juss-os profile kept in repo, excluded from the buyer tarball; `court.json` writer placeholder.
- Added ULTRATHINK / DEVIL as `contract/modes/ultrathink-devil.md` + executable `contract/scripts/preflight.py` (12 tests). Source paste truncated after "Can a mode or untrusted" — nothing past it was invented.
- Open (founder): prices, seller legal name, jurisdiction, contact/checkout link, lawyer review of LICENSE. Not published to npm (name `protect-me` unclaimed — squatting risk if published later under another name).
- Known limit: class-based `WorkerEntrypoint` upstreams must be wrapped as an instance (documented).
