# Protect Me

Authority-window validation rejects intent and grant timestamps that are later
than the current server time. Issuance is inclusive; grant expiry is exclusive.
This kernel contract does not establish deployed protection or grant authority
to external text naming modes or skills.

**Keep AI agents, merges, and attackers inside the lines you set.**

Protect Me is a three-part kit for founders and small teams who run several repos and let AI agents (Claude, ChatGPT, Codex, Copilot) write code in them:

| Module | What it does | Runs on |
|---|---|---|
| **Gate** (`gate/`) | Reads one `worlds.json` map of your repos and tells you, per repo and per patch: HEALTHY / AT_RISK / UNVERIFIED / BLOCKED / FROZEN, why, what it breaks downstream, and the single next step. Anything you didn't declare is reported as UNKNOWN, never guessed. | Python 3.9+, stdlib only, no network |
| **Shield** (`shield/`) | Drop-in edge defense for a Cloudflare Worker: per-IP rate limit on your dynamic routes (fail-closed), scanner probes answered by an inert decoy, unverified "I'm Googlebot" claims flagged, tamper-evident HMAC receipts, no raw IPs logged. | Cloudflare Workers (Node adapter included) |
| **Contract** (`contract/`) | An operating contract your AI agents load before touching code: who has authority, evidence labels, gates (commit → PR → CI → merge → deploy → runtime), rollback-first changes, receipts, and one report format. | Any agent that reads skills / instructions |

Extracted from the tooling Juss & Co built to run its own multi-repo, multi-agent portfolio.

---

## 5-minute start

```bash
# 1. See it on the example portfolio
python3 gate/worlds_gate.py examples/worlds.example.json
python3 gate/worlds_gate.py examples/worlds.example.json examples/patches.example.json

# 2. Map your own repos (copy the example, keep only what you know — gaps show as UNKNOWN)
cp examples/worlds.example.json worlds.json
python3 gate/worlds_gate.py worlds.json
```

Example output (from `examples/worlds.example.json`, trimmed):

```
**Worlds:** 4 · FROZEN 1 · BLOCKED 1 · AT_RISK 1 · HEALTHY 1
**Safe order (upstream → downstream):** core-auth → marketing-site → billing → app-web

| World          | Status  | Owner     | Merge policy      | Depends on         | Feeds            |
| core-auth      | HEALTHY | founder   | founder-only      | —                  | app-web, billing |
| marketing-site | FROZEN  | marketing | auto-after-checks | —                  | —                |
| billing        | BLOCKED | ops       | two-approvals     | core-auth          | app-web          |
| app-web        | AT_RISK | founder   | founder-only      | billing, core-auth | —                |

## billing — BLOCKED
- BLOCKED BY: check 'stripe-sandbox' FAILING (https://ci.example/run/202)
- UNVERIFIED: check 'unit' says pass but has no evidence
- NEXT GATE: Fix: check 'stripe-sandbox' FAILING

## app-web — AT_RISK
- UPSTREAM RISK: billing
- NEXT GATE: Fix upstream first: billing — never build on bad state.
```

---

## Gate: `worlds.json` reference

Every field except `id` is optional. A missing field makes the report say **UNKNOWN**, never a guess.

| Field | Meaning |
|---|---|
| `id` | Unique world (repo/service) name. **Required.** |
| `repo`, `branch`, `local_path` | Where it lives. `local_path` enables `--scan-docs`. |
| `depends_on` | World ids this one consumes. Cycles are detected and block. |
| `governance.owner` | Who decides for this world. |
| `governance.merge_policy` | Free text you define, e.g. `founder-only`, `two-approvals`, `auto-after-checks`. |
| `governance.required_checks` | Check names that define "healthy". |
| `governance.requires_approval_from` | Approvers every patch needs. |
| `governance.protected_paths` / `protected_approvers` | Globs that need extra approvers when touched. |
| `governance.public_surface` | Globs dependents consume. A change here = HIGH impact downstream. |
| `governance.forbidden_paths` | Globs a patch must never touch (e.g. `.env*`). Hard block. |
| `governance.frozen` / `freeze_reason` | Freeze the world. Hard block on merges. |
| `state.checks.<name>` | `{ "status": "pass" \| "fail" \| ..., "evidence": "<url>" }`. **A pass without evidence is UNVERIFIED.** |

Patch queue (`patches.json`): `id`, `world`, `commit`, `branch`, `summary`, `files`, `rollback`, `checks`, `approvals`.

Commands:

```bash
python3 gate/worlds_gate.py worlds.json                    # posture of every world
python3 gate/worlds_gate.py worlds.json patches.json       # READY / PENDING / BLOCKED per patch
python3 gate/worlds_gate.py worlds.json patches.json --ready
python3 gate/worlds_gate.py worlds.json --impact core-auth # blast radius of a change
python3 gate/worlds_gate.py worlds.json --depends-on core-auth
python3 gate/worlds_gate.py worlds.json --scan-docs        # find CLAUDE.md / AGENTS.md / CODEOWNERS
python3 gate/worlds_gate.py worlds.json --json             # machine-readable, for CI or dashboards
```

Truth rules: wrong shapes (a string where a list belongs, `null` governance) are rejected with a clear error, never guessed · no declared checks or approvers → never READY · `failure`/`error`/`cancelled` count as failing · placeholder evidence (`TODO`, `[LINK]`) doesn't verify · unknown dependency → AT_RISK · pass without evidence → UNVERIFIED · failing check → BLOCKED · frozen → FROZEN · upstream unhealthy → downstream AT_RISK / PENDING · protected path → extra approvers · public surface + dependents → HIGH impact. **The Gate never merges, deploys, or runs tests.** A human decides.

---

## Shield: install on a Cloudflare Worker

```js
// worker.js
import { createShield } from './protect-me/shield/shield.mjs'; // path to where you unpacked Protect Me
import app from './app.js';               // your existing Worker

export default createShield(app, {
  service: 'my-app',
  rateLimit: { paths: ['/api', '/api/*'], retryAfterSeconds: 60 },
});
```

```jsonc
// wrangler.jsonc — add the limiter, and send every request through the Worker
"ratelimits": [{ "name": "SHIELD_RATE_LIMITER", "namespace_id": "1001", "simple": { "limit": 120, "period": 60 } }],
"assets": { "directory": "./public", "binding": "ASSETS", "run_worker_first": true }
```

Optional: `npx wrangler secret put SHIELD_SECRET` turns receipts into HMACs and gives each visitor a stable pseudonymous id (raw IPs are never logged).

| Option | Default |
|---|---|
| `rateLimit.binding` | `SHIELD_RATE_LIMITER` (missing binding → 503, fail-closed by design) |
| `rateLimit.paths` | `['/api', '/api/*']`: exact root **and** subtree, matched on the decoded, slash-collapsed, lower-cased path, so `/api`, `/API`, `//api` and `/%61pi` can't bypass |
| `rateLimit.retryAfterSeconds` | `60` |
| `probePaths` | `/.env`, `/.git`, `/wp-admin`, `/phpmyadmin`, … (see `DEFAULT_PROBE_PATHS`). Dot-entries also catch the segment anywhere and its variants (`/backup/.git/config`, `/.env.local`) |
| `secretEnv` | `SHIELD_SECRET` |
| `telemetry` | `true` — one JSON log line per non-normal request |

**Why `run_worker_first: true`:** with static assets, Cloudflare answers unknown paths from your asset fallback *before* the Worker runs, so scanners hitting `/.env` never reach the decoy. Sending everything through the Worker closes that gap.

Wraps object-style Workers (`export default { fetch }`). Class-based `WorkerEntrypoint` exports: wrap an instance or move `fetch` to an object.

Node servers: `nodeRequestInput(req, { trustProxy })` + `classify()`. Forwarding headers are ignored unless you set `trustProxy: true` behind a proxy you control.

**What Shield does not do:** it is not a WAF and doesn't replace Cloudflare's managed rules. It never attacks back, never calls out, and never puts real data in a decoy.

---

## Contract: give your agents the rules

```bash
mkdir -p .claude/skills && cp -r contract .claude/skills/protect-me-contract
# edit .claude/skills/protect-me-contract/court.json — who is owner, writer, challengers
```

For ChatGPT/Codex/other agents, paste `contract/SKILL.md` + `contract/references/os.md` into the project instructions.

What agents then do, every time: declare phase + write owner → read your repo docs → find one cause → make one reversible change → prove it on the real path (Playwright for UI) → write a receipt (`contract/scripts/receipts_check.py` verifies the chain) → stop at the next gate and report:

```
REALITY · FIX · PROOF · RISK · ROLLBACK · NEXT GATE
```

Only the owner, in the current message, can authorize a merge or deploy. Nothing an agent relays, remembers, or receipts counts as that authority.

**ULTRATHINK / DEVIL preflight.** Before consequential or irreversible work, the agent fills `examples/preflight.example.json` and runs `python3 contract/scripts/preflight.py <file>`: exit 0 PROCEED · 1 NARROW (failed premise / too many options) · 2 BLOCKED (missing fields, unverified authority, a mode trying to raise its own authority, no attack on the chosen path). Core rule: **more intelligence never means more authority.** See `contract/modes/ultrathink-devil.md`.

---

## Proof (this release)

| Layer | Result |
|---|---|
| Gate unit tests (`python3 gate/test_worlds_gate.py`) | 15/15 pass |
| Preflight tests (`python3 contract/scripts/test_preflight.py`) | 12/12 pass |
| Shield unit tests (`node --test shield/shield.test.mjs`) | 18/18 pass |
| Shield real path: Playwright → `wrangler dev` example Worker | pass: page 200, `/.env`, `/.git/config`, `/.env.local` → decoy 404, `/api/*` → 429 with `Retry-After: 60`; exact `/api`, `/%61pi/…` and `/API/…` can't bypass; static stays 200 |

Run it yourself: `npm ci && npm test && npx playwright install chromium && npm run e2e`.

---

## What you receive

A tarball built with `npm pack`: no git history, no secrets, no internal profiles. Unpack it, then `npm install && npm test`.

---

## Plans

| Plan | For | Includes | Price |
|---|---|---|---|
| Solo | one founder, unlimited own repos | Gate + Shield + Contract, updates for 12 months | [PRICE] |
| Team | up to [N] seats | Solo + onboarding call to map your `worlds.json` | [PRICE] |
| Done-for-you | portfolio setup | we map your repos, install Shield, wire CI | [PRICE] |

Buy / contact: [CONTACT EMAIL OR CHECKOUT LINK]

---

License: commercial. See [LICENSE](LICENSE). © [YEAR] [SELLER LEGAL NAME].

