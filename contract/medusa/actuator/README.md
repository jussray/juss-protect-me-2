# Medusa Layer 4: guarded-action preflight (offline, inert)

**STATUS: HOLD.** Layer 2's signed local event bus is present. Its evidence
can be authenticated locally, but it is not independently anchored and it
cannot authorize filesystem changes. This directory deliberately contains
**no executable actuator**:
no `execute`, no `undo`, no `shutil.move`, no network, no writes. It is a
read-only preflight for a future gated quarantine primitive.

This preflight *does* verify the actual local Layer 1 signed grant and ledger
using `authority_grant.verify_record`, inspect current revocation and delegation,
check normalized target paths, scope, exclusions, single-target blast radius,
file type/links, detection shape, evidence refs, rule hash, severity, target
binding, and event age. All checks may pass structurally, but the terminal result remains HOLD.
The legacy `inspect` mode accepts caller-supplied JSON only; `inspect-bus`
independently reads the real signed local ledger and binds the original source
events to the requested target, but remains non-executable.

`python3 actuator_guard.py inspect --grant <id> --detection <local.json> --target <absolute>`

`python3 actuator_guard.py inspect-bus --grant <id> --target <absolute> --detection-event <signed-64hex-event-id>`

**Exit 2 on every input, never ALLOW.** The bus-inspection mode reports
`layer2_chain_verified=true` only after checking the signed local ledger and
source-target references; it still returns HOLD. The output includes no raw file contents
and only a SHA256 of the requested target pathname. It does not emit a signed
action_result and cannot confer production authority.

Future real actuator requirements, not implemented:

1. Independent **off-host evidence custody** beyond locally configured signing
   keys; original source-event references must remain authenticated at action time.
   A caller-supplied `evidence_tag: VERIFIED` is not independent proof.
2. Action request must be bound to the actual affected target in the original
   signed evidence, never a separately supplied target assertion.
3. Real-path open/lock and inode checks at action time; refuse hardlinks,
   symlinks, directory files, and races. Same-device atomic rename only.
4. Durable, exclusive, signed undo journal plus idempotent operation ID before
   the effect, with fsync on file and parent directories.
5. Recovery after crash, signed outcome recording, safe undo identity binding,
   exclusive no-overwrite restoration and expiry-window enforcement.
6. Per-grant cumulative rate / byte budget, independent monitoring, and
   human escalation for any ambiguity or irreversible action.
7. Synthetic lab rehearsal + exact-head CI + Playwright only when an actual
   user-facing runtime is changed, then independently reviewed release.

`python3 -m unittest discover -s contract/medusa/actuator -p 'test_actuator_guard.py' -v`
