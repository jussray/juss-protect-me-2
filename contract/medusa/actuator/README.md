# Medusa Layer 4: guarded-action preflight (offline, inert)

**STATUS: HOLD.** Layer 2's signed event bus is absent. The preceding Layer 3
snapshot detector cannot prove that event IDs and original target paths are
authentic. Therefore this directory deliberately contains **no actuator**:
no `execute`, no `undo`, no `shutil.move`, no network, no writes. It is a
read-only preflight for a future gated quarantine primitive.

This preflight *does* verify the actual local Layer 1 signed grant and ledger
using `authority_grant.verify_record`, inspect current revocation and delegation,
check normalized target paths, scope, exclusions, single-target blast radius,
file type/links, detection shape, evidence refs, rule hash, severity, target
binding, and event age. All checks may pass structurally, but the terminal
result remains HOLD because no signed Layer 2 event proof exists.

`python3 actuator_guard.py inspect --grant <id> --detection <local.json> --target <absolute>`

**Exit 2 on every input, never ALLOW.** The output includes no raw file contents
and only a SHA256 of the requested target pathname. It does not emit a signed
action_result and cannot confer production authority.

Future real actuator requirements, not implemented:

1. Independently authenticated signed Layer 2 event bus + verified referenced
   source events; cannot trust `evidence_tag: VERIFIED` alone.
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
