# Medusa Layer 2: locally signed evidence bus and Layer 3 adapter

**Scope: offline and locally authenticated only.** No network, sensing, action, grant lookup, supervisor or containment. No implicit sensor self-registration. Trust for `sensor_id -> Ed25519 public key` is explicitly provisioned by a separate administrator in `MEDUSA_TRUSTED_SENSORS` (`{"sensors":{"fs-1":"<base64 32-byte public key>","detect-1":"<base64 ...>"}}`). Trust manifest and parent must be owned by the current user or root, not group/world-writable. The private signing keys stay outside the repository and need mode 0600.

`MEDUSA_BUS_DIR` must be a private directory (0700). An append takes a POSIX `flock`, verifies the signed chain and local `head.json`, appends a canonical signed record to `events.jsonl`, fsyncs it, then atomically replaces and fsyncs the head. A crash between the two writes causes **HOLD / fail-closed** until separately inspected. There is no automatic repair that could discard evidence. `verified_snapshot()` gives the event records and an exact prefix `(count,last_event_hash)` from one lock epoch. `verify_snapshot_continuity()` confirms that the same signed prefix survives later appends; a rewritten prefix, invalid signatures, missing head, partial line, or missing records blocks. An attacker with authority to rewrite ledger + head and provision trust remains outside local custody: **independent external anchoring has not been implemented**.

Layer 3 is unchanged. `detection/bus_adapter.py` passes authenticated source event snapshots to its existing pure `detect_core.detect()` API. For signed-source hits only, it attaches a prefix anchor and evidence references, and **atomically rechecks** the chain prefix/evidence references while appending signed `detection_feedback`. The signer must be independently registered under a `detect-` ID. Duplicate identical feedback is refused by a deterministic `detection_id` at the bus's writer lock. Appended feedback events never feed back into detection as observations. The adapter never creates a grant or calls the actuator. `VERIFIED` refers only to **local cryptographic provenance**, not sensor truth, independent attestation, or authorization to act. Baseline-absence anomalies remain `INFERRED` even when their source observations are signed. Evidence from over 100 distinct filesystem paths is not partially bound to targets; the target list remains empty and `target_binding_incomplete` is recorded (so the guard cannot authorize an individual target).

The existing rule engine orders events by timestamp then event ID. Where ordered sequence rules would rely on tied timestamps, the adapter **refuses** instead of claiming event-ID order is reliable. Future ordered correlation should use authenticated bus sequence order after an explicit, reviewed core change.

## Offline usage (existing trust + keys required)

```sh
python3 contract/medusa/eventbus.py verify
python3 contract/medusa/detection/bus_adapter.py --rules contract/medusa/detection/rules.filesystem.json
# Optional, append signed findings. No action is possible:
python3 contract/medusa/detection/bus_adapter.py --rules contract/medusa/detection/rules.filesystem.json --emit --emit-key /private/detect-1.pem
```

## Tests and release gates

```sh
python3 -m unittest discover -s contract/medusa -p 'test_eventbus.py' -q
python3 -m unittest discover -s contract/medusa/detection -p 'test_bus_adapter.py' -q
python3 -m unittest discover -s contract/medusa/detection -p 'test_detect*.py' -q
```

The ledger tests include 25 concurrent processes and 250 events, signature/trust corruption, record tamper, truncation, anchor continuation, and atomic deduplicated feedback; detector tests preserve pure-core behavior and include synthetic signed bus-to-feedback integration. A 25-writer × 100-event sustained-load result, independent anchored custody, and enforced cumulative wall-clock runtime deadline remain open. The canonical Layer 4 `actuator_guard.py` remains inert and returns HOLD; it does **not** read the bus yet and it does not permit a quarantine, undo, or automatic containment. No Layer 6 rollout.
