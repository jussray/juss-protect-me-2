# Medusa Layer 3: offline detection core, not yet integrated

Status: standalone reference prototype. Layer 2's signed event bus is missing in the current repository. This module accepts caller-supplied event snapshots, immutable JSON rulesets and frozen baseline values. It never reads a network resource, mutates a baseline, emits to the bus, consults grants or performs an action. ALL hits are tagged INFERRED until an independent Layer 2 verifier provides authenticated events. Therefore this is **not** a production detector and **cannot authorize Layer 4**.

Run `python3 -m unittest discover -s . -p 'test_detect_core.py' -v`.

The rule vocabulary is intentionally smaller than the user-supplied prototype. `path_glob` uses bounded wildcard matching instead of potentially catastrophic backtracking regex. `sequence` supports ordered, distinct-sensor multi-event patterns. `count` preserves all event IDs (up to 1000), never just the first 20. Unknown predicates, missing baselines and malformed events fail closed. There is no wall-clock timeout; finite rule/event/input limits are the safety control. Match-time profiling needs to be added before production. The 5k events x 200 rules bound is an upper bound, not a performance guarantee.

Next integration gate: implement, test and independently verify an append-only signed Layer 2 event bus, then adapt this core to consume its authenticated immutable snapshot, reverify evidence IDs and append `detection_feedback` with a separate signing key. There is NO automatic promotion to VERIFIED by passing a boolean. Run full CI and a safe replay test; do not enable actions.
