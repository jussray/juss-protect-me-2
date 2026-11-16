# Medusa Layer 3: offline detection core, not yet integrated

Status: pure offline detector, now also consumed by the separately verified Layer 2 `bus_adapter.py`. This core does not contact the bus or authorize an action. This module accepts caller-supplied event snapshots, immutable JSON rulesets and frozen baseline values. It never reads a network resource, mutates a baseline, emits to the bus, consults grants or performs an action. ALL hits are tagged INFERRED until an independent Layer 2 verifier provides authenticated events. Therefore this is **not** a production detector and **cannot authorize Layer 4**.

Run `python3 -m unittest discover -s . -p 'test_detect_core.py' -v`.

The rule vocabulary is intentionally smaller than the user-supplied prototype. `path_glob` uses bounded wildcard matching instead of potentially catastrophic backtracking regex. `sequence` supports ordered, distinct-sensor multi-event patterns. `count` preserves all event IDs (up to 1000), never just the first 20. Unknown predicates, missing baselines and malformed events fail closed. A 30-second cumulative POSIX wall-clock deadline now covers the entire `detect()` call, including validation; expiry aborts with `DetectionError` and returns no partial findings. Unsupported platforms, worker threads, or an existing process alarm fail closed. Finite rule/event/input limits remain in force, and throughput profiling is still needed before production.

Layer 2 now provides a locally signed ledger and separate adapter for source verification, anchored snapshots, and signed `detection_feedback`. The pure core still only emits `INFERRED`; the adapter verifies local provenance before any locally `VERIFIED` claim. Independent off-host custody, sustained operations and live containment remain on HOLD.

## Offline CLI (snapshot only)

`python3 detect.py validate --rules rules.filesystem.json`

`python3 detect.py run --events events.json --rules rules.filesystem.json --baseline baseline.json --json`

The events input is a JSON array of `{event_id,event_type,sensor_id,observed_at,payload}`. Baseline is a JSON object mapping baseline names to known-string lists, e.g. `{"paths-30d": ["/srv/app/.env"]}`. Every emitted finding remains `INFERRED`, not `VERIFIED`, because snapshot authenticity is not proven by this standalone tool. Error status 2 is fail-closed. Output status 0 never authorizes an action.
