#!/usr/bin/env python3
"""Medusa Layer 6 lab supervisor: config sensor -> signed bus -> detection.

Opt-in only: MEDUSA_LAB_MODE=1. NEVER actuates, deploys, contacts a network,
creates a trusted signer, or treats a detection as authority. The existing
actuator_guard stays HOLD. Persistent scheduling is deliberately external.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "detection"))

import eventbus as BUS
import config_sensor as SENSOR
from detection import bus_adapter as DETECT


def require_lab():
    if os.environ.get("MEDUSA_LAB_MODE") != "1":
        raise BUS.BusError("MEDUSA_LAB_MODE=1 required; no production supervisor")


def run_once(*, paths, sensor_key, rulesets, sensor_id="config-1",
             detect_key=None, detect_id="detect-1", baseline=None):
    require_lab()
    changes = SENSOR.scan_once(paths, key=sensor_key, sensor_id=sensor_id)
    # This validates the whole authenticated event chain and detects within
    # one snapshot. Signed detector feedback requires a distinct trusted key.
    findings = DETECT.run(rulesets, baseline, emit=detect_key is not None,
                          emit_key=detect_key, sensor_id=detect_id)
    return {
        "sensor_events": changes,
        "detections": findings,
        "chain": BUS.verify_chain(),
        "authority": "evidence_only",
        "can_authorize": False,
        "effect_executed": False,
        "actuator_state": "HOLD",
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--path", action="append", required=True, help="explicit absolute local config path")
    p.add_argument("--sensor-key", required=True, help="registered sensor private key")
    p.add_argument("--sensor-id", default="config-1")
    p.add_argument("--rules", action="append", required=True, help="explicit local JSON ruleset")
    p.add_argument("--baseline", help="optional frozen JSON baselines")
    p.add_argument("--detect-key", help="registered detector key; enables signed feedback")
    p.add_argument("--detect-id", default="detect-1")
    p.add_argument("--cycles", type=int, default=1, help="bounded lab cycles, 1..10")
    p.add_argument("--interval-s", type=float, default=1, help="seconds between lab cycles, 1..300")
    args = p.parse_args(argv)
    try:
        require_lab()
        if not 1 <= args.cycles <= 10 or not 1 <= args.interval_s <= 300:
            raise BUS.BusError("bounded lab cycles/interval required")
        rulesets = [json.loads(Path(path).read_text(encoding="utf-8")) for path in args.rules]
        baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8")) if args.baseline else None
        for turn in range(args.cycles):
            result = run_once(paths=args.path, sensor_key=args.sensor_key,
                              sensor_id=args.sensor_id, rulesets=rulesets,
                              detect_key=args.detect_key, detect_id=args.detect_id,
                              baseline=baseline)
            print(json.dumps({"cycle": turn + 1, **result}, sort_keys=True))
            if turn + 1 < args.cycles:
                time.sleep(args.interval_s)
        return 0
    except (BUS.BusError, OSError, ValueError, TypeError, KeyError, RuntimeError) as exc:
        print("MEDUSA LAB HOLD: " + type(exc).__name__ + ": " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
