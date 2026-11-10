#!/usr/bin/env python3
"""Offline Medusa Layer 3 preview CLI. Does not act, emit, fetch, or verify a bus."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import stat
import sys
from detect_core import detect, validate_ruleset, DetectionError

MAX_INPUT_FILE = 2 * 1024 * 1024


def read_json(path):
    p = Path(path)
    if p.is_symlink():
        raise DetectionError(f"refusing symlink: {p.name}")
    try:
        with p.open('rb') as fh:
            st = os.fstat(fh.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_INPUT_FILE:
                raise DetectionError(f"input must be a small regular file: {p.name}")
            data = fh.read(MAX_INPUT_FILE + 1)
        if len(data) > MAX_INPUT_FILE:
            raise DetectionError(f"input too large: {p.name}")
        return json.loads(data)
    except (OSError, ValueError, UnicodeError) as exc:
        raise DetectionError(f"invalid input: {p.name}") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='cmd', required=True)
    run = sub.add_parser('run', help='detect on saved local event snapshot; advisory only')
    run.add_argument('--events', required=True, help='JSON list of frozen event envelopes')
    run.add_argument('--rules', action='append', required=True, help='JSON ruleset, repeatable')
    run.add_argument('--baseline', help='JSON snapshot of baseline values')
    run.add_argument('--json', action='store_true', help='machine-readable detections')
    val = sub.add_parser('validate', help='check a ruleset, no execution')
    val.add_argument('--rules', action='append', required=True)
    args = parser.parse_args(argv)
    try:
        rules=[read_json(p) for p in args.rules]
        if args.cmd=='validate':
            checks=[{'ruleset_id':r['ruleset_id'],'sha256':validate_ruleset(r)} for r in rules]
            print(json.dumps({'validated':checks},sort_keys=True))
            return 0
        events=read_json(args.events)
        baseline=read_json(args.baseline) if args.baseline else None
        findings=detect(events,rules,baseline)
        if args.json:print(json.dumps({'detections':findings,'count':len(findings),'authority':'NONE'},sort_keys=True))
        else:
            print(f"MEDUSA OFFLINE DETECTOR: {len(findings)} findings, NO AUTHORITY, NO ACTION")
            for item in findings:
                print(f"{item['rule_id']}: {item['severity']} / {item['confidence']} / {item['evidence_tag']} refs={len(item['evidence_ref'])}")
        return 0
    except (DetectionError, KeyError, TypeError) as exc:
        print(f"MEDUSA DETECTION BLOCKED: {type(exc).__name__}: {exc}",file=sys.stderr)
        return 2


if __name__=='__main__':
    raise SystemExit(main())
