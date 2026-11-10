#!/usr/bin/env python3
"""Medusa Layer 4 preflight. NO EFFECTS, NO UNDO, NO AUTHORIZATION.

Read-only admission checks against locally signed Layer 1 grants. A real
actuator MUST additionally verify a signed Layer 2 event chain, bind the
referenced original events to every requested target, lock/revalidate target
identity, durably reserve an undo journal and append a signed result.
These dependencies are absent. This executable ALWAYS exits non-zero and
NEVER returns ALLOW; its output cannot be used as permission to act.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import authority_grant as GRANT
import eventbus as BUS

VERSION = "0.1.0-L4-PREFLIGHT"
MAX_EVENT_BYTES = 32768
MAX_TARGET_BYTES = 5 * 1024 * 1024
MAX_AGE_SECONDS = 300
SHA256 = re.compile(r"^[0-9a-f]{64}$")
ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
SUPPORTED = frozenset({"quarantine_file"})
SEVERITY = GRANT.SEVERITY


class GuardError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(value, code):
    if not value:
        raise GuardError(code)


def outcome(status, code, *, grant_id=None, target=None):
    result = {"status": status, "reason": code, "authority": "NONE",
              "effect_executed": False, "undo_token_issued": False,
              "layer2_chain_verified": False, "releasable": False}
    if isinstance(grant_id, str) and GRANT.IDENTIFIER.fullmatch(grant_id):
        result["grant_id"] = grant_id
    if isinstance(target, str):
        result["target_path_sha256"] = hashlib.sha256(target.encode()).hexdigest()
    return result


def inspect_target(target, grant):
    require(isinstance(target, str) and target.startswith("/") and "\\" not in target and "\x00" not in target,
            "TARGET_INVALID")
    require(".." not in target.split("/") and "." not in target.split("/"), "TARGET_TRAVERSAL")
    p = Path(target)
    require(os.path.normpath(target) == target, "TARGET_NOT_NORMALIZED")
    try:
        resolved = p.resolve(strict=True)
        st = os.lstat(p)
        scope = Path(grant["target_scope"]).resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        raise GuardError("TARGET_UNREADABLE")
    # Reject symlinks anywhere in path and in the scope root, not just leaf.
    require(str(resolved) == target and str(scope) == grant["target_scope"], "SYMLINK_OR_ALIAS")
    require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1, "NOT_SINGLE_LINK_REGULAR_FILE")
    require(st.st_size <= MAX_TARGET_BYTES, "TARGET_TOO_LARGE")
    require(GRANT.within(target, str(scope)), "TARGET_OUT_OF_SCOPE")
    for excluded in grant["excluded_paths"]:
        require(not GRANT.within(target, excluded), "TARGET_EXCLUDED")
    return target


def inspect_event(record, target, grant, *, clock=None):
    require(isinstance(record, dict) and set(record) == {"event", "payload"}, "BAD_DETECTION_ENVELOPE")
    ev, payload = record["event"], record["payload"]
    require(isinstance(ev, dict) and isinstance(payload, dict), "BAD_DETECTION_ENVELOPE")
    require(ev.get("event_type") == "detection_feedback", "NOT_DETECTION_FEEDBACK")
    eid = ev.get("event_id")
    require(isinstance(eid, str) and ID.fullmatch(eid), "BAD_DETECTION_ID")
    require(isinstance(ev.get("sensor_id"), str) and ev["sensor_id"].startswith("detect-"),
            "UNTRUSTED_DETECTOR_ID")
    try:
        observed = GRANT.when(ev.get("observed_at"))
    except (GRANT.GrantError, TypeError, ValueError):
        raise GuardError("BAD_DETECTION_TIME")
    now = clock or datetime.now(timezone.utc)
    age = (now - observed).total_seconds()
    require(0 <= age <= MAX_AGE_SECONDS, "STALE_OR_FUTURE_DETECTION")
    refs = payload.get("evidence_ref")
    require(isinstance(refs, list) and 1 <= len(refs) <= 1000 and all(
        isinstance(x, str) and ID.fullmatch(x) for x in refs), "MISSING_EVIDENCE_REFERENCES")
    require(len(refs) == len(set(refs)) and eid not in refs, "BAD_EVIDENCE_REFERENCES")
    require(isinstance(payload.get("rule_id"), str) and ID.fullmatch(payload["rule_id"]), "BAD_RULE_ID")
    require(isinstance(payload.get("ruleset_sha256"), str) and SHA256.fullmatch(payload["ruleset_sha256"]),
            "MISSING_RULE_HASH")
    severity = payload.get("severity")
    require(severity in SEVERITY, "BAD_SEVERITY")
    require(SEVERITY[severity] >= SEVERITY[grant["requires_detection_severity"]], "BELOW_SEVERITY_THRESHOLD")
    evidence = payload.get("evidence_tag")
    require(evidence in GRANT.EVIDENCE, "BAD_EVIDENCE_TAG")
    require(evidence == "VERIFIED" and grant["requires_evidence_tag"] == "VERIFIED",
            "NO_VERIFIED_EVENT_EVIDENCE")
    targets = payload.get("target_paths")
    require(isinstance(targets, list) and len(targets) == 1 and targets[0] == target,
            "TARGET_NOT_BOUND_TO_DETECTION")
    return True


def review(grant_id, target, detection, *, clock=None):
    """No execution path. Structural + signature checks for diagnostic review."""
    try:
        GRANT.safe_id(grant_id)
        # GRANT.directory() can create missing storage. Preflight must not.
        store = Path(os.environ.get('MEDUSA_GRANTS_DIR', str(Path.home() / '.config/medusa/grants')))
        require(store.is_dir() and not store.is_symlink(), 'GRANT_STORE_MISSING_OR_UNSAFE')
        trusted = GRANT.signer_db()
        grant = GRANT.verify_record(grant_id, trusted)
        require(grant["action_class"] in SUPPORTED, "ACTION_NOT_IMPLEMENTED")
        require(grant["undo_required"] is True, "UNDO_NOT_REQUIRED")
        require(type(grant["max_blast_radius"]) is int and grant["max_blast_radius"] >= 1,
                "BLAST_RADIUS_EXCEEDED")
        require(len([target]) <= grant["max_blast_radius"], "BLAST_RADIUS_EXCEEDED")
        normalized = inspect_target(target, grant)
        inspect_event(detection, normalized, grant, clock=clock)
        # Caller-supplied VERIFIED flags are NOT cryptographic evidence. Never
        # return ALLOW until signed Layer 2 verification is implemented.
        return outcome("HOLD", "NO_SIGNED_EVENT_BUS", grant_id=grant_id, target=normalized)
    except (GRANT.GrantError, GuardError, OSError, ValueError, KeyError, TypeError) as exc:
        reason = exc.code if isinstance(exc, GuardError) else "INVALID_GRANT_OR_LOCAL_STATE"
        return outcome("BLOCKED", reason, grant_id=grant_id, target=target)



def review_signed_bus(grant_id, target, detection_event_id, *, clock=None):
    """Read-only inspection of real signed feedback and its original witnesses.

    An authenticated local bus is NOT independent custody or permission to act.
    Returns only BLOCKED or HOLD. Never moves, deletes or restores a file.
    """
    try:
        require(isinstance(detection_event_id, str) and SHA256.fullmatch(detection_event_id),
                'INVALID_SIGNED_DETECTION_ID')
        root = BUS.busdir()
        lock = root / '.lock'
        require(root.is_dir() and not root.is_symlink() and
                lock.is_file() and not lock.is_symlink(), 'SIGNED_BUS_NOT_INITIALIZED')
        snap = BUS.verified_snapshot()
        records = snap['records']
        matches = [r for r in records if r['event']['event_id'] == detection_event_id]
        require(len(matches) == 1, 'SIGNED_DETECTION_NOT_FOUND')
        rec = matches[0]
        require(rec['event']['event_type'] == 'detection_feedback', 'NOT_DETECTION_FEEDBACK')
        payload = rec['payload']
        n = BUS._valid_anchor(payload.get('chain_anchor'), records)
        require(n < rec['event']['seq'], 'DETECTION_ANCHOR_NOT_BEFORE_FEEDBACK')
        refs = payload.get('evidence_ref')
        require(isinstance(refs, list) and 1 <= len(refs) <= 1000 and
                all(isinstance(x, str) and SHA256.fullmatch(x) for x in refs) and
                len(set(refs)) == len(refs), 'BAD_SIGNED_EVIDENCE_REFS')
        idx = {r['event']['event_id']: r for r in records[:n]}
        source_types = {'sensor_heartbeat','fs_change','ci_event','config_change',
                        'process_event','network_event','auth_event'}
        paths = []
        for ref in refs:
            source = idx.get(ref)
            require(source is not None and source['event']['event_type'] in source_types,
                    'EVIDENCE_NOT_IN_SIGNED_PREFIX')
            if source['event']['event_type'] == 'fs_change':
                path = source['payload'].get('path')
                if isinstance(path, str) and path.startswith('/') and path not in paths:
                    paths.append(path)
        require(payload.get('target_paths') == paths,
                'TARGETS_NOT_DERIVED_FROM_SIGNED_SOURCES')
        require(paths == [target], 'TARGET_NOT_SUPPORTED_BY_SIGNED_SOURCE')
        result = review(grant_id, target, rec, clock=clock)
        if result['status'] == 'HOLD':
            result['reason'] = 'SIGNED_FEEDBACK_VERIFIED_GUARD_INERT'
            result['layer2_chain_verified'] = True
        return result
    except (BUS.BusError, GuardError, GRANT.GrantError, OSError,
            ValueError, KeyError, TypeError, AttributeError) as exc:
        reason = exc.code if isinstance(exc, GuardError) else (
            'INVALID_SIGNED_EVENT_BUS' if isinstance(exc, BUS.BusError)
            else 'INVALID_SIGNED_FEEDBACK_OR_LOCAL_STATE')
        return outcome('BLOCKED', reason, grant_id=grant_id, target=target)


def load_event(path):
    p = Path(path)
    if p.is_symlink():
        raise GuardError("DETECTION_FILE_SYMLINK")
    try:
        fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as handle:
            st = os.fstat(handle.fileno())
            require(stat.S_ISREG(st.st_mode) and st.st_size <= MAX_EVENT_BYTES,
                    "DETECTION_FILE_UNSAFE")
            content = handle.read(MAX_EVENT_BYTES + 1)
        require(len(content) <= MAX_EVENT_BYTES, "DETECTION_FILE_TOO_LARGE")
        return json.loads(content)
    except (OSError, UnicodeError, ValueError):
        raise GuardError("DETECTION_FILE_UNREADABLE")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Medusa Layer 4: read-only guard, NEVER an actuator")
    cmd = ap.add_subparsers(dest="command", required=True)
    preflight = cmd.add_parser("inspect", help="read-only diagnostic; ALWAYS returns exit 2")
    preflight.add_argument("--grant", required=True)
    preflight.add_argument("--target", required=True)
    preflight.add_argument("--detection", required=True, help="local JSON record, never trusted as signed")
    signed = cmd.add_parser("inspect-bus", help="verify actual signed feedback; always HOLD or BLOCKED")
    signed.add_argument("--grant", required=True)
    signed.add_argument("--target", required=True)
    signed.add_argument("--detection-event", required=True)
    args = ap.parse_args(argv)
    try:
        if args.command == 'inspect-bus':
            res = review_signed_bus(args.grant, args.target, args.detection_event)
        else:
            det = load_event(args.detection)
            res = review(args.grant, args.target, det)
    except GuardError as exc:
        res = outcome("BLOCKED", exc.code, grant_id=args.grant, target=args.target)
    print(json.dumps(res, sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
