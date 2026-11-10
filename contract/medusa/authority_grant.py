#!/usr/bin/env python3
"""Medusa Layer 1: local, signed, scope-bounded grants (NO actuators/network).

External, owner-controlled trusted_signers.json is the root of authority.
Successful verification proves a locally configured signature and scope only;
it does NOT identify a human, authorize a deployment, or execute an action.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import re
import stat
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import fcntl  # POSIX-only, fail closed on unsupported systems
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
except ImportError as exc:
    raise SystemExit(f"authority_grant: required local dependency unavailable: {exc}")

VERSION = "1.0.0-L1"
# Conservative: token revocation and host isolation have no demonstrated undo.
AUTO_CLASSES = {"log_only", "block_deploy", "quarantine_file"}
MANUAL_CLASSES = {"reject_request", "revoke_token", "isolate_host", "delete_file", "encrypt_file", "transfer_ownership"}
SEVERITY = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
EVIDENCE = {"UNVERIFIED": 1, "INFERRED": 2, "VERIFIED": 3}
IDENTIFIER = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$")
EMPTY_SHA = "0" * 64
MAX_GRANT_BYTES = 32768
MAX_AUDIT_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 8


class GrantError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise GrantError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(value):
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def when(value):
    require(isinstance(value, str), "invalid timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GrantError("invalid timestamp") from exc
    require(parsed.tzinfo is not None, "timestamp must include timezone")
    return parsed.astimezone(timezone.utc)


def safe_id(value):
    require(isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None,
            "unsafe grant_id; use only letters, digits, - and _")
    return value


def canonical_path(value):
    require(isinstance(value, str) and value.startswith("/"), "target_scope must be absolute")
    require("\x00" not in value and "\\" not in value, "invalid scope path")
    parts = value.split("/")
    require(".." not in parts and "." not in parts, "scope path may not contain traversal")
    result = os.path.normpath(value)
    require(result == value and result != "/", "scope must be normalized and may not be filesystem root")
    return result


def within(child, parent):
    return os.path.commonpath((child, parent)) == parent


def ensure_dir(path):
    p = Path(path)
    if p.exists() or p.is_symlink():
        require(p.is_dir() and not p.is_symlink(), "grants directory must be a real directory")
    else:
        p.mkdir(mode=0o700, parents=True, exist_ok=True)
    require((p.stat().st_mode & 0o022) == 0, "grants directory must not be group/world writable")
    return p


def file_bytes(path, limit=MAX_GRANT_BYTES):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as fh:
            info = os.fstat(fh.fileno())
            require(stat.S_ISREG(info.st_mode), "must be a regular file")
            require(info.st_size <= limit, "oversize file")
            return fh.read(limit + 1)
    except OSError as exc:
        raise GrantError(f"cannot read {Path(path).name}: {exc.strerror}") from exc


def json_file(path, limit=MAX_GRANT_BYTES):
    try:
        obj = json.loads(file_bytes(path, limit))
    except (ValueError, UnicodeError) as exc:
        raise GrantError(f"invalid JSON in {Path(path).name}") from exc
    require(isinstance(obj, dict), "JSON must be an object")
    return obj


def write_once(path, content):
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
    except OSError as exc:
        raise GrantError(f"refusing overwrite or unsafe path: {Path(path).name}") from exc


def directory():
    return ensure_dir(os.environ.get("MEDUSA_GRANTS_DIR", str(Path.home() / ".config/medusa/grants")))


def signer_db():
    p = Path(os.environ.get("MEDUSA_TRUSTED_SIGNERS", str(Path.home() / ".config/medusa/trusted_signers.json")))
    # Protect local root-of-trust against writable files, symlink substitution
    # and replacement through a writable immediate parent directory.
    for candidate, kind in ((p, "file"), (p.parent, "directory")):
        try:
            info = candidate.lstat()
        except OSError as exc:
            raise GrantError(f"trust {kind} not available") from exc
        require(not stat.S_ISLNK(info.st_mode), f"trust {kind} may not be a symlink")
        require(stat.S_ISREG(info.st_mode) if kind == "file" else stat.S_ISDIR(info.st_mode),
                f"trust {kind} has unsafe type")
        require(info.st_uid in (os.getuid(), 0), f"trust {kind} owner not authorized")
        require((info.st_mode & 0o022) == 0, f"trust {kind} permissions allow untrusted writes")
    data = json_file(p)
    require(isinstance(data.get("signers"), list), "signers list missing")
    by_name = {}
    used_keys = set()
    for entry in data["signers"]:
        require(isinstance(entry, dict) and isinstance(entry.get("decider"), str), "invalid signer")
        decider = entry["decider"]
        require(decider not in by_name, "duplicate decider in trust file")
        pub = entry.get("public_key_b64")
        try:
            key = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub, validate=True))
        except (ValueError, TypeError) as exc:
            raise GrantError("invalid signer public key") from exc
        canonical_key = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        require(canonical_key not in used_keys, "duplicate public signing key across deciders")
        used_keys.add(canonical_key)
        by_name[decider] = (entry, key)
    return by_name


def key_for(decider, trusted):
    require(decider in trusted, "decider not trusted")
    return trusted[decider][1]


def private_key(path, decider, trusted):
    try:
        key = serialization.load_pem_private_key(file_bytes(path), password=None)
    except (ValueError, TypeError) as exc:
        raise GrantError("cannot load Ed25519 private key") from exc
    require(isinstance(key, Ed25519PrivateKey), "Ed25519 key required")
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    expected = trusted[decider][1].public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    require(raw == expected, "signing key does not belong to named decider")
    return key


def signature_valid(payload, signature, key):
    try:
        key.verify(bytes.fromhex(signature), canonical(payload))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def load_grant(gid):
    safe_id(gid)
    g = json_file(directory() / (gid + ".grant.json"))
    require(g.get("grant_id") == gid, "grant filename/identity mismatch")
    return g


def validate_shape(g):
    required = {"schema", "grant_id", "decider", "granted_at", "expires_at", "action_class",
                "max_blast_radius", "requires_evidence_tag", "requires_detection_severity",
                "target_scope", "excluded_paths", "delegates_to", "delegation_depth_remaining",
                "escalation_to", "undo_required", "delegates_from", "signature"}
    require(set(g) == required, "unexpected or missing grant fields")
    require(g["schema"] == VERSION, "unsupported grant schema")
    safe_id(g["grant_id"])
    require(isinstance(g["decider"], str) and g["decider"], "decider missing")
    require(g["action_class"] in AUTO_CLASSES, "action class not auto-grantable (no verified undo)")
    require(type(g["max_blast_radius"]) is int and g["max_blast_radius"] > 0, "blast radius must be positive integer")
    require(g["requires_evidence_tag"] == "VERIFIED", "automatic actions require VERIFIED evidence")
    require(g["requires_detection_severity"] in SEVERITY, "invalid severity")
    scope = canonical_path(g["target_scope"])
    require(isinstance(g["excluded_paths"], list), "excluded paths must be list")
    require(len(g["excluded_paths"]) == len(set(g["excluded_paths"])), "duplicate excluded paths")
    for path in g["excluded_paths"]:
        canonical_path(path)
        require(within(path, scope), "excluded path outside grant scope")
    require(isinstance(g["delegates_to"], list) and len(g["delegates_to"]) == len(set(g["delegates_to"])), "bad delegate list")
    require(all(isinstance(x, str) and x for x in g["delegates_to"]), "invalid delegate identity")
    require(type(g["delegation_depth_remaining"]) is int and 0 <= g["delegation_depth_remaining"] <= MAX_DEPTH,
            "bad delegation depth")
    require(not g["delegates_to"] or g["delegation_depth_remaining"] > 0, "no remaining delegation authority")
    require(isinstance(g["escalation_to"], str) and g["escalation_to"], "escalation target missing")
    require(g["undo_required"] is True, "undo must be required")
    require(g["delegates_from"] is None or isinstance(g["delegates_from"], str), "bad parent id")
    if g["delegates_from"] is not None:
        safe_id(g["delegates_from"])
    require(isinstance(g["signature"], str), "signature missing")
    start, end = when(g["granted_at"]), when(g["expires_at"])
    require(start < end, "grant expires before issuance")
    return start, end


def narrow(g, parent):
    require(g["action_class"] == parent["action_class"], "delegation changes action class")
    require(g["decider"] in parent["delegates_to"], "parent did not authorize this delegate")
    require(parent["delegation_depth_remaining"] > 0, "parent cannot delegate")
    require(g["delegation_depth_remaining"] < parent["delegation_depth_remaining"], "delegation depth widens")
    require(g["max_blast_radius"] <= parent["max_blast_radius"], "delegation widens blast radius")
    require(SEVERITY[g["requires_detection_severity"]] >= SEVERITY[parent["requires_detection_severity"]],
            "delegation lowers severity threshold")
    require(EVIDENCE[g["requires_evidence_tag"]] >= EVIDENCE[parent["requires_evidence_tag"]],
            "delegation lowers evidence threshold")
    require(within(g["target_scope"], parent["target_scope"]), "delegation widens target scope")
    require(not any(within(g["target_scope"], x) for x in parent["excluded_paths"]),
            "delegation enters excluded path")
    inherited = {x for x in parent["excluded_paths"] if within(x, g["target_scope"])}
    require(inherited.issubset(g["excluded_paths"]), "delegation removes excluded paths")
    require(when(g["expires_at"]) <= when(parent["expires_at"]), "delegation outlives parent")
    require(when(g["granted_at"]) >= when(parent["granted_at"]), "delegation predates parent")


def root_caps(g, authority):
    require(isinstance(authority, dict), "root decider has no explicit authority caps")
    require(g["action_class"] in authority.get("action_classes", []), "action not within root authority")
    require(type(authority.get("max_blast_radius")) is int and g["max_blast_radius"] <= authority["max_blast_radius"],
            "root blast radius exceeded")
    require(SEVERITY[g["requires_detection_severity"]] >= SEVERITY.get(authority.get("min_detection_severity"), 999),
            "root severity threshold exceeded")
    require(EVIDENCE[g["requires_evidence_tag"]] >= EVIDENCE.get(authority.get("min_evidence_tag"), 999),
            "root evidence threshold exceeded")
    scopes = authority.get("target_scopes", [])
    require(isinstance(scopes, list) and any(within(g["target_scope"], canonical_path(s)) for s in scopes),
            "grant exceeds root target scope")
    excluded = authority.get("excluded_paths", [])
    require(isinstance(excluded, list), "root exclusions invalid")
    for excluded_path in excluded:
        canonical_path(excluded_path)
    require(not any(within(g["target_scope"], x) for x in excluded),
            "grant targets an excluded root path")
    inherited = {x for x in excluded if within(x, g["target_scope"])}
    require(inherited.issubset(g["excluded_paths"]), "grant removes root exclusions")
    require(when(g["expires_at"]) <= when(authority.get("expires_at")), "grant outlives root authority")
    if g["delegates_to"]:
        require(authority.get("can_delegate") is True, "root may not delegate")
        require(type(authority.get("max_delegation_depth")) is int and
                g["delegation_depth_remaining"] <= authority["max_delegation_depth"],
                "root delegation depth exceeded")


def check_grant(g, trusted, at=None, visited=None, depth=0):
    """Validate signed capability and every ancestor; not sufficient to execute a response."""
    visited = visited or set()
    require(depth <= MAX_DEPTH, "delegation depth exceeded")
    validate_shape(g)
    gid = g["grant_id"]
    require(gid not in visited, "cyclic delegation")
    visited = visited | {gid}
    key = key_for(g["decider"], trusted)
    payload = {k: v for k, v in g.items() if k != "signature"}
    require(signature_valid(payload, g["signature"], key), "invalid grant signature")
    at = at or utc_now()
    require(when(g["granted_at"]) <= at < when(g["expires_at"]), "grant not active at verification time")
    revpath = directory() / (gid + ".revocation.json")
    if revpath.exists() or revpath.is_symlink():
        r = json_file(revpath)
        p = {k: v for k, v in r.items() if k != "signature"}
        require(r.get("grant_id") == gid and r.get("decider") == g["decider"] and
                r.get("grant_sha256") == digest(g) and
                signature_valid(p, r.get("signature", ""), key), "invalid signed revocation")
        raise GrantError("grant revoked")
    if g["delegates_from"]:
        parent = load_grant(g["delegates_from"])
        check_grant(parent, trusted, at=at, visited=visited, depth=depth+1)
        narrow(g, parent)
    else:
        root_caps(g, trusted[g["decider"]][0].get("authority"))
    return True


def verify_ledger(trusted):
    """Local hash chain + per-event Ed25519 signatures, not independently anchored."""
    path = directory() / "_audit.jsonl"
    if not path.exists():
        require(not list(directory().glob("*.grant.json")), "audit log missing for existing grants")
        return []
    raw = file_bytes(path, MAX_AUDIT_BYTES)
    require(raw.endswith(b"\n"), "truncated audit log")
    records = []
    prev = EMPTY_SHA
    for n, line in enumerate(raw.splitlines(), 1):
        try:
            row = json.loads(line)
        except ValueError as exc:
            raise GrantError("invalid audit record") from exc
        require(row.get("seq") == n and row.get("prev_hash") == prev,
                "broken audit chain")
        decider = row.get("decider", "")
        key = key_for(decider, trusted)
        data = {k: v for k, v in row.items() if k not in ("signature", "record_hash")}
        require(signature_valid(data, row.get("signature", ""), key), "invalid audit signature")
        require(row.get("record_hash") == digest({k: v for k, v in row.items() if k != "record_hash"}),
                "invalid audit hash")
        require(row.get("event") in ("issue", "revoke"), "unknown audit event")
        prev = row["record_hash"]
        records.append(row)
    return records


def audit_event(event, gid, signer, priv, trusted, grant_hash):
    """Append under single-writer lock. Verify old chain first."""
    root = directory()
    lockpath = root / "_audit.lock"
    fd = os.open(lockpath, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "rb+") as lk:
        fcntl.flock(lk.fileno(), fcntl.LOCK_EX)
        old = verify_ledger(trusted)
        require(not any(r["event"] == event and r["grant_id"] == gid for r in old),
                "duplicate audit event")
        p = {"seq":len(old)+1,"prev_hash":old[-1]["record_hash"] if old else EMPTY_SHA,
             "event":event,"grant_id":gid,"grant_sha256":grant_hash,"decider":signer,"at":iso(utc_now())}
        row = {**p, "signature":priv.sign(canonical(p)).hex()}
        row["record_hash"] = digest(row)
        path = root / "_audit.jsonl"
        flags = os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
        outf = os.open(path, flags, 0o600)
        with os.fdopen(outf, "ab") as fh:
            fh.write(canonical(row) + b"\n")
            fh.flush()
            os.fsync(fh.fileno())
        fcntl.flock(lk.fileno(), fcntl.LOCK_UN)
    return row


def verify_record(gid, trusted):
    g = load_grant(gid)
    check_grant(g, trusted)
    log = verify_ledger(trusted)
    require(any(r["event"] == "issue" and r["grant_id"] == gid and r["grant_sha256"] == digest(g)
                for r in log), "no matching signed issuance record")
    require(not any(r["event"] == "revoke" and r["grant_id"] == gid for r in log), "grant revoked in audit log")
    return g


def issue(args):
    trusted = signer_db()
    require(args.decider in trusted, "unknown decider")
    priv = private_key(args.key, args.decider, trusted)
    require(args.action_class in AUTO_CLASSES, "action is manual-only or lacks verified undo")
    require(type(args.blast_radius) is int and args.blast_radius > 0, "blast radius must be positive")
    require(math.isfinite(args.hours) and 0 < args.hours <= 24 * 30, "grant hours must be > 0 and <= 720")
    start = utc_now()
    end = start + timedelta(hours=args.hours)
    gid = safe_id(args.grant_id or "g-" + uuid.uuid4().hex[:20])
    exclusions = sorted(set(canonical_path(x) for x in (args.exclude or [])))
    g = {"schema":VERSION,"grant_id":gid,"decider":args.decider,"granted_at":iso(start),
         "expires_at":iso(end),"action_class":args.action_class,
         "max_blast_radius":args.blast_radius,"requires_evidence_tag":"VERIFIED",
         "requires_detection_severity":args.severity,"target_scope":canonical_path(args.target_scope),
         "excluded_paths":exclusions,"delegates_to":sorted(set(args.delegate_to or [])),
         "delegation_depth_remaining":args.delegation_depth,
         "escalation_to":args.escalate_to or args.decider,"undo_required":True,
         "delegates_from":args.delegates_from}
    g["signature"] = priv.sign(canonical(g)).hex()
    # Reject malformed or widening grants before writing anything.
    check_grant(g, trusted, at=start)
    verify_ledger(trusted)
    path = directory() / (gid + ".grant.json")
    require(not path.exists() and not path.is_symlink(), "grant ID already exists")
    # Log first: failed final file creation leaves an unusable, auditable orphan,
    # rather than silently writing an unlogged capability.
    audit_event("issue", gid, args.decider, priv, trusted, digest(g))
    write_once(path, canonical(g) + b"\n")
    print(f"ISSUED: {gid} (OFFLINE / no action authority without a future independently verified actuator gate)")
    return 0


def revoke(args):
    trusted = signer_db()
    g = verify_record(args.grant_id, trusted)
    require(args.decider == g["decider"], "only granting decider may revoke")
    priv = private_key(args.key, args.decider, trusted)
    p = {"grant_id":args.grant_id,"grant_sha256":digest(g),"decider":args.decider,"revoked_at":iso(utc_now())}
    r = {**p,"signature":priv.sign(canonical(p)).hex()}
    write_once(directory() / (args.grant_id + ".revocation.json"), canonical(r) + b"\n")
    audit_event("revoke", args.grant_id, args.decider, priv, trusted, digest(g))
    print(f"REVOKED: {args.grant_id}")
    return 0


def verify(args):
    trusted = signer_db()
    g = verify_record(args.grant_id, trusted)
    print(f"VALID: {g['grant_id']} ({g['action_class']}, expiry {g['expires_at']}); NO ACTUATOR AUTHORIZED")
    return 0


def list_grants(_args):
    trusted = signer_db()
    verify_ledger(trusted)
    for p in sorted(directory().glob("*.grant.json")):
        gid = p.name[:-len(".grant.json")]
        try:
            verify_record(gid, trusted)
            state = "VALID"
        except GrantError as exc:
            state = f"INVALID: {exc}"
        print(gid, state)
    return 0


def audit(_args):
    records = verify_ledger(signer_db())
    print(f"AUDIT CHAIN VERIFIED LOCALLY: {len(records)} events. Tail truncation needs an external anchor.")
    return 0


def build_parser():
    ap = argparse.ArgumentParser(prog="authority_grant.py", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    issue_cmd = sub.add_parser("issue")
    issue_cmd.add_argument("--decider", required=True)
    issue_cmd.add_argument("--key", required=True)
    issue_cmd.add_argument("--action-class", required=True, choices=sorted(AUTO_CLASSES | MANUAL_CLASSES))
    issue_cmd.add_argument("--target-scope", required=True)
    issue_cmd.add_argument("--blast-radius", type=int, default=1)
    issue_cmd.add_argument("--severity", choices=sorted(SEVERITY), default="High")
    issue_cmd.add_argument("--hours", type=float, default=24)
    issue_cmd.add_argument("--exclude", action="append")
    issue_cmd.add_argument("--delegate-to", action="append")
    issue_cmd.add_argument("--delegation-depth", type=int, default=0)
    issue_cmd.add_argument("--escalate-to")
    issue_cmd.add_argument("--delegates-from")
    issue_cmd.add_argument("--grant-id")
    revoke_cmd = sub.add_parser("revoke")
    revoke_cmd.add_argument("grant_id")
    revoke_cmd.add_argument("--decider", required=True)
    revoke_cmd.add_argument("--key", required=True)
    verify_cmd = sub.add_parser("verify")
    verify_cmd.add_argument("grant_id")
    sub.add_parser("list")
    sub.add_parser("audit")
    return ap


def main(argv=None):
    try:
        args = build_parser().parse_args(argv)
        return {"issue": issue, "revoke": revoke, "verify":verify, "list":list_grants, "audit":audit}[args.cmd](args)
    except (GrantError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"authority_grant: BLOCKED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
