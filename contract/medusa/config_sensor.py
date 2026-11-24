#!/usr/bin/env python3
"""Medusa Layer 5: opt-in, offline config integrity sensor.

Only explicitly named local regular files are inspected. The signed evidence
bus stores hashes and a pseudonymous path ID, never the file contents or path.
No network, automatic remediation, trust enrollment, or background service.
"""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import eventbus as BUS

MAX_CONFIG_BYTES = 8 * 1024 * 1024


def fingerprint(filename):
    """Hash a regular file via a no-follow descriptor, rejecting replacement races."""
    path = Path(filename)
    if not path.is_absolute() or str(path) in ("", "/"):
        raise BUS.BusError("config path must be an explicit absolute file path")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise BUS.BusError("config path could not be opened safely") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_CONFIG_BYTES or before.st_nlink != 1:
            raise BUS.BusError("config file type, size, or hardlink unsafe")
        h = hashlib.sha256()
        n = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            n += len(chunk)
            if n > MAX_CONFIG_BYTES:
                raise BUS.BusError("config file exceeds byte cap")
            h.update(chunk)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            raise BUS.BusError("config changed while reading")
        current = path.lstat()
        if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
            raise BUS.BusError("config path changed while reading")
        return h.hexdigest()
    except FileNotFoundError as exc:
        raise BUS.BusError("config path replaced while reading") from exc
    finally:
        os.close(fd)


def scan_once(paths, *, key, sensor_id="config-1"):
    """Compare to authenticated prior config state and emit signed deltas.

    First observation is baseline, NOT a finding. The baseline is derived only
    from signed bus events from this same sensor. No silent ledger repair.
    """
    if not isinstance(paths, list) or not paths or len(paths) > 64:
        raise BUS.BusError("explicit config paths required (1..64)")
    if len(paths) != len(set(paths)):
        raise BUS.BusError("duplicate config path")
    snapshot = BUS.verified_snapshot()
    previous = {}
    for record in snapshot["records"]:
        ev = record["event"]
        if ev["sensor_id"] == sensor_id and ev["event_type"] == "config_change":
            payload = record["payload"]
            if isinstance(payload.get("path_id"), str):
                previous[payload["path_id"]] = payload.get("content_sha256")
    # Validate and fingerprint the entire requested set before any ledger write;
    # an unsafe second path must not leave a partial first-path baseline.
    pending = []
    for filename in paths:
        if not isinstance(filename, str) or not os.path.isabs(filename):
            raise BUS.BusError("config path must be absolute")
        if os.path.normpath(filename) != filename:
            raise BUS.BusError("config path must be normalized")
        path_id = hashlib.sha256(os.fsencode(filename)).hexdigest()
        digest = fingerprint(filename)
        if path_id in previous and previous[path_id] == digest:
            continue
        action = ("baseline" if path_id not in previous else
                  "missing" if digest is None else
                  "restored" if previous[path_id] is None else "modified")
        pending.append((path_id, digest, action))
    if not pending:
        return []
    # The preflight above remains complete before any ledger write. Each
    # config delta retains its own signed event ID and ordered sequence.
    events = [{"event_type": "config_change",
               "payload": {"path_id": path_id, "content_sha256": digest, "action": action}}
              for path_id, digest, action in pending]
    ids = BUS.append_source_batch(sensor_id, events, key)
    return [{"event_id": event_id, "action": action, "path_id": path_id}
            for event_id, (path_id, digest, action) in zip(ids, pending)]
