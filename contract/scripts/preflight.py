#!/usr/bin/env python3
"""Protect Me preflight — ULTRATHINK / DEVIL decision gate.

Validates the decision frame an agent must fill in BEFORE material work
(see contract/modes/ultrathink-devil.md). Core invariant: more intelligence
never means more authority — a reasoning mode can deepen analysis but can
never raise permissions, so consequential or irreversible work needs a
VERIFIED authority holder no matter how much reasoning was spent.

Usage:
  preflight.py <preflight.json> [--compact]

Exit: 0 PROCEED · 1 NARROW (premise failed / too many options — rescope) · 2 BLOCKED
Stdlib only.
"""
import argparse
import json
import sys

TRUTH_STATES = ("VERIFIED", "INFERRED", "UNKNOWN", "BLOCKED", "STALE")
CONSEQUENCE = ("informational", "reversible", "consequential", "irreversible")
BUDGET_CLASSES = ("direct", "investigation", "repair", "release")
PREFLIGHT_FIELDS = (
    "authoritative_source", "target", "goal", "consequence_class", "authority",
    "bottleneck", "first_evidence", "budget", "stop_condition",
)
OPTION_FIELDS = (
    "founder_value", "evidence", "consequence", "authority_required",
    "reversibility", "cost", "failure_mode", "proof_required",
)
MAX_OPTIONS = 3


def _filled(v):
    """A field is filled if it has a value; the literal 'UNKNOWN' is an honest value."""
    if isinstance(v, str):
        return bool(v.strip())
    return v is not None and v != [] and v != {}


def check(doc):
    blocked, narrow, notes = [], [], []
    if not isinstance(doc, dict):
        return dict(verdict="BLOCKED", blocked=["preflight must be a JSON object"], narrow=[], notes=[])

    for f in PREFLIGHT_FIELDS:
        if not _filled(doc.get(f)):
            blocked.append(f"preflight field '{f}' missing — write a value or UNKNOWN, never leave it blank")

    cc = doc.get("consequence_class")
    if cc is not None and cc not in CONSEQUENCE:
        blocked.append(f"consequence_class '{cc}' not one of {', '.join(CONSEQUENCE)}")

    auth = doc.get("authority") if isinstance(doc.get("authority"), dict) else {}
    a_state = str(auth.get("state", "UNKNOWN")).upper()
    if a_state not in TRUTH_STATES:
        blocked.append(f"authority.state '{auth.get('state')}' not one of {', '.join(TRUTH_STATES)}")
    if cc in ("consequential", "irreversible"):
        if a_state != "VERIFIED":
            blocked.append(f"{cc} work needs VERIFIED authority (have {a_state}) — more reasoning never means more authority")
        if not _filled(auth.get("holder")) or not _filled(auth.get("action")):
            blocked.append(f"{cc} work needs authority.holder and authority.action named")
    if cc == "irreversible" and not _filled(doc.get("rollback")):
        notes.append("irreversible: no rollback exists by definition — owner must accept that explicitly")

    planes = doc.get("planes") if isinstance(doc.get("planes"), dict) else {}
    if planes.get("requested_authority_change") is True:
        blocked.append("a reasoning mode requested an authority change — modes compose across planes but never promote themselves")

    budget = doc.get("budget") if isinstance(doc.get("budget"), dict) else None
    if doc.get("budget") is not None and budget is None:
        blocked.append("budget must be an object {class, max_rounds, require_evidence, stop_when}")
    if budget:
        if budget.get("class") not in BUDGET_CLASSES:
            blocked.append(f"budget.class '{budget.get('class')}' not one of {', '.join(BUDGET_CLASSES)}")
        mr = budget.get("max_rounds")
        if not (isinstance(mr, int) and not isinstance(mr, bool) and mr > 0):
            blocked.append("budget.max_rounds must be a positive integer — budget loops and uncertainty, not evidence")
        if not isinstance(budget.get("stop_when"), list) or not budget.get("stop_when"):
            blocked.append("budget.stop_when must list at least one stop condition")
        if budget.get("class") in ("repair", "release") and budget.get("require_evidence") is not True:
            blocked.append(f"budget.class '{budget.get('class')}' requires require_evidence: true")

    options = doc.get("options") or []
    if not isinstance(options, list):
        blocked.append("options must be a list")
        options = []
    if len(options) > MAX_OPTIONS and doc.get("breadth_requested") is not True:
        narrow.append(f"{len(options)} options — keep ≤{MAX_OPTIONS} serious ones unless the owner asked for breadth")
    names = []
    for i, o in enumerate(options):
        if not isinstance(o, dict):
            blocked.append(f"option {i} is not an object")
            continue
        names.append(o.get("name"))
        missing = [f for f in OPTION_FIELDS if not _filled(o.get(f))]
        if missing:
            blocked.append(f"option '{o.get('name', i)}' missing: {', '.join(missing)}")
    sel = doc.get("selected")
    if options and sel not in names:
        blocked.append(f"selected option '{sel}' is not one of the listed options")

    d1 = doc.get("devil_i") if isinstance(doc.get("devil_i"), dict) else None
    if cc != "informational":
        if not d1:
            blocked.append("devil_i (premise attack) missing")
        else:
            if not _filled(d1.get("falsifier")):
                blocked.append("devil_i.falsifier missing — name the evidence that would kill the premise")
            if d1.get("premise_holds") is False:
                narrow.append("premise attack failed — narrow, test, defer, or reject the plan")
            elif d1.get("premise_holds") is not True:
                blocked.append("devil_i.premise_holds must be true or false")
        d2 = doc.get("devil_ii") if isinstance(doc.get("devil_ii"), dict) else None
        if not d2 or not _filled(d2.get("breaking_assumption")):
            blocked.append("devil_ii (attack on the selected path) missing a breaking_assumption — attack before mutating")
        elif not _filled(d2.get("stale_state_risk")):
            blocked.append("devil_ii.stale_state_risk missing — say how stale state could look current")

    verdict = "BLOCKED" if blocked else ("NARROW" if narrow else "PROCEED")
    return dict(verdict=verdict, blocked=blocked, narrow=narrow, notes=notes,
                consequence_class=cc, authority_state=a_state)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("preflight")
    ap.add_argument("--compact", action="store_true")
    a = ap.parse_args(argv)
    try:
        with open(a.preflight, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(json.dumps(dict(verdict="BLOCKED", blocked=[f"cannot read preflight: {e}"])))
        return 2
    r = check(doc)
    if a.compact:
        first = (r["blocked"] or r["narrow"] or ["all gates satisfied"])[0]
        print(f"PREFLIGHT: {r['verdict']} · {r['consequence_class']} · authority {r['authority_state']} · {first}")
    else:
        print(json.dumps(r, indent=2))
    return {"PROCEED": 0, "NARROW": 1, "BLOCKED": 2}[r["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
