#!/usr/bin/env python3
"""
Protect Me Gate — world posture, patch readiness, governance, and cross-world impact.

Two modes:
  worlds_gate.py worlds.json               -> posture of every world (no patch queue needed)
  worlds_gate.py worlds.json patches.json  -> per-patch READY / PENDING / BLOCKED

Pure Python stdlib. No network. NEVER merges, deploys, or runs tests.
It reads what you declare (worlds + patches + evidence) and tells you, per patch:
READY / PENDING / BLOCKED, why, what it breaks downstream, and the next gate.

Truth rule: a check marked "pass" with no evidence link is UNVERIFIED -> PENDING, never READY.
"""
import argparse
import fnmatch
import json
import os
import sys
from collections import defaultdict, deque

GOV_FILES = ["GOVERNANCE.md", "AGENTS.md", "CLAUDE.md", "CODEOWNERS", ".github/CODEOWNERS",
             "SECURITY.md", "CONTRIBUTING.md", "docs/GOVERNANCE.md"]


FAIL_STATUSES = {"fail", "failed", "failure", "error", "cancelled", "canceled", "timed_out"}
PASS_STATUSES = {"pass", "passed", "success", "succeeded"}
PLACEHOLDER_EVIDENCE = {"todo", "tbd", "n/a", "na", "none", "pending", "-", "?", "link", "url"}
LIST_FIELDS = ("required_checks", "requires_approval_from", "protected_paths", "protected_approvers",
               "public_surface", "forbidden_paths")


def norm_status(check):
    st = str((check or {}).get("status", "unknown")).strip().lower()
    return "fail" if st in FAIL_STATUSES else "pass" if st in PASS_STATUSES else st


def real_evidence(ev):
    """Evidence counts only if it is a non-placeholder string (a URL, artifact path, run id...)."""
    if not isinstance(ev, str):
        return None
    e = ev.strip()
    if not e or e.lower() in PLACEHOLDER_EVIDENCE or (e.startswith("[") and e.endswith("]")):
        return None
    return e


def _is_str_list(v):
    return isinstance(v, list) and all(isinstance(x, str) for x in v)


def validate(worlds, patches):
    """Reject shapes that would otherwise be silently misread (strings iterated as lists, nulls, ...)."""
    errs = []
    for i, w in enumerate(worlds):
        wid = w.get("id", f"#{i}")
        if "depends_on" in w and not _is_str_list(w["depends_on"]):
            errs.append(f"world '{wid}': depends_on must be a list of world ids")
        for key in ("governance", "state"):
            if key in w and not isinstance(w[key], dict):
                errs.append(f"world '{wid}': {key} must be an object")
        gov = w.get("governance") if isinstance(w.get("governance"), dict) else {}
        for f in LIST_FIELDS:
            if f in gov and not _is_str_list(gov[f]):
                errs.append(f"world '{wid}': governance.{f} must be a list of strings")
        st = w.get("state") if isinstance(w.get("state"), dict) else {}
        checks = st.get("checks", {})
        if not isinstance(checks, dict) or not all(isinstance(c, dict) for c in checks.values()):
            errs.append(f"world '{wid}': state.checks must map check name -> {{status, evidence}}")
    for i, p in enumerate(patches):
        pid = p.get("id", f"#{i}")
        for f in ("files", "approvals"):
            if f in p and not _is_str_list(p[f]):
                errs.append(f"patch '{pid}': {f} must be a list of strings")
        checks = p.get("checks", {})
        if not isinstance(checks, dict) or not all(isinstance(c, dict) for c in checks.values()):
            errs.append(f"patch '{pid}': checks must map check name -> {{status, evidence}}")
    if errs:
        raise ValueError("invalid input:\n  - " + "\n  - ".join(errs))


def build_graph(worlds):
    ids = {w["id"] for w in worlds}
    problems = []
    deps = {}
    for w in worlds:
        ds = w.get("depends_on", [])
        for d in ds:
            if d not in ids:
                problems.append(f"world '{w['id']}' depends on unknown world '{d}'")
        deps[w["id"]] = [d for d in ds if d in ids]
    rdeps = defaultdict(list)
    for w, ds in deps.items():
        for d in ds:
            rdeps[d].append(w)
    return deps, rdeps, problems


def cycle_members(deps):
    """Return only nodes that are actually members of dependency cycles."""
    index = 0
    stack, on_stack = [], set()
    indices, lowlink, members = {}, {}, set()

    def visit(v):
        nonlocal index
        indices[v] = lowlink[v] = index
        index += 1
        stack.append(v)
        on_stack.add(v)
        for w in deps.get(v, []):
            if w not in indices:
                visit(w)
                lowlink[v] = min(lowlink[v], lowlink[w])
            elif w in on_stack:
                lowlink[v] = min(lowlink[v], indices[w])
        if lowlink[v] == indices[v]:
            component = []
            while True:
                w = stack.pop()
                on_stack.remove(w)
                component.append(w)
                if w == v:
                    break
            if len(component) > 1 or (len(component) == 1 and v in deps.get(v, [])):
                members.update(component)

    for v in sorted(deps):
        if v not in indices:
            visit(v)
    return sorted(members)


def topo_order(deps):
    indeg = {w: len(ds) for w, ds in deps.items()}
    rd = defaultdict(list)
    for w, ds in deps.items():
        for d in ds:
            rd[d].append(w)
    q = deque(sorted(w for w, n in indeg.items() if n == 0))
    order = []
    while q:
        n = q.popleft()
        order.append(n)
        for m in sorted(rd[n]):
            indeg[m] -= 1
            if indeg[m] == 0:
                q.append(m)
    return order, cycle_members(deps)


def walk(start, edges):
    seen, q = [], deque([start])
    while q:
        n = q.popleft()
        for m in sorted(edges.get(n, [])):
            if m not in seen and m != start:
                seen.append(m)
                q.append(m)
    return seen


def touches(files, patterns):
    return sorted({f for f in files for p in patterns if fnmatch.fnmatch(f, p)})


def upstream_failing_checks(world):
    """Required checks that are recorded as failing on a world's own baseline."""
    gov, checks = world.get("governance", {}), world.get("state", {}).get("checks", {})
    return [n for n in gov.get("required_checks", []) if norm_status(checks.get(n)) == "fail"]


def eval_patch(p, W, deps, rdeps, cyclic, upstream_status):
    wid = p.get("world")
    blocked, pending, risks, proof = [], [], [], []
    if wid not in W:
        return dict(patch=p, world=None, status="BLOCKED",
                    blocked=[f"target world '{wid}' not declared in worlds file"],
                    pending=[], risks=[], proof=[], downstream=[], upstream=[], impact="UNKNOWN")
    w = W[wid]
    gov = w.get("governance", {})
    state = w.get("state", {})
    files = p.get("files", [])

    if gov.get("frozen"):
        blocked.append(f"world frozen ({gov.get('freeze_reason', 'no reason given')})")
    if wid in cyclic:
        blocked.append("world is in a dependency cycle — order cannot be proven")
    hit_forbidden = touches(files, gov.get("forbidden_paths", []))
    if hit_forbidden:
        blocked.append(f"touches forbidden paths: {', '.join(hit_forbidden)}")

    checks = {**state.get("checks", {}), **p.get("checks", {})}
    if not gov.get("required_checks"):
        pending.append("world declares no required_checks — readiness is UNKNOWN, not READY")
    if not gov.get("requires_approval_from"):
        pending.append("world declares no requires_approval_from — nobody is named to approve")
    for name in gov.get("required_checks", []):
        c = checks.get(name)
        if c is None:
            pending.append(f"check '{name}' not run")
            continue
        st, ev = norm_status(c), real_evidence(c.get("evidence"))
        if st == "fail":
            blocked.append(f"check '{name}' FAILING" + (f" ({ev})" if ev else ""))
        elif st == "pass" and ev:
            proof.append(f"VERIFIED {name}: {ev}")
        elif st == "pass":
            pending.append(f"check '{name}' says pass but has no real evidence — UNVERIFIED")
        else:
            pending.append(f"check '{name}' status '{st}'")

    approvals = set(p.get("approvals", []))
    need = set(gov.get("requires_approval_from", []))
    hit_protected = touches(files, gov.get("protected_paths", []))
    if hit_protected:
        need |= set(gov.get("protected_approvers", gov.get("requires_approval_from", [])) or ["owner"])
    missing = sorted(need - approvals)
    if missing:
        why = f" (protected paths: {', '.join(hit_protected)})" if hit_protected else ""
        pending.append(f"approval missing from: {', '.join(missing)}{why}")

    upstream = walk(wid, deps)
    cyclic_upstream = sorted(set(upstream) & set(cyclic))
    if cyclic_upstream:
        blocked.append(f"upstream dependency cycle involves: {', '.join(cyclic_upstream)} — order cannot be proven")
    for u in upstream:
        st = upstream_status.get(u)
        if st == "BLOCKED":
            pending.append(f"upstream world '{u}' has a BLOCKED patch — fix upstream first")
        elif st == "PENDING":
            pending.append(f"upstream world '{u}' has a PENDING patch — land upstream first")
        failing = upstream_failing_checks(W[u])
        if failing:
            pending.append(f"upstream world '{u}' is failing {', '.join(failing)} — never build on bad state")

    down = walk(wid, rdeps)
    public = touches(files, gov.get("public_surface", []))
    if not down:
        impact = "NONE"
    elif public:
        impact = "HIGH"
        risks.append(f"changes public surface ({', '.join(public)}) consumed by: {', '.join(down)}")
    elif not gov.get("public_surface"):
        impact = "UNKNOWN"
        risks.append(f"world declares no public_surface — cannot tell if dependents {', '.join(down)} are affected; treat as HIGH")
    else:
        impact = "LOW"
    for d in down:
        dg = W[d].get("governance", {})
        if dg.get("frozen"):
            risks.append(f"downstream '{d}' is frozen — it cannot absorb a breaking change right now")
    if not files:
        risks.append("patch lists no files — impact and protected-path checks are blind")

    status = "BLOCKED" if blocked else ("PENDING" if pending else "READY")
    return dict(patch=p, world=w, status=status, blocked=blocked, pending=pending,
                risks=risks, proof=proof, downstream=down, upstream=upstream, impact=impact)


def evaluate(worlds, patches):
    validate(worlds, patches)
    ids = [w.get("id") for w in worlds]
    missing_ids = [i for i, wid in enumerate(ids) if not isinstance(wid, str) or not wid.strip()]
    if missing_ids:
        raise ValueError(f"world entries missing a non-empty string id at indexes: {missing_ids}")
    duplicates = sorted({wid for wid in ids if ids.count(wid) > 1})
    if duplicates:
        raise ValueError(f"duplicate world id(s): {', '.join(duplicates)}")
    W = {w["id"]: w for w in worlds}
    deps, rdeps, problems = build_graph(worlds)
    order, cyclic = topo_order(deps)
    rank = {w: i for i, w in enumerate(order)}
    queue = sorted(patches, key=lambda p: rank.get(p.get("world"), 10**6))
    world_status, results = {}, []
    sev = {"BLOCKED": 2, "PENDING": 1, "READY": 0}
    for p in queue:
        r = eval_patch(p, W, deps, rdeps, cyclic, world_status)
        results.append(r)
        wid = p.get("world")
        prev = world_status.get(wid)
        if prev is None or sev[r["status"]] > sev[prev]:
            world_status[wid] = r["status"]
    return dict(W=W, deps=deps, rdeps=rdeps, problems=problems, order=order,
                cyclic=cyclic, results=results, world_status=world_status)


def next_gate(r):
    if r["blocked"]:
        return f"Clear hard stop: {r['blocked'][0]}"
    if r["pending"]:
        return f"Resolve: {r['pending'][0]}"
    pol = (r["world"] or {}).get("governance", {}).get("merge_policy", "human-approval")
    down = r["downstream"]
    tail = f" Then re-run required checks in: {', '.join(down)}." if down else ""
    return f"Merge per policy '{pol}' (a human decides — this tool never merges).{tail}"


def render_md(E, title="Worlds Patch Report"):
    out = [f"# {title}", ""]
    res = E["results"]
    counts = {s: sum(1 for r in res if r["status"] == s) for s in ("READY", "PENDING", "BLOCKED")}
    out.append(f"**Patches:** {len(res)} · READY {counts['READY']} · PENDING {counts['PENDING']} · BLOCKED {counts['BLOCKED']}")
    out.append(f"**Safe execution order (upstream → downstream):** {' → '.join(E['order']) or '—'}")
    if E["cyclic"]:
        out.append(f"**⚠ Dependency cycle:** {', '.join(E['cyclic'])} — order unprovable until broken.")
    for pr in E["problems"]:
        out.append(f"**⚠ Map problem:** {pr}")
    out += ["", "| Patch | World | Status | Impact | Downstream |", "|---|---|---|---|---|"]
    for r in res:
        p = r["patch"]
        out.append(f"| {p.get('id','?')} | {p.get('world')} | {r['status']} | {r['impact']} | {', '.join(r['downstream']) or '—'} |")
    untouched = [w for w in E["order"] if w not in E["world_status"]]
    if untouched:
        out.append(f"\n_Worlds with no queued patch:_ {', '.join(untouched)}")
    out.append("")
    for r in res:
        p = r["patch"]
        w = r["world"] or {}
        gov = w.get("governance", {})
        out.append(f"## {p.get('id','?')} → {p.get('world')} — {r['status']}")
        out.append(f"- **REALITY:** commit `{p.get('commit','?')}` on `{p.get('branch', w.get('branch','?'))}` in {w.get('repo','?')}. Owner: {gov.get('owner','undeclared')}. Depends on: {', '.join(r['upstream']) or 'nothing'}.")
        out.append(f"- **FIX:** {p.get('summary','(no summary)')} — files: {', '.join(p.get('files', [])) or 'none listed'}")
        proof = r["proof"] or ["none — nothing here is VERIFIED yet"]
        out.append("- **PROOF:** " + "; ".join(proof))
        if r["blocked"]:
            out.append("- **BLOCKED BY:** " + "; ".join(r["blocked"]))
        if r["pending"]:
            out.append("- **PENDING ON:** " + "; ".join(r["pending"]))
        out.append("- **RISK:** " + ("; ".join(r["risks"]) if r["risks"] else f"impact {r['impact']}"))
        out.append(f"- **ROLLBACK:** {p.get('rollback') or ('git revert ' + str(p.get('commit','<sha>')))}" + (f" — then re-verify {', '.join(r['downstream'])}" if r["downstream"] else ""))
        out.append(f"- **NEXT GATE:** {next_gate(r)}")
        out.append("")
    return "\n".join(out)


def to_json(E):
    def clean(r):
        return {k: v for k, v in r.items() if k != "world"} | {"next_gate": next_gate(r)}
    return json.dumps(dict(order=E["order"], cyclic=E["cyclic"], problems=E["problems"],
                           world_status=E["world_status"], results=[clean(r) for r in E["results"]]), indent=2)


SEV = {"HEALTHY": 0, "UNVERIFIED": 1, "UNKNOWN": 1, "AT_RISK": 2, "BLOCKED": 3, "FROZEN": 3}


def world_posture(E):
    """Posture of each world from worlds.json alone. Missing fields become UNKNOWN, never guesses."""
    W, deps, rdeps, cyclic = E["W"], E["deps"], E["rdeps"], set(E["cyclic"])
    out = {}
    for wid in E["order"] + sorted(c for c in cyclic if c not in E["order"]):
        w = W[wid]
        gov = w.get("governance", {})
        checks = w.get("state", {}).get("checks", {})
        blocked, unverified, unknown, proof = [], [], [], []
        if wid in cyclic:
            blocked.append("in a dependency cycle — order cannot be proven")
        required = gov.get("required_checks")
        if not required:
            unknown.append("required_checks not declared — nothing defines 'healthy'")
        for name in required or []:
            c = checks.get(name)
            if c is None:
                unverified.append(f"check '{name}' has no recorded result")
                continue
            st, ev = norm_status(c), real_evidence(c.get("evidence"))
            if st == "fail":
                blocked.append(f"check '{name}' FAILING" + (f" ({ev})" if ev else ""))
            elif st == "pass" and ev:
                proof.append(f"VERIFIED {name}: {ev}")
            elif st == "pass":
                unverified.append(f"check '{name}' says pass but has no real evidence")
            else:
                unverified.append(f"check '{name}' status '{st}'")
        for field in ("owner", "merge_policy", "requires_approval_from"):
            if not gov.get(field):
                unknown.append(f"governance.{field} not declared")
        if rdeps.get(wid) and "public_surface" not in gov:
            unknown.append(f"public_surface not declared but {', '.join(sorted(rdeps[wid]))} depend on it")
        if not w.get("repo"):
            unknown.append("repo not declared")
        ghost = [d for d in w.get("depends_on", []) if d not in W]
        if ghost:
            unknown.append(f"depends on undeclared world(s): {', '.join(ghost)} — upstream health cannot be checked")
        if gov.get("frozen"):
            status = "FROZEN"
        elif blocked:
            status = "BLOCKED"
        elif unverified:
            status = "UNVERIFIED"
        elif not required:
            status = "UNKNOWN"
        else:
            status = "HEALTHY"
        out[wid] = dict(world=wid, status=status, blocked=blocked, unverified=unverified,
                        unknown=unknown, proof=proof, upstream=walk(wid, deps),
                        downstream=walk(wid, rdeps), frozen_reason=gov.get("freeze_reason"),
                        merge_policy=gov.get("merge_policy"), owner=gov.get("owner"))
    for wid, r in out.items():
        bad = [u for u in r["upstream"] if out.get(u, {}).get("status") in ("BLOCKED", "UNVERIFIED", "UNKNOWN", "AT_RISK")]
        bad += [d for d in W[wid].get("depends_on", []) if d not in W]
        r["upstream_risk"] = bad
        if bad and r["status"] in ("HEALTHY", "UNVERIFIED", "UNKNOWN"):
            r["status"] = "AT_RISK"
    for wid, r in out.items():
        r["next_gate"] = posture_gate(r)
    return out


def posture_gate(r):
    if r["status"] == "FROZEN":
        return f"Frozen ({r['frozen_reason'] or 'no reason given'}) — no merges until the owner lifts the freeze."
    if r["blocked"]:
        return f"Fix: {r['blocked'][0]}"
    if r["upstream_risk"]:
        return f"Fix upstream first: {', '.join(r['upstream_risk'])} — never build on bad state."
    if r["unverified"]:
        return f"Prove: {r['unverified'][0]} — attach an evidence link."
    if r["status"] == "UNKNOWN":
        return "Declare governance.required_checks so health can be measured."
    pol = r["merge_policy"] or "undeclared merge policy"
    return f"Healthy. Merges follow '{pol}' (a human decides — this tool never merges)."


def render_posture_md(E, P, title="World Posture Report"):
    out = [f"# {title}", ""]
    counts = {}
    for r in P.values():
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    out.append("**Worlds:** " + str(len(P)) + " · " + " · ".join(f"{k} {v}" for k, v in sorted(counts.items(), key=lambda kv: -SEV[kv[0]])))
    out.append(f"**Safe order (upstream → downstream):** {' → '.join(E['order']) or '—'}")
    if E["cyclic"]:
        out.append(f"**⚠ Dependency cycle:** {', '.join(E['cyclic'])} — order unprovable until broken.")
    for pr in E["problems"]:
        out.append(f"**⚠ Map problem:** {pr}")
    out += ["", "| World | Status | Owner | Merge policy | Depends on | Feeds |", "|---|---|---|---|---|---|"]
    for r in P.values():
        out.append(f"| {r['world']} | {r['status']} | {r['owner'] or 'UNKNOWN'} | {r['merge_policy'] or 'UNKNOWN'} | {', '.join(r['upstream']) or '—'} | {', '.join(r['downstream']) or '—'} |")
    out.append("")
    for r in P.values():
        w = E["W"][r["world"]]
        out.append(f"## {r['world']} — {r['status']}")
        out.append(f"- **REALITY:** {w.get('repo', 'repo UNKNOWN')} @ `{w.get('branch', 'branch UNKNOWN')}`. Owner: {r['owner'] or 'UNKNOWN'}.")
        out.append("- **PROOF:** " + ("; ".join(r["proof"]) or "none — nothing here is VERIFIED yet"))
        if r["blocked"]:
            out.append("- **BLOCKED BY:** " + "; ".join(r["blocked"]))
        if r["unverified"]:
            out.append("- **UNVERIFIED:** " + "; ".join(r["unverified"]))
        if r["upstream_risk"]:
            out.append("- **UPSTREAM RISK:** " + ", ".join(r["upstream_risk"]))
        if r["unknown"]:
            out.append("- **UNKNOWN:** " + "; ".join(r["unknown"]))
        out.append(f"- **NEXT GATE:** {r['next_gate']}")
        out.append("")
    return "\n".join(out)


def scan_docs(worlds):
    out = ["# Governance docs found", ""]
    for w in worlds:
        lp = w.get("local_path")
        if not lp:
            out.append(f"- {w['id']}: no local_path declared — UNKNOWN (open the repo and look for {', '.join(GOV_FILES[:4])})")
            continue
        if not os.path.isdir(lp):
            out.append(f"- {w['id']}: local_path '{lp}' not found — BLOCKED")
            continue
        found = [g for g in GOV_FILES if os.path.exists(os.path.join(lp, g))]
        out.append(f"- {w['id']}: {', '.join(found) if found else 'none — governance is only what worlds.json declares'}")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("worlds")
    ap.add_argument("patches", nargs="?")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--ready", action="store_true", help="only READY patches")
    ap.add_argument("--depends-on", metavar="WORLD", help="only patches in worlds that (transitively) depend on WORLD, plus WORLD")
    ap.add_argument("--impact", metavar="WORLD", help="show what a change in WORLD reaches")
    ap.add_argument("--scan-docs", action="store_true")
    a = ap.parse_args()

    try:
        with open(a.worlds, encoding="utf-8") as f:
            wdoc = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        ap.error(f"cannot read worlds file: {e}")
    worlds = wdoc.get("worlds") if isinstance(wdoc, dict) else wdoc
    if not isinstance(worlds, list) or not all(isinstance(w, dict) for w in worlds):
        ap.error("worlds must be a JSON array of objects (or an object with a 'worlds' array)")
    if a.scan_docs:
        print(scan_docs(worlds))
        return
    patches = []
    if a.patches:
        try:
            with open(a.patches, encoding="utf-8") as f:
                pdoc = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            ap.error(f"cannot read patches file: {e}")
        patches = pdoc.get("patches") if isinstance(pdoc, dict) else pdoc

    if not isinstance(worlds, list) or not all(isinstance(w, dict) for w in worlds):
        ap.error("worlds must be a JSON array of objects (or an object with a 'worlds' array)")
    if not isinstance(patches, list) or not all(isinstance(p, dict) for p in patches):
        ap.error("patches must be a JSON array of objects (or an object with a 'patches' array)")
    try:
        E = evaluate(worlds, patches)
    except (KeyError, TypeError, ValueError) as e:
        ap.error(str(e))

    if a.impact:
        if a.impact not in E["W"]:
            sys.exit(f"unknown world '{a.impact}'")
        down = walk(a.impact, E["rdeps"])
        gov = E["W"][a.impact].get("governance", {})
        print(f"# Impact of changing '{a.impact}'\n")
        print(f"- Reaches: {', '.join(down) or 'nothing — leaf world'}")
        print(f"- Public surface (changes here hit dependents): {', '.join(gov.get('public_surface', [])) or 'UNDECLARED — assume everything'}")
        for d in down:
            dg = E["W"][d].get("governance", {})
            print(f"- After patching, re-verify '{d}': {', '.join(dg.get('required_checks', [])) or 'no checks declared — add one'}" + (" ⚠ FROZEN" if dg.get("frozen") else ""))
        return

    title = "Worlds Patch Report"
    if a.depends_on:
        if a.depends_on not in E["W"]:
            sys.exit(f"unknown world '{a.depends_on}'")
        scope = set(walk(a.depends_on, E["rdeps"])) | {a.depends_on}
        E["results"] = [r for r in E["results"] if r["patch"].get("world") in scope]
        title += f" — worlds depending on {a.depends_on}"
    if a.ready:
        E["results"] = [r for r in E["results"] if r["status"] == "READY"]
        title += " — READY now"

    if not a.patches:
        P = world_posture(E)
        if a.depends_on:
            P = {k: v for k, v in P.items() if k in scope}
        print(json.dumps(dict(order=E["order"], cyclic=E["cyclic"], problems=E["problems"],
                              worlds=list(P.values())), indent=2) if a.json else render_posture_md(E, P))
        return
    print(to_json(E) if a.json else render_md(E, title))


if __name__ == "__main__":
    main()
