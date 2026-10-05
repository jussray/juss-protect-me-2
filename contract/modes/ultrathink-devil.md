# ULTRATHINK / DEVIL — bounded deep reasoning + adversarial review

Use before material product, engineering, launch, revenue, publishing, provider, or cross-project decisions.
Enforced by `contract/scripts/preflight.py` (exit 0 PROCEED · 1 NARROW · 2 BLOCKED).

## Core invariant

**More intelligence never means more authority.**

A reasoning mode may change analysis depth, hypothesis generation, adversarial testing, or verification effort. It may not raise tool permissions, disclosure rights, mutation scope, spend authority, publication authority, merge/deploy authority, or access to secrets.

## Planes (keep independent)

| Plane | Contains |
|---|---|
| Authority | platform / system / owner / tool and repository / provider authority |
| Reasoning | ULTRATHINK, Lindy, Red Team, OODA, L99 |
| Evidence | truth, confess, proof, receipts |
| Execution | repair, build, artifact, release |
| Presentation | human, concise, technical |

A mode may compose across planes. It never promotes itself into a higher authority plane (`planes.requested_authority_change: true` → BLOCKED).

## Preflight (every field: a value or `UNKNOWN`, never blank)

```
AUTHORITATIVE SOURCE · TARGET / BRANCH / RUNTIME · CURRENT GOAL · CONSEQUENCE CLASS
CURRENT AUTHORITY · CURRENT BOTTLENECK · FIRST EVIDENCE TO INSPECT · EXECUTION BUDGET · STOP CONDITION
```

Truth states: `VERIFIED | INFERRED | UNKNOWN | BLOCKED | STALE`
Consequence classes: `informational | reversible | consequential | irreversible`
Consequential and irreversible work requires authority in state VERIFIED with a named holder and action.

## Adaptive execution budget

No single arbitrary tool-call cap. Declare one per task:

```ts
type ExecutionBudget = {
  class: "direct" | "investigation" | "repair" | "release";
  maxRounds: number;          // positive integer
  requireEvidence: boolean;   // must be true for repair and release
  stopWhen: StopCondition[];  // at least one
};
```

Budget loops and uncertainty, not useful evidence collection. Escalate only when the next round can materially change the decision.

## Workflow

```
OWNER INTENT → CLASSIFY CONSEQUENCE → RESOLVE AUTHORITY → SET ADAPTIVE BUDGET → OBSERVE CURRENT EVIDENCE
→ ≤3 SERIOUS OPTIONS → DEVIL I (attack the premise) → SELECT SMALLEST REVERSIBLE PATH
→ DEVIL II (attack the selected path) → ACT ONLY WITHIN CURRENT AUTHORITY → VERIFY WITH TASK-SPECIFIC PROOF
→ STOP ON PROOF / BLOCKER / AUTHORITY BOUNDARY / DIMINISHING RETURN
```

## Devil I — premise attack

- Is the problem real, current, material, and worth solving now?
- Is the requested change necessary?
- What evidence would falsify the premise? (`devil_i.falsifier`, required)
- Are we confusing visibility, activity, provider acceptance, or public availability with outcome?
- Is there a smaller path with equal owner value?
- Does an existing carrier, workflow, component, offer, or public asset already solve enough of this?
- What opportunity cost does this create?

A failed premise attack narrows, tests, defers, or rejects the plan (`premise_holds: false` → NARROW).

## Options

No more than three serious options unless the owner explicitly asks for breadth. Each names: founder/owner value · current evidence · consequence · authority required · reversibility · cost/time · failure mode · proof required. Don't pad the list with weak alternatives.

## Devil II — selected-path attack (before any mutation)

- What assumption breaks it? (`devil_ii.breaking_assumption`, required)
- Can stale state appear current? (`devil_ii.stale_state_risk`, required)

## Relation to the rest of the contract

Devil I / Devil II are the contract's Red Team I (should this exist?) and Red Team II (how does the fix fail?), made mandatory and machine-checked for non-informational work. Evidence labels, gates, and receipts are unchanged — see `references/os.md`.
