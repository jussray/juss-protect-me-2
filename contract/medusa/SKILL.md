---
name: medusa
description: Standalone deep red team for consequential or irreversible plans, decisions, documents, and changes. Trigger on "medusa" or "/medusa". One assumption stone test, adversary and rebuttal rounds, reversal rule. No other skill, tools, network or memory required; never widens authority.
version: 1.1.0
---

# Medusa: Standalone Deep Red Team

Medusa works with only the supplied, in-scope material. The optional Python checker verifies the shape and local evidence integrity of a completed assessment; it does **not** generate findings, prove truth, authenticate a human, or authorize a release.

## Trigger and limits

Run on `medusa` or `/medusa`; do not claim bare `/devil` or `ULTRATHINK`. More reasoning adds depth, never authority to publish, spend, merge, deploy, send, delete, disclose or change access. Remain offline for A–D; an independently invoked fetcher is **not** part of Medusa's reasoning runtime. Do not attack people, run exploits, or test live systems without owner authorization. A finding never grants authority to punish or expose anyone.

Four principles: **borrowed tools** (independently checkable evidence), **whose label** (test who defines the adversary), **custody** (decider alone sees report unless explicitly expanded), and **the other vein** (Hold/Stop names reversal evidence).

## Preflight

Record: `target` name/version/date, `decider`, `stakes`, `audience`, `scope` (exact local artifacts), and `budget` (one round per pass). Stakes: `routine` = Pass 1 only, `consequential` = Passes 1–5, `irreversible` = Passes 1–5 plus strict custody. Stop at the context checkpoint and name unfinished work. Quote in-scope material before attacking. Redact secrets before display.

## Pass 1: Attack

Examine exactly ten classes: premise, assumptions, failure modes, misuse, authority, evidence, reversibility, Lindy (one-year durability), second-order effects, cheaper path. Each finding records an attack, scenario, consequence, evidence tag, likelihood, and basis. `VERIFIED` requires an inspectable source quote or artifact, not only a hash. `INFERRED` names its basis. `UNVERIFIED` names the check required.

## Pass 2: Adversary

For outsider, insider, and untrusted input (including prompt injection) record who, why, reach, first attempted behavior **without exploit instructions**, and frame check: who defines the threat and whether the labeled party is the one harmed. Attack unfair framing, not people.

## Pass 3: Stone test

Name the one breaking assumption. If VERIFIED, cite a passage in scope or an independently inspectable artifact. If not verified, it is the top finding whatever the other scores. Name reversal evidence. No possible reversal = Stop.

## Pass 4: Rebuttal

For every Critical/High finding, give the strongest defense available from in-scope material and classify `Stands`, `Narrows`, or `Rejected`. A rejection requires a checkable supporting quote. Confidence is not evidence.

## Pass 5: Final cut

Deduplicate; keep Critical/High that stood or narrowed; include Medium/Low only for distinct paths; rank by consequence and likelihood. Choose `Proceed` only with no standing Critical/High and verified stone; `Proceed with named changes` when a fix is explicitly named for standing findings; `Hold` if stone unverified; `Stop` if there is an unreversible standing finding. These are *advisory*, never machine authority.

## Severity and two-dimensional evidence

Critical = irreversible/large damage; High = normal-path consequential failure; Medium = conditional recoverable damage; Low = clarity/quality. Likelihood high/medium/low and basis separately.

`evidence_tag` = VERIFIED / INFERRED / UNVERIFIED, independently of `source_of_knowledge` = AUTHORED / OBSERVED / USER-REPORTED / VERIFIED. Do not confuse a quote with proof that a claim is true. `VERIFIED` requires source and exact checkable quotation or independently inspectable artifact. Hash binds identity only.

## Output

```
MEDUSA REPORT
TARGET: name @ version/date
STAKES: class; audience: decider (unless explicitly expanded)
STONE TEST: assumption | verified: yes/no | reversal evidence
FINDINGS (post-rebuttal):
 ID | pass/adversary | frame check | severity | attack | scenario | consequence | evidence tag | knowledge origin | likelihood + basis | rebuttal
REJECTED: finding + quoted rebuttal evidence
VERDICT: Proceed / Proceed with named changes / Hold / Stop; driven by finding IDs

REALITY: inspected facts and unresolved unknowns
FIX: none in red-team pass
PROOF: quotes and independent checks
RISK: untested threats and limitations
ROLLBACK: nothing changed
NEXT GATE: exactly one decider action
```

## Offline checker (optional)

A completed JSON assessment can be tested with `python3 medusa.py gate <assessment.json>` and exported safely with `python3 medusa.py protect <assessment.json> --out <new.json>`. Run `python3 -m unittest discover -s . -p 'test_medusa*.py' -v`. The checker checks scope and consistency; it **cannot** certify actual security, independently verify source accuracy or authorize release. A `--only` diagnostic mode **always exits 2** regardless of result. Never automatically admit fetched evidence. The separate `medusa_fetch.py` requires an explicit per-URL invocation and `admit` verifies bytes only; human must review and include the file in the assessment scope.

## Worked example

Mass email: assumption every recipient consented to promotional email. No consent record in scope = unverified stone; reversal evidence: per-recipient consent or mailing only consented contacts; verdict Hold. Frame finding: recipients bear the consequences, not merely the team that sends it.
