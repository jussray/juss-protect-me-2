#!/usr/bin/env python3
"""Signed Layer 2 snapshot adapter for the existing pure Layer 3 detector.

No sensors, network, grants, actions, supervisor, or automatic containment.
An authenticated local bus is necessary, but not independent external custody.
"""
from __future__ import annotations
import hashlib
import json
import sys
from pathlib import Path

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
sys.path.insert(0,str(HERE.parent))
import detect_core as CORE
import eventbus as BUS

SOURCE_TYPES={'sensor_heartbeat','fs_change','ci_event','config_change','process_event','network_event','auth_event'}

def _checked_source_snapshot():
    snap=BUS.verified_snapshot()
    rows=[r for r in snap['records'] if r['event']['event_type'] in SOURCE_TYPES]
    ids={r['event']['event_id']:r for r in rows}
    return snap,rows,ids

def evaluate(rulesets, baseline=None):
    """Evaluate rules over one verified, consistent source-only ledger snapshot.

    Returns (findings, anchor). We never accept a caller-supplied VERIFIED claim.
    """
    snap,rows,idx=_checked_source_snapshot()
    frozen={} if baseline is None else baseline
    # Core orders by observed_at plus event_id. For sequence rules, concurrent
    # equal timestamps provide no trustworthy order; refuse instead of silently
    # substituting lexicographic event IDs for ledger sequence.
    has_sequence=any('sequence' in rule.get('when',{}) for doc in rulesets for rule in doc.get('rules',[]))
    observed=[r['event']['observed_at'] for r in rows]
    if has_sequence and len(observed)!=len(set(observed)):
        raise BUS.BusError('ambiguous equal timestamps for ordered correlation')
    events=[{k:r['event'][k] for k in ('event_id','event_type','sensor_id','observed_at')}
            | {'payload':r['payload']} for r in rows]
    findings=CORE.detect(events,rulesets,frozen)
    anomaly_rules={(doc['ruleset_id'],doc['version'],r['id']) for doc in rulesets
                   for r in doc.get('rules',[]) if 'not_in_baseline' in r.get('when',{})}
    for det in findings:
        refs=det['evidence_ref']
        if not refs or any(ref not in idx for ref in refs):
            raise BUS.BusError('detector emitted missing evidence reference')
        # Local signature + chain integrity proven at snapshot time. This does
        # not certify the truth of observations or independently anchor history.
        anomaly=(det['ruleset_id'],det['ruleset_version'],det['rule_id']) in anomaly_rules
        det['evidence_tag']='INFERRED' if anomaly else 'VERIFIED'
        det['evidence_note']=('source events signed; baseline anomaly remains inferred'
                              if anomaly else 'source events authenticated in locally signed ledger snapshot')
        det['chain_anchor']=dict(snap['anchor'])
        det['detection_id']=BUS.digest({'rule_id':det['rule_id'],
                 'ruleset_sha256':det['ruleset_sha256'],
                 'baseline_sha256':det['baseline_sha256'],
                 'evidence_ref':refs})
        # Target bindings are sourced from cited, signed FS change events only.
        paths=[]
        for ref in refs:
            item=idx[ref]
            if item['event']['event_type']=='fs_change':
                path=item['payload'].get('path')
                if isinstance(path,str) and path.startswith('/') and path not in paths:
                    paths.append(path)
        if len(paths)>100:
            det['target_paths']=[]
            det['target_binding_incomplete']=True
        else:
            det['target_paths']=paths
    return findings,dict(snap['anchor'])

def run(rulesets, baseline=None, *, emit=False, emit_key=None, sensor_id='detect-1'):
    """Deterministic snapshot evaluation; optional signed, atomic feedback emission.

    Concurrent appends are allowed. Prefix continuity is reverified under the
    same writer lock as feedback signing, so a changed history cannot promote.
    """
    findings,anchor=evaluate(rulesets,baseline)
    if emit:
        if not emit_key:raise BUS.BusError('feedback signing key required')
        for d in findings:
            payload={key:value for key,value in d.items() if key!='evidence_note'}
            BUS.append_event(sensor_id,'detection_feedback',payload,emit_key,
                dedupe_key='detection_id',chain_anchor=anchor)
    return findings

def main(argv=None):
    """Explicit local CLI. Default is report only; --emit requires detector key."""
    import argparse
    from detect import read_json
    ap=argparse.ArgumentParser(description='Medusa signed offline bus-to-detector adapter (no actions)')
    ap.add_argument('--rules',action='append',required=True,help='JSON ruleset; repeatable')
    ap.add_argument('--baseline',help='optional frozen baseline JSON')
    ap.add_argument('--emit',action='store_true',help='append signed detection_feedback')
    ap.add_argument('--emit-key',help='registered detector private key')
    ap.add_argument('--sensor-id',default='detect-1')
    args=ap.parse_args(argv)
    try:
        if args.emit and not args.emit_key:raise BUS.BusError('--emit requires --emit-key')
        rulesets=[read_json(x) for x in args.rules]
        baseline=read_json(args.baseline) if args.baseline else None
        hits=run(rulesets,baseline,emit=args.emit,emit_key=args.emit_key,sensor_id=args.sensor_id)
        print(json.dumps({'detections':hits,'count':len(hits),'authority':'NONE','effect_executed':False},sort_keys=True))
        return 0
    except (BUS.BusError,CORE.DetectionError,OSError,ValueError,TypeError,KeyError) as exc:
        print(f'MEDUSA SIGNED DETECTION BLOCKED: {type(exc).__name__}: {exc}',file=sys.stderr)
        return 2

if __name__=='__main__':
    raise SystemExit(main())
