#!/usr/bin/env python3
"""Medusa Layer 3 preview: offline, deterministic detection over supplied event snapshots.

NO bus, sockets, authority lookup, actions, implicit verification, or writes.
Until signed Layer 2 bus verification is available evidence cannot be VERIFIED.
"""
from __future__ import annotations
import fnmatch
import hashlib
import json
import posixpath
import signal
from datetime import datetime, timezone
from collections import defaultdict

SEVERITIES = {'Low':1, 'Medium':2, 'High':3, 'Critical':4}
CONFIDENCES = {'low':1,'medium':2,'high':3}
MAX_RULES = 200
MAX_EVENTS = 5000
MAX_REFS = 1000
MAX_OUTPUT = 200
MAX_SEQUENCE = 6
MAX_WINDOW = 86400
MAX_BASELINE = 10000
# Hard resource budgets; exceeding a limit aborts the report, never drops evidence.
MAX_PREDICATE_NODES = 50
MAX_MATCH_CALLS = 20000
MAX_DETECTION_BYTES = 64 * 1024
MAX_RUN_TIME_S = 30.0  # Complete detection call, including input validation.

class DetectionError(ValueError):
    pass

def need(test, message):
    if not test:
        raise DetectionError(message)

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')

def digest(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()

def timestamp(value):
    need(isinstance(value,str) and len(value) <= 40, 'invalid timestamp')
    try:
        dt = datetime.fromisoformat(value.replace('Z','+00:00'))
    except (ValueError, TypeError) as exc:
        raise DetectionError('invalid observed_at') from exc
    need(dt.tzinfo is not None, 'event timestamp requires timezone')
    return dt.astimezone(timezone.utc)

def event_value(ev,field):
    if field in ('event_type','sensor_id','event_id','observed_at'):
        return ev.get(field)
    return ev.get('payload', {}).get(field)

def validate_events(events):
    need(isinstance(events,list) and len(events) <= MAX_EVENTS,'events must be a bounded list')
    seen=set(); out=[]
    for e in events:
        need(isinstance(e,dict) and set(('event_id','event_type','sensor_id','observed_at','payload')) <= set(e), 'event envelope incomplete')
        need(isinstance(e['event_id'],str) and 1 <= len(e['event_id']) <= 128, 'invalid event id')
        need(e['event_id'] not in seen, 'duplicate event id')
        seen.add(e['event_id'])
        need(isinstance(e['event_type'],str) and len(e['event_type']) <= 80,'invalid event type')
        need(isinstance(e['sensor_id'],str) and len(e['sensor_id']) <= 80,'invalid sensor id')
        need(isinstance(e['payload'],dict) and len(canonical(e['payload'])) <= 8192,'invalid event payload')
        out.append((timestamp(e['observed_at']),e))
    out.sort(key=lambda x:(x[0],x[1]['event_id']))
    return out

def _predicate_nodes(root):
    # A predicate tree may be shallow but very wide. Count nodes, not only depth.
    pending = [root]
    count = 0
    while pending:
        node = pending.pop()
        count += 1
        need(count <= MAX_PREDICATE_NODES, 'predicate node budget exceeded')
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ('all', 'any') and isinstance(value, list):
                    pending.extend(value)
                elif key == 'not':
                    pending.append(value)
    return count

def validate_predicate(p, depth=0):
    if depth == 0:
        _predicate_nodes(p)
    need(depth <= 8 and isinstance(p,dict) and p,'bad predicate')
    allowed={'event_type','where','path_glob','sensor_id_prefix','all','any','not'}
    need(set(p)<=allowed,'unknown predicate (fail-closed)')
    for k,v in p.items():
        if k in ('all','any'):
            need(isinstance(v,list) and 1 <= len(v) <= 12,'bad predicate group')
            for child in v: validate_predicate(child,depth+1)
        elif k=='not': validate_predicate(v,depth+1)
        elif k=='where':
            need(isinstance(v,dict) and 1 <= len(v) <= 12,'invalid where')
            for f,expected in v.items():
                need(isinstance(f,str) and 1 <= len(f) <= 60 and isinstance(expected,(str,int,bool)),'bad where term')
        elif k=='path_glob':
            need(isinstance(v,str) and 1 <= len(v) <= 150 and v.count('*') <= 4 and not any(c in v for c in '[]{}\\'),'unsafe path glob')
        else: need(isinstance(v,str) and 1 <= len(v) <= 100,'bad string predicate')

def matches(e,p,budget=None):
    if budget is not None:
        budget[0] += 1
        need(budget[0] <= MAX_MATCH_CALLS, 'rule match budget exceeded')
    # Conjunction across every supplied key, not just first matching key.
    for k,v in p.items():
        if k=='all': ok=all(matches(e,x,budget) for x in v)
        elif k=='any': ok=any(matches(e,x,budget) for x in v)
        elif k=='not': ok=not matches(e,v,budget)
        elif k=='where': ok=all(event_value(e,f)==expected for f,expected in v.items())
        elif k=='path_glob':
            path=event_value(e,'path')
            ok=isinstance(path,str) and len(path)<1024 and (fnmatch.fnmatchcase(path,v) or (v.startswith('**/') and fnmatch.fnmatchcase(path,v[3:])))
        elif k=='event_type': ok=event_value(e,k)==v
        elif k=='sensor_id_prefix': ok=e['sensor_id'].startswith(v)
        else: raise DetectionError('unknown predicate')
        if not ok:return False
    return True

def validate_ruleset(doc):
    need(isinstance(doc,dict) and set(doc)=={'ruleset_id','version','rules'}, 'ruleset fields invalid')
    need(isinstance(doc['ruleset_id'],str) and 1 <= len(doc['ruleset_id']) <= 64,'invalid ruleset_id')
    need(isinstance(doc['version'],str) and 1 <= len(doc['version']) <= 60,'invalid version')
    rules=doc['rules'];need(isinstance(rules,list) and len(rules)<=MAX_RULES,'too many rules')
    seen=set()
    for r in rules:
        need(isinstance(r,dict) and set(r)=={'id','description','severity','confidence','confidence_basis','window_seconds','when'},'invalid rule shape')
        need(isinstance(r['id'],str) and 1<=len(r['id'])<=80 and r['id'] not in seen,'duplicate or invalid rule id');seen.add(r['id'])
        need(isinstance(r['description'],str) and len(r['description'])<=300,'invalid description')
        need(r['severity'] in SEVERITIES and r['confidence'] in CONFIDENCES,'invalid rating')
        need(isinstance(r['confidence_basis'],str) and 1<=len(r['confidence_basis'])<=300,'confidence needs basis')
        need(type(r['window_seconds']) is int and 0<=r['window_seconds']<=MAX_WINDOW,'invalid time window')
        when=r['when'];need(isinstance(when,dict),'invalid when')
        if 'count' in when:
            need(set(when)=={'count'},'count cannot mix predicates')
            spec=when['count'];need(isinstance(spec,dict) and set(spec)=={'match','threshold','group_by'},'invalid count')
            validate_predicate(spec['match'])
            need(type(spec['threshold']) is int and 1<=spec['threshold']<=MAX_REFS,'invalid threshold')
            need(spec['group_by'] in (None,'path_prefix','sensor_id'),'unsupported count group')
        elif 'sequence' in when:
            need(set(when)<= {'sequence','distinct_sensors'} and set(when)>={'sequence'},'invalid sequence')
            seq=when['sequence'];need(isinstance(seq,list) and 2<=len(seq)<=MAX_SEQUENCE,'sequence length')
            for p in seq:validate_predicate(p)
            need(type(when.get('distinct_sensors',False)) is bool,'distinct_sensors boolean')
            need(r['window_seconds']>0,'sequence needs window')
        elif 'not_in_baseline' in when:
            need(set(when)=={'not_in_baseline','match','baseline'},'invalid anomaly rule')
            need(isinstance(when['not_in_baseline'],str) and 1<=len(when['not_in_baseline'])<=60,'invalid baseline field')
            need(isinstance(when['baseline'],str) and 1<=len(when['baseline'])<=60,'invalid baseline name')
            validate_predicate(when['match'])
        else:validate_predicate(when)
    return digest(doc)

def _group(e, field):
    if field=='sensor_id':return e['sensor_id']
    if field=='path_prefix':
        path=event_value(e,'path')
        return posixpath.dirname(path) if isinstance(path,str) and path.startswith('/') else None
    return '_'

def _sequence(seq, ordered, window, distinct, budget):
    """Bounded streaming correlation. Overflow BLOCKS rather than silently missing hits."""
    # Each stage retains candidate witnesses for future steps. Greedy one-state
    # matching is incorrect under distinct_sensors and window constraints.
    stages=[[] for _ in seq]
    MAX_STATES_PER_STAGE=96
    for t,e in ordered:
        for step in range(len(seq)-1,-1,-1):
            if not matches(e,seq[step],budget):
                continue
            if step==0:
                candidate=(t,(e['event_id'],),frozenset((e['sensor_id'],)))
                if len(stages[0]) >= MAX_STATES_PER_STAGE:
                    raise DetectionError('correlation state budget exceeded')
                stages[0].append(candidate)
                continue
            candidates=[]
            for t0,refs,sensors in stages[step-1]:
                if (t-t0).total_seconds()>window or (distinct and e['sensor_id'] in sensors):
                    continue
                candidates.append((t0,refs+(e['event_id'],),sensors|{e['sensor_id']}))
            if candidates:
                if step==len(seq)-1:
                    return list(candidates[0][1])
                if len(stages[step])+len(candidates)>MAX_STATES_PER_STAGE:
                    raise DetectionError('correlation state budget exceeded')
                stages[step].extend(candidates)
        # Remove out-of-window partial witnesses rather than accumulating them.
        for i in range(len(stages)-1):
            stages[i]=[row for row in stages[i] if (t-row[0]).total_seconds()<=window]
    return None

def _deadline_expired(_signum, _frame):
    raise DetectionError('detection cumulative runtime deadline exceeded')


def detect(events, rulesets, baseline=None):
    """Run the pure detector with a hard cumulative POSIX wall-clock budget.

    Do not return partial findings when the budget expires. Nested process
    alarm timers and worker-thread invocations are rejected, not bypassed.
    """
    required = ('SIGALRM', 'ITIMER_REAL', 'getitimer', 'setitimer')
    if any(not hasattr(signal, name) for name in required):
        raise DetectionError('detection runtime deadline unavailable')
    try:
        active = signal.getitimer(signal.ITIMER_REAL)
        if active[0] > 0 or active[1] > 0:
            raise DetectionError('detection runtime deadline conflicts with active timer')
        prior = signal.getsignal(signal.SIGALRM)
        signal.signal(signal.SIGALRM, _deadline_expired)
    except DetectionError:
        raise  # Preserve specific fail-closed collision reason.
    except (OSError, ValueError) as exc:
        raise DetectionError('detection runtime deadline unavailable') from exc
    try:
        signal.setitimer(signal.ITIMER_REAL, MAX_RUN_TIME_S)
        return _detect_impl(events, rulesets, baseline)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, prior)


def _detect_impl(events, rulesets, baseline=None):
    """Return detections; no mutation. All findings at most INFERRED until Layer 2 verifies events."""
    ordered=validate_events(events)
    need(isinstance(rulesets,list) and rulesets and len(rulesets)<=10,'rulesets must be 1..10')
    baseline={} if baseline is None else baseline
    need(isinstance(baseline,dict) and len(canonical(baseline))<=MAX_BASELINE,'invalid baseline snapshot')
    rules=[]
    for document in rulesets:
        h=validate_ruleset(document)
        rules.extend((r,document['ruleset_id'],document['version'],h) for r in document['rules'])
    need(len(rules)<=MAX_RULES,'too many rules total')
    out=[]
    end=ordered[-1][0] if ordered else None
    for rule,rid,version,rhash in rules:
        when=rule['when'];window=rule['window_seconds'];budget=[0]
        events_in_window=[(t,e) for t,e in ordered if end is not None and (not window or 0<=(end-t).total_seconds()<=window)]
        refs=[];extras={}
        if 'count' in when:
            spec=when['count'];groups=defaultdict(list)
            for _,e in events_in_window:
                if matches(e,spec['match'],budget):
                    g=_group(e,spec['group_by'])
                    if g is not None:groups[g].append(e['event_id'])
            qualified=[(g,ids) for g,ids in groups.items() if len(ids)>=spec['threshold']]
            if qualified:
                group,refs=sorted(qualified,key=lambda x:(-len(x[1]),str(x[0])))[0]
                need(len(refs)<=MAX_REFS,'count witness too large')
                extras={'group':group,'count':len(refs)}
        elif 'sequence' in when:
            refs=_sequence(when['sequence'],events_in_window,window,when.get('distinct_sensors',False),budget) or []
        elif 'not_in_baseline' in when:
            values=baseline.get(when['baseline'])
            need(isinstance(values,list) and all(isinstance(x,str) for x in values),'baseline absent or invalid (fail closed)')
            known=set(values)
            refs=[e['event_id'] for _,e in events_in_window if matches(e,when['match'],budget) and
                  isinstance(event_value(e,when['not_in_baseline']),str) and
                  event_value(e,when['not_in_baseline']) not in known]
        else:refs=[e['event_id'] for _,e in events_in_window if matches(e,when,budget)]
        if refs:
            need(len(refs)<=MAX_REFS,'evidence witness too large')
            out.append({'rule_id':rule['id'],'ruleset_id':rid,'ruleset_version':version,
                        'ruleset_sha256':rhash,'baseline_sha256':digest(baseline),
                        'severity':rule['severity'],'confidence':rule['confidence'],
                        'confidence_basis':rule['confidence_basis'],'description':rule['description'],
                        'evidence_tag':'INFERRED',
                        'evidence_note':'Layer 2 signed event chain not yet verified',
                        'evidence_ref':refs,**extras})
            need(len(canonical(out[-1])) <= MAX_DETECTION_BYTES, 'detection exceeds size budget')
            need(len(out)<=MAX_OUTPUT,'too many detections')
    out.sort(key=lambda d:(-SEVERITIES[d['severity']],-CONFIDENCES[d['confidence']],d['rule_id']))
    return out
