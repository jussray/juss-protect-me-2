#!/usr/bin/env python3
"""Medusa Layer 2 prerequisite: offline, signed, append-only local evidence bus.

It never senses, fetches or acts. Verification authenticates a configured local
sensor public key, NOT the truth of the sensor's observation or a human identity.
A root user or writer of both ledger and head can bypass local custody; external
anchoring remains a separate release gate. No self-registration from event data.
"""
from __future__ import annotations
import argparse, base64, fcntl, hashlib, json, os, re, stat, sys, copy
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ZERO='0'*64
MAX_EVENTS=10000
MAX_PAYLOAD_BYTES=16384
MAX_RECORD_BYTES=32768
MAX_LEDGER_BYTES=32*1024*1024
ID=re.compile(r'^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$')
EVENT_TYPES={'sensor_heartbeat','fs_change','ci_event','config_change','process_event','network_event','auth_event','detection_feedback','action_request','action_result'}

class BusError(Exception): pass

def canon(v): return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')
def digest(v): return hashlib.sha256(canon(v)).hexdigest()
def utc_now(): return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00','Z')
def parse_iso(value):
    if not isinstance(value,str): raise BusError('invalid timestamp')
    try: out=datetime.fromisoformat(value.replace('Z','+00:00'))
    except ValueError as e: raise BusError('invalid timestamp') from e
    if out.utcoffset() is None: raise BusError('timestamp missing timezone')
    return out.astimezone(timezone.utc)

def busdir(): return Path(os.environ.get('MEDUSA_BUS_DIR',str(Path.home()/'.config/medusa/bus'))).expanduser().absolute()
def trustpath(): return Path(os.environ.get('MEDUSA_TRUSTED_SENSORS',str(Path.home()/'.config/medusa/trusted_sensors.json'))).expanduser()

def regular_bytes(path:Path,max_bytes:int):
    flags=os.O_RDONLY | getattr(os,'O_NOFOLLOW',0)
    try: fd=os.open(path,flags)
    except OSError as e: raise BusError(f'cannot read {path.name}: {e.strerror}') from e
    try:
        s=os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_size>max_bytes: raise BusError('invalid file or size exceeded')
        return os.read(fd,max_bytes+1)
    finally: os.close(fd)

def trusted():
    p=trustpath()
    try:
        for candidate,is_dir in ((p,False),(p.parent,True)):
            try:s=candidate.lstat()
            except OSError as e:raise BusError('trusted-sensor manifest or directory missing') from e
            if stat.S_ISLNK(s.st_mode) or (not stat.S_ISDIR(s.st_mode) if is_dir else not stat.S_ISREG(s.st_mode)):
                raise BusError('trusted-sensor manifest or directory has unsafe type')
            if s.st_uid not in (os.getuid(),0) or s.st_mode&0o022:
                raise BusError('trusted-sensor manifest or directory writable by untrusted user')
        obj=json.loads(regular_bytes(p,32768))
    except (ValueError,UnicodeError) as e: raise BusError('invalid trusted-sensor manifest') from e
    if not isinstance(obj,dict) or set(obj)!={'sensors'} or not isinstance(obj['sensors'],dict): raise BusError('invalid trusted-sensor manifest')
    keys={}
    for sensor, b64 in obj['sensors'].items():
        if not isinstance(sensor,str) or not ID.fullmatch(sensor): raise BusError('invalid sensor identifier')
        try:
            raw=base64.b64decode(b64,validate=True)
            if len(raw)!=32: raise ValueError()
            keys[sensor]=Ed25519PublicKey.from_public_bytes(raw)
        except (ValueError,TypeError): raise BusError('invalid trusted sensor public key')
    return keys

def _validate_event(rec,index,previous,keys):
    if not isinstance(rec,dict) or set(rec)!={'event','payload'}: raise BusError('invalid ledger record')
    event=rec['event'];payload=rec['payload']
    required={'version','event_id','sensor_id','event_type','observed_at','seq','prev_sha256','payload_sha256','signature'}
    if not isinstance(event,dict) or set(event)!=required: raise BusError('invalid event schema')
    if event['version']!=1 or type(event['seq']) is not int or event['seq']!=index: raise BusError('event sequence violation')
    if not isinstance(event['event_id'],str) or not re.fullmatch(r'[0-9a-f]{64}',event['event_id']): raise BusError('bad event identity')
    if not isinstance(event['prev_sha256'],str) or not re.fullmatch(r'[0-9a-f]{64}',event['prev_sha256']): raise BusError('bad previous hash')
    if event['prev_sha256']!=previous: raise BusError('event chain discontinuity')
    if not isinstance(event['sensor_id'],str) or not ID.fullmatch(event['sensor_id']) or not isinstance(event['event_type'],str): raise BusError('invalid event identifiers')
    if event['sensor_id'] not in keys or event['event_type'] not in EVENT_TYPES: raise BusError('untrusted sensor or event type')
    if event['event_type']=='detection_feedback' and not event['sensor_id'].startswith('detect-'): raise BusError('feedback must be detector-signed')
    if not isinstance(payload,dict) or len(canon(payload))>MAX_PAYLOAD_BYTES: raise BusError('invalid event payload')
    safe_payload(payload)
    if event['payload_sha256']!=digest(payload): raise BusError('event payload tampered')
    parse_iso(event['observed_at'])
    base={k:v for k,v in event.items() if k not in ('signature','event_id')}
    if event['event_id']!=digest(base): raise BusError('event identity tampered')
    try: keys[event['sensor_id']].verify(bytes.fromhex(event['signature']),canon({**base,'event_id':event['event_id']}))
    except (ValueError,InvalidSignature): raise BusError('event signature invalid')
    if len(canon(rec))>MAX_RECORD_BYTES: raise BusError('record too large')
    return digest(rec)

@contextmanager
def lock_bus():
    # Do not accept a symlink or a group/world-writable bus root.
    d=busdir(); d.mkdir(parents=True,exist_ok=True,mode=0o700)
    st=d.lstat()
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or st.st_uid not in (os.getuid(),0) or st.st_mode&0o077:
        raise BusError('unsafe bus directory')
    lf=d/'.lock';fd=os.open(lf,os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        lockstat=os.fstat(fd)
        if not stat.S_ISREG(lockstat.st_mode) or lockstat.st_uid not in (os.getuid(),0) or lockstat.st_mode&0o077: raise BusError('unsafe lock file')
        fcntl.flock(fd,fcntl.LOCK_EX)
        yield d
    finally:
        fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)

def _read_unlocked(d,keys):
    ledger=d/'events.jsonl';head=d/'head.json'
    exists=ledger.exists();head_exists=head.exists()
    if exists!=head_exists: raise BusError('ledger/head snapshot mismatch')
    if not exists:return []
    b=regular_bytes(ledger,MAX_LEDGER_BYTES)
    if len(b)>MAX_LEDGER_BYTES or (b and not b.endswith(b'\n')): raise BusError('truncated ledger')
    lines=b.splitlines()
    if len(lines)>MAX_EVENTS: raise BusError('event count cap exceeded')
    records=[];previous=ZERO
    for index,line in enumerate(lines,1):
        if len(line)>MAX_RECORD_BYTES: raise BusError('oversized ledger record')
        try:rec=json.loads(line)
        except ValueError as e:raise BusError('invalid ledger JSON') from e
        previous=_validate_event(rec,index,previous,keys)
        records.append(rec)
    try:state=json.loads(regular_bytes(head,4096))
    except ValueError as e:raise BusError('invalid head snapshot') from e
    if not isinstance(state,dict) or state!={'seq':len(records),'last_sha256':previous}:
        raise BusError('head snapshot mismatch (possible truncation)')
    return records

def read_events():
    # An authenticated, consistent copy under the same writer lock.
    with lock_bus() as d:return _read_unlocked(d,trusted())

def _anchor(records):
    return {'count':len(records), 'last_event_hash':digest(records[-1]) if records else ZERO}

def verified_snapshot():
    """Return authenticated records and their prefix anchor from a single lock epoch.

    Caller must not construe this as an external/notarized checkpoint.
    Privileged local rewriting of BOTH ledger and head remains outside this trust model.
    """
    with lock_bus() as d:
        records=_read_unlocked(d,trusted())
        return {'anchor':_anchor(records),'records':copy.deepcopy(records)}

def _valid_anchor(anchor,records):
    if not isinstance(anchor,dict) or set(anchor)!={'count','last_event_hash'}:
        raise BusError('invalid chain anchor')
    n=anchor['count']
    if type(n) is not int or n<0 or n>len(records) or not isinstance(anchor['last_event_hash'],str):
        raise BusError('invalid or removed chain anchor')
    actual=digest(records[n-1]) if n else ZERO
    if actual!=anchor['last_event_hash']:
        raise BusError('chain prefix changed since detection')
    return n

def verify_snapshot_continuity(anchor):
    try:
        with lock_bus() as d:
            records=_read_unlocked(d,trusted())
            _valid_anchor(anchor,records)
            return {'ok':True, **_anchor(records)}
    except (BusError,OSError,ValueError,TypeError) as e:
        return {'ok':False, 'reason':str(e)}

def verify_chain():
    try:
        snap=verified_snapshot()
        return {'ok':True, **snap['anchor']}
    except (BusError,OSError,ValueError,TypeError) as e:
        return {'ok':False,'reason':str(e)}

def _validate_detection_payload(payload,records,anchor):
    # Event presence + signature + continuous chain were already verified by
    # _read_unlocked in the SAME lock epoch. Claiming VERIFIED without an anchor
    # and every referenced source event is prohibited.
    required=('rule_id','ruleset_sha256','severity','confidence','evidence_tag','evidence_ref','detection_id')
    if any(k not in payload for k in required): raise BusError('incomplete detection feedback')
    if payload['evidence_tag'] not in ('VERIFIED','INFERRED'): raise BusError('invalid or unverified feedback evidence')
    if not isinstance(payload['evidence_ref'],list) or not (1<=len(payload['evidence_ref'])<=1000):
        raise BusError('invalid cited event list')
    if len(payload['evidence_ref'])!=len(set(payload['evidence_ref'])): raise BusError('duplicate cited event')
    if not isinstance(payload['detection_id'],str) or not re.fullmatch('[0-9a-f]{64}',payload['detection_id']):
        raise BusError('invalid detection id')
    if not isinstance(payload['ruleset_sha256'],str) or not re.fullmatch('[0-9a-f]{64}',payload['ruleset_sha256']):
        raise BusError('invalid ruleset hash')
    n=_valid_anchor(anchor,records)
    idx={rec['event']['event_id']:rec for rec in records[:n]}
    for eid in payload['evidence_ref']:
        rec=idx.get(eid)
        if rec is None or rec['event']['event_type'] in ('detection_feedback','action_result','action_request'):
            raise BusError('detection evidence missing or not a source event')
    if payload.get('chain_anchor')!=anchor: raise BusError('detection anchor mismatch')


def _save_head(d,seq,last_hash):
    target=d/'head.json';tmp=d/f'.head-{os.getpid()}.tmp'
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0)
    fd=os.open(tmp,flags,0o600)
    try:
        with os.fdopen(fd,'wb') as f:f.write(canon({'seq':seq,'last_sha256':last_hash}));f.flush();os.fsync(f.fileno())
        os.replace(tmp,target)
        dirfd=os.open(d,os.O_RDONLY)
        try:os.fsync(dirfd)
        finally:os.close(dirfd)
    finally:
        try:tmp.unlink(missing_ok=True)
        except OSError:pass

def safe_payload(value):
    dangerous={'password','passwd','pwd','token','access_token','api_key','apikey','secret','client_secret','private_key','session','sessionid','cookie','authorization','bearer','credential','refresh_token'}
    def walk(item,depth):
        if depth>10:raise BusError('payload too deeply nested')
        if isinstance(item,dict):
            for k,v in item.items():
                if not isinstance(k,str):raise BusError('payload keys must be strings')
                if k.lower().replace('-','_') in dangerous:raise BusError('secret-like field in event payload')
                walk(v,depth+1)
        elif isinstance(item,list):
            for v in item:walk(v,depth+1)
        elif isinstance(item,str) and re.search(r'(?i)\bbearer\s+[^\s]{8,}|\b(?:sk|ghp|github_pat|xoxb)[_-][A-Za-z0-9_-]{10,}',item):
            raise BusError('secret-like value in event payload')
        elif not isinstance(item,(str,int,float,bool,type(None))):raise BusError('invalid payload value')
    walk(value,0)

def append_event(sensor_id,event_type,payload,key,observed_at=None,dedupe_key=None,chain_anchor=None):
    if event_type not in EVENT_TYPES: raise BusError('event type not allowed')
    if event_type=='detection_feedback' and not sensor_id.startswith('detect-'): raise BusError('detector identity required')
    if event_type=='detection_feedback' and (chain_anchor is None or dedupe_key!='detection_id'):
        raise BusError('feedback requires a verified snapshot anchor and dedupe key')
    if not isinstance(sensor_id,str) or not ID.fullmatch(sensor_id): raise BusError('invalid sensor_id')
    if not isinstance(payload,dict) or len(canon(payload))>MAX_PAYLOAD_BYTES:raise BusError('payload invalid or too large')
    safe_payload(payload)
    if dedupe_key is not None and (event_type!='detection_feedback' or dedupe_key!='detection_id' or not isinstance(payload.get(dedupe_key),str)):
        raise BusError('invalid feedback dedupe key')
    if not key: raise BusError('signing key required')
    key_path=Path(key)
    key_state=key_path.lstat()
    if not stat.S_ISREG(key_state.st_mode) or key_state.st_nlink!=1 or (key_state.st_mode&0o077):
        raise BusError('private key file permission or type unsafe')
    private=serialization.load_pem_private_key(regular_bytes(key_path,8192),password=None)
    if not hasattr(private,'public_key') or not hasattr(private,'sign'):raise BusError('invalid signing key type')
    public=private.public_key().public_bytes(encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw)
    with lock_bus() as d:
        keys=trusted()
        if sensor_id not in keys: raise BusError('sensor must be registered by a trusted administrator')
        expected=keys[sensor_id].public_bytes(encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw)
        if expected!=public:raise BusError('sensor key mismatch')
        records=_read_unlocked(d,keys)
        if event_type=='detection_feedback':_validate_detection_payload(payload,records,chain_anchor)
        if dedupe_key is not None:
            if any(rec['event']['event_type']==event_type and rec['payload'].get(dedupe_key)==payload[dedupe_key] for rec in records):
                return None
        if len(records)>=MAX_EVENTS:raise BusError('event cap exceeded')
        prev=digest(records[-1]) if records else ZERO
        base={'version':1,'sensor_id':sensor_id,'event_type':event_type,'observed_at':observed_at or utc_now(),'seq':len(records)+1,'prev_sha256':prev,'payload_sha256':digest(payload)}
        parse_iso(base['observed_at']);eid=digest(base)
        event={**base,'event_id':eid,'signature':private.sign(canon({**base,'event_id':eid})).hex()}
        rec={'event':event,'payload':payload};line=canon(rec)+b'\n'
        if len(line)-1>MAX_RECORD_BYTES: raise BusError('event record too large')
        path=d/'events.jsonl'
        fd=os.open(path,os.O_CREAT|os.O_WRONLY|os.O_APPEND|getattr(os,'O_NOFOLLOW',0),0o600)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):raise BusError('ledger not regular')
            with os.fdopen(fd,'ab') as f:
                f.write(line);f.flush();os.fsync(f.fileno())
        finally: pass
        _save_head(d,len(records)+1,digest(rec))
        return eid


# Opt-in throughput path. One full validation and durable checkpoint per bounded
# batch, not one full-history scan and fsync for every event. The canonical
# single-event append (including deduplicated detection_feedback) is unchanged.
MAX_SOURCE_BATCH = 100
SOURCE_TYPES = {'sensor_heartbeat', 'fs_change', 'ci_event', 'config_change',
                'process_event', 'network_event', 'auth_event'}


def append_source_batch(sensor_id, events, key):
    """Append 1..100 source observations atomically under the writer lock.

    Input: [{"event_type": SOURCE_TYPE, "payload": dict,
             "observed_at": optional RFC3339 timestamp}, ...]
    Returns event IDs in exactly the ledger order. No feedback/action events.
    Every existing event and the head are reverified before the batch, then
    the entire signed batch is fsynced before an atomic head update. A crash
    between writes blocks subsequent reads/appends until inspected; no replay
    or silent repair. This is NOT independent off-host evidence custody.
    """
    if not isinstance(sensor_id, str) or not ID.fullmatch(sensor_id):
        raise BusError('invalid sensor_id')
    if not isinstance(events, list) or not 1 <= len(events) <= MAX_SOURCE_BATCH:
        raise BusError('source batch must contain 1..100 events')
    validated = []
    for item in events:
        if not isinstance(item, dict) or not {'event_type', 'payload'} <= item.keys() \
                or set(item) - {'event_type', 'payload', 'observed_at'}:
            raise BusError('invalid batch source event schema')
        kind, payload = item['event_type'], item['payload']
        if kind not in SOURCE_TYPES:
            raise BusError('batch only accepts source event types')
        if not isinstance(payload, dict) or len(canon(payload)) > MAX_PAYLOAD_BYTES:
            raise BusError('batch payload invalid or oversized')
        safe_payload(payload)
        when = item.get('observed_at') or utc_now()
        parse_iso(when)
        validated.append((kind, payload, when))
    if not key:
        raise BusError('batch signing key required')
    key_path = Path(key)
    key_state = key_path.lstat()
    if not stat.S_ISREG(key_state.st_mode) or key_state.st_nlink != 1 or key_state.st_mode & 0o077:
        raise BusError('private key file permission or type unsafe')
    private = serialization.load_pem_private_key(regular_bytes(key_path, 8192), password=None)
    if not hasattr(private, 'public_key') or not hasattr(private, 'sign'):
        raise BusError('invalid signing key type')
    public = private.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                                format=serialization.PublicFormat.Raw)
    with lock_bus() as d:
        keys = trusted()
        if sensor_id not in keys:
            raise BusError('sensor must be registered by a trusted administrator')
        expected = keys[sensor_id].public_bytes(encoding=serialization.Encoding.Raw,
                                                format=serialization.PublicFormat.Raw)
        if expected != public:
            raise BusError('sensor key mismatch')
        prior = _read_unlocked(d, keys)  # Every earlier signature, hash and head.
        if len(prior) + len(validated) > MAX_EVENTS:
            raise BusError('event cap exceeded')
        previous = digest(prior[-1]) if prior else ZERO
        seq = len(prior)
        ids, lines = [], []
        for kind, payload, when in validated:
            seq += 1
            base = {'version': 1, 'sensor_id': sensor_id, 'event_type': kind,
                    'observed_at': when, 'seq': seq, 'prev_sha256': previous,
                    'payload_sha256': digest(payload)}
            event_id = digest(base)
            event = {**base, 'event_id': event_id,
                     'signature': private.sign(canon({**base, 'event_id': event_id})).hex()}
            record = {'event': event, 'payload': payload}
            line = canon(record) + b'\n'
            if len(line) - 1 > MAX_RECORD_BYTES:
                raise BusError('batch event record too large')
            lines.append(line)
            ids.append(event_id)
            previous = digest(record)
        ledger = d / 'events.jsonl'
        old_bytes = ledger.stat().st_size if ledger.exists() else 0
        block = b''.join(lines)
        if old_bytes + len(block) > MAX_LEDGER_BYTES:
            raise BusError('ledger byte cap exceeded')
        fd = os.open(ledger, os.O_CREAT | os.O_WRONLY | os.O_APPEND |
                     getattr(os, 'O_NOFOLLOW', 0), 0o600)
        with os.fdopen(fd, 'ab') as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                raise BusError('ledger not regular')
            written = f.write(block)
            if written != len(block):
                raise BusError('incomplete batch write; ledger HOLD')
            f.flush()
            os.fsync(f.fileno())
        _save_head(d, seq, previous)
        return ids


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    s=p.add_subparsers(dest='cmd',required=True)
    x=s.add_parser('emit');x.add_argument('--sensor-id',required=True);x.add_argument('--event-type',required=True);x.add_argument('--key',required=True);x.add_argument('--payload',required=True)
    s.add_parser('verify');s.add_parser('list')
    try:
        a=p.parse_args(argv)
        if a.cmd=='emit':
            eid=append_event(a.sensor_id,a.event_type,json.loads(a.payload),a.key);print('EVENT',eid)
        else:
            r=read_events();print('VERIFIED_CHAIN',len(r)) if a.cmd=='verify' else print(json.dumps([x['event'] for x in r],indent=2))
        return 0
    except (BusError,OSError,ValueError,TypeError) as e:
        print(f'eventbus: BLOCKED: {type(e).__name__}: {e}',file=sys.stderr);return 2
if __name__=='__main__':sys.exit(main())
