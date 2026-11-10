"""Synthetic-only tests for Medusa signed local ledger; no real sensors or effects."""
from __future__ import annotations
import base64
import json
import multiprocessing as mp
import os
import sys
import tempfile
import unittest
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0,str(Path(__file__).resolve().parent))
import eventbus as B


def _worker(root, writer, count, queue):
    os.environ['MEDUSA_BUS_DIR']=str(Path(root)/'bus')
    os.environ['MEDUSA_TRUSTED_SENSORS']=str(Path(root)/'trusted.json')
    try:
        for i in range(count):
            B.append_event('fs-1','sensor_heartbeat',{'writer':writer,'iteration':i},str(Path(root)/'fs.pem'))
        queue.put(('ok',writer))
    except Exception as exc:
        queue.put(('error',writer,type(exc).__name__,str(exc)))


class BusTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory(prefix='medusa-ledger-')
        self.addCleanup(t.cleanup)
        self.root=Path(t.name)
        env={key:os.environ.get(key) for key in ('MEDUSA_BUS_DIR','MEDUSA_TRUSTED_SENSORS')}
        self.addCleanup(lambda: [(os.environ.pop(k,None) if v is None else os.environ.__setitem__(k,v)) for k,v in env.items()])
        os.environ['MEDUSA_BUS_DIR']=str(self.root/'bus')
        os.environ['MEDUSA_TRUSTED_SENSORS']=str(self.root/'trusted.json')
        self.priv={}
        trusted={}
        for sensor, file in [('fs-1','fs.pem'),('detect-1','det.pem')]:
            key=Ed25519PrivateKey.generate();path=self.root/file
            path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
            path.chmod(0o600)
            raw=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
            trusted[sensor]=base64.b64encode(raw).decode()
            self.priv[sensor]=str(path)
        manifest=self.root/'trusted.json';manifest.write_text(json.dumps({'sensors':trusted}));manifest.chmod(0o600)

    def add(self, payload=None, **kwargs):
        return B.append_event('fs-1','fs_change',{'path':'/tmp/fake/.env','action':'write'} if payload is None else payload,self.priv['fs-1'],**kwargs)

    def test_sign_and_verify_snapshot(self):
        e1=self.add();e2=self.add({'path':'/tmp/fake/ok','action':'write'})
        snap=B.verified_snapshot()
        self.assertEqual([r['event']['event_id'] for r in snap['records']],[e1,e2])
        self.assertEqual(snap['anchor']['count'],2)
        self.assertTrue(B.verify_chain()['ok'])
        self.assertTrue(B.verify_snapshot_continuity(snap['anchor'])['ok'])
        self.assertEqual(B.read_events()[0]['event']['seq'],1)

    def test_append_after_snapshot_does_not_invalidate_prefix(self):
        self.add();a=B.verified_snapshot()['anchor'];self.add({'path':'/tmp/fake/ok','action':'write'})
        self.assertTrue(B.verify_snapshot_continuity(a)['ok'])

    def test_unknown_sensor_and_key_mismatch_fail_closed(self):
        with self.assertRaises(B.BusError):B.append_event('other','fs_change',{'a':1},self.priv['fs-1'])
        with self.assertRaises(B.BusError):B.append_event('fs-1','fs_change',{'a':1},self.priv['detect-1'])
        self.assertTrue(B.verify_chain()['ok'])

    def test_untrusted_sensor_manifest_is_not_mutated(self):
        old=(self.root/'trusted.json').read_bytes()
        with self.assertRaises(B.BusError):B.append_event('new','fs_change',{'a':1},self.priv['fs-1'])
        self.assertEqual((self.root/'trusted.json').read_bytes(),old)

    def test_reject_world_writable_trust_manifest(self):
        (self.root/'trusted.json').chmod(0o666)
        with self.assertRaisesRegex(B.BusError,'untrusted user'):self.add()

    def test_tampered_event_payload_detected(self):
        self.add();self.add({'path':'/tmp/fake/ok','action':'write'})
        p=self.root/'bus/events.jsonl'
        lines=p.read_text().splitlines();r=json.loads(lines[0]);r['payload']['path']='/tmp/other'
        lines[0]=json.dumps(r);p.write_text('\n'.join(lines)+'\n')
        self.assertFalse(B.verify_chain()['ok'])
        with self.assertRaises(B.BusError):B.verified_snapshot()

    def test_truncation_detected_by_head(self):
        self.add();self.add({'path':'/tmp/fake/ok','action':'write'})
        p=self.root/'bus/events.jsonl';p.write_text(p.read_text().splitlines()[0]+'\n')
        self.assertFalse(B.verify_chain()['ok'])

    def test_partial_line_detected(self):
        self.add();p=self.root/'bus/events.jsonl';p.write_bytes(p.read_bytes()[:-1])
        self.assertFalse(B.verify_chain()['ok'])

    def test_source_signed_feedback_requires_anchor(self):
        self.add()
        with self.assertRaisesRegex(B.BusError,'anchor'):
            B.append_event('detect-1','detection_feedback',{'test':True},self.priv['detect-1'])
        with self.assertRaisesRegex(B.BusError,'detector identity'):
            B.append_event('fs-1','detection_feedback',{'test':True},self.priv['fs-1'])

    def test_secret_like_payload_refused(self):
        with self.assertRaisesRegex(B.BusError,'secret'):
            self.add({'access_token':'synthetic'})

    def test_feedback_references_and_dedupe(self):
        eid=self.add();snap=B.verified_snapshot()
        payload={'rule_id':'r','ruleset_sha256':'e'*64,'severity':'High','confidence':'medium',
                 'evidence_tag':'VERIFIED','evidence_ref':[eid],
                 'detection_id':'a'*64,'chain_anchor':snap['anchor']}
        a=B.append_event('detect-1','detection_feedback',payload,self.priv['detect-1'],
                         dedupe_key='detection_id',chain_anchor=snap['anchor'])
        self.assertIsNotNone(a)
        again=B.append_event('detect-1','detection_feedback',payload,self.priv['detect-1'],
                         dedupe_key='detection_id',chain_anchor=snap['anchor'])
        self.assertIsNone(again)
        self.assertEqual(B.verified_snapshot()['anchor']['count'],2)

    def test_feedback_rejects_forged_evidence_and_anchor(self):
        eid=self.add();a=B.verified_snapshot()['anchor']
        p={'rule_id':'r','ruleset_sha256':'e'*64,'severity':'High','confidence':'medium',
           'evidence_tag':'VERIFIED','evidence_ref':['not-signed'],
           'detection_id':'a'*64,'chain_anchor':a}
        with self.assertRaises(B.BusError):
            B.append_event('detect-1','detection_feedback',p,self.priv['detect-1'],
                           dedupe_key='detection_id',chain_anchor=a)
        p['evidence_ref']=[eid];p['chain_anchor']={'count':0,'last_event_hash':B.ZERO}
        with self.assertRaisesRegex(B.BusError,'anchor mismatch'):
            B.append_event('detect-1','detection_feedback',p,self.priv['detect-1'],
                           dedupe_key='detection_id',chain_anchor=a)

    def test_rewrite_prefix_refused_during_feedback(self):
        eid=self.add();a=B.verified_snapshot()['anchor']
        self.add({'path':'/tmp/fake/ok','action':'write'})
        p=self.root/'bus/events.jsonl';r=p.read_text().splitlines();first=json.loads(r[0]);first['payload']['path']='/tmp/other';r[0]=json.dumps(first);p.write_text('\n'.join(r)+'\n')
        payload={'rule_id':'r','ruleset_sha256':'e'*64,'severity':'High','confidence':'medium',
                 'evidence_tag':'VERIFIED','evidence_ref':[eid],
                 'detection_id':'a'*64,'chain_anchor':a}
        with self.assertRaises(B.BusError):
            B.append_event('detect-1','detection_feedback',payload,self.priv['detect-1'],
                           dedupe_key='detection_id',chain_anchor=a)

    def test_25_concurrent_writers_serialized(self):
        writers,count=25,10
        ctx=mp.get_context('fork')
        q=ctx.Queue()
        procs=[ctx.Process(target=_worker,args=(str(self.root),i,count,q)) for i in range(writers)]
        for p in procs:p.start()
        for p in procs:p.join(40)
        for p in procs:
            if p.is_alive():p.terminate();p.join(5)
        outputs=[q.get(timeout=2) for _ in range(writers)]
        self.assertEqual(outputs.count(('ok',0)),1)
        self.assertTrue(all(x[0]=='ok' for x in outputs),outputs)
        self.assertTrue(all(p.exitcode==0 for p in procs))
        snap=B.verified_snapshot()
        self.assertEqual(snap['anchor']['count'],writers*count)
        ids=[r['event']['event_id'] for r in snap['records']]
        self.assertEqual(len(ids),len(set(ids)))
        self.assertEqual([r['event']['seq'] for r in snap['records']],list(range(1,writers*count+1)))

if __name__=='__main__':unittest.main()
