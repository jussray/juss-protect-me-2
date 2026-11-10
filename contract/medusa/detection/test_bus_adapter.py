"""Signed bus to pure detector to signed feedback tests; no actuator."""
from __future__ import annotations
import base64, json, os, sys, tempfile, unittest
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
import eventbus as B
import bus_adapter as A

RULES=[{'ruleset_id':'filesystem-test','version':'1',
'rules':[{'id':'env-write','description':'synthetic sensitive file write',
'severity':'High','confidence':'medium','confidence_basis':'exact event+path glob match',
'window_seconds':0,'when':{'event_type':'fs_change','where':{'action':'write'},'path_glob':'**/.env'}}]}]

class AdapterTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory(prefix='medusa-integrate-');self.addCleanup(t.cleanup)
        self.root=Path(t.name)
        keys={};self.files={}
        for sid in ['fs-1','detect-1']:
            key=Ed25519PrivateKey.generate();p=self.root/(sid+'.pem')
            p.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));p.chmod(0o600)
            keys[sid]=base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode()
            self.files[sid]=str(p)
        trust=self.root/'trusted.json';trust.write_text(json.dumps({'sensors':keys}));trust.chmod(0o600)
        old={k:os.environ.get(k) for k in ('MEDUSA_BUS_DIR','MEDUSA_TRUSTED_SENSORS')}
        self.addCleanup(lambda: [(os.environ.pop(k,None) if v is None else os.environ.__setitem__(k,v)) for k,v in old.items()])
        os.environ['MEDUSA_BUS_DIR']=str(self.root/'bus');os.environ['MEDUSA_TRUSTED_SENSORS']=str(trust)

    def source(self,path='/srv/app/.env',action='write'):
        return B.append_event('fs-1','fs_change',{'path':path,'action':action},self.files['fs-1'])

    def test_signed_end_to_end_and_idempotent_feedback(self):
        first=self.source();self.source('/srv/app/readme.txt');self.source('/srv/app/.env',action='read')
        findings=A.run(RULES,emit=True,emit_key=self.files['detect-1'])
        self.assertEqual(len(findings),1)
        hit=findings[0]
        self.assertEqual(hit['evidence_tag'],'VERIFIED')
        self.assertEqual(hit['evidence_ref'],[first])
        self.assertEqual(hit['target_paths'],['/srv/app/.env'])
        records=B.verified_snapshot()['records']
        feedback=[r for r in records if r['event']['event_type']=='detection_feedback']
        self.assertEqual(len(feedback),1)
        self.assertEqual(feedback[0]['payload']['detection_id'],hit['detection_id'])
        A.run(RULES,emit=True,emit_key=self.files['detect-1'])
        self.assertEqual(len([r for r in B.read_events() if r['event']['event_type']=='detection_feedback']),1)
        self.assertTrue(B.verify_snapshot_continuity(hit['chain_anchor'])['ok'])

    def test_mutating_chain_after_evaluate_blocks_emission(self):
        self.source();hits,anchor=A.evaluate(RULES)
        path=self.root/'bus/events.jsonl';lines=path.read_text().splitlines();rec=json.loads(lines[0]);rec['payload']['path']='/srv/other';lines[0]=json.dumps(rec);path.write_text('\n'.join(lines)+'\n')
        with self.assertRaises(B.BusError):
            B.append_event('detect-1','detection_feedback',hits[0],self.files['detect-1'],dedupe_key='detection_id',chain_anchor=anchor)

    def test_concurrent_append_after_evaluate_preserves_anchor(self):
        self.source();hits,anchor=A.evaluate(RULES)
        self.source('/srv/app/other.txt')
        self.assertTrue(B.verify_snapshot_continuity(anchor)['ok'])
        B.append_event('detect-1','detection_feedback',hits[0],self.files['detect-1'],
                       dedupe_key='detection_id',chain_anchor=anchor)
        self.assertEqual(B.verified_snapshot()['anchor']['count'],3)

    def test_equal_timestamps_ambiguous_sequence_fails_closed(self):
        stamp='2026-11-08T12:00:00Z'
        B.append_event('fs-1','fs_change',{'path':'/srv/app/a','action':'write'},self.files['fs-1'],observed_at=stamp)
        B.append_event('fs-1','fs_change',{'path':'/srv/app/b','action':'write'},self.files['fs-1'],observed_at=stamp)
        seq=[{'ruleset_id':'s','version':'1','rules':[{
            'id':'seq','description':'synthetic sequence','severity':'Low','confidence':'low',
            'confidence_basis':'synthetic','window_seconds':60,
            'when':{'sequence':[{'event_type':'fs_change'},{'event_type':'fs_change'}]}}]}]
        with self.assertRaisesRegex(B.BusError,'ambiguous equal timestamps'):
            A.run(seq)

    def test_anomaly_remains_inferred_with_signed_source(self):
        self.source('/srv/app/never-seen')
        anomaly=[{'ruleset_id':'anomaly','version':'1','rules':[{
           'id':'unseen','description':'not in baseline','severity':'Low','confidence':'low',
           'confidence_basis':'baseline absence','window_seconds':0,
           'when':{'not_in_baseline':'path','baseline':'known','match':{'event_type':'fs_change'}}}]}]
        findings=A.run(anomaly,{'known':[]},emit=True,emit_key=self.files['detect-1'])
        self.assertEqual(findings[0]['evidence_tag'],'INFERRED')
        self.assertEqual([r['payload']['evidence_tag'] for r in B.read_events() if r['event']['event_type']=='detection_feedback'],['INFERRED'])

    def test_unsigned_data_never_promoted(self):
        # The core remains advisory and does NOT accept claims of signature truth.
        event={'event_id':'fake','event_type':'fs_change','sensor_id':'fs-1',
               'observed_at':'2026-11-08T01:00:00Z','payload':{'path':'/srv/app/.env','action':'write'}}
        import detect_core as CORE
        self.assertEqual(CORE.detect([event],RULES)[0]['evidence_tag'],'INFERRED')

    def test_no_source_sensor_registration_fails_closed(self):
        trust=self.root/'trusted.json';obj=json.loads(trust.read_text());del obj['sensors']['fs-1'];trust.write_text(json.dumps(obj));trust.chmod(0o600)
        with self.assertRaises(B.BusError):self.source()

if __name__=='__main__':unittest.main()
