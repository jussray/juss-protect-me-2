"""Synthetic unit tests: no real filesystem containment or external network."""
from __future__ import annotations
import base64
import contextlib
from datetime import timedelta
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
import actuator_guard as guard
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'detection'))
A=guard.GRANT
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class ActuatorPreflightTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root=Path(t.name)
        self.scope=self.root/'app';self.scope.mkdir()
        self.sec=self.scope/'secrets';self.sec.mkdir()
        self.target=self.scope/'example.txt';self.target.write_bytes(b'synthetic fixture\n')
        self.secret=self.sec/'secret.txt';self.secret.write_bytes(b'fake fixture\n')
        self.grants=self.root/'grants';self.grants.mkdir(mode=0o700)
        self.trust=self.root/'trusted.json'
        key=Ed25519PrivateKey.generate()
        self.key=self.root/'alice.pem'
        self.key.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        self.key.chmod(0o600)
        pub=base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode()
        self.trust.write_text(json.dumps({'signers':[{'decider':'alice','public_key_b64':pub,
         'authority':{'action_classes':['quarantine_file','block_deploy'], 'max_blast_radius':2,
         'target_scopes':[str(self.scope)],'excluded_paths':[str(self.sec)],
         'min_detection_severity':'High','min_evidence_tag':'VERIFIED',
         'expires_at':A.iso(A.utc_now()+timedelta(hours=2)),
         'can_delegate':False,'max_delegation_depth':0}}]}))
        self.trust.chmod(0o600)
        env=(os.environ.get('MEDUSA_GRANTS_DIR'),os.environ.get('MEDUSA_TRUSTED_SIGNERS'))
        self.addCleanup(lambda: self._restore_env(env))
        os.environ['MEDUSA_GRANTS_DIR']=str(self.grants)
        os.environ['MEDUSA_TRUSTED_SIGNERS']=str(self.trust)
        self._issue('quarantine_file','g-quarantine')
        self.event={'event':{'event_id':'d1','event_type':'detection_feedback',
           'sensor_id':'detect-1','observed_at':A.iso(A.utc_now())},
           'payload':{'rule_id':'fs-001','ruleset_sha256':'0'*64,
           'severity':'High','evidence_tag':'VERIFIED','evidence_ref':['evt1'],
           'target_paths':[str(self.target)]}}

    @staticmethod
    def _restore_env(old):
        for name,value in zip(('MEDUSA_GRANTS_DIR','MEDUSA_TRUSTED_SIGNERS'),old):
            if value is None: os.environ.pop(name,None)
            else: os.environ[name]=value

    def _issue(self,action,gid):
        with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            code=A.main(['issue','--decider','alice','--key',str(self.key),
              '--grant-id',gid,'--action-class',action,'--target-scope',str(self.scope),
              '--exclude',str(self.sec),'--blast-radius','1','--hours','1'])
        self.assertEqual(code,0)

    def assess(self,ev=None,target=None,grant='g-quarantine'):
        return guard.review(grant,str(self.target) if target is None else str(target),
                            self.event if ev is None else ev)

    def test_eligible_claim_still_holds_without_signed_bus(self):
        before=self.target.read_bytes()
        r=self.assess()
        self.assertEqual((r['status'],r['reason']),("HOLD","NO_SIGNED_EVENT_BUS"))
        self.assertEqual(self.target.read_bytes(),before)
        self.assertFalse(r['effect_executed'])
        self.assertFalse(r['undo_token_issued'])
        self.assertNotIn('target',r)

    def test_inferred_never_auto_authorizes(self):
        e=json.loads(json.dumps(self.event));e['payload']['evidence_tag']='INFERRED'
        self.assertEqual(self.assess(e)['reason'],'NO_VERIFIED_EVENT_EVIDENCE')

    def test_no_source_references(self):
        e=json.loads(json.dumps(self.event));e['payload']['evidence_ref']=[]
        self.assertEqual(self.assess(e)['reason'],'MISSING_EVIDENCE_REFERENCES')

    def test_duplicate_and_self_reference_rejected(self):
        for refs in (['evt1','evt1'],['d1']):
            e=json.loads(json.dumps(self.event));e['payload']['evidence_ref']=refs
            self.assertEqual(self.assess(e)['reason'],'BAD_EVIDENCE_REFERENCES')

    def test_wrong_raw_event_type(self):
        e=json.loads(json.dumps(self.event));e['event']['event_type']='fs_change'
        self.assertEqual(self.assess(e)['reason'],'NOT_DETECTION_FEEDBACK')

    def test_unbound_target(self):
        e=json.loads(json.dumps(self.event));e['payload']['target_paths']=[]
        self.assertEqual(self.assess(e)['reason'],'TARGET_NOT_BOUND_TO_DETECTION')

    def test_different_target_refused_even_inside_scope(self):
        alternative=self.scope/'other.txt';alternative.write_bytes(b'other synthetic file')
        self.assertEqual(self.assess(target=alternative)['reason'],'TARGET_NOT_BOUND_TO_DETECTION')

    def test_out_of_scope_refused(self):
        outside=self.root/'outside.txt';outside.write_bytes(b'not in scope')
        self.assertEqual(self.assess(target=outside)['reason'],'TARGET_OUT_OF_SCOPE')

    def test_excluded_path_refused(self):
        self.assertEqual(self.assess(target=self.secret)['reason'],'TARGET_EXCLUDED')

    def test_symlink_refused(self):
        shortcut=self.scope/'link.txt';shortcut.symlink_to(self.target)
        self.assertEqual(self.assess(target=shortcut)['reason'],'SYMLINK_OR_ALIAS')

    def test_hardlink_refused(self):
        companion=self.scope/'alias.txt'
        os.link(self.target,companion)
        self.assertEqual(self.assess()['reason'],'NOT_SINGLE_LINK_REGULAR_FILE')

    def test_directories_refused(self):
        self.assertEqual(self.assess(target=self.scope)['reason'],'NOT_SINGLE_LINK_REGULAR_FILE')

    def test_wrong_threshold_refused(self):
        e=json.loads(json.dumps(self.event));e['payload']['severity']='Low'
        self.assertEqual(self.assess(e)['reason'],'BELOW_SEVERITY_THRESHOLD')

    def test_old_and_future_detections_blocked(self):
        for delta in (-700,+700):
            e=json.loads(json.dumps(self.event))
            e['event']['observed_at']=A.iso(A.utc_now()+timedelta(seconds=delta))
            self.assertEqual(self.assess(e)['reason'],'STALE_OR_FUTURE_DETECTION')

    def test_wrong_ruleset_hash_blocked(self):
        e=json.loads(json.dumps(self.event));e['payload']['ruleset_sha256']='abc'
        self.assertEqual(self.assess(e)['reason'],'MISSING_RULE_HASH')

    def test_inert_for_other_declared_action(self):
        self._issue('block_deploy','g-deploy')
        self.assertEqual(self.assess(grant='g-deploy')['reason'],'ACTION_NOT_IMPLEMENTED')

    def test_revoke_checked_at_review_time(self):
        with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(A.main(['revoke','g-quarantine','--decider','alice','--key',str(self.key)]),0)
        r=self.assess()
        self.assertEqual(r['status'],'BLOCKED')
        self.assertEqual(r['reason'],'INVALID_GRANT_OR_LOCAL_STATE')

    def test_signed_grant_tampering_blocks(self):
        gp=self.grants/'g-quarantine.grant.json';doc=json.loads(gp.read_text());doc['max_blast_radius']=300
        gp.write_text(json.dumps(doc))
        self.assertEqual(self.assess()['reason'],'INVALID_GRANT_OR_LOCAL_STATE')

    def test_cli_is_diagnostic_and_does_not_write(self):
        evidence=self.root/'detection.json'
        evidence.write_text(json.dumps(self.event))
        before={p.relative_to(self.root).as_posix():p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        with contextlib.redirect_stdout(io.StringIO()) as o:
            code=guard.main(['inspect','--grant','g-quarantine','--target',str(self.target),
                             '--detection',str(evidence)])
        self.assertEqual(code,2)
        self.assertEqual(json.loads(o.getvalue())['status'],'HOLD')
        after={p.relative_to(self.root).as_posix():p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        self.assertEqual(before,after)

    def test_missing_grant_store_is_not_created(self):
        import shutil
        shutil.rmtree(self.grants)
        self.assertEqual(self.assess()['reason'], 'GRANT_STORE_MISSING_OR_UNSAFE')
        self.assertFalse(self.grants.exists())

    def test_symlink_grant_store_refused(self):
        moved = self.root / 'actual_grants'
        self.grants.rename(moved)
        self.grants.symlink_to(moved)
        self.assertEqual(self.assess()['reason'], 'GRANT_STORE_MISSING_OR_UNSAFE')


    def _setup_bus_inputs(self):
        import eventbus as B
        import bus_adapter as A
        keys = {}
        pubs = {}
        for sensor in ('fs-1','detect-1'):
            key = Ed25519PrivateKey.generate()
            p = self.root / (sensor + '.pem')
            p.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            p.chmod(0o600)
            keys[sensor] = str(p)
            pubs[sensor] = base64.b64encode(key.public_key().public_bytes(
                serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode()
        trust = self.root / 'sensors.json'
        trust.write_text(json.dumps({'sensors':pubs}));trust.chmod(0o600)
        prior = {k:os.environ.get(k) for k in ('MEDUSA_BUS_DIR','MEDUSA_TRUSTED_SENSORS')}
        self.addCleanup(lambda: self._restore_bus_env(prior))
        os.environ['MEDUSA_BUS_DIR'] = str(self.root / 'bus')
        os.environ['MEDUSA_TRUSTED_SENSORS'] = str(trust)
        return B,A,keys

    @staticmethod
    def _restore_bus_env(old):
        for k,v in old.items():
            if v is None:os.environ.pop(k,None)
            else:os.environ[k]=v

    def _real_feedback(self):
        B,A,keys = self._setup_bus_inputs()
        B.append_event('fs-1','fs_change',
            {'path':str(self.target),'action':'write'},keys['fs-1'])
        rules=[{'ruleset_id':'synthetic','version':'1','rules':[{
            'id':'fs-001','description':'synthetic fixture',
            'severity':'High','confidence':'medium','confidence_basis':'synthetic-only',
            'window_seconds':0,'when':{'event_type':'fs_change',
                'where':{'action':'write'},'path_glob':'**/example.txt'}}]}]
        out=A.run(rules,emit=True,emit_key=keys['detect-1'])
        self.assertEqual(len(out),1)
        feedback=[x for x in B.read_events() if x['event']['event_type']=='detection_feedback']
        self.assertEqual(len(feedback),1)
        return B,keys,feedback[0]['event']['event_id']

    def test_signed_bus_verified_feedback_still_holds(self):
        B,keys,eid=self._real_feedback()
        old=self.target.read_bytes()
        result=guard.review_signed_bus('g-quarantine',str(self.target),eid)
        self.assertEqual(result['status'],'HOLD')
        self.assertTrue(result['layer2_chain_verified'])
        self.assertFalse(result['releasable'])
        self.assertFalse(result['effect_executed'])
        self.assertEqual(self.target.read_bytes(),old)

    def test_signed_bus_unknown_event_blocks(self):
        self._real_feedback()
        result=guard.review_signed_bus('g-quarantine',str(self.target),'a'*64)
        self.assertEqual(result['reason'],'SIGNED_DETECTION_NOT_FOUND')
        self.assertEqual(result['status'],'BLOCKED')

    def test_signed_bus_tampered_source_blocks(self):
        B,keys,eid=self._real_feedback()
        ledger=self.root/'bus'/'events.jsonl'
        lines=ledger.read_text().splitlines()
        changed=json.loads(lines[0]);changed['payload']['path']='/tampered'
        lines[0]=json.dumps(changed)
        ledger.write_text('\n'.join(lines)+'\n')
        result=guard.review_signed_bus('g-quarantine',str(self.target),eid)
        self.assertEqual(result['status'],'BLOCKED')
        self.assertEqual(result['reason'],'INVALID_SIGNED_EVENT_BUS')
        self.assertTrue(self.target.exists())

    def test_signed_bus_forged_target_claim_blocks(self):
        B,A,keys=self._setup_bus_inputs()
        eid=B.append_event('fs-1','fs_change',
            {'path':str(self.scope/'unrelated.txt'),'action':'write'},keys['fs-1'])
        anchor=B.verified_snapshot()['anchor']
        payload={'rule_id':'fs-001','ruleset_sha256':'b'*64,
                 'severity':'High','confidence':'medium','evidence_tag':'VERIFIED',
                 'evidence_ref':[eid],'detection_id':'a'*64,
                 'target_paths':[str(self.target)],'chain_anchor':anchor}
        feedback=B.append_event('detect-1','detection_feedback',
             payload,keys['detect-1'],dedupe_key='detection_id',chain_anchor=anchor)
        result=guard.review_signed_bus('g-quarantine',str(self.target),feedback)
        self.assertEqual(result['reason'],'TARGETS_NOT_DERIVED_FROM_SIGNED_SOURCES')
        self.assertEqual(result['status'],'BLOCKED')

    def test_signed_bus_cli_never_allows(self):
        B,keys,eid=self._real_feedback()
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc=guard.main(['inspect-bus','--grant','g-quarantine','--target',
                 str(self.target),'--detection-event',eid])
        self.assertEqual(rc,2)
        self.assertEqual(json.loads(out.getvalue())['status'],'HOLD')

    def test_no_effect_capability(self):
        self.assertFalse(hasattr(guard,'execute'))
        self.assertFalse(hasattr(guard,'undo'))
        self.assertFalse(hasattr(guard,'quarantine'))

if __name__=='__main__':unittest.main()
