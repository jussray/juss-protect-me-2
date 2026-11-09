import copy, json, pathlib, unittest
from datetime import datetime,timezone,timedelta
import detect_core as d
BASE=datetime(2026,11,8,12,0,tzinfo=timezone.utc)

def ev(i, action='write',path='/srv/app/.env',kind='fs_change',sensor='fs-1',sec=0):
    return dict(event_id=str(i),event_type=kind,sensor_id=sensor,observed_at=(BASE+timedelta(seconds=sec)).isoformat(),payload={'path':path,'action':action})

def rule(when,**kw):
    return {'id':'r1','description':'demo','severity':'High','confidence':'medium','confidence_basis':'factual match only','window_seconds':0,'when':when,**kw}

def doc(r):return {'ruleset_id':'fs','version':'1','rules':[r]}
class DetectionTests(unittest.TestCase):
    def test_conjunction_all_keys(self):
        r=rule({'event_type':'fs_change','where':{'action':'write'}})
        self.assertFalse(d.detect([ev('a',action='read')],[doc(r)]))
        self.assertEqual(d.detect([ev('a')],[doc(r)])[0]['evidence_ref'],['a'])
    def test_no_blind_verified_promotion(self):
        hit=d.detect([ev('a')],[doc(rule({'event_type':'fs_change'}))])[0]
        self.assertEqual(hit['evidence_tag'],'INFERRED')
    def test_critical_no_match_in_ci(self):
        rulefile=json.loads((pathlib.Path(__file__).parent/'rules.filesystem.json').read_text())
        self.assertEqual(d.detect([ev('a',sensor='ci-runner')],[{'ruleset_id':'fs','version':'1','rules':[rulefile['rules'][0]]}]),[])
    def test_unknown_predicate_rejected(self):
        with self.assertRaisesRegex(d.DetectionError,'unknown predicate'):d.detect([ev('a')],[doc(rule({'execute':'command'}))])
    def test_glob_and_unicode_paths(self):
        self.assertTrue(d.detect([ev('a')],[doc(rule({'path_glob':'**/.env'}))]))
    def test_duplicate_event_rejected(self):
        with self.assertRaisesRegex(d.DetectionError,'duplicate'):d.detect([ev('a'),ev('a')],[doc(rule({'event_type':'fs_change'}))])
    def test_ruleset_hash_stable(self):
        doc1=doc(rule({'event_type':'fs_change'}));doc2=copy.deepcopy(doc1)
        self.assertEqual(d.detect([ev('a')],[doc1]),d.detect([ev('a')],[doc2]))
    def test_ruleset_hash_changes_with_rule(self):
        a=doc(rule({'event_type':'fs_change'}));b=copy.deepcopy(a);b['rules'][0]['confidence_basis']='new reason'
        self.assertNotEqual(d.detect([ev('a')],[a])[0]['ruleset_sha256'],d.detect([ev('a')],[b])[0]['ruleset_sha256'])
    def test_baseline_absent_fail_closed(self):
        with self.assertRaisesRegex(d.DetectionError,'baseline absent'):d.detect([ev('a')],[doc(rule({'not_in_baseline':'path','baseline':'b','match':{'event_type':'fs_change'}}))])
    def test_baseline_novel_and_not_novel(self):
        r=doc(rule({'not_in_baseline':'path','baseline':'b','match':{'event_type':'fs_change'}}))
        self.assertEqual(d.detect([ev('a')],[r],{'b':['/srv/app/.env']}),[])
        self.assertEqual(d.detect([ev('a',path='/new')],[r],{'b':['/srv/app/.env']})[0]['evidence_ref'],['a'])
    def test_sequence_order_and_distinct_sensors(self):
        q={'sequence':[{'event_type':'auth_failure'},{'event_type':'privilege_change'}],'distinct_sensors':True}
        events=[ev('1',kind='auth_failure',sensor='auth-1',sec=2),ev('2',kind='privilege_change',sensor='sec-2',sec=5)]
        r=doc(rule(q,window_seconds=60))
        self.assertEqual(d.detect(events,[r])[0]['evidence_ref'],['1','2'])
        self.assertEqual(d.detect(events[::-1],[r])[0]['evidence_ref'],['1','2'])
        self.assertEqual(d.detect([ev('1',kind='privilege_change',sec=2),ev('2',kind='auth_failure',sec=5)],[r]),[])
        self.assertEqual(d.detect([ev('1',kind='auth_failure',sensor='s',sec=2),ev('2',kind='privilege_change',sensor='s',sec=5)],[r]),[])
    def test_sequence_window(self):
        r=doc(rule({'sequence':[{'event_type':'auth_failure'},{'event_type':'privilege_change'}]},window_seconds=30))
        self.assertEqual(d.detect([ev('a',kind='auth_failure',sec=0),ev('b',kind='privilege_change',sec=80)],[r]),[])
    def test_count_full_witness(self):
        r=doc(rule({'count':{'match':{'event_type':'fs_change','where':{'action':'write'}},'threshold':100,'group_by':'path_prefix'}},window_seconds=60))
        events=[ev(str(i),path=f'/srv/app/x{i}',sec=i%30) for i in range(101)]
        hit=d.detect(events,[r])[0]
        self.assertEqual(len(hit['evidence_ref']),101);self.assertEqual(hit['count'],101)
    def test_count_cannot_use_mixed_directories(self):
        r=doc(rule({'count':{'match':{'event_type':'fs_change'},'threshold':100,'group_by':'path_prefix'}},window_seconds=60))
        events=[ev(str(i),path=f'/srv/{i%2}/x',sec=i%30) for i in range(101)]
        self.assertEqual(d.detect(events,[r]),[])
    def test_invalid_timestamp_fails_closed(self):
        e=ev('a');e['observed_at']='yesterday'
        with self.assertRaises(d.DetectionError):d.detect([e],[doc(rule({'event_type':'fs_change'}))])
    def test_duplicate_rule_rejected(self):
        r=rule({'event_type':'fs_change'})
        with self.assertRaisesRegex(d.DetectionError,'duplicate'):d.detect([ev('a')],[{'ruleset_id':'fs','version':'1','rules':[r,r]}])
    def test_pure_does_not_mutate_inputs(self):
        es=[ev('a')];rs=[doc(rule({'event_type':'fs_change'}))];b={'b':['x']}
        saved=copy.deepcopy((es,rs,b));d.detect(es,rs,b);self.assertEqual((es,rs,b),saved)
    def test_limits_fail_closed(self):
        with self.assertRaises(d.DetectionError):d.detect([ev(str(i)) for i in range(d.MAX_EVENTS+1)],[doc(rule({'event_type':'fs_change'}))])
    def test_predicate_node_budget_refuses_wide_rule(self):
        broad={'all':[{'all':[{'event_type':'fs_change'} for _ in range(10)]}
                      for _ in range(5)]}
        with self.assertRaisesRegex(d.DetectionError,'predicate node budget'):
            d.detect([ev('a')],[doc(rule(broad))])

    def test_detection_size_budget_refuses_full_witness_without_truncation(self):
        # Full evidence remains required; huge IDs cannot be quietly truncated.
        matches=[ev(('x'*100)+str(i).zfill(4)) for i in range(900)]
        with self.assertRaisesRegex(d.DetectionError,'detection exceeds size budget'):
            d.detect(matches,[doc(rule({'event_type':'fs_change'}))])

    def test_match_budget_fails_closed(self):
        many=[ev(str(i)) for i in range(3000)]
        r=doc(rule({'all':[{'event_type':'fs_change'} for _ in range(12)]}))
        with self.assertRaisesRegex(d.DetectionError,'rule match budget exceeded'):
            d.detect(many,[r])

    def test_no_actuator_import(self):
        import inspect
        source=inspect.getsource(d)
        self.assertNotIn('import authority_grant',source)
        self.assertNotIn('import eventbus',source)
        self.assertNotIn('socket.',source)
if __name__=='__main__':unittest.main()
