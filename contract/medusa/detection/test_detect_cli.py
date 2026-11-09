import contextlib,io,json,tempfile,unittest
from pathlib import Path
from detect import main

RULES={'ruleset_id':'r','version':'1','rules':[{'id':'s','description':'demo','severity':'High','confidence':'medium','confidence_basis':'test','window_seconds':0,'when':{'event_type':'fs_change','where':{'action':'write'}}}]}
EVENTS=[{'event_id':'a','event_type':'fs_change','sensor_id':'s','observed_at':'2026-11-08T00:00:00Z','payload':{'action':'write'}}]
class CLITests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        p=Path(tmp.name);self.events=p/'events.json';self.rules=p/'rules.json'
        self.events.write_text(json.dumps(EVENTS));self.rules.write_text(json.dumps(RULES))
    def call(self,*args):
        with contextlib.redirect_stdout(io.StringIO()) as out,contextlib.redirect_stderr(io.StringIO()) as err:
            rc=main(list(args))
        return rc,out.getvalue(),err.getvalue()
    def test_valid_report_is_advisory(self):
        rc,out,_=self.call('run','--events',str(self.events),'--rules',str(self.rules),'--json')
        self.assertEqual(rc,0);self.assertEqual(json.loads(out)['authority'],'NONE');self.assertEqual(json.loads(out)['count'],1)
    def test_bad_snapshot_exits_two(self):
        self.events.write_text('{');self.assertEqual(self.call('run','--events',str(self.events),'--rules',str(self.rules))[0],2)
    def test_symlink_is_refused(self):
        link=self.events.with_name('link.json');link.symlink_to(self.events)
        self.assertEqual(self.call('run','--events',str(link),'--rules',str(self.rules))[0],2)
    def test_validate_mode(self):
        rc,out,_=self.call('validate','--rules',str(self.rules));self.assertEqual(rc,0);self.assertEqual(len(json.loads(out)['validated']),1)
if __name__=='__main__':unittest.main()
