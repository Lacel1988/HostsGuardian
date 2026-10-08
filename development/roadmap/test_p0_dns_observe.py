import datetime
import json
from pathlib import Path
import tempfile
import unittest
from p0_dns_observe import collect,Conflict


class ObserveTests(unittest.TestCase):
    def test_read_only_bounded_and_deduplicated_never_claims_response_proof(self):
        ticks=[0];calls=[];stamp=datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=1)
        class Fixture:
            def call(self,path):
                calls.append(path)
                if path.endswith('dns-observations'):return dict(observations=[dict(request=dict(receivedAtUtc=stamp.isoformat(),sourceAddress='192.0.2.20'),deviceId='fixture',blocked=True)])
                return {}
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'evidence.jsonl'
            result=collect(Fixture(),5,path,clock=lambda:ticks[0],pause=lambda x:ticks.__setitem__(0,ticks[0]+x))
            self.assertEqual(result['uniqueClientDecisions'],1);self.assertEqual(result['dnsResponseAcceptance'],'PENDING')
            self.assertEqual(len(path.read_text().splitlines()),3)
            self.assertTrue(all('/replace' not in p for p in calls))
    def test_missing_evidence_and_transport_failure_are_not_pass(self):
        class Fixture:
            def call(self,path):raise OSError('fixture unavailable')
        ticks=[0]
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'evidence'
            result=collect(Fixture(),5,path,clock=lambda:ticks[0],pause=lambda x:ticks.__setitem__(0,ticks[0]+x))
            self.assertEqual(result['uniqueClientDecisions'],0)
            self.assertEqual(json.loads(path.read_text().splitlines()[0])['errorType'],'OSError')
    def test_unbounded_window_rejected(self):
        for seconds in (0,301):
            with self.assertRaises(Conflict):collect(None,seconds,Path('not-created'))
