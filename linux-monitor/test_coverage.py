import unittest
from operations import overview
class CoverageTests(unittest.TestCase):
    def test_listener_and_coverage_are_separate_and_unknown_is_not_green(self):
        unit={'ActiveState':'active','SubState':'running','MainPID':1}
        status={'udpState':'Listening','tcpState':'Listening','managementState':'Listening','policyLoaded':True}
        for state in ('UNKNOWN','PARTIAL','COMPLETE','invented'):
            status.update(ipv6UdpState='Faulted',ipv6TcpState='Listening',coverage={'state':state})
            value=overview(unit,{'status':status})
            self.assertIn('IPv6 UDP Faulted',value['dns'])
            self.assertIn('DNS coverage: '+(state if state!='invented' else 'UNKNOWN'),value['evidence'])
            self.assertEqual(value['health'],'Unknown')
        self.assertEqual(status['policyLoaded'],True)
