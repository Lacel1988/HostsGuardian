import copy
import unittest
from p0_policy_restore import restore,Conflict


class RecoveryTests(unittest.TestCase):
    def session(self):
        return dict(original=dict(policy=dict(globalBlockedDomains=[],devices=[dict(deviceId='a'),dict(deviceId='b')],overrides=[dict(deviceId='a',domain='youtube.com',state='Inherit')],program={})),approvedOverrides=[['a','youtube.com']])
    def api(self,session,changed=True):
        class Fixture:
            def __init__(self):
                self.policy=copy.deepcopy(session['original']['policy']);self.revision=23;self.posts=0
                if changed:self.policy['overrides'][0]['state']='Block'
            def call(self,path,body=None):
                if body is not None:
                    self.posts+=1
                    if body['expectedRevision']!=self.revision or body['expectedInstanceId']!='fixture':raise Conflict('CAS conflict')
                    self.revision+=1;self.policy=copy.deepcopy(body['policy']);return dict(ok=True,revision=self.revision)
                return dict(policy=copy.deepcopy(self.policy),revision=self.revision,instanceId='fixture')
        return Fixture()
    def test_exact_inherit_restore_and_idempotent_repeat(self):
        session=self.session();api=self.api(session)
        self.assertTrue(restore(session,api)['restored']);self.assertEqual(api.policy,session['original']['policy'])
        self.assertTrue(restore(session,api)['alreadyOriginal']);self.assertEqual(api.posts,1)
    def test_independent_retry_after_network_failure_restores_exact_original(self):
        session=self.session();api=self.api(session);original=api.call;calls=[0]
        def broken(*args):
            calls[0]+=1
            if calls[0]==1:raise OSError('Engine unavailable')
            return original(*args)
        api.call=broken
        with self.assertRaises(OSError):restore(session,api)
        self.assertTrue(restore(session,api)['restored'])
    def test_unrelated_global_registration_control_override_changes_are_not_overwritten(self):
        for field in ('global','registry','control'):
            session=self.session();api=self.api(session)
            if field=='global':api.policy['globalBlockedDomains']=['example.com']
            if field=='registry':api.policy['devices'].pop()
            if field=='control':api.policy['overrides'].append(dict(deviceId='b',domain='youtube.com',state='Block'))
            with self.assertRaises(Conflict):restore(session,api)
            self.assertEqual(api.posts,0)
    def test_missing_scope_and_unregistered_target_are_rejected(self):
        for approved in ([],[['unknown','youtube.com']],[['a','other.com']]):
            session=self.session();session['approvedOverrides']=approved;api=self.api(session)
            with self.assertRaises(Conflict):restore(session,api)
            self.assertEqual(api.posts,0)
    def test_ack_without_exact_readback_is_never_success(self):
        session=self.session();api=self.api(session);original=api.call
        def broken(path,body=None):
            if body is not None:return dict(ok=True,revision=24)
            return original(path,body)
        api.call=broken
        with self.assertRaises(Conflict):restore(session,api)
    def test_revision_race_fails_without_forced_overwrite(self):
        session=self.session();api=self.api(session);original=api.call
        def racing(path,body=None):
            if body is not None:api.revision+=1
            return original(path,body)
        api.call=racing
        with self.assertRaises(Conflict):restore(session,api)
