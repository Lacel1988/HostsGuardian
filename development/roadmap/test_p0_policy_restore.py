import copy
import unittest
import tempfile
import json
import hashlib
from pathlib import Path
from prepare_recovery_session import write_session
from p0_policy_restore import restore,Conflict,make_session,validate_scope


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
        for approved in ([],[['unknown','youtube.com']],[['a','*.other.com']]):
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
    def test_four_domain_absent_and_explicit_exact_restore(self):
        for state in (None,'Inherit','Allow','Block'):
            session=self.session()
            session['approvedOverrides']=[['a',d] for d in ('youtube.com','googlevideo.com','ytimg.com','youtubei.googleapis.com')]
            if state is not None:session['original']['policy']['overrides'].append(dict(deviceId='a',domain='googlevideo.com',state=state))
            api=self.api(session)
            api.policy['overrides']=[r for r in api.policy['overrides'] if r['domain']!='googlevideo.com']
            api.policy['overrides'].extend(dict(deviceId='a',domain=d,state='Block') for d in ('googlevideo.com','ytimg.com','youtubei.googleapis.com'))
            self.assertTrue(restore(session,api)['restored'])
            self.assertEqual(api.policy,session['original']['policy'])
            self.assertTrue(restore(session,api)['alreadyOriginal'])
    def test_partial_exact_wpf_restore_only_remaining_rules(self):
        session=self.session();session['approvedOverrides']=[['a',d] for d in ('youtube.com','googlevideo.com','ytimg.com','youtubei.googleapis.com')]
        session['original']['policy']['overrides'].append(dict(deviceId='a',domain='ytimg.com',state='Allow'))
        api=self.api(session,False) # youtube Inherit and absent googlevideo already restored
        api.policy['overrides']=[r for r in api.policy['overrides'] if r['domain']!='ytimg.com']
        api.policy['overrides'].extend(dict(deviceId='a',domain=d,state='Block') for d in ('ytimg.com','youtubei.googleapis.com'))
        self.assertTrue(restore(session,api)['restored']);self.assertEqual(api.policy,session['original']['policy'])
    def test_absent_is_not_replaced_by_explicit_inherit_workaround(self):
        session=self.session();session['approvedOverrides'].append(['a','googlevideo.com']);api=self.api(session)
        api.policy['overrides'].append(dict(deviceId='a',domain='googlevideo.com',state='Inherit'))
        with self.assertRaises(Conflict):restore(session,api)
        self.assertEqual(api.posts,0)
    def test_second_device_scope_rejected(self):
        session=self.session();session['approvedOverrides'].append(['b','ytimg.com']);api=self.api(session)
        with self.assertRaises(Conflict):restore(session,api)
        self.assertEqual(api.posts,0)

    def test_generic_domain_exact_states_and_partial_restore(self):
        for state in (None,'Inherit','Allow','Block'):
            session=self.session()
            if state is not None:session['original']['policy']['overrides'].append(dict(deviceId='a',domain='index.hu',state=state))
            session=make_session(session['original'],{},'a',['index.hu','www.index.hu'])
            api=self.api(session,False)
            api.policy['overrides']=[r for r in api.policy['overrides'] if r['domain']!='index.hu']
            api.policy['overrides'].append(dict(deviceId='a',domain='index.hu',state='Block'))
            self.assertTrue(restore(session,api)['restored'])
            self.assertEqual(api.policy,session['original']['policy'])
            self.assertTrue(restore(session,api)['alreadyOriginal'])
            self.assertEqual(api.posts,0 if state=='Block' else 1)

    def test_generic_scope_malformed_and_duplicates_rejected_before_api(self):
        for rows in ([['a','index.hu'],['a','index.hu']], [['a','INDEX.HU']],
                     [['a','index.hu.']], [['a','192.168.1.1']], [['a','a..hu']],
                     [['a','-bad.hu']], [['a','https://index.hu']], [['a','index.hu','Block']],
                     ['a'], [['a','index.hu']]*65):
            session=self.session();session['approvedOverrides']=rows;api=self.api(session)
            with self.assertRaises(Conflict):restore(session,api)
            self.assertEqual(api.posts,0)

    def test_original_ledger_cannot_redefine_absent_as_inherit(self):
        session=make_session(self.session()['original'],{},'a',['index.hu'])
        self.assertIsNone(session['originalOverrideStates'][0]['original'])
        session['originalOverrideStates'][0]['original']=dict(deviceId='a',domain='index.hu',state='Inherit')
        with self.assertRaises(Conflict):validate_scope(session)

    def test_generic_failed_post_and_readback_retry_preserves_other_policy(self):
        session=make_session(self.session()['original'],{},'a',['index.hu'])
        api=self.api(session,False);api.policy['overrides'].append(dict(deviceId='a',domain='index.hu',state='Block'))
        original=api.call
        def failure(path,body=None):
            if body is not None:raise OSError('Unavailable')
            return original(path,body)
        api.call=failure
        with self.assertRaises(OSError):restore(session,api)
        self.assertEqual(api.policy['overrides'][-1]['state'],'Block')
        api.call=original
        self.assertTrue(restore(session,api)['restored'])
        self.assertEqual(api.policy,session['original']['policy'])

    def test_new_session_file_exclusive_pinned_and_absent_ledger(self):
        session=make_session(self.session()['original'],{},'a',['index.hu'])
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'session.json'
            pin=write_session(path,session)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),pin)
            self.assertEqual(json.loads(path.read_bytes()),session)
            with self.assertRaises(FileExistsError):write_session(path,self.session())
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),pin)

    def test_ambiguous_registry_rejected_without_post(self):
        session=self.session();session['original']['policy']['devices'].append(dict(deviceId='a'))
        api=self.api(session)
        with self.assertRaises(Conflict):restore(session,api)
        self.assertEqual(api.posts,0)

    def test_generic_partial_absent_inherit_allow_and_control_isolation(self):
        base=self.session()['original']
        base['policy']['overrides'].extend([dict(deviceId='a',domain='www.index.hu',state='Inherit'),
            dict(deviceId='a',domain='example.org',state='Allow'),dict(deviceId='b',domain='index.hu',state='Block')])
        session=make_session(base,{},'a',['index.hu','www.index.hu','example.org'])
        api=self.api(session,False)
        # Explicit Inherit is already restored; two session rules remain Block.
        api.policy['overrides']=[r for r in api.policy['overrides'] if (r['deviceId'],r['domain'])!=('a','example.org')]
        api.policy['overrides'].extend(dict(deviceId='a',domain=d,state='Block') for d in ['index.hu','example.org'])
        self.assertTrue(restore(session,api)['restored'])
        self.assertEqual(api.policy,base['policy'])

    def test_generic_session_cas_conflict_never_forces_restore(self):
        session=make_session(self.session()['original'],{},'a',['index.hu'])
        api=self.api(session,False);api.policy['overrides'].append(dict(deviceId='a',domain='index.hu',state='Block'))
        original=api.call
        def racing(path,body=None):
            if body is not None:api.revision+=1
            return original(path,body)
        api.call=racing
        with self.assertRaises(Conflict):restore(session,api)
        self.assertEqual(api.policy['overrides'][-1]['state'],'Block')
