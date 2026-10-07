import unittest
from orchestrator.linux_candidate import LinuxDevelopmentWorker, CandidateImportWorker
from orchestrator.model import Operation


class LinuxDevelopmentTests(unittest.TestCase):
    def test_candidate_root_and_exact_commands_are_closed(self):
        worker = LinuxDevelopmentWorker('configured-alias', '/approved/dev/candidate', '/approved/dev', 'a'*40, 'origin', 'dev/candidate')
        allowed = Operation('core', ('dotnet','run','--project','HostsGuardian.RegressionTests'), '/approved/dev/candidate', category='owned-development')
        self.assertFalse(worker.approval_required(allowed))
        self.assertFalse(worker.approval_required(Operation('package',('python3','development/roadmap/build-candidate.py'),allowed.cwd,category='owned-development')))
        for command in [('sudo','anything'), ('systemctl','daemon-reload'), ('git','push'), ('python3','-c','arbitrary')]:
            self.assertTrue(worker.approval_required(Operation('denied', command, allowed.cwd, category='owned-development')))
        self.assertTrue(worker.approval_required(Operation('outside',allowed.argv,'/production',category='owned-development')))
        with self.assertRaises(ValueError): LinuxDevelopmentWorker('configured-alias','/production','/approved/dev','a'*40,'origin','dev/candidate')
    def test_handoff_allows_only_its_bound_import_operation(self):
        worker = CandidateImportWorker('configured-alias','/approved/dev','fixed code')
        self.assertFalse(worker.approval_required(Operation('import',('candidate-import',),'/approved/dev',category='owned-development')))
        self.assertTrue(worker.approval_required(Operation('import',('candidate-import',),'/production',category='owned-development')))
        self.assertTrue(worker.approval_required(Operation('arbitrary',('python3','-c','code'),'/approved/dev',category='owned-development')))


if __name__=='__main__': unittest.main()
