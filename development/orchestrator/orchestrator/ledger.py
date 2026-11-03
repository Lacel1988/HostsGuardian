"""Append-only, fsync-backed ledger. Recovery reads history; never replays commands."""
import json
import os
import hashlib
import math
import re
from pathlib import Path
from .model import now, Result
from .budget import checkpoint


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def evidence_hash(value):
    return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()


def strict_json(text):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('Duplicate evidence field')
            value[key] = item
        return value
    return json.loads(text, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite evidence')))


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def read_evidence(path):
    """Known evidence files only; never follow links or instantiate a writer."""
    path = Path(path).absolute()
    for part in (path, *path.parents):
        stat = part.lstat()
        require(not part.is_symlink() and not getattr(stat, 'st_file_attributes', 0) & 0x400,
                'Linked/reparse evidence is not supported')
    require(path.is_file(), 'Missing evidence file')
    checkpoint()
    value = path.read_bytes()
    checkpoint()
    return value


class Ledger:
    def __init__(self, path, observer=None, binding=None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.observer = observer
        self.sequence = len(self.read(self.path)) if self.path.exists() else 0
        self.binding = strict_json(canonical(binding)) if binding is not None else None
        self.head = '0' * 64
        self.raw_hash = hashlib.sha256()
        if self.binding is not None and self.sequence:
            raise ValueError('Managed evidence never resumes or appends to an existing ledger')

    def record(self, task, kind, message, worker=None, result=None):
        self.sequence += 1
        event = {'sequence': self.sequence, 'timestamp': now(), 'task_id': task.id,
                 'task_name': task.name, 'state': task.state, 'event': kind,
                 'worker': worker, 'operation': message, 'result': result,
                 'task': task.snapshot()}
        if self.binding is not None:
            checkpoint()
            event['run_binding'] = self.binding
            event['previous_hash'] = self.head
            event['event_hash'] = evidence_hash(event)
        line = json.dumps(event, ensure_ascii=False) + '\n'
        with self.path.open('a', encoding='utf-8', newline='\n' if self.binding is not None else None) as stream:
            stream.write(line)
            stream.flush()
            os.fsync(stream.fileno())
        if self.binding is not None:
            self.head = event['event_hash']
            self.raw_hash.update(line.encode('utf-8'))
            checkpoint()
        if self.observer:
            self.observer(event)

    @staticmethod
    def read(path):
        # A torn final record is reported as corruption, never silently discarded.
        return [strict_json(line) for line in Path(path).read_text(encoding='utf-8').splitlines()]

    def verify_live(self, summary=None, result=None):
        if summary is not None:
            summary = strict_json(canonical(summary))
        raw = read_evidence(self.path)
        require(hashlib.sha256(raw).hexdigest() == self.raw_hash.hexdigest(),
                'Raw ledger bytes differ from the live writer anchor')
        events = self._events(raw)
        require(len(events) == self.sequence and events[-1]['event_hash'] == self.head,
                'Ledger differs from the live writer anchor')
        return self._validate(events, self.binding, summary, result)

    @staticmethod
    def _events(raw):
        require(raw.endswith(b'\n'), 'Torn or missing ledger terminator')
        events = [strict_json(line) for line in raw.decode('utf-8').splitlines()]
        require(bool(events), 'Empty evidence chain')
        previous = '0' * 64
        for index, event in enumerate(events, 1):
            checkpoint()
            require(type(event) is dict and type(event.get('sequence')) is int and event['sequence'] == index,
                    'Missing, reordered or duplicate ledger record')
            payload = {k: v for k, v in event.items() if k != 'event_hash'}
            require(event.get('previous_hash') == previous and event.get('event_hash') == evidence_hash(payload),
                    'Ledger hash chain mismatch')
            previous = event['event_hash']
        return events

    @staticmethod
    def _validate(events, binding, summary=None, result=None):
        """One managed operation's evidence protocol, not a second executor."""
        def valid_hash(value):
            return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None
        def check_binding(value):
            require(type(value) is dict, 'Missing evidence binding')
            auth, op, ws = value['authorization'], value['operation'], value['workspace']
            require(value['operation_identity'] == evidence_hash({'operation': op, 'payload_sha256': value['payload_sha256']}),
                    'Operation identity mismatch')
            require(value['authorization_identity'] == evidence_hash(auth), 'Authorization identity mismatch')
            for key in ('operation_identity', 'profile_identity', 'source_identity'):
                require(valid_hash(value[key]) and auth[key] == value[key], 'Authorization/source binding mismatch')
            require(bool(auth['id']) and bool(auth['evidence_refs']) and op['category'] == 'owned-development' and
                    value['canonical_cwd'] == ws['root'] and ws['branch'].casefold() not in {'', 'main', 'master'} and
                    re.fullmatch('[0-9a-f]{40}', ws['baseline']) is not None, 'Invalid managed scope binding')
            require(op['argv'] == ['git', '--no-optional-locks', 'diff', '--check'] or
                    (len(op['argv']) == 2 and op['argv'][0] == 'owned-edits'), 'Unsupported evidence operation')
        check_binding(binding)
        task_id = events[0]['task_id']
        require(events[0]['event'] == 'CREATED', 'Missing task creation')
        attempts, active, guards, attempt_result, g4, command, starts = [], None, 0, None, None, None, 0
        guard_decision, transitions, start_worker = None, [], None
        last_elapsed = 0
        for event in events:
            checkpoint()
            require(event.get('run_binding') == binding and event['task_id'] == task_id and
                    event['task']['id'] == task_id and event['task']['state'] == event['state'],
                    'Task/run binding mismatch')
            kind, value = event['event'], event['result']
            require(kind in {'CREATED', 'TRANSITION', 'COMMAND_START', 'G3_ATTEMPT', 'GOVERNANCE_DECISION',
                             'WORKER', 'G3_ATTEMPT_RESULT', 'G4_REVALIDATION', 'COMMAND_RESULT'},
                    'Unexpected managed evidence record')
            if kind == 'TRANSITION':
                require(value['to'] not in {'FAILED', 'CANCELLED', 'WAITING_FOR_HUMAN'}, 'Failed task in success evidence')
                previous_state = 'PLANNING' if not transitions else transitions[-1]
                require(value['from'] == previous_state, 'Contradictory task transition')
                transitions.append(value['to'])
            elif kind == 'COMMAND_START':
                starts += 1
                require(value == binding['operation'] and not attempts, 'Operation start mismatch')
                start_worker = event['worker']
            elif kind == 'G3_ATTEMPT':
                require(starts == 1 and command is None and g4 is None, 'Invalid attempt ordering')
                if attempts:
                    require(attempt_result is not None and guards == 1 and
                            attempt_result['outcome'] == 'FAILED' and attempt_result['dispatched'] is False and
                            attempt_result['exit_code'] is None and attempt_result['failure_code'] == 'PROCESS_START_TRANSIENT' and
                            attempt_result['retry_transient'] is True and
                            binding['operation']['argv'] == ['git', '--no-optional-locks', 'diff', '--check'],
                            'Unapproved retry in evidence')
                active = value['binding']
                check_binding(active)
                require({k: v for k, v in active.items() if k not in {'authorization', 'authorization_identity'}} ==
                        {k: v for k, v in binding.items() if k not in {'authorization', 'authorization_identity'}},
                        'Retry operation/workspace/source changed')
                require(active['authorization']['id'] not in [a['authorization']['id'] for a in attempts],
                        'Reused retry authorization')
                if not attempts:
                    require(active == binding, 'First attempt authorization mismatch')
                attempts.append(active)
                require(value['attempts'] == len(attempts) and type(value['max_attempts']) is int and
                        1 <= len(attempts) <= value['max_attempts'] <= 3 and
                        math.isfinite(value['total_timeout_seconds']) and 0 < value['total_timeout_seconds'] <= 300,
                        'Invalid G3 attempt limits')
                guards, attempt_result = 0, None
                budget_spec = {k: value[k] for k in ('max_attempts', 'total_timeout_seconds', 'retry_transient')}
                if len(attempts) == 1:
                    original_budget = budget_spec
                require(budget_spec == original_budget, 'Budget reset in retry')
            if kind in {'G3_ATTEMPT', 'GOVERNANCE_DECISION', 'WORKER', 'G3_ATTEMPT_RESULT', 'G4_REVALIDATION', 'COMMAND_RESULT'}:
                require(active is not None and value['binding'] == active and value['attempt'] == len(attempts),
                        'Attempt evidence binding mismatch')
                require(event['worker'] == start_worker, 'Execution worker identity mismatch')
            if kind in {'G3_ATTEMPT', 'G3_ATTEMPT_RESULT'}:
                elapsed = value['elapsed_seconds']
                require(math.isfinite(elapsed) and last_elapsed <= elapsed < original_budget['total_timeout_seconds'],
                        'Deadline or time ordering violation')
                require({k: value[k] for k in original_budget} == original_budget and value['attempts'] == len(attempts),
                        'Inconsistent attempt budget')
                last_elapsed = elapsed
            if kind == 'GOVERNANCE_DECISION':
                guards += 1
                require(guards == 1 and attempt_result is None and value['status'] == 'PASS' and
                        value['reason_code'] == 'DISPATCH_AUTHORIZED' and value['source_identity'] == active['source_identity'] and
                        value['policy_ids'] == ['G1', 'G2'] and value['policy_version'] == active['profile_version'] and
                        value['managed_boundary'] == 'local-development-worker.run',
                        'Missing or conflicting G1/G2 approval')
                require(all(prefix + active[key] in value['evidence_refs'] for prefix, key in
                            [('operation-sha256:', 'operation_identity'), ('source-sha256:', 'source_identity'),
                             ('profile-sha256:', 'profile_identity')]), 'Guard evidence identity mismatch')
                guard_decision = {k: v for k, v in value.items() if k not in {'binding', 'attempt'}}
            elif kind == 'WORKER':
                require(guards == 1 and attempt_result is None, 'Worker ran outside its approved attempt')
            elif kind == 'G3_ATTEMPT_RESULT':
                require(guards == 1 and attempt_result is None and valid_hash(value['result_identity']),
                        'Missing/duplicate result evidence')
                attempt_result = value
            elif kind == 'G4_REVALIDATION':
                require(g4 is None and attempt_result is not None and attempt_result['outcome'] == 'SUCCESS' and
                        attempt_result['dispatched'] is True and attempt_result['exit_code'] == 0 and
                        value['status'] == 'PASS' and value['policy_ids'] == ['G4'] and
                        value['reason_code'] == 'POSTCONDITIONS_VERIFIED' and
                        value['managed_boundary'] == 'managed-post-execution' and
                        value['policy_version'] == active['profile_version'] and valid_hash(value['source_identity']),
                        'Missing or invalid G4 revalidation')
                refs = value['evidence_refs']
                require('operation-sha256:' + active['operation_identity'] in refs and
                        'before-source-sha256:' + active['source_identity'] in refs and
                        'after-source-sha256:' + value['source_identity'] in refs and
                        all(any(r.startswith(prefix) and valid_hash(r[len(prefix):]) for r in refs)
                            for prefix in ('expected-targets-sha256:', 'index-sha256:')), 'Incomplete G4 evidence')
                g4 = {k: v for k, v in value.items() if k not in {'binding', 'attempt'}}
            elif kind == 'COMMAND_RESULT':
                require(command is None and g4 is not None and value['operation'] == binding['operation']['name'],
                        'Missing or duplicate final result')
                actual = {k: value[k] for k in Result.__dataclass_fields__}
                require(actual['outcome'] == 'SUCCESS' and type(actual['exit_code']) is int and
                        actual['exit_code'] == 0 and actual['dispatched'] is True and value['worker'] == start_worker and
                        math.isfinite(actual['elapsed']) and actual['elapsed'] >= 0 and
                        evidence_hash(actual) == attempt_result['result_identity'], 'Contradictory execution result')
                if result is not None:
                    require(actual == strict_json(canonical(result)), 'Live execution result differs from evidence')
                command = value
        require(starts == 1 and bool(attempts) and g4 is not None and command is not None,
                'Incomplete mandatory evidence chain')
        require(transitions == (['QUEUED', 'RUNNING', 'VERIFYING', 'COMPLETE'] if summary is not None else
                                ['QUEUED', 'RUNNING', 'VERIFYING']), 'Missing or conflicting task transitions')
        final = events[-1]
        require(final['event'] == 'TRANSITION' and final['result']['to'] == ('COMPLETE' if summary is not None else 'VERIFYING'),
                'Missing completion/verification transition')
        if summary is not None:
            require(summary['completion'] == 'CERTIFICATE_REQUIRED' and summary['task'] == final['task'] and
                    summary['task']['state'] == 'COMPLETE' and summary['task']['results'] == [command] and
                    summary['revalidation'] == g4 and summary['dispatch_decision'] == guard_decision and
                    summary['task']['steps'] == [{'worker': start_worker, **binding['operation']}],
                    'Summary contradicts verified evidence')
            require(summary['g3']['attempts'] == len(attempts) and
                    {k: summary['g3'][k] for k in original_budget} == original_budget and
                    last_elapsed <= summary['g3']['elapsed_seconds'] < original_budget['total_timeout_seconds'],
                    'Finalization exceeded or reset G3 budget')
        return {'task_id': task_id, 'binding': binding, 'attempt': len(attempts),
                'attempt_binding': active, 'result_identity': attempt_result['result_identity'],
                'g4_identity': evidence_hash(g4)}

    def finalize_managed(self, summary_path, summary, result):
        checkpoint()
        facts = self.verify_live(summary, result)
        summary_raw = read_evidence(summary_path)
        require(strict_json(summary_raw.decode('utf-8')) == strict_json(canonical(summary)), 'Summary write/read mismatch')
        ledger_raw = read_evidence(self.path)
        certificate = {'schema': 'hg-managed-completion-v1', 'status': 'PASS', **facts,
                       'ledger_sha256': hashlib.sha256(ledger_raw).hexdigest(),
                       'ledger_events': self.sequence, 'chain_head': self.head,
                       'summary_sha256': hashlib.sha256(summary_raw).hexdigest()}
        path = self.path.parent / 'completion.json'
        checkpoint()
        content = canonical(certificate) + '\n'
        anchor = hashlib.sha256(content.encode('utf-8')).hexdigest()
        with path.open('x', encoding='utf-8', newline='\n') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        checkpoint()
        report = self.verify_managed(self.path.parent, expected_certificate=anchor, expected_binding=self.binding)
        require(report['status'] == 'PASS', 'Completion readback failed')
        checkpoint()
        return report

    @staticmethod
    def verify_managed(directory, expected_certificate=None, expected_binding=None):
        """Read-only. Unanchored historical consistency is UNKNOWN, never origin proof."""
        try:
            root = Path(directory)
            raw = read_evidence(root / 'events.jsonl')
            if not (root / 'completion.json').exists():
                legacy = [strict_json(x) for x in raw.decode('utf-8').splitlines()]
                if legacy and all('event_hash' not in x and not
                                  (isinstance(x.get('result'), dict) and 'binding' in x['result']) for x in legacy):
                    return {'status': 'UNKNOWN', 'reason': 'Legacy unsealed evidence; completion not proven.'}
                raise ValueError('Missing completion certificate')
            cert_raw = read_evidence(root / 'completion.json')
            cert_hash = hashlib.sha256(cert_raw).hexdigest()
            if expected_certificate is not None:
                require(cert_hash == expected_certificate, 'Trusted certificate reference mismatch')
            cert = strict_json(cert_raw.decode('utf-8'))
            summary_raw = read_evidence(root / 'summary.json')
            summary = strict_json(summary_raw.decode('utf-8'))
            require(cert['schema'] == 'hg-managed-completion-v1' and cert['status'] == 'PASS' and
                    cert['ledger_sha256'] == hashlib.sha256(raw).hexdigest() and
                    cert['summary_sha256'] == hashlib.sha256(summary_raw).hexdigest(), 'Sealed file hash mismatch')
            events = Ledger._events(raw)
            facts = Ledger._validate(events, cert['binding'], summary)
            require(all(cert[k] == v for k, v in facts.items()) and cert['ledger_events'] == len(events) and
                    cert['chain_head'] == events[-1]['event_hash'], 'Completion certificate binding mismatch')
            if expected_binding is not None:
                require(cert['binding'] == expected_binding, 'Expected operation/workspace/authorization mismatch')
            checkpoint()
            return {'status': 'PASS' if expected_certificate is not None else 'UNKNOWN',
                    'reason': 'Integrity and binding verified; trusted caller reference required for historical completion.',
                    'certificate_sha256': cert_hash, 'task_id': cert['task_id'], 'attempt': cert['attempt'],
                    'integrity': 'VERIFIED', 'origin_authentication': 'NOT_PROVIDED', 'g6': 'NOT_EVALUATED'}
        except Exception as exc:
            return {'status': 'BLOCK', 'reason': 'Evidence verification failed (' + type(exc).__name__ + ').'}

    @staticmethod
    def recover(path):
        events = Ledger.read(path)
        if not events:
            raise ValueError('Empty ledger')
        if any('event_hash' in event for event in events):
            raise ValueError('Managed completion requires verify_managed, never a provisional task snapshot')
        return events[-1]['task']
