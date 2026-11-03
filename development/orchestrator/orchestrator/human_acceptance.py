"""Read-only G6: completed G5 evidence plus separately reviewed operator input.

No approval issuer, worker dispatch, budget, ledger writer or signature service.
Caller references are trusted-operator assertions, not authenticated human identity.
"""
import hashlib
from pathlib import Path

from .ledger import Ledger, read_evidence, require, strict_json


POLICY = 'g6-managed-v1'


def human_requirement(binding):
    argv = binding['operation']['argv']
    if tuple(argv) == ('git', '--no-optional-locks', 'diff', '--check'):
        required = False
    elif len(argv) == 2 and argv[0] == 'owned-edits':
        required = True
    else:
        raise ValueError('Unsupported managed human-acceptance scope')
    return {'policy_id': POLICY, 'required': required,
            'status': 'PENDING' if required else 'PASS',
            'decision': 'PENDING' if required else 'NOT_REQUIRED',
            'technical_completion_is_human_acceptance': False}


def verify_human_acceptance(directory, expected_certificate=None, record_path=None, expected_record=None):
    """Only inspect. A new G3 budget is neither created nor activated here."""
    try:
        technical = Ledger.verify_managed(directory, expected_certificate=expected_certificate)
        require(technical['status'] == 'PASS', 'Verified G5 technical completion reference required')
        root = Path(directory).resolve()
        cert_raw = read_evidence(root / 'completion.json')
        require(hashlib.sha256(cert_raw).hexdigest() == expected_certificate, 'Completion changed during inspection')
        cert = strict_json(cert_raw.decode('utf-8'))
        summary_raw = read_evidence(root / 'summary.json')
        require(hashlib.sha256(summary_raw).hexdigest() == cert['summary_sha256'], 'Summary changed during inspection')
        summary = strict_json(summary_raw.decode('utf-8'))
        requirement = human_requirement(cert['binding'])
        base = {**requirement, 'technical_status': 'PASS', 'certificate_sha256': expected_certificate,
                'human_identity_authentication': 'NOT_PROVIDED', 'g3_budget_reopened': False}
        if not requirement['required']:
            require(record_path is None and expected_record is None, 'No human decision input needed for diff-check')
            return base
        if record_path is None:
            require(expected_record is None, 'Acceptance reference without a record')
            return {**base, 'reason': 'Technical completion preserved; separate human decision pending.'}
        require(isinstance(expected_record, str) and len(expected_record) == 64,
                'Separately reviewed operator record digest required; worker text is not approval')
        path = Path(record_path)
        raw = read_evidence(path)
        actual = path.resolve()
        workspace = Path(cert['binding']['workspace']['root']).resolve()
        require(all(actual != protected and protected not in actual.parents for protected in (workspace, root)) and
                not any(part.casefold() == '.git' for part in actual.parts) and path.stat().st_nlink == 1,
                'Operator decision must be separate from source, worker evidence and Git metadata')
        require(hashlib.sha256(raw).hexdigest() == expected_record, 'Operator record reference mismatch')
        packet = strict_json(raw.decode('utf-8'))
        require(type(packet) is dict and set(packet) == {'schema', 'records'} and
                packet['schema'] == 'hg-operator-acceptance-v1' and type(packet['records']) is list and
                len(packet['records']) == 1, 'Missing, repeated or conflicting operator decisions')
        record = packet['records'][0]
        expected = {'policy_id': POLICY, 'completion_certificate_sha256': expected_certificate,
                    'task_id': cert['task_id'], 'operation_identity': cert['binding']['operation_identity'],
                    'authorization_identity': cert['attempt_binding']['authorization_identity'],
                    'workspace': cert['binding']['workspace'],
                    'source_identity': cert['attempt_binding']['source_identity'],
                    'post_source_identity': summary['revalidation']['source_identity'],
                    'attempt': cert['attempt'], 'g4_identity': cert['g4_identity']}
        require(type(record) is dict and set(record) == set(expected) | {'id', 'decision', 'input_origin', 'evidence_refs'},
                'Malformed post-execution operator decision')
        require(all(record[k] == value for k, value in expected.items()) and
                type(record['attempt']) is int, 'Acceptance is for another execution/result/certificate')
        require(record['input_origin'] == 'operator-reviewed' and
                isinstance(record['id'], str) and bool(record['id'].strip()) and
                not any(ord(c) < 32 or ord(c) == 127 for c in record['id']) and
                record['id'] != cert['attempt_binding']['authorization']['id'] and
                type(record['evidence_refs']) is list and bool(record['evidence_refs']) and
                all(isinstance(r, str) and r.strip() for r in record['evidence_refs']),
                'Separate reviewed operator identity/reference required')
        require(record['decision'] in {'ACCEPT', 'REJECT', 'PENDING'}, 'Unknown human decision')
        status = {'ACCEPT': 'PASS', 'REJECT': 'BLOCK', 'PENDING': 'PENDING'}[record['decision']]
        return {**base, 'status': status, 'decision': record['decision'], 'decision_id': record['id'],
                'acceptance_record_sha256': expected_record,
                'reason': 'Separately reviewed decision binding verified; no dispatch or source/evidence modification.'}
    except Exception as exc:
        return {'status': 'BLOCK', 'decision': 'INVALID', 'policy_id': POLICY,
                'reason': 'Human acceptance verification failed (' + type(exc).__name__ + ').',
                'g3_budget_reopened': False, 'human_identity_authentication': 'NOT_PROVIDED'}
