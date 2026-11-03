"""G1/G2 local managed edits. No policy file is itself proof of human identity.

The embedding operator must load reviewed profile/authorization documents. This
is a deterministic dispatch gate in a trusted Python process, not an OS sandbox.
"""
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import subprocess
from .decisions import Decision, Status, ExecutionFailure, blocked
from .development import DevelopmentWindowsWorker, prepare_edits
from .model import Operation
from .workers import Worker
from .workbench import snapshot


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()).hexdigest()


def source_identity(root):
    """Read-only source identity, including dirty tracked/nonignored files."""
    return digest(snapshot(Path(root).resolve()))


def scoped_path(root, name):
    # Reject ambiguous Windows spellings even when tests run on another OS.
    if not isinstance(name, str) or not name or '\\' in name or ':' in name:
        raise ValueError('Noncanonical relative path')
    parts = name.split('/')
    reserved = {'con', 'prn', 'aux', 'nul', *(f'com{i}' for i in range(1, 10)), *(f'lpt{i}' for i in range(1, 10))}
    if any(p in {'', '.', '..'} or p.rstrip(' .') != p or
           p.casefold() == '.git' or p.split('.')[0].casefold() in reserved or
           any(c in '~<>"|?*' or ord(c) < 32 or ord(c) == 127 for c in p) for p in parts):
        raise ValueError('Unsafe path component')
    relative = PurePosixPath(name)
    if relative.is_absolute():
        raise ValueError('Absolute target path')
    root = Path(root).resolve(strict=True)
    target = root.joinpath(*parts)
    if root not in target.resolve().parents:
        raise ValueError('Path escapes owned worktree')
    # Reject every link/reparse ancestor, including links staying inside root.
    cursor = root
    for part in parts:
        cursor /= part
        if cursor.is_symlink() or (cursor.exists() and getattr(cursor.lstat(), 'st_file_attributes', 0) & 0x400):
            raise ValueError('Link/junction target is not permitted')
        if cursor != target and (cursor / '.git').exists():
            raise ValueError('Nested repository target is not permitted')
    if target.is_file() and target.stat().st_nlink != 1:
        raise ValueError('Hard-linked targets are not permitted')
    return target


@dataclass(frozen=True)
class Profile:
    id: str
    version: str
    root: str
    branch: str
    baseline: str
    components: tuple[tuple[str, tuple[str, ...]], ...]
    operations: tuple[str, ...]
    requirements: tuple[tuple[str, tuple[str, ...]], ...] = ()

    @classmethod
    def load(cls, value):
        if set(value) != {'id', 'version', 'root', 'branch', 'baseline', 'components', 'operations', 'requirements'}:
            raise ValueError('Invalid profile fields')
        if (not isinstance(value['components'], dict) or not isinstance(value['requirements'], dict) or
                not isinstance(value['operations'], list) or
                not all(isinstance(v, list) for v in (*value['components'].values(), *value['requirements'].values()))):
            raise ValueError('Explicit component, operation and applicability lists required')
        profile = cls(value['id'], value['version'], value['root'], value['branch'], value['baseline'],
                      tuple((k, tuple(v)) for k, v in value['components'].items()),
                      tuple(value['operations']), tuple((k, tuple(v)) for k, v in value['requirements'].items()))
        profile.validate()
        return profile

    def validate(self):
        if not all(isinstance(v, str) and v for v in (self.id, self.version, self.root, self.branch, self.baseline)):
            raise ValueError('Explicit profile identities required')
        if not Path(self.root).is_absolute() or str(Path(self.root).resolve()) != self.root:
            raise ValueError('Profile root must be canonical and absolute')
        if self.branch.casefold() in {'master', 'main'} or self.branch.startswith('refs/'):
            raise ValueError('Protected or noncanonical branch')
        if not re.fullmatch('[0-9a-f]{40}', self.baseline):
            raise ValueError('Full baseline SHA required')
        if not self.operations or not set(self.operations) <= {'edit', 'diff-check'}:
            raise ValueError('Unknown managed operation')
        names = [name for name, _ in self.components]
        if not names or len(set(names)) != len(names):
            raise ValueError('Unique components required')
        for name, paths in self.components:
            if not isinstance(name, str) or not name or not paths:
                raise ValueError('Explicit component paths required')
            for path in paths:
                scoped_path(self.root, path)
        for name, components in self.requirements:
            if not isinstance(name, str) or not name or not components or not set(components) <= set(names):
                raise ValueError('Requirement applicability must name known components')


@dataclass(frozen=True)
class Authorization:
    id: str
    profile_identity: str
    source_identity: str
    operation_identity: str
    components: tuple[str, ...]
    evidence_refs: tuple[str, ...]

    @classmethod
    def load(cls, value):
        if set(value) != {'id', 'profile_identity', 'source_identity', 'operation_identity', 'components', 'evidence_refs'}:
            raise ValueError('Invalid authorization fields')
        if not isinstance(value['components'], list) or not isinstance(value['evidence_refs'], list):
            raise ValueError('Authorization components and evidence must be lists')
        return cls(value['id'], value['profile_identity'], value['source_identity'], value['operation_identity'],
                   tuple(value['components']), tuple(value['evidence_refs']))


def profile_identity(profile):
    from dataclasses import asdict
    return digest(asdict(profile))


def operation_identity(operation):
    from dataclasses import asdict
    payload = None
    if operation.argv[:1] == ('owned-edits',) and len(operation.argv) == 2:
        payload = hashlib.sha256(Path(operation.argv[1]).read_bytes()).hexdigest()
    return digest({'operation': asdict(operation), 'payload_sha256': payload})


class ManagedDevelopmentWorker(DevelopmentWindowsWorker):
    """Only run() is a protected dispatch entry. Direct low-level calls are external."""
    def __init__(self, identity, profile, authorization):
        super().__init__(identity, profile.root)
        self.profile, self.authorization = profile, authorization
        self.last_decision = None
        self._consumed = False

    def evaluate(self, operation):
        profile, auth = self.profile, self.authorization
        current = ''
        def decision(status, code, reason, evidence=(), requirements=()):
            return Decision(status, ('G1', 'G2'), code, reason,
                            'Dispatch only this operation; obtain separate acceptance evidence.' if status == Status.PASS else
                            'Review profile, source and authorization; issue a fresh exact-operation authorization.',
                            tuple(evidence), current, profile.version, requirements=tuple(requirements))
        try:
            profile.validate()
            if not (self.root / '.git').is_file():
                return decision(Status.BLOCK, 'ISOLATED_WORKTREE_REQUIRED', 'A linked development worktree is required.')
            state = snapshot(self.root)
            current = digest(state)
            if state['root'] != profile.root or state['branch'] != profile.branch or state['head'] != profile.baseline:
                return decision(Status.BLOCK, 'SOURCE_IDENTITY_MISMATCH', 'Resolved root, branch or baseline differs from the approved profile.')
            if state['branch'].casefold() in {'master', 'main', ''}:
                return decision(Status.BLOCK, 'PROTECTED_BRANCH', 'An isolated development branch is required.')
            if type(auth) is not Authorization or not isinstance(auth.id, str) or not auth.id:
                return decision(Status.BLOCK, 'AUTHORIZATION_MISSING', 'Reviewed authorization is required.')
            if self._consumed:
                return decision(Status.BLOCK, 'AUTHORIZATION_CONSUMED', 'Authorization is single-use within this worker instance.')
            if auth.profile_identity != profile_identity(profile) or auth.source_identity != current:
                return decision(Status.BLOCK, 'STALE_AUTHORIZATION', 'Policy or source identity no longer matches authorization.')
            if type(operation) is not Operation or operation.category != 'owned-development' or Path(operation.cwd).resolve() != self.root:
                return decision(Status.BLOCK, 'OPERATION_MISMATCH', 'Exact owned development operation and root required.')
            if not isinstance(operation.timeout, (float, int)) or isinstance(operation.timeout, bool) or not math.isfinite(operation.timeout) or not 0 < operation.timeout <= 300:
                return decision(Status.BLOCK, 'INVALID_TIMEOUT', 'Timeout must be finite and within 0–300 seconds.')
            if auth.operation_identity != operation_identity(operation):
                return decision(Status.BLOCK, 'OPERATION_MISMATCH', 'Operation arguments or edit payload differ from authorization.')
            if operation.argv[:1] == ('owned-edits',) and len(operation.argv) == 2:
                kind = 'edit'
                edits = json.loads(Path(operation.argv[1]).read_text(encoding='utf-8'))
                if not isinstance(edits, list) or not edits:
                    raise ValueError('Nonempty edit list required')
                paths = []
                for edit in edits:
                    if not isinstance(edit, dict) or not {'path', 'before_sha256'} <= set(edit) or not set(edit) <= {'path', 'before_sha256', 'content', 'replacements'}:
                        raise ValueError('Invalid edit fields')
                    path = scoped_path(self.root, edit['path'])
                    before = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
                    if before != edit['before_sha256']:
                        return decision(Status.BLOCK, 'EDIT_HASH_MISMATCH', 'Source bytes differ from the authorized before hash.')
                    paths.append(edit['path'])
                if len({str(scoped_path(self.root, p)).casefold() for p in paths}) != len(paths):
                    raise ValueError('Duplicate edit target')
                prepare_edits(self.root, edits, scoped_path)
            elif operation.argv == ('git', '--no-optional-locks', 'diff', '--check'):
                kind, paths = 'diff-check', []
            else:
                return decision(Status.BLOCK, 'UNKNOWN_OPERATION', 'Historical builds, tests and arbitrary commands are not managed operations in this profile.')
            if kind not in profile.operations:
                return decision(Status.BLOCK, 'OPERATION_NOT_APPROVED', 'Operation is not approved by the development profile.')
            affected = set()
            for path in paths:
                matches = [name for name, prefixes in profile.components if any(path == prefix or path.startswith(prefix + '/') for prefix in prefixes)]
                if len(matches) != 1:
                    return decision(Status.BLOCK, 'COMPONENT_SCOPE', 'Each target must belong to exactly one approved component.')
                affected.add(matches[0])
            if not isinstance(auth.components, tuple) or set(auth.components) != affected:
                return decision(Status.BLOCK, 'COMPONENT_AUTHORIZATION', 'Authorization must explicitly cover exactly the affected components.')
            if not auth.evidence_refs or not all(isinstance(ref, str) and ref.strip() for ref in auth.evidence_refs):
                return decision(Status.REVISE, 'EVIDENCE_MISSING', 'A reviewed authorization evidence reference is required before dispatch.')
            requirements = [(name, 'APPLICABLE' if set(components) & affected else 'NOT_APPLICABLE') for name, components in profile.requirements]
            evidence = (*auth.evidence_refs, 'profile-sha256:' + profile_identity(profile), 'source-sha256:' + current,
                        'operation-sha256:' + auth.operation_identity)
            verified = ('target paths, before hashes and component authorization' if kind == 'edit' else
                        'exact diff-check arguments and empty modification component scope')
            return decision(Status.PASS, 'DISPATCH_AUTHORIZED',
                            'Verified linked worktree root, development branch, baseline, source and policy identities, exact operation/payload, ' + verified + '. Permission to dispatch only.',
                            evidence, requirements)
        except (ValueError, TypeError, KeyError, AttributeError, OSError, subprocess.SubprocessError) as exc:
            # Exception strings and worker output are not trusted approval text.
            return decision(Status.BLOCK, 'INVALID_INPUT', 'Policy, source, operation or target validation failed (' + type(exc).__name__ + ').')

    def run(self, operation, cancel, notify):
        self.last_decision = self.evaluate(operation)  # never accepts a caller-supplied PASS
        notify('GOVERNANCE_DECISION', self.identity, self.last_decision.to_dict())
        if self.last_decision.status != Status.PASS:
            raise ExecutionFailure(self.last_decision.reason, self.last_decision)
        if cancel.is_set():
            raise ExecutionFailure('Cancelled before managed dispatch', blocked('CANCELLED', 'Cancelled before managed dispatch.'))
        # Re-read source, links and edit payload immediately at the dispatch boundary.
        rechecked = self.evaluate(operation)
        if rechecked != self.last_decision:
            self.last_decision = rechecked
            notify('GOVERNANCE_DECISION', self.identity, rechecked.to_dict())
            raise ExecutionFailure('Decision changed before dispatch', rechecked)
        self._consumed = True
        self._managed_active = True
        try:
            return Worker.run(self, operation, cancel, notify)
        finally:
            self._managed_active = False


def acceptance_pending():
    return Decision(Status.NOT_EVALUATED, ('G4', 'G6'), 'ACCEPTANCE_NOT_EVALUATED',
                    'G1/G2 dispatch permission does not verify tests or final acceptance.',
                    'Run approved verification and obtain the required acceptance separately.',
                    managed_boundary='final-task-acceptance')
