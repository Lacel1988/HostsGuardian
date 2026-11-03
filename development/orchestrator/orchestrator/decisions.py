"""GOV-UI-01: one decision for JSON, ledger and terminal rendering."""
from dataclasses import asdict, dataclass
from enum import Enum
import json
import unicodedata


class Status(str, Enum):
    BLOCK = 'BLOCK'
    PASS = 'PASS'
    REVISE = 'REVISE'
    NOT_EVALUATED = 'NOT_EVALUATED'


@dataclass(frozen=True)
class Decision:
    status: Status
    policy_ids: tuple[str, ...]
    reason_code: str
    reason: str
    next_action: str
    evidence_refs: tuple[str, ...] = ()
    source_identity: str = ''
    policy_version: str = ''
    decision_origin: str = 'deterministic-orchestrator'
    managed_boundary: str = 'local-development-worker.run'
    requirements: tuple[tuple[str, str], ...] = ()

    def __post_init__(self):
        if type(self.status) is not Status:
            raise ValueError('Typed governance status required')
        if self.status == Status.PASS and not self.evidence_refs:
            raise ValueError('PASS requires explicit verification evidence')

    def to_dict(self):
        return asdict(self)

    def render(self, unicode=True, color=False):
        symbols = {Status.BLOCK: '🔴', Status.PASS: '🟢', Status.REVISE: '🟡', Status.NOT_EVALUATED: '⚪'}
        colors = {Status.BLOCK: 31, Status.PASS: 32, Status.REVISE: 33, Status.NOT_EVALUATED: 37}
        heading = (symbols[self.status] + ' ' if unicode else '') + self.status.value
        if color:
            heading = f'\x1b[{colors[self.status]}m{heading}\x1b[0m'
        def quoted(value):
            # No line breaks, ANSI, bidi controls or invisible formatting in fields.
            value = ''.join(f'\\u{ord(c):04x}' if unicodedata.category(c).startswith('C') else c for c in value)
            return json.dumps(value, ensure_ascii=not unicode)
        return (heading + ' | ' + ','.join(quoted(p) for p in self.policy_ids) +
                ' | ' + quoted(self.reason_code) + ': ' + quoted(self.reason) +
                ' | Next: ' + quoted(self.next_action) +
                ' | Evidence: ' + quoted(', '.join(self.evidence_refs) or 'unavailable'))


class ExecutionFailure(RuntimeError):
    """Typed stop, optionally carrying the authoritative governance decision."""
    def __init__(self, message, decision=None):
        super().__init__(message)
        self.decision = decision


def blocked(code, reason, boundary='local-development-worker.run'):
    return Decision(Status.BLOCK, ('G1', 'G2'), code, reason,
                    'Supply reviewed scope and matching authorization; re-evaluate before dispatch.',
                    managed_boundary=boundary)
