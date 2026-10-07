"""Project-independent task, command, worker and result contracts."""
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime, timezone
import uuid


def now():
    return datetime.now(timezone.utc).isoformat()


class TaskState(str, Enum):
    PLANNING = 'PLANNING'
    QUEUED = 'QUEUED'
    RUNNING = 'RUNNING'
    WAITING_FOR_WORKER = 'WAITING_FOR_WORKER'
    TESTING = 'TESTING'
    VERIFYING = 'VERIFYING'
    WAITING_FOR_HUMAN = 'WAITING_FOR_HUMAN'
    FAILED = 'FAILED'
    COMPLETE = 'COMPLETE'
    CANCELLED = 'CANCELLED'


class WorkerState(str, Enum):
    OFFLINE = 'OFFLINE'
    IDLE = 'IDLE'
    BUSY = 'BUSY'
    WAITING_FOR_HUMAN = 'WAITING_FOR_HUMAN'
    ERROR = 'ERROR'


class Outcome(str, Enum):
    SUCCESS = 'SUCCESS'
    FAILED = 'FAILED'
    TIMED_OUT = 'TIMED_OUT'
    CANCELLED = 'CANCELLED'
    UNCERTAIN = 'UNCERTAIN'


@dataclass(frozen=True)
class Operation:
    name: str
    argv: tuple[str, ...]
    cwd: str
    timeout: float = 20
    category: str = 'repository-read'


@dataclass
class Result:
    outcome: Outcome
    exit_code: int | None
    stdout: str = ''
    stderr: str = ''
    elapsed: float = 0
    reason: str = ''
    dispatched: bool | None = False


@dataclass
class Task:
    name: str
    description: str
    requirements: list[str]
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created: str = field(default_factory=now)
    started: str | None = None
    ended: str | None = None
    _state: TaskState = field(default=TaskState.PLANNING, init=False, repr=False)
    steps: list[dict] = field(default_factory=list)
    results: list[dict] = field(default_factory=list)
    blocker: str | None = None

    @property
    def state(self):
        return self._state

    def snapshot(self):
        value = asdict(self)
        value['state'] = value.pop('_state')
        return value


TERMINAL = {TaskState.FAILED, TaskState.COMPLETE, TaskState.CANCELLED}
TRANSITIONS = {
    TaskState.PLANNING: {TaskState.QUEUED, TaskState.WAITING_FOR_HUMAN},
    TaskState.QUEUED: {TaskState.WAITING_FOR_WORKER, TaskState.RUNNING, TaskState.WAITING_FOR_HUMAN},
    TaskState.WAITING_FOR_WORKER: {TaskState.RUNNING, TaskState.WAITING_FOR_HUMAN},
    TaskState.RUNNING: {TaskState.WAITING_FOR_WORKER, TaskState.TESTING, TaskState.VERIFYING, TaskState.WAITING_FOR_HUMAN},
    TaskState.TESTING: {TaskState.VERIFYING, TaskState.WAITING_FOR_HUMAN},
    TaskState.VERIFYING: {TaskState.COMPLETE, TaskState.WAITING_FOR_WORKER, TaskState.WAITING_FOR_HUMAN},
    TaskState.WAITING_FOR_HUMAN: {TaskState.QUEUED},
}


class StateMachine:
    def __init__(self, task, ledger):
        self.task, self.ledger = task, ledger
        self.ledger.record(task, 'CREATED', 'Task accepted')

    def transition(self, target, message, worker=None):
        source = self.task.state
        allowed = set(TRANSITIONS.get(source, set()))
        if source not in TERMINAL:
            allowed |= {TaskState.FAILED, TaskState.CANCELLED}
        if target not in allowed:
            self.ledger.record(self.task, 'INVALID_TRANSITION', f'{source.value} -> {target.value}')
            raise ValueError(f'Invalid transition {source.value} -> {target.value}')
        self.task._state = target
        if target == TaskState.RUNNING and self.task.started is None:
            self.task.started = now()
        if target in TERMINAL:
            self.task.ended = now()
        self.ledger.record(self.task, 'TRANSITION', message, worker,
                           {'from': source, 'to': target})
