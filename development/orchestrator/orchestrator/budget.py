"""G3 cooperative limits for the existing managed execution path (no resumption)."""
from contextlib import contextmanager
from contextvars import ContextVar
import math
import time

from .decisions import Decision, ExecutionFailure, Status


active_budget = ContextVar('managed_execution_budget', default=None)


def g3_blocked(code, reason):
    return Decision(Status.BLOCK, ('G3',), code, reason,
                    'Stop; inspect evidence and obtain separate authorization. No automatic resume.')


class ExecutionBudget:
    def __init__(self, total_timeout_seconds, max_attempts=1, retry_transient=False,
                 *, clock=time.monotonic, started=None):
        if (type(max_attempts) is not int or not 1 <= max_attempts <= 3 or
                type(total_timeout_seconds) not in (int, float) or
                not math.isfinite(total_timeout_seconds) or not 0 < total_timeout_seconds <= 300 or
                type(retry_transient) is not bool):
            raise ValueError('Invalid G3 budget')
        self.clock = clock
        self.started = clock() if started is None else started
        if not math.isfinite(self.started):
            raise ValueError('Invalid monotonic start')
        self.deadline = self.started + total_timeout_seconds
        self.max_attempts = max_attempts
        self.retry_transient = retry_transient
        self.attempts = 0
        self.authorization_ids = set()
        self.cancel = None
        self.failure = None
        self.finished = False
        self.execution_complete = False
        self.last_time = self.started

    @classmethod
    def load(cls, value, **kwargs):
        if (not isinstance(value, dict) or 'total_timeout_seconds' not in value or
                not set(value) <= {'total_timeout_seconds', 'max_attempts', 'retry_transient'}):
            raise ValueError('Explicit G3 total time budget required')
        return cls(**value, **kwargs)

    def stop(self, code, reason):
        if self.failure is None:
            self.failure = g3_blocked(code, reason)
        raise ExecutionFailure(self.failure.reason, self.failure)

    def remaining(self):
        current = self.clock()
        if not math.isfinite(current) or current < self.last_time:
            self.stop('G3_CLOCK_INVALID', 'Monotonic clock is invalid or moved backwards.')
        self.last_time = current
        return self.deadline - current

    def check(self):
        if self.failure is not None:
            raise ExecutionFailure(self.failure.reason, self.failure)
        if self.finished:
            self.stop('G3_FINISHED', 'Completed budgets cannot be reused.')
        if self.cancel is not None and self.cancel.is_set():
            self.stop('G3_CANCELLED', 'Cancellation is terminal.')
        if self.remaining() <= 0:
            self.stop('G3_DEADLINE', 'Total execution deadline exhausted.')

    def begin_attempt(self, authorization):
        self.check()
        if self.execution_complete:
            self.stop('G3_FINISHED', 'Successful operations cannot be replayed with remaining attempts.')
        if self.attempts >= self.max_attempts:
            self.stop('G3_ATTEMPTS', 'Total attempt limit exhausted.')
        self.attempts += 1
        identifier = getattr(authorization, 'id', None)
        if self.attempts > 1 and (not identifier or identifier in self.authorization_ids):
            self.stop('G3_FRESH_AUTHORIZATION', 'Retry requires a new reviewed authorization ID.')
        self.authorization_ids.add(identifier)

    def snapshot(self):
        return {'max_attempts': self.max_attempts, 'attempts': self.attempts,
                'total_timeout_seconds': self.deadline - self.started,
                'retry_transient': self.retry_transient,
                'elapsed_seconds': self.last_time - self.started}

    @contextmanager
    def activate(self):
        token = active_budget.set(self)
        try:
            self.check()
            yield self
        finally:
            active_budget.reset(token)


def checkpoint():
    budget = active_budget.get()
    if budget is not None:
        budget.check()


def bounded_timeout(limit):
    checkpoint()
    budget = active_budget.get()
    if budget is None:
        return limit
    remaining = budget.remaining()
    if remaining <= 0:
        budget.stop('G3_DEADLINE', 'Total execution deadline exhausted.')
    return min(limit, remaining)
