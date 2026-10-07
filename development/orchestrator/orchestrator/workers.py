"""Bounded subprocess execution and configured capability-based workers."""
from dataclasses import asdict
import os
import shlex
import subprocess
import time
import uuid
import sys
from .model import Outcome, Result, WorkerState
from .snapshot import script


def run_process(argv, cwd, timeout, cancel, heartbeat=None):
    start = time.monotonic()
    if cancel.is_set():
        return Result(Outcome.CANCELLED, None, reason='Cancelled before process dispatch')
    try:
        process = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace')
    except OSError as exc:
        return Result(Outcome.FAILED, None, reason=str(exc), elapsed=time.monotonic()-start)
    outcome = None
    while True:
        elapsed = time.monotonic()-start
        if cancel.is_set():
            outcome = Outcome.CANCELLED
        elif elapsed >= timeout:
            outcome = Outcome.TIMED_OUT
        if outcome:
            process.kill()
            try:
                stdout, stderr = process.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                # A descendant may retain a pipe; do not wait without a bound.
                process.stdout.close()
                process.stderr.close()
                return Result(outcome, process.returncode, elapsed=time.monotonic()-start,
                              reason='Process stopped; descendant pipe/lifetime not proven', dispatched=True)
            return Result(outcome, process.returncode, stdout, stderr, time.monotonic()-start,
                          outcome.value, True)
        try:
            stdout, stderr = process.communicate(timeout=min(.25, max(.01, timeout-elapsed)))
            return Result(Outcome.SUCCESS if process.returncode == 0 else Outcome.FAILED,
                          process.returncode, stdout, stderr, time.monotonic()-start,
                          '' if process.returncode == 0 else 'Non-zero command exit', True)
        except subprocess.TimeoutExpired:
            if heartbeat:
                heartbeat(elapsed)


def requires_approval(operation):
    """MVP is a closed read-only git recipe, not an arbitrary shell executor."""
    prefix = ('git', '--no-optional-locks')
    allowed = {('rev-parse', '--show-toplevel'), ('rev-parse', '--is-inside-work-tree'),
               ('rev-parse', 'HEAD'), ('remote', 'get-url', 'origin'),
               ('status', '--porcelain=v1', '--untracked-files=all'),
               ('branch', '--show-current')}
    if operation.category != 'repository-read':
        return True
    return operation.argv != ('repository-snapshot',) and (operation.argv[:2] != prefix or operation.argv[2:] not in allowed)


class Worker:
    def __init__(self, identity, capabilities):
        self.identity = identity
        self.capabilities = frozenset(capabilities)
        self.state = WorkerState.IDLE

    def run(self, operation, cancel, notify):
        if self.approval_required(operation):
            self.state = WorkerState.WAITING_FOR_HUMAN
            raise PermissionError(f'Human approval required: {operation.category} / {operation.name}')
        self.state = WorkerState.BUSY
        notify('WORKER', self.identity, {'state': self.state, 'operation': operation.name})
        try:
            result = self.execute(operation, cancel, notify)
            if self.state != WorkerState.OFFLINE:
                self.state = WorkerState.IDLE if result.outcome == Outcome.SUCCESS else WorkerState.ERROR
            return result
        except Exception as exc:
            self.state = WorkerState.ERROR
            return Result(Outcome.UNCERTAIN, None,
                          reason=f'Unexpected worker error; dispatch not proven: {type(exc).__name__}: {exc}', dispatched=None)
        finally:
            notify('WORKER', self.identity, {'state': self.state, 'operation': operation.name})

    def approval_required(self, operation):
        return requires_approval(operation)


class LocalWindowsWorker(Worker):
    def execute(self, operation, cancel, notify):
        if os.name != 'nt':
            return Result(Outcome.FAILED, None, reason='Windows worker requires Windows')
        argv = (sys.executable, '-c', script()) if operation.argv == ('repository-snapshot',) else operation.argv
        return run_process(argv, operation.cwd, operation.timeout, cancel,
                           lambda seconds: notify('HEARTBEAT', self.identity, {'operation': operation.name, 'elapsed': round(seconds, 2)}))


def retry_preflight(result):
    # Only recognized transport failures during a harmless readiness probe.
    return (result.outcome == Outcome.FAILED and result.exit_code == 255 and
            any(text in result.stderr.lower() for text in
                ['timed out', 'connection refused', 'no route to host']) and
            not any(text in result.stderr.lower() for text in ['host key', 'host identification']))


def remote_result(result, start_marker, end_marker):
    started = start_marker in result.stdout.splitlines()
    completed = end_marker in result.stdout.splitlines()
    result.dispatched = True if started else None
    result.stdout = '\n'.join(line for line in result.stdout.splitlines()
                              if line not in {start_marker, end_marker})
    if result.exit_code == 255 or result.outcome in {Outcome.TIMED_OUT, Outcome.CANCELLED} or not completed or not started:
        result.outcome = Outcome.UNCERTAIN
        result.reason = 'Remote execution may have begun; completion/cancellation cannot be proven. No retry.'
    return result


class SshLinuxWorker(Worker):
    def __init__(self, identity, capabilities, alias, connect_timeout=8, probe_attempts=2, runner=run_process):
        super().__init__(identity, capabilities)
        self.alias, self.connect_timeout, self.probe_attempts = alias, connect_timeout, probe_attempts
        if not alias or alias.startswith('-') or not all(c.isalnum() or c in '-_.' for c in alias):
            raise ValueError('SSH alias must be a configured plain host alias')
        if not 1 <= probe_attempts <= 3 or not 1 <= connect_timeout <= 30:
            raise ValueError('Unbounded SSH settings')
        self.runner = runner

    def ssh(self, script, timeout, cancel, notify):
        argv = ['ssh', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                '-o', f'ConnectTimeout={self.connect_timeout}', '-o', 'ConnectionAttempts=1',
                '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=1', self.alias, script]
        return self.runner(argv, None, timeout, cancel,
                           lambda seconds: notify('HEARTBEAT', self.identity, {'elapsed': round(seconds, 2)}))

    def execute(self, operation, cancel, notify):
        total_start = time.monotonic()
        for attempt in range(self.probe_attempts):
            probe = self.ssh("printf 'ORCH_READY\\n'", self.connect_timeout+5, cancel, notify)
            notify('SSH_PREFLIGHT', self.identity, {'attempt': attempt+1, **asdict(probe)})
            if probe.outcome == Outcome.SUCCESS and probe.stdout.strip() == 'ORCH_READY':
                break
            if not retry_preflight(probe) or attempt+1 == self.probe_attempts:
                self.state = WorkerState.OFFLINE
                probe.dispatched = False  # repository command was never sent
                probe.reason = 'Readiness failed before repository command dispatch: '+probe.reason
                return probe
        if cancel.is_set():
            return Result(Outcome.CANCELLED, None, reason='Cancelled before repository dispatch')
        nonce = uuid.uuid4().hex
        start_marker, end_marker = f'ORCH_START_{nonce}', f'ORCH_END_{nonce}'
        argv = ('python3', '-c', script()) if operation.argv == ('repository-snapshot',) else operation.argv
        command = shlex.join(argv)
        # Mark dispatch before cd; even cwd failure must have a completed envelope.
        remote_script = (f"printf '%s\\n' {shlex.quote(start_marker)}; "
                  f"(cd -- {shlex.quote(operation.cwd)} && {command}); rc=$?; "
                  f"printf '\\n%s\\n' {shlex.quote(end_marker)}; exit \"$rc\"")
        result = remote_result(self.ssh(remote_script, operation.timeout, cancel, notify), start_marker, end_marker)
        result.elapsed = time.monotonic()-total_start
        return result


class Router:
    def __init__(self, workers):
        self.workers = workers

    def select(self, capability):
        matches = [worker for worker in self.workers if capability in worker.capabilities]
        if len(matches) != 1:
            raise ValueError(f'Expected one worker for {capability}; found {len(matches)}')
        return matches[0]
