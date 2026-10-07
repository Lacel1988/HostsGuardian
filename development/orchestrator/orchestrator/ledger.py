"""Append-only, fsync-backed ledger. Recovery reads history; never replays commands."""
import json
import os
from pathlib import Path
from .model import now


class Ledger:
    def __init__(self, path, observer=None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.observer = observer
        self.sequence = len(self.read(self.path)) if self.path.exists() else 0

    def record(self, task, kind, message, worker=None, result=None):
        self.sequence += 1
        event = {'sequence': self.sequence, 'timestamp': now(), 'task_id': task.id,
                 'task_name': task.name, 'state': task.state, 'event': kind,
                 'worker': worker, 'operation': message, 'result': result,
                 'task': task.snapshot()}
        with self.path.open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(event, ensure_ascii=False) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        if self.observer:
            self.observer(event)

    @staticmethod
    def read(path):
        # A torn final record is reported as corruption, never silently discarded.
        return [json.loads(line) for line in Path(path).read_text(encoding='utf-8').splitlines()]

    @staticmethod
    def recover(path):
        events = Ledger.read(path)
        if not events:
            raise ValueError('Empty ledger')
        return events[-1]['task']
