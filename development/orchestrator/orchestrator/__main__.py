import argparse
import json
from pathlib import Path
import signal
import threading
import time
from .ledger import Ledger
from .model import TaskState
from .workers import LocalWindowsWorker, SshLinuxWorker, Router
from .recipe import same_commit, validate_config


def main():
    parser = argparse.ArgumentParser(description='Read-only development orchestration MVP')
    parser.add_argument('--config', type=Path)
    parser.add_argument('--artifacts', type=Path)
    parser.add_argument('--show-ledger', type=Path)
    args = parser.parse_args()
    if args.show_ledger:
        print(json.dumps(Ledger.recover(args.show_ledger), indent=2))
        return 0
    if not args.config or not args.artifacts:
        parser.error('--config and --artifacts required for execution')
    config = json.loads(args.config.read_text(encoding='utf-8'))
    validate_config(config, args.artifacts)
    # Unique run directories, never overwrite previous evidence.
    run = args.artifacts.resolve()/('run-'+time.strftime('%Y%m%d-%H%M%S')+'-'+__import__('uuid').uuid4().hex[:8])
    run.mkdir(parents=True)
    (run/'config.json').write_text(json.dumps(config, indent=2), encoding='utf-8')
    cancel = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: cancel.set())
    started = time.monotonic()
    last_heartbeat = 0
    transcript = run/'operator.log'

    def observe(event):
        nonlocal last_heartbeat
        elapsed = time.monotonic()-started
        if event['event'] == 'HEARTBEAT' and elapsed-last_heartbeat < 2:
            return
        last_heartbeat = elapsed
        text = (f"{event['task_name']} [{event['task_id'][:8]}] {event['state'].value} "
                f"elapsed={elapsed:.1f}s worker={event['worker'] or '-'} "
                f"{event['event']}: {event['operation']}")
        if event['result'] is not None:
            text += ' '+json.dumps(event['result'], ensure_ascii=False)
        print(text, flush=True)
        with transcript.open('a', encoding='utf-8') as stream:
            stream.write(text+'\n')

    workers = []
    for value in config['workers']:
        if value['type'] == 'local-windows':
            worker = LocalWindowsWorker(value['id'], value['capabilities'])
        elif value['type'] == 'ssh-linux':
            worker = SshLinuxWorker(value['id'], value['capabilities'], value['alias'],
                                    connect_timeout=value.get('connect_timeout',8),
                                    probe_attempts=value.get('probe_attempts',2))
        else:
            raise ValueError('Unsupported worker type')
        workers.append(worker)
        print(f'{worker.identity} {worker.state.value} capabilities={sorted(worker.capabilities)}')
    ledger = Ledger(run/'events.jsonl', observe)
    task = same_commit(config, Router(workers), ledger, run, cancel)
    print(f'{task.state.value}; evidence={run}; events={ledger.sequence}')
    return 0 if task.state == TaskState.COMPLETE else 1


if __name__ == '__main__':
    raise SystemExit(main())
