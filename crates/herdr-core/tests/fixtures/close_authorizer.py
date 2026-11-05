"""Disposable policy fixture for native transaction tests, never an installed authorizer."""
import json
from pathlib import Path
import sys
import time

mode, folder = sys.argv[1:]
folder = Path(folder)
request = json.loads(sys.stdin.readline())
import os
assert 'HC_TERMINAL_ID' not in os.environ and 'HC_SCOPE' not in os.environ
assert os.environ.get('HC_SOCKET')
(folder / 'request.json').write_text(json.dumps(request), encoding='utf-8')
op = request['operation_id']
def emit(state, **extra):
    print(json.dumps({'version': 1, 'operation_id': op, 'state': state, **extra}), flush=True)
if mode == 'denied':
    emit('denied', allow=False)
    sys.exit(1)
if mode == 'oversized':
    print('x' * (256 * 1024 + 1), flush=True)
    sys.exit(1)
if mode == 'eof':
    sys.exit(1)
if mode == 'never_ready':
    sys.stdin.readline()
    sys.exit(1)
if mode in ('wait', 'bad_cancel'):
    deadline = time.monotonic() + 10
    while not (folder / 'go').exists():
        if time.monotonic() > deadline:
            sys.exit(1)
        time.sleep(.01)
(folder / 'lease').write_text('held', encoding='utf-8')
emit('ready', allow=True, token='fixture-token', targets=request['targets'])
outcome = json.loads(sys.stdin.readline())
assert (folder / 'lease').exists()
assert outcome['operation_id'] == op and outcome['token'] == 'fixture-token'
(folder / 'outcome.json').write_text(json.dumps(outcome), encoding='utf-8')
if mode == 'never_ack':
    sys.stdin.readline()
    sys.exit(1)
if mode == 'wait_ack':
    deadline = time.monotonic() + 10
    while not (folder / 'go_ack').exists():
        if time.monotonic() > deadline:
            sys.exit(1)
        time.sleep(.01)
if outcome['state'] == 'cancelled':
    if mode == 'bad_cancel':
        emit('unclear', allow=False)
        sys.exit(1)
    emit('cancelled', allow=False)
    (folder / 'lease').unlink()
    sys.exit(1)
if mode == 'bad_ack' and (request.get('context') or {}).get('mode') != 'reconcile':
    emit('unclear', allow=False)
    sys.exit(1)
emit('closed', allow=False)
(folder / 'lease').unlink()
