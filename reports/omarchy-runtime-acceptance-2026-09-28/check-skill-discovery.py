#!/usr/bin/env python3
"""Query installed Codex skill discovery only; never start a model turn."""
import json
import os
from pathlib import Path
import selectors
import subprocess
import time

root = Path.home() / 'omarchy-night-test-20260928'
proc = subprocess.Popen(['codex', 'app-server', '--stdio'], stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
selector = selectors.DefaultSelector()
selector.register(proc.stdout, selectors.EVENT_READ)
buffer = b''

def send(value):
    proc.stdin.write((json.dumps(value) + '\n').encode())
    proc.stdin.flush()

def receive(request_id):
    global buffer
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        while b'\n' in buffer:
            line, buffer = buffer.split(b'\n', 1)
            value = json.loads(line)
            if value.get('id') == request_id:
                if 'error' in value:
                    raise RuntimeError(value['error'])
                return value['result']
        if selector.select(max(0, deadline - time.monotonic())):
            data = os.read(proc.stdout.fileno(), 65536)
            if not data:
                raise RuntimeError('app-server closed before response')
            buffer += data
            if len(buffer) > 2 * 1024 * 1024:
                raise RuntimeError('response buffer exceeded limit')
    raise TimeoutError('app-server response timeout')

try:
    send({'id': 1, 'method': 'initialize', 'params': {
        'clientInfo': {'name': 'omarchy-skill-discovery-check', 'version': '1.0'},
        'capabilities': {'experimentalApi': True}}})
    receive(1)
    send({'method': 'initialized', 'params': {}})
    cwds = [str(root / name) for name in ('omarchy-vpnrouter', 'stt-parrot',
                                        'omarchy-plugin-observatory')]
    send({'id': 2, 'method': 'skills/list', 'params': {
        'cwds': cwds, 'forceReload': True}})
    result = receive(2)
    path = root / 'evidence' / 'codex-skills-list.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2) + '\n')
    entries = result.get('data', [])
    if sorted(entry.get('cwd', '') for entry in entries) != sorted(cwds):
        raise RuntimeError('skills/list did not cover all requested directories')
    for entry in entries:
        if entry.get('errors'):
            raise RuntimeError('skill catalog reports loading errors')
        found = {s['name'] for s in entry.get('skills', []) if s.get('enabled')}
        if not {'omarchy', 'omarchy-plugin-patterns'} <= found:
            raise RuntimeError('required Omarchy skills missing or disabled')
    print('PASS: required skills discovered in all three project contexts')
    print(path)
finally:
    selector.close()
    proc.stdin.close()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
