#!/usr/bin/env python3
"""Agent hook: appends what an agent says it is doing to the claims ledger.

Install as a PreToolUse and PostToolUse command hook in Claude Code (`hook.py claude`) and in Codex
(`hook.py codex`); both send the same JSON on stdin, and Codex adds turn_id. A PostToolUse claim records the SHA-256
of each file the tool named, as the tool left it, so the reconciler can match an observed write to the call that made
it. File contents are never stored. An error exits 1, which both agents report without blocking the tool.

The hook never steers the agent: it prints only at SessionStart, and only a systemMessage, which both agents show to
the user and not to the model. It names the project's alerts that are new since the last one it showed, one line each.

It also keeps the watcher running. A SessionStart event registers the project (its git top level) in HOME/roots, which
a running watcher notices by itself; every event starts a watcher, detached into its own session, unless one already
holds HOME/watch.lock. The first start compiles watch.swift, cached by its hash. `hook.py launch` is that detached
step: compile if needed, then become the watcher.
"""
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import unicodedata
from pathlib import Path

HOME = Path(os.environ.get('AGENT_LEDGER_HOME', Path.home() / '.agent-ledger'))
PATH_KEYS = ('file_path', 'path', 'notebook_path', 'filePath')
PATCH_FILE = re.compile(r'^\*\*\* (?:Add|Update|Delete) File: (.+)$|^\*\*\* Move to: (.+)$', re.M)


def strings(tool_input):
    """Every string value in the tool input, one level into lists (Codex passes commands as argument lists)."""
    for value in tool_input.values():
        yield from [value] if isinstance(value, str) else [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def claim(agent, event, now_ms):
    tool_input, cwd = event.get('tool_input') or {}, canonical(event.get('cwd') or os.getcwd())
    named = [tool_input[k] for k in PATH_KEYS if isinstance(tool_input.get(k), str)]
    patches = [s for s in strings(tool_input) if '*** Begin Patch' in s]
    named += [a or b for p in patches for a, b in PATCH_FILE.findall(p)]
    command = tool_input.get('command', tool_input.get('cmd'))
    if isinstance(command, list):
        command = ' '.join(c for c in command if '*** Begin Patch' not in c)
    record = {'schema': 1, 't_ms': now_ms, 'agent': agent, 'event': event.get('hook_event_name'), 'session': event.get('session_id'),
              'turn': event.get('turn_id'), 'tool': event.get('tool_name'), 'tool_use_id': event.get('tool_use_id'),
              'cwd': cwd, 'command': command or tool_input.get('code'), 'paths': sorted({canonical(os.path.join(cwd, p)) for p in named})}
    if record['event'] == 'PostToolUse':
        record['sha256'] = {p: sha256(p) for p in record['paths']}
    return record


def canonical(path):
    """The real path (symlinks such as /tmp resolved, as the watcher reports it), in Unicode NFC."""
    return unicodedata.normalize('NFC', os.path.realpath(path))


def sha256(path):
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except (FileNotFoundError, IsADirectoryError):  # the tool deleted it, or named a directory: no content to bind
        return None


def register(cwd):
    """Adds the project holding `cwd` to HOME/roots, once, and returns it."""
    top = subprocess.run(['git', '-C', cwd, 'rev-parse', '--show-toplevel'], capture_output=True, text=True)
    root, roots = canonical(top.stdout.strip() if top.returncode == 0 else cwd), HOME / 'roots'
    if not roots.exists() or root not in roots.read_text().splitlines():
        with open(roots, 'a') as f:
            f.write(root + '\n')
    return root


def announce(root):
    """Prints the alerts under `root` newer than the last one shown there, as a systemMessage, and records them as shown.
    The watcher stamps each record when it writes it, so a change found later sorts after everything shown before.
    With nothing recorded under `root` it says so, since no alert would then mean nothing: the plugin also loads where
    no watcher runs, such as a Linux host of a Desktop SSH session, or a Mac without swiftc or without folder access."""
    import reconcile as r  # only SessionStart pays for this import
    observations = r.load(HOME / 'observations.jsonl')
    if not any(r.under(o['path'], root) for o in observations):
        print(json.dumps({'systemMessage': 'Agent Ledger: nothing recorded for this project on this machine yet. If that '
                                           'persists, its watcher is not running here: it runs only on macOS, needs swiftc '
                                           "for its first start, and needs the app's access to this folder "
                                           f'(log: {HOME / "watch.log"}).'}))
        return
    shown = json.loads((HOME / 'shown.json').read_text()) if (HOME / 'shown.json').exists() else {}
    found = r.reconcile(observations, r.load(HOME / 'claims.jsonl'), HOME)
    new = [a for a in found if a['kinds'] != ['GIT'] and r.under(a['o']['path'], root) and a['o']['t_ms'] > shown.get(root, 0)]
    if new:
        shown[root] = max(a['o']['t_ms'] for a in new)
        (HOME / 'shown.json').write_text(json.dumps(shown))
        check = f"python3 '{Path(__file__).resolve().with_name('reconcile.py')}' --diff"
        print(json.dumps({'systemMessage': f'Agent Ledger: {len(new)} new alert(s) in this project. Details and restore lines: '
                                           f'/agent-ledger:check in Claude Code, or {check}\n' + '\n'.join(map(r.headline, new))}))


def ensure_watcher():
    """Starts a detached watcher unless one already holds the lock."""
    with open(HOME / 'watch.lock', 'a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:  # a watcher holds it
            return
    with open(HOME / 'watch.log', 'a') as log:
        subprocess.Popen([sys.executable, __file__, 'launch'], start_new_session=True, stdin=subprocess.DEVNULL, stdout=log, stderr=log)


def launch():
    source = Path(__file__).with_name('watch.swift')
    binary = HOME / 'bin' / ('watch-' + hashlib.sha256(source.read_bytes()).hexdigest()[:12])
    if not binary.exists():
        binary.parent.mkdir(mode=0o700, exist_ok=True)
        building = binary.with_name(f'{binary.name}.{os.getpid()}')
        subprocess.run(['swiftc', '-O', '-o', str(building), str(source)], check=True)
        building.replace(binary)
    os.execv(binary, [str(binary), str(HOME)])


def main():
    HOME.mkdir(mode=0o700, parents=True, exist_ok=True)  # the ledger describes source code: owner-only
    if sys.argv[1] == 'launch':
        return launch()
    record = claim(sys.argv[1], json.load(sys.stdin), round(time.time() * 1000))
    with open(HOME / 'claims.jsonl', 'a') as f:
        f.write(json.dumps(record, sort_keys=True) + '\n')
    root = register(record['cwd']) if record['event'] == 'SessionStart' else None
    ensure_watcher()
    if root:
        announce(root)  # after the watcher starts, so a failure here never stops the recording


if __name__ == '__main__':
    main()
