#!/usr/bin/env python3
"""Agent hook: appends what an agent says it is doing to the claims ledger.

Install as a PreToolUse and PostToolUse command hook in Claude Code (`hook.py claude`, where PostToolUseFailure, for a
call that fails, runs it too) and in Codex (`hook.py codex`); both send the same JSON on stdin, and Codex adds turn_id.
A PostToolUse or PostToolUseFailure claim records the SHA-256 of each file the tool named, as the tool left it, so the
reconciler can match an observed write to the call that made it. File contents are never stored. An error exits 1, which both agents report without blocking the tool.

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
import shlex
import subprocess
import sys
import time
import unicodedata
from pathlib import Path

HOME = Path(os.environ.get('AGENT_LEDGER_HOME', Path.home() / '.agent-ledger'))
PATH_KEYS = ('file_path', 'path', 'notebook_path', 'filePath')
PATCH_FILE = re.compile(r'^\*\*\* (?:Add|Update|Delete) File: (.+)$|^\*\*\* Move to: (.+)$', re.M)
HEREDOC = re.compile(r"""cat\s*(>>?)\s*(\S+)\s*<<-?\s*(['"])(\w+)\3[^\n]*\n(.*?\n)??\4[ \t]*(?=\n|$)""", re.S)  # quoted: its body is literal
REDIRECT = re.compile(r'(?<![0-9&<>])(>>?)\s*([^\s;&|<>()]+)')


def strings(tool_input):
    """Every string value in the tool input, one level into lists (Codex passes commands as argument lists)."""
    for value in tool_input.values():
        yield from [value] if isinstance(value, str) else [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def content(path):
    try:
        return Path(path).read_bytes()
    except (FileNotFoundError, IsADirectoryError):
        return None


def expects(tool, tool_input, cwd, command, read=content):
    """What a call is set to leave in the files it writes, worked out before it runs: {path: SHA-256, or None when only
    the target is known}. None for a tool this cannot read. A Write leaves its content. An Edit leaves the file with its
    one replacement made (or all, when asked), if the text before it allows exactly that. A shell command writes the
    files it redirects into, and `cat > f <<'EOF'` leaves its literal body there (`>>` after what the file held); it is
    given no other file, whatever else its text mentions. `read` returns a file's bytes, or None."""
    at = lambda p: canonical(os.path.join(cwd, p))
    path = tool_input.get('file_path')
    if tool == 'Write' and isinstance(path, str) and isinstance(tool_input.get('content'), str):
        return {at(path): hashlib.sha256(tool_input['content'].encode()).hexdigest()}
    if tool == 'Edit' and isinstance(path, str) and isinstance(tool_input.get('old_string'), str) and isinstance(tool_input.get('new_string'), str):
        try:
            text = read(at(path)).decode()
        except (AttributeError, UnicodeDecodeError):  # no file, or not UTF-8 text: no result this can foretell
            return {}
        old, new = tool_input['old_string'], tool_input['new_string']
        if not old or (text.count(old) != 1 and not (tool_input.get('replace_all') and old in text)):
            return {}  # the edit will fail, or is ambiguous
        return {at(path): hashlib.sha256(text.replace(old, new).encode()).hexdigest()}
    if not isinstance(command, str):
        return None
    writes = [(m.start(), m.group(1), m.group(2), (m.group(5) or '').encode()) for m in HEREDOC.finditer(command)]
    rest = HEREDOC.sub(lambda m: ' ' * len(m.group(0)), command)  # a body's own text is no redirection
    writes += [(m.start(), m.group(1), m.group(2), None) for m in REDIRECT.finditer(rest)]
    left = {}
    for _, how, target, body in sorted(writes, key=lambda w: w[0]):
        target = target.strip('\'"')
        if target.startswith('/dev/') or '$' in target:
            continue
        p = at(target)
        before = (left[p] if p in left else read(p) or b'') if how == '>>' else b''
        left[p] = None if body is None or before is None else before + body
    return {p: data if data is None else hashlib.sha256(data).hexdigest() for p, data in left.items()}


def claim(agent, event, now_ms):
    tool_input, cwd = event.get('tool_input') or {}, canonical(event.get('cwd') or os.getcwd())
    named = [tool_input[k] for k in PATH_KEYS if isinstance(tool_input.get(k), str)]
    patches = [s for s in strings(tool_input) if '*** Begin Patch' in s]
    named += [a or b for p in patches for a, b in PATCH_FILE.findall(p)]
    command = None if patches else tool_input.get('command', tool_input.get('cmd'))  # a patch writes only the files it names
    if isinstance(command, list):
        command = ' '.join(c for c in command if isinstance(c, str))
    record = {'schema': 1, 't_ms': now_ms, 'agent': agent, 'event': event.get('hook_event_name'), 'session': event.get('session_id'),
              'turn': event.get('turn_id'), 'tool': event.get('tool_name'), 'tool_use_id': event.get('tool_use_id'),
              'cwd': cwd, 'command': command or tool_input.get('code'), 'paths': sorted({canonical(os.path.join(cwd, p)) for p in named})}
    if record['event'] == 'PreToolUse':
        foretold = expects(record['tool'], tool_input, cwd, command)
        if foretold is not None:
            record['expects'] = foretold
    if record['event'] in ('PostToolUse', 'PostToolUseFailure'):  # a failed call ends too; this samples its files afterwards
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
        check = shlex.join(['python3', str(Path(__file__).resolve().with_name('reconcile.py')), '--home', str(HOME), '--project', root, '--diff'])
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
    with open(HOME / 'claims.jsonl', 'a+b') as f:
        f.seek(0, os.SEEK_END)
        cut = f.tell() > 0 and (f.seek(-1, os.SEEK_END), f.read(1))[1] != b'\n'  # a line cut short: end it, so this one stands alone
        f.write(b'\n' * cut + json.dumps(record, sort_keys=True).encode() + b'\n')
    root = register(record['cwd']) if record['event'] == 'SessionStart' else None
    ensure_watcher()
    if root:
        announce(root)  # after the watcher starts, so a failure here never stops the recording


if __name__ == '__main__':
    main()
