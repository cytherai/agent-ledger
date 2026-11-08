#!/usr/bin/env python3
"""Reconciles what agents claimed (claims.jsonl, from hook.py) with what the watcher observed (observations.jsonl).

Alerts:
- UNCLAIMED: a change no agent claimed. A tool call covers a change that fell inside the call (PreToolUse to
  PostToolUse, plus 2 s) to a path it named, or, for a shell call, to any path under its working directory. Read-only
  tools cover nothing.
- STALE-REVERT: a change back to content the file held earlier (not the version just before) that no call aimed at
  this file made: it is unclaimed, or credited to a shell call only by its time window. Checked whatever the claims
  say. A shell command's text cannot show that it only reads (a test run may write), so the test is whether the call
  named the file as its target.
- REVERTED: such a change made by a call that named the file (an Edit, Write or patch of it).
  Both list every call that named the file while it held the returning content: who had seen that version.
- UNWATCHED: a change made while the watcher was stopped, found at its next start; it cannot be attributed.
- PARTIAL: a change found by rescanning after the operating system dropped events, or by the watcher's minutely
  checkpoint after the event stream missed it; it cannot be attributed.
Not alerts:
- Git operations (shown as GIT and counted). Within 2 s of the change, either:
  - a reflog moved and the file now holds what that move promises: a new HEAD entry, the file's content at the new
    commit; a new stash entry, its content at HEAD; a popped stash entry, its content in that stash;
  - or the change falls in an agent's shell call that runs a worktree-writing git command (checkout, restore, reset,
    stash, switch, rebase, merge, pull, cherry-pick, revert, am, apply).
  `git restore` and `checkout -- <file>` move no reflog, so on disk they look exactly like a stale write of the
  committed version beside a `git status`. Both stay STALE-REVERT, labelled with the evidence `git-index` (the index
  changed and git stores the content: possibly your own restore).
- Paths git ignores (`git check-ignore`).
Paths are compared as the file system compares them: Unicode NFC, and without case on a case-insensitive volume.
Each alert states its evidence: hook-claim, time-window, provenance, rescan, checkpoint, git-index, or none. Provenance counts only
when a stamp appeared or changed with this version, and names an app, never a session: a copy carries its source's
stamp. An unclaimed change's writer is "not established". Each alert names the change it undid, and a one-line restore
of the version before it, which refuses if the file changed after the alert. With --explain, Claude writes an
incident report for each alert from its first line, content and restore lines and diff; it is never told the writer,
who saw the version, or the change undone. That sends file contents to Anthropic's API (ANTHROPIC_API_KEY), after
keys, tokens and passwords are redacted on this machine.
Usage: reconcile.py [--home DIR] [--project DIR] [--checkpoint | --answered ID] [--diff] [--explain]
       reconcile.py [--home DIR] --restore PATH EXPECTED VERSION
"""
import argparse
import ctypes
import difflib
import functools
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import unicodedata
import uuid
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

GRACE_MS = 2000
VCS_WINDOW_MS = 2000
STALE_MS = 150_000  # the watcher sends a heartbeat every 60 s; none for this long is a gap
CHECK_WAIT_S = 15  # how long a check waits for the watcher's answer; none by then is coverage unknown
UNSETTLED = {'unwatched': 'the watcher is not watching this project', 'unreadable': 'the watcher could not read the project',
             'unreadable-files': 'the watcher could not read some of its files', 'unsettled': 'files kept changing during the check'}
GIT_WRITES = re.compile(r'\bgit\s+(?:-C\s+\S+\s+)?(?:checkout|restore|reset|stash|switch|rebase|merge|pull|cherry-pick|revert|am|apply)\b')
READ_ONLY = {'Read', 'Glob', 'Grep', 'LS', 'WebFetch', 'WebSearch'}  # Claude Code tools that cannot write a file
MARKERS = {'ChatGPT app (Codex)': '~/.codex/logs_2.sqlite'}  # a file only that app writes: its stamp names the app
MODEL = 'claude-opus-5-5'
ABSENT = 'absent'  # the state of a deleted file, where a restore expects a hash
SECRETS = [  # (pattern, replacement): private keys, known token formats, then values assigned to secret-looking names
    (re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----', re.S), '[REDACTED PRIVATE KEY]'),
    (re.compile(r'\b(?:sk-ant-[\w-]{20,}|sk-[\w-]{20,}|A[KS]IA[0-9A-Z]{16}|gh[pousr]_\w{30,}|github_pat_\w{40,}|xox[abprs]-[\w-]{10,}'
                r'|AIza[\w-]{35}|[rs]k_live_\w{20,}|eyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,})'), '[REDACTED]'),
    (re.compile(r'(?i)((?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)\w*["\']?\s*[:=]\s*["\']?|bearer\s+)[^\s"\']{6,}'),
     r'\1[REDACTED]'),
]
SENT = ('  content:', '  restore:', '    ')  # --explain sends these after an alert's first line; never writer, seen by, undoes
BRIEF = ('You write incident reports for an agent write ledger. From the facts and diff given, and nothing else, say in '
         'under 200 words: what changed, what was lost, and the next step. You are not told who wrote the change; do not '
         'guess, because the alert printed with your report states what is known. Separate what the evidence shows from '
         'what it only suggests. Copy paths, hashes and commands exactly, never shortened.')


def load(path):
    path = Path(path)
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()] if path.exists() else []


def calls(claims):
    """One entry per tool call, its PreToolUse and PostToolUse claims merged into a time window."""
    merged = {}
    for c in sorted(claims, key=lambda c: c['t_ms']):
        call = merged.setdefault(c['tool_use_id'], {**c, 'start': c['t_ms'], 'sha256': {}, 'paths': []})
        call['end'] = c['t_ms']
        call['sha256'].update(c.get('sha256') or {})
        call['paths'] = sorted(set(call['paths']) | set(c['paths']))
    return list(merged.values())


@functools.cache
def case_sensitive(directory):
    while not os.path.exists(directory):
        directory = os.path.dirname(directory)
    libc = ctypes.CDLL(None)
    libc.pathconf.restype = ctypes.c_long
    return libc.pathconf(os.fsencode(directory), 11) != 0  # _PC_CASE_SENSITIVE: 0 means insensitive; -1 (unknown) compares exactly


def key(path):
    """The path as the file system compares names: NFC, and case-folded on a case-insensitive volume."""
    path = unicodedata.normalize('NFC', path)
    return path if case_sensitive(os.path.dirname(path) or '/') else path.casefold()


def under(path, folder):
    """Whether `path` lies inside `folder`, its names compared as the file system compares them."""
    return key(path).startswith(key(folder).rstrip('/') + '/')


def names(call, path):
    return key(path) in {key(p) for p in call['paths']}


def covers(call, o):
    if call['tool'] in READ_ONLY or not call['start'] <= o['t_ms'] <= call['end'] + GRACE_MS:
        return False
    return names(call, o['path']) or (bool(call.get('command')) and key(o['path']).startswith(key(call['cwd']).rstrip('/') + '/'))


@functools.cache
def repository(directory):
    """The root of the git working tree holding `directory`, or None."""
    while directory != os.path.dirname(directory):
        if os.path.isdir(os.path.join(directory, '.git')):
            return directory
        directory = os.path.dirname(directory)
    return None


def git(root, *args, data=None):
    return subprocess.run(['git', '-C', root, *args], input=data, capture_output=True)


def ignored(paths):
    """The paths their repository's ignore rules exclude."""
    by_root = {}
    for path in paths:
        if root := repository(os.path.dirname(path)):
            by_root.setdefault(root, []).append(path)
    found = set()
    for root, group in by_root.items():
        result = git(root, 'check-ignore', '--stdin', '-z', data='\0'.join(group).encode())
        if result.returncode > 1:  # 0: some ignored, 1: none ignored, anything else: git failed
            raise subprocess.CalledProcessError(result.returncode, result.args, result.stdout, result.stderr)
        found |= {os.fsdecode(p) for p in result.stdout.split(b'\0') if p}
    return found


def reflog_moves(observations, home):
    """(t_ms, root, revision) for each reflog line added or removed between consecutive kept versions of a repository's
    HEAD and stash reflogs: the revision whose content the worktree should now hold."""
    moves, seen = [], {}
    for o in sorted((o for o in observations if o['kind'] == 'vcs' and '/.git/logs/' in o['path']), key=lambda o: o['t_ms']):
        lines = (home / 'versions' / o['sha256']).read_text().splitlines() if o.get('sha256') else []
        before, stash, root = seen.get(o['path']), o['path'].endswith('/refs/stash'), o['path'].split('/.git/')[0]
        if before is not None:  # the first version is the baseline
            moves += [(o['t_ms'], root, line.split()[1] + ('^1' if stash else '')) for line in lines if line not in before]
            moves += [(o['t_ms'], root, line.split()[1]) for line in before if stash and line not in lines]
        seen[o['path']] = lines
    return moves


def blob(root, version_file):
    return git(root, 'hash-object', '--', str(version_file)).stdout.decode().strip()


def git_operation(o, covering, moves, home):
    """Whether git made this change: an agent's shell call that ran a worktree-writing git command covers it, or a reflog
    move within the window promises exactly this content (or this deletion)."""
    if any(GIT_WRITES.search(c.get('command') or '') for c in covering):
        return True
    root = repository(os.path.dirname(o['path']))
    nearby = [rev for t, r, rev in moves if r == root and abs(t - o['t_ms']) <= VCS_WINDOW_MS]
    if not nearby:
        return False
    actual = blob(root, home / 'versions' / o['sha256']) if o.get('sha256') else None
    relative = os.path.relpath(o['path'], root)
    return any((git(root, 'rev-parse', '--verify', '--quiet', f'{rev}:{relative}').stdout.decode().strip() or None) == actual for rev in nearby)


def index_refresh(o, markers, home):
    """The index changed within the window and git stores the new content: a `git restore`, or a stale write of a
    committed version beside a `git status`. The two cannot be told apart on disk."""
    root = repository(os.path.dirname(o['path']))
    if root is None or not o.get('sha256') or not any(m['root'] == root and abs(m['t_ms'] - o['t_ms']) <= VCS_WINDOW_MS for m in markers):
        return False
    return git(root, 'cat-file', '-e', blob(root, home / 'versions' / o['sha256'])).returncode == 0


def mentions(call, path):
    relative = os.path.relpath(path, call['cwd'])
    command = call.get('command') or ''
    return path in call['paths'] or path in command or (not relative.startswith('..') and relative in command)


def new_stamp(o, previous):
    """The provenance stamp that appeared or changed with this version, or None: a stamp the file already had says
    nothing about this write."""
    return o.get('provenance') if o.get('provenance') != (previous or {}).get('provenance') else None


def evidence(o, by, previous):
    basis = ['hook-claim' if names(by, o['path']) else 'time-window'] if by else []
    basis += ['provenance'] if new_stamp(o, previous) else []
    basis += {'startup': ['rescan'], 'rescan': ['rescan'], 'checkpoint': ['checkpoint']}.get(o['kind'], [])
    return basis or ['none']


def swept(observations, root):
    """The latest span of the watcher's minutely sweeps of `root`, readable and unbroken: (start, end), or None. History
    only: a check decides coverage from its own checkpoint, never from past heartbeats."""
    beats = sorted((o for o in observations if o['kind'] == 'heartbeat' and under(root + '/', o['path'])), key=lambda o: o['t_ms'])
    last = max((i for i, b in enumerate(beats) if b['readable']), default=None)
    if last is None:
        return None
    start = beats[last]
    for b in reversed(beats[:last]):
        if start['t_ms'] - b['t_ms'] > STALE_MS or not b['readable']:
            break
        start = b
    return start['t_ms'], beats[last]['t_ms']


def request_checkpoint(home, project, wait=CHECK_WAIT_S):
    """Asks the running watcher to compare `project` with its records now. Returns the `sweep` record it writes once
    that is complete, or None when none came within `wait` seconds; the request is then withdrawn."""
    rid, folder = uuid.uuid4().hex, Path(home, 'requests')
    folder.mkdir(mode=0o700, exist_ok=True)
    (folder / f'.{rid}').write_text(json.dumps({'id': rid, 'path': project}))
    (folder / f'.{rid}').rename(folder / f'{rid}.json')  # whole or absent: the watcher reads only *.json
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        answer = next((o for o in load(Path(home, 'observations.jsonl')) if o['kind'] == 'sweep' and o.get('request') == rid), None)
        if answer:
            return answer
        time.sleep(0.2)
    (folder / f'{rid}.json').unlink(missing_ok=True)
    return None


def reconcile(observations, claims, home=None):
    """Alerts in time order: {'o', 'kinds', 'evidence', 'by', 'previous', 'undoes', 'held', 'seen_by'}. A change git
    made is returned with kinds ['GIT'] so it is visible but not alarming. `home` holds the kept versions."""
    markers = [{'root': os.path.dirname(os.path.dirname(o['path'])), 't_ms': o['t_ms']} for o in observations
               if o['kind'] == 'vcs' and o['path'].endswith('/.git/index')]
    moves = reflog_moves(observations, home) if home else []
    files = [o for o in observations if o['kind'] in ('startup', 'change', 'rescan', 'checkpoint')]
    skip = ignored({o['path'] for o in files})
    tool_calls, history, alerts = calls(claims), {}, []
    for o in sorted((o for o in files if o['path'] not in skip), key=lambda o: o['t_ms']):
        before = history.setdefault(o['path'], [])
        covering = [c for c in tool_calls if covers(c, o)]
        by = max(covering, key=lambda c: c['start'], default=None)  # the most recent call that could have made it
        kinds = []
        if o['kind'] == 'change' and by is None:
            kinds.append('UNCLAIMED')
        if o['kind'] in ('startup', 'rescan', 'checkpoint') and before:
            kinds.append('UNWATCHED' if o['kind'] == 'startup' else 'PARTIAL')
        spans = [(p['t_ms'], (before + [o])[i + 1]['t_ms']) for i, p in enumerate(before[:-1])
                 if o.get('sha256') is not None and p.get('sha256') == o['sha256']]
        if spans:
            kinds.append('REVERTED' if by is not None and names(by, o['path']) else 'STALE-REVERT')
        if kinds and o['kind'] == 'change' and git_operation(o, covering, moves, home):  # git's evidence outranks a time window
            kinds = ['GIT']
        if kinds:
            previous = before[-1] if before else None
            basis = evidence(o, by, previous) + (['git-index'] if 'STALE-REVERT' in kinds and index_refresh(o, markers, home) else [])
            alerts.append({'o': o, 'kinds': kinds, 'evidence': [b for b in basis if b != 'none'] or ['none'], 'by': by, 'previous': previous, 'held': spans,
                           'undoes': previous and next((c for c in tool_calls if covers(c, previous)), None),
                           'seen_by': [c for c in tool_calls if mentions(c, o['path']) and any(s <= c['start'] < e for s, e in spans)]})
        before.append(o)
    return alerts


def stamp(path):
    """The com.apple.provenance value of a file, as hex, or None."""
    libc = ctypes.CDLL(None)
    libc.getxattr.restype = ctypes.c_ssize_t
    buffer = ctypes.create_string_buffer(64)
    n = libc.getxattr(os.fsencode(path), b'com.apple.provenance', buffer, ctypes.c_size_t(64), ctypes.c_uint32(0), ctypes.c_int(0))
    return buffer.raw[:n].hex() if n > 0 else None


def clock(ms):
    return datetime.fromtimestamp(ms / 1000).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]


def describe(call):
    turn = f" turn {call['turn'][:8]}" if call.get('turn') else ''
    return f"{call['agent']} session {call['session'][:8]}{turn} {call['tool']} at {clock(call['start'])[11:]}" + \
        (f": {call['command'][:90]}" if call.get('command') else '')


def headline(a):
    """An alert's first line: when, what kind, which file."""
    return f"{clock(a['o']['t_ms'])}  {' '.join(a['kinds'])}  {a['o']['path']}"


def lines(a, labels, home):
    """An alert as text: its facts, then the diff from the version before when both versions are kept."""
    o, previous = a['o'], a['previous']
    out = [headline(a), f"  evidence: {', '.join(a['evidence'])}"]
    if a['by'] is None:
        app = new_stamp(o, previous) and labels.get(o['provenance'], f"an app with provenance {o['provenance']}")
        out.append('  writer:   not established: no agent claimed this change'
                   + (f'; a provenance stamp of {app} appeared with this version' if app else ''))
    else:
        out.append(f"  writer:   {describe(a['by'])}")
    out += [f"  content:  back to the version held {clock(s)[11:]} to {clock(e)[11:]} ({o['sha256'][:8]})" for s, e in a['held']]
    out += [f'  seen by:  {describe(call)}' for call in a['seen_by']]
    if previous and a['undoes']:
        out.append(f"  undoes:   the {clock(previous['t_ms'])[11:]} change by {describe(a['undoes'])}")
    if previous and previous.get('sha256'):
        out.append('  restore:  ' + restore_command(home, o['path'], o.get('sha256') or ABSENT, previous['sha256']))
        if o.get('sha256'):
            old, new = [(home / 'versions' / s).read_text().splitlines(keepends=True) for s in (previous['sha256'], o['sha256'])]
            out.append(''.join('    ' + line for line in difflib.unified_diff(old, new, 'before', 'after')).rstrip())
    return out


def restore_command(home, path, expected, version):
    return f"python3 '{Path(__file__).resolve()}' --home '{Path(home).resolve()}' --restore '{path}' {expected} {version}"


def sha256(path):
    """The SHA-256 of a file's bytes, or None when there is no file."""
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except FileNotFoundError:  # deleted: the state a restore compares as ABSENT
        return None


def restore(home, path, expected, version):
    """Puts the kept `version` back at `path`, only if the file is still `expected` (its hash, or ABSENT) when checked:
    a change made after the alert is not overwritten unless its own state is passed instead. The bytes are checked
    against their hash in a temporary file beside `path`, which then replaces it in one rename, so a failure leaves the
    file as it was. The check and the rename are not one atomic step: a write landing between them is lost."""
    kept = Path(home) / 'versions' / version
    if not kept.exists():
        raise SystemExit(f'restore: no kept version {version} in {kept.parent}; nothing changed')
    temporary = Path(path).with_name(f'.{Path(path).name}.restore-{os.getpid()}')
    try:
        shutil.copyfile(kept, temporary)
        if sha256(temporary) != version:
            raise SystemExit(f'restore: the kept version {version[:8]} no longer matches its hash; nothing changed')
        current = sha256(path) or ABSENT
        if current != expected:
            raise SystemExit(f'restore: refused, {path} is now {current}, not {expected}: it changed after the alert. '
                             f'To overwrite it anyway: {restore_command(home, path, current, version)}')
        if current != ABSENT:
            shutil.copymode(path, temporary)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    print(f'restored {path} to {version[:8]}')


def redact(text):
    for pattern, replacement in SECRETS:
        text = pattern.sub(replacement, text)
    return text


def explain(facts, send=None):
    """Claude's incident report for one alert's facts, redacted before they leave the machine. `send` posts a request
    and returns the parsed response. The model always thinks, and thinking counts toward max_tokens, so effort is low and
    the cap leaves room for it. A declined request is retried on Anthropic's fallback model for its category."""
    body = {'model': MODEL, 'max_tokens': 4096, 'output_config': {'effort': 'low'}, 'fallbacks': 'default',
            'system': BRIEF, 'messages': [{'role': 'user', 'content': redact(facts)}]}
    response = (send or post)(body)
    if response['stop_reason'] != 'end_turn':  # 'refusal' (every model declined) or 'max_tokens': no report, or half of one
        raise SystemExit(f"--explain: Claude stopped with {response['stop_reason']}: {response.get('stop_details')}")
    return ''.join(block['text'] for block in response['content'] if block['type'] == 'text')


def post(body):
    request = urllib.request.Request('https://api.anthropic.com/v1/messages', data=json.dumps(body).encode(), headers={
        'x-api-key': os.environ['ANTHROPIC_API_KEY'], 'anthropic-version': '2023-06-01', 'content-type': 'application/json',
        'anthropic-beta': 'server-side-fallback-2026-07-01'})  # the beta `fallbacks: 'default'` needs
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            return json.load(response)
    except urllib.error.HTTPError as e:  # urllib's message is only the status; the API's reason is in the body
        raise SystemExit(f'--explain: HTTP {e.code}: {e.read().decode()}') from e


def report(alerts, labels, home, diff, explained):
    for a in (a for a in alerts if a['kinds'] != ['GIT']):
        text = lines(a, labels, home)
        print('\n'.join(text if diff else [line for line in text if not line.startswith('    ')]))
        if explained:
            facts = text[:1] + [line for line in text[1:] if line.startswith(SENT)]
            print('\n  incident report (Claude):\n' + '\n'.join('    ' + line for line in explain('\n'.join(facts)).splitlines()))
        print()


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--home', default=os.environ.get('AGENT_LEDGER_HOME', Path.home() / '.agent-ledger'))
    p.add_argument('--diff', action='store_true', help='show each alert as a unified diff from the version before')
    p.add_argument('--explain', action='store_true',
                   help="add Claude's incident report; sends the facts and diff to Anthropic's API after redacting keys, tokens and passwords")
    p.add_argument('--restore', nargs=3, metavar=('PATH', 'EXPECTED', 'VERSION'),
                   help=f'put the kept VERSION back at PATH, only if PATH still has the hash EXPECTED ({ABSENT} if deleted)')
    p.add_argument('--project', default='/', help='only alerts under this folder; exits 1 if nothing was ever recorded under it')
    check = p.add_mutually_exclusive_group()
    check.add_argument('--checkpoint', action='store_true',
                       help='ask the running watcher to compare the project with its records now; without a settled answer, coverage is unknown')
    check.add_argument('--answered', metavar='ID', help="judge coverage by the recorded answer to the project's check request ID, without asking")
    a = p.parse_args()
    home = Path(a.home)
    if a.restore:
        return restore(home, *a.restore)
    labels = {stamp(os.path.expanduser(marker)): name for name, marker in MARKERS.items() if os.path.exists(os.path.expanduser(marker))}
    observations, project = load(home / 'observations.jsonl'), os.path.realpath(a.project)
    if not any(under(o['path'], project) for o in observations):  # there "0 alerts" would read as an all-clear
        raise SystemExit(f'nothing recorded under {project} on this machine, so no alert there means nothing. The watcher '
                         "runs only on macOS, needs swiftc for its first start, and needs the app's access to the folder; "
                         f'see {home / "watch.log"}.')
    if a.checkpoint:
        answer, observations = request_checkpoint(home, project), load(home / 'observations.jsonl')  # with what the check found
    else:  # an answer for this project only
        answer = next((o for o in observations if o['kind'] == 'sweep' and o.get('request') == a.answered and o['path'] == project), None)
    found = [x for x in reconcile(observations, load(home / 'claims.jsonl'), home) if under(x['o']['path'], project)]
    alerts = [x for x in found if x['kinds'] != ['GIT']]
    if a.explain and alerts:
        print(f"--explain: sending {len(alerts)} alert(s) to Anthropic's API; keys, tokens and passwords are redacted first", file=sys.stderr)
    report(alerts, labels, home, a.diff, a.explain)
    print(f'{len(alerts)} alert(s); {len(found) - len(alerts)} change(s) made by git')
    why = ('no check was asked for (run with --checkpoint)' if not (a.checkpoint or a.answered) else
           'no watcher answered the check' if answer is None else
           None if answer['status'] == 'settled' else UNSETTLED.get(answer['status'], f"the watcher answered {answer['status']}"))
    print(f"State: {'ALERTS_PRESENT' if alerts else 'COVERAGE_UNKNOWN' if why else 'NO_ALERTS_OBSERVED'} under {project}.")
    if why:
        print(f'Coverage unknown: {why}.')
    else:
        print(f"Checkpoint {answer['sequence']}, completed {clock(answer['t_ms'])}: every tracked file under {project} matched "
              'its last record, and none changed while it was compared.')
    span = swept(observations, project)
    if span:
        print(f"The watcher's minutely sweeps of the folder ran unbroken from {clock(span[0])} to {clock(span[1])}.")
    print('None of this shows that monitoring had no gap, or that no change was made and undone between two sweeps '
          'without the event stream seeing it.')


if __name__ == '__main__':
    main()
