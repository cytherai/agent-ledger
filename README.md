# Agent Ledger

Agent Ledger flags file changes that no coding agent claimed, and keeps earlier versions so you can put a file back
with a guarded restore. It is a Claude Code plugin for macOS.

When two agents, or an agent and an editor, work in the same folder, one can silently undo another's edit, and each
agent's own log clears it, because each knows only what it did. Agent Ledger compares what agents say they change,
recorded by their hooks, with what actually changed on disk, recorded by a file watcher, and tells you about the
difference.

## Install

```sh
claude plugin marketplace add cytherai/agent-ledger
claude plugin install agent-ledger@cytherai
```

Or, in a session on Claude Code 2.1.275 or later: `/plugin install agent-ledger --marketplace cytherai/agent-ledger`.
It needs macOS, and `python3` and `swiftc`, both from Xcode's command-line tools (`xcode-select --install`).

## What it detects

- **UNCLAIMED:** a file changed and no agent's tool call covers the change.
- **STALE-REVERT:** a file went back to content it held earlier, and no call aimed at that file made the change. This
  is the pattern of a stale copy overwriting newer work.
- **REVERTED:** the same, made by a call that named the file.
- **UNWATCHED:** a file changed while the watcher wasn't running, found when it started again.
- **PARTIAL:** found by a rescan after macOS dropped file events; it can't be attributed.

Checkouts, stashes, merges and commits are counted as git operations, not alerted. `git restore` leaves no trace a
stale write wouldn't, so it stays an alert, labelled `git-index`.

## What it can't tell you

- **Who wrote a change no agent claimed.** The writer is "not established". If a macOS provenance stamp appeared with
  the change, the alert names the app it belongs to: a clue, not proof.
- **Changes outside the time it can vouch for.** Each minute the watcher compares every file with its last record
  and sends a heartbeat. `/agent-ledger:check` names the span those heartbeats cover, or says coverage is unknown and
  since when. A change made and undone between two comparisons, if the event stream missed it, leaves no trace.
- **Overlapping shell work.** Two agents running shell commands in one folder at the same time can cover each other's
  writes, because a shell write is attributed to the call whose time window it falls in.
- **Fast or large writes.** Two writes within about 50 ms keep only the last version. Files over 64 MB are not tracked.
- **Files it can't read.** A file the watcher can't read is skipped, never recorded as deleted, so its content isn't
  vouched for while it stays unreadable.

## Alerts

- **At session start,** a message lists the project's new alerts, one line each. It is shown to you, not to the model.
  If nothing has been recorded for the project on this machine, it says so.
- **`/agent-ledger:check`** shows the project's alerts in full, with the diff and a restore command for each. It ends
  with a state, never "clean": `ALERTS_PRESENT`; `NO_ALERTS_OBSERVED`, with the span the watcher's heartbeats cover; or
  `COVERAGE_UNKNOWN`, with the reason. With no records at all, it says it can't tell.

## Recovery is guarded

Each alert prints one restore command. It puts back the exact bytes and permissions of the version before the change,
and only if the file still has the hash the alert saw. If the file changed since, it refuses and prints the command
that would override. Nothing is restored automatically. The check and the replacement are two steps, so a write that
lands between them is lost, and the restore itself shows up as an alert.

## What it runs and keeps

- **Hooks.** At session start, and before and after each tool call, a Python script records what the agent says it is
  doing: agent, session, tool, the command text, the paths the call names and, after the call, their SHA-256. Never
  file contents.
- **A background watcher.** The first hook starts it, detached so it outlives the session, one per machine; its first
  start compiles `watch.swift` with `swiftc`. It watches each project where a session started (its git top level),
  records every change's hash, size and provenance stamp, and keeps a copy of each version. Once a minute it compares
  every file whose metadata changed with its last version, catching anything the event stream missed, and records a
  heartbeat saying whether it could read the folder; a folder it can't read is reported, not swept. It stops after 30
  minutes without agent activity. The next hook starts it again, and it then compares every file with its last version.
- **Storage.** Everything is in `~/.agent-ledger`, readable only by you: the claims, the observations, and the kept
  copies of your files. Those include files git ignores, such as `.env`. Only `.git`, `.build`, `node_modules`,
  `__pycache__` and files over 64 MB are skipped. Nothing is pruned.

## What leaves your machine

The hooks and the watcher send nothing anywhere. The output of `/agent-ledger:check` (file paths, commands, session IDs
and the diffs of your files) becomes part of your conversation, so it reaches Anthropic like anything else in the
session. `reconcile.py --explain`, which only you run, sends alerts to Anthropic's API with your own API key, after
redacting keys and tokens on your machine.

## Where it runs

| Surface | Agent Ledger |
|---|---|
| Claude Code on macOS: the terminal, VS Code and JetBrains, the desktop app's Code tab with **Local** | Records and alerts |
| The Code tab with **SSH**, or an IDE window on a remote host | Records only if that host is a Mac |
| claude.ai/code, the mobile app, the Code tab with **Cloud** | Doesn't load: cloud sessions don't install your plugins |
| claude.ai chat | Ignores hooks, so it can't record |
| Cowork | Not tested |

The plugin includes a Codex manifest, but it hasn't been tested in Codex. Codex runs a plugin's hooks only after you
trust them in `/hooks`.

## Uninstall

```sh
claude plugin uninstall agent-ledger@cytherai
pkill -f "$HOME/.agent-ledger/bin/watch-"
rm -rf ~/.agent-ledger
```

The second line stops the watcher now instead of at its idle exit. The last line deletes the ledger, including the
kept copies of your files.

## License

Apache-2.0
