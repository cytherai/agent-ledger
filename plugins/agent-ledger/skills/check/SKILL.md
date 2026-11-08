---
description: Shows this project's Agent Ledger alerts, each file change no agent claimed or that put back an earlier version, with who had seen it and a one-line restore. Use when the user asks to check the ledger, what changed or overwrote a file, or whether an edit was undone.
---

Run this and show the user its output exactly as printed, in a code block:

```sh
python3 "${CLAUDE_PLUGIN_ROOT}/reconcile.py" --diff --project "${CLAUDE_PROJECT_DIR}"
```

If it exits with "nothing recorded", tell the user that Agent Ledger has no record of this project on this machine, so it can't say whether anything changed. Never present that as a clean result.

With no alerts, say what the last line says: the ledger found none in the period it has records for. Don't say nothing else happened. If the user knows of changes after that period that the ledger doesn't show, say that its watcher may not be running here.

When you discuss an alert, keep to what it states:
- The writer is what its `writer:` line says, and no more. A provenance stamp names an app, never a session or command. A `seen by` or `undoes` call read or edited an earlier version, which says nothing about who wrote this one.
- Run a `restore:` line only when the user asks to restore that file. It refuses if the file changed after the alert.
- Add `--explain` only when the user asks for it: it sends file contents to Anthropic's API.
