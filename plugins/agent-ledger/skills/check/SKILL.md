---
description: Shows this project's Agent Ledger alerts, each file change no agent claimed or that put back an earlier version, with who had seen it and a one-line restore. Use when the user asks to check the ledger, what changed or overwrote a file, or whether an edit was undone.
---

Run this and show the user its output exactly as printed, in a code block:

```sh
python3 "${CLAUDE_PLUGIN_ROOT}/reconcile.py" --checkpoint --diff --project "${CLAUDE_PROJECT_DIR}"
```

If it exits with "nothing recorded", tell the user that Agent Ledger has no record of this project on this machine, so it can't say whether anything changed. Never present that as a clean result.

Report the `State:` line as it is, and never call the project clean. `NO_ALERTS_OBSERVED` means that at the time on the `Checkpoint` line, every file matched its last record and no recorded change raised an alert: a point-in-time check, not proof that monitoring had no gap. `COVERAGE_UNKNOWN` means the ledger can't say whether anything changed, for the reason it gives. The line about earlier sweeps is history, not current coverage.

When you discuss an alert, keep to what it states:
- The writer is what its `writer:` line says, and no more. A provenance stamp names an app, never a session or command. A `seen by` or `undoes` call read or edited an earlier version, which says nothing about who wrote this one.
- Run a `restore:` line only when the user asks to restore that file. It refuses if the file changed after the alert.
- Add `--explain` only when the user asks for it: it sends file contents to Anthropic's API.
