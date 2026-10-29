# Privacy and cleanup model

Clean My Mac is a local storage tool. The app reads metadata from a small allowlist under the signed-in user's home folder and asks macOS for the startup volume's capacity. It does not send scan results, file names, or file contents to a server. It has no analytics or account service.

## What a scan can inspect

The scanner looks for stale coding-agent session records, old caches and logs, selected rebuildable developer data, and large files in Downloads. It does not index all of Macintosh HD. Downloads results are review-only, since a large file may hold important work.

| Category | Locations |
| --- | --- |
| Agent transcripts | JSONL files under `~/.codex/sessions`, `~/.codex/archived_sessions`, and `~/.claude/projects` |
| Caches | Known Xcode, Homebrew, npm, pnpm, Yarn, pip, uv, Playwright, and Cypress folders under `~/Library/Caches`; `~/.npm/_cacache`; `~/.cache/Homebrew` |
| Logs | `~/Library/Logs/DiagnosticReports` |
| Developer files | Children of `~/Library/Developer/Xcode/DerivedData` |
| Large files | Files of at least 512 MiB directly inside `~/Downloads`, for Finder review only |

Agent session data can contain prompts, tool output, or source code. The app shows a path and a short cleanup reason so the user can decide whether to keep it. Current sessions stay protected, and recent history stays protected until it is at least 30 days old. The app excludes agent preferences, authentication files, API keys, and other configuration. It does not inspect or copy file contents for display.

## Cleanup

A scan does not alter files. The user selects cleanable entries and confirms before cleanup. Clean My Mac asks macOS to move those entries to Trash. It does not permanently unlink files or use administrator access. A file that is still active, has changed since the scan, sits outside an approved directory, or cannot safely be moved is skipped and shown as a failure.

Each scan is limited to 12 seconds, 100,000 visited entries, and 5,000 findings. Agent scans use part of this budget so other categories can still be checked. It skips symbolic links, reports unreadable locations as warnings, and may return partial results when it reaches a limit. System locations, application bundles, personal libraries, and agent credentials are outside its cleanup allowlist.

## Restoring items

Cleanup moves selected items into the macOS Trash. Finder's Put Back option may not be available for files moved this way. Clean My Mac keeps an in-memory receipt with the original paths. It is available in the app until the app closes or the user completes another cleanup. To restore an item, drag it from Trash to its listed original folder. The receipt is local and is not saved after the app closes.

These safeguards reduce accidental loss. A user should review the displayed names and sizes before confirming, especially for agent records that may contain useful context.

Session cleanup removes transcript files only. Agent databases and workspace indexes stay intact, so an agent may still list a removed conversation. Closing an agent and scanning again is required before its eligible transcripts can be selected.
