# Privacy and cleanup model

Clean My Mac is a local storage tool. The app reads metadata from a small allowlist under the signed-in user's home folder and asks macOS for the startup volume's capacity. It does not send scan results, file names, or file contents to a server. It has no analytics or account service.

## What a scan can inspect

The scanner checks known coding-agent history, caches and logs, selected developer data, and large files directly in Downloads. It does not scan all of Macintosh HD. Older inactive caches can be recommended. Recent or in-use histories and caches, Hugging Face model files, and Downloads files can be selected manually after an explicit risk acknowledgement.

| Category | Locations |
| --- | --- |
| Agent transcripts | JSONL files under `~/.codex/sessions`, `~/.codex/archived_sessions`, and `~/.claude/projects` |
| Caches | Named folders under `~/Library/Caches`: `com.apple.dt.Xcode`, `Homebrew`, `npm`, `pnpm`, `yarn`, `pip`, `uv`, `playwright`, `ms-playwright`, `Cypress`, `CocoaPods`, `com.spotify.client`, and `com.microsoft.VSCode.ShipIt`; `~/.npm/_cacache`; `~/.cache/Homebrew`, `~/.cache/uv`, `~/.cache/puppeteer`, `~/.cache/pre-commit`, and `~/.cache/huggingface/hub`; `~/Library/Application Support/Spotify/PersistentCache`; `~/Library/Application Support/stremio-server/stremio-cache`; `~/Library/iTunes/iPhone Software Updates` |
| Logs | `~/Library/Logs/DiagnosticReports` |
| Developer files | Children of `~/Library/Developer/Xcode/DerivedData` |
| Large files | Files of at least 512 MiB directly inside `~/Downloads` |

Agent session data can contain prompts, tool output, or source code. The app shows a path and a short cleanup reason so the user can decide whether to keep it. Older inactive histories may be recommended. Recent or active histories can be selected manually after the risk acknowledgement. The app does not scan agent preferences, authentication files, API keys, or other configuration. It does not inspect or copy file contents for display. Hugging Face model cache entries always require review because removing them may make models unavailable offline. `~/.cache/huggingface/lerobot` is not scanned.

## Cleanup

A scan does not alter files. The user selects eligible entries and confirms before cleanup. Items marked for review require an explicit acknowledgement before Clean My Mac asks macOS to move them to Trash. This includes recent or in-use histories and caches, Hugging Face model files, and direct Downloads files. The app does not permanently unlink files or use administrator access. A path that changed since the scan, is a symbolic link, falls outside a known root, or cannot safely be moved is rejected or skipped and shown as a failure.

Each scan is limited to 30 seconds, 500,000 visited entries, and 5,000 findings. Agent traversal has separate limits of 5 seconds, 30,000 visited entries, and 1,500 findings. It skips symbolic links, reports unreadable locations as warnings, and may return partial results when it reaches a limit. Unlisted personal data, system locations, application bundles, settings, and credentials are outside its cleanup allowlist.

## Restoring items

Cleanup moves selected items into the macOS Trash. Finder's Put Back option may not be available for files moved this way. Clean My Mac keeps an in-memory receipt with the original paths. It is available in the app until the app closes or the user completes another cleanup. To restore an item, drag it from Trash to its listed original folder. The receipt is local and is not saved after the app closes.

These safeguards reduce accidental loss. A user should review the displayed names and sizes before confirming, especially for agent records that may contain useful context.

Session cleanup removes transcript files only. Agent databases and workspace indexes stay intact, so an agent may still list a removed conversation until its own index refreshes.
