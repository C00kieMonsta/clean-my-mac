# Privacy and cleanup model

Clean My Mac runs on your Mac. Scan results, paths, and file contents are not sent to a server. The app has no analytics or account service. Cleanup scans read filesystem metadata to find candidate sizes and do not open file contents to display or measure them. They skip symbolic links and do not scan the whole disk. Separate system insights query macOS for limited diagnostic information described below.

## Scan coverage

Quick scan checks known locations under the signed-in user's home folder. These include agent transcript folders, named caches and logs, selected developer data, Xcode DerivedData, generated `cdk.out` and Jest folders in the current user's temporary directory, and large files directly inside Downloads.

Deep scan includes the quick scan and adds bounded discovery under `~/Developer`, `~/Projects`, `~/Code`, and `~/src`. It looks for recognized project outputs such as Rust `target` folders, `node_modules`, JavaScript framework output, Python environments and bytecode, test reports, QA screenshots, qualifying `dist` or `build` folders, and linked Git worktrees. All scan modes also check known application cache locations, browser profile cache subfolders, and direct children of `~/Library/Caches` and `~/.cache` that are not on the exclusion list. Project discovery reads directory names and selected marker metadata. It does not read source file contents.

The scanner uses per-stage limits to stay responsive. Agent history is limited to 5 seconds, 30,000 visited entries, and 1,500 findings. Quick scans limit temporary output to 10 seconds and 200,000 entries. Deep scans allow 120 seconds and 3,000,000 entries for this stage. The other primary scan stages have 30-second and 500,000-entry limits, with at most 5,000 findings. Deep discovery has separate limits of 20 seconds, 50,000 entries, depth 7, and 2,500 candidates. Git discovery has a separate 20-second stage for repositories already found. Measuring additional findings has another 30-second and 500,000-entry limit for quick scans, or 120 seconds and 3,000,000 entries for deep scans. Limits apply to separate stages and are not a promise that every scan finishes within one combined time limit. Warnings indicate when results may be partial.

| Finding type | Examples |
| --- | --- |
| Agent history | JSONL transcripts in `~/.codex/sessions`, `~/.codex/archived_sessions`, and `~/.claude/projects` |
| Known caches | Package and build caches such as npm, pnpm, Yarn, Bun, Deno, pip, uv, Gradle, Maven, NuGet, Go, pre-commit, Playwright, Puppeteer, Cypress, CocoaPods, Homebrew, SwiftPM, and Xcode caches |
| App and browser caches | Spotify, Stremio, browser profile cache folders for Chrome, Firefox, and Edge, and other direct cache folders under `~/Library/Caches` or `~/.cache` |
| Developer output | Xcode DerivedData, Rust build output, project dependency folders, framework output, Python environments, test coverage, and QA screenshots |
| Temporary output | `cdk.out*` and `jest_*` directories directly inside the current user's temporary directory |
| Large downloads | Files of at least 512 MiB directly inside `~/Downloads` |

Some findings are marked sensitive and are read-only. They can explain storage use, but cannot be selected for cleanup in the app. These include Hugging Face, Ollama, LM Studio, and llama.cpp model data; Android SDKs and virtual devices; iPhone and iPad backups; Xcode archives and device logs; Cursor application state and databases; Docker's virtual machine disk; and some project build output. Removing these may delete personal state, offline models, backups, or data used by active apps.

Agent transcripts may contain prompts, tool output, paths, or source code. The app shows names, paths, sizes, and cleanup reasons so you can review them. It does not inspect or copy transcript contents for display. Authentication files, credentials, keychains, browser passwords, cookies, browsing history, and protected application data are excluded. Browser cleanup candidates are cache subfolders only.

## System insights

System insights are read-only. Docker usage is read through `docker system df` with a separate eight-second timeout. It lists images, containers, volumes, and build cache without pruning them. Unused volumes can still contain valuable databases. They report local Time Machine or APFS snapshots and purgeability when macOS provides it, the top 20 processes by resident memory, launch-agent and launch-daemon plist labels and executable paths, and deleted files that are still open by a process. Launch-agent inspection reads only the label and `Program` or first `ProgramArguments` value. It does not read launch-agent environment variables or expose the remaining argument list. A missing executable path is only a possible orphan, not proof that an app was uninstalled.

The app does not delete or resize snapshots, unload launch services, terminate processes, or close open files. It provides links to macOS Storage, Time Machine, and Login Items settings, plus Disk Utility so you can review system-managed items there. macOS may reclaim purgeable snapshots when it needs space.

The storage overview reports immediately free space and macOS's available-for-important-use capacity separately. The difference is presented as potentially reclaimable space. It is an operating-system estimate, not a guarantee that Clean My Mac can reclaim it. It does not represent snapshot sizes, and snapshots are not included as cleanup candidates.

## Git worktrees

Deep discovery can find Git-linked worktrees registered by repositories found beneath the supported project roots. It does not scan their full contents during discovery. It uses Git status and metadata to decide whether a worktree is eligible. The main checkout, locked or detached worktrees, worktrees with uncommitted or untracked files, worktrees with unrecognized ignored local files, and worktrees with an active process are protected.

For an eligible worktree, the app rechecks its status and invokes `git worktree remove` without `--force`. The branch is preserved. Git removes the worktree files directly. They are not moved to macOS Trash, cannot be restored from Trash, and are not recoverable through the app receipt. Git itself can refuse removal if the worktree changes before the command runs.

## Cleanup

Hard-linked files are counted once within each finding. APFS snapshots and shared blocks can still make listed sizes differ from physical space released.

A scan does not change files. You select eligible findings and confirm the cleanup. Recent or active histories and caches, model cache data, Downloads files, manually chosen folders, and Git worktrees require an explicit risk acknowledgement. Sensitive findings and protected worktrees are not cleanable.

Ordinary files are moved to macOS Trash. They continue using disk space until Trash is emptied. A manually selected folder is treated as one item, so all its contents move to Trash if confirmed. A path that changed since scanning, contains a symbolic link, is outside an approved root, overlaps another selected path, or cannot safely be moved is rejected or skipped. The app does not permanently unlink files or request administrator access.

Cleanup receipts exist only in memory. A receipt lists successfully moved or removed items from the latest completed cleanup response, including original paths and sizes. Another completed cleanup response replaces that list. Quitting the app discards it. The app does not save receipts to disk. Trash items can be dragged to their listed original folders; Finder's Put Back option may not be available. Git worktree files bypass Trash and cannot be restored from the receipt.

Session cleanup removes transcript files only. Agent databases and workspace indexes stay intact, so an agent may still list a removed conversation until its own index refreshes.
