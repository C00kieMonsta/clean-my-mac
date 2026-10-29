# Clean My Mac

Clean My Mac is a native macOS storage inspector and cleaner built with Tauri 2, Rust, React 19, TypeScript, Vite, and pnpm. It searches for replaceable clutter, unusual storage consumers, and old Git worktrees. You choose what to keep or clean.

Scans run locally. The app does not upload file names, paths, or contents, and it has no analytics or account service. It does not read file contents to calculate sizes. It skips symbolic links. Nothing is removed during a scan.

## Finding clutter

Quick scan checks known coding-agent transcripts, named application and developer caches, selected temporary build output, Xcode DerivedData, and large files directly in Downloads. It also reports selected model and app data as read-only findings. Deep scan adds bounded discovery under common project folders such as `Developer`, `Projects`, `Code`, and `src`. It looks for known build artifacts, dependency folders, and Git-linked worktrees. It can find more locations, but it does not search every disk path.

The scan has independent safety limits. Agent history is limited to 5 seconds, 30,000 visited entries, and 1,500 findings. Quick scans limit temporary output to 10 seconds and 200,000 entries. Deep scans allow 120 seconds and 3,000,000 entries for this stage. Other scan stages use 30-second and 500,000-entry limits, with up to 5,000 findings. Deep discovery has its own 20-second, 50,000-entry, depth-7, and 2,500-candidate limits. Additional measurement allows 30 seconds and 500,000 entries in quick scans, or 120 seconds and 3,000,000 entries in deep scans. The app reports when a scan reaches a limit, so results may be partial.

Some findings are intentionally read-only because they may contain valuable or required data. Examples include local model downloads, Android SDKs and virtual devices, iPhone backups, Xcode archives and device logs, Cursor application databases, Docker's virtual machine disk, and some project build output. These findings help explain disk use. They cannot be selected for deletion by Clean My Mac.

The System insights view separately reports local snapshots, top memory-using processes, launch services with missing executable paths, and deleted files still held open by processes. These are context only. The app does not delete snapshots, unload services, or stop processes. Buttons open the relevant macOS Storage, Time Machine, and Login Items settings.

## Reviewing and cleaning

Each finding shows its path, size, age or reason where available, and cleanup risk. You can select individual findings. Click Potential cleanup to show only eligible findings, then use Select all eligible or choose individual checkboxes. Cleanup updates disk capacity and removes completed entries without forcing another deep scan. Use Scan again when you want a fresh scan. Recent or active histories and caches, model caches, personal Downloads files, and manually selected folders require a risk acknowledgement. Sensitive app data and protected worktrees remain read-only.

Ordinary files are moved to the macOS Trash after you review and confirm. They continue to use disk space until the Trash is emptied. A changed path, unsafe link, path outside the cleanup allowlist, or item that cannot safely be moved is rejected.

Clean, inactive Git worktrees can be removed through `git worktree remove`. This keeps their branches. Git is never invoked with `--force`. Worktrees with uncommitted or untracked changes, unrecognized ignored local files, a detached or locked state, or an active process are protected. Git removes worktree files directly. They do not go to Trash and cannot be restored from the app's receipt.

The cleanup receipt lists only items successfully moved or removed by the latest completed cleanup response. It stays in memory while the app is open. A later completed cleanup replaces it, and quitting the app clears it. The receipt is not saved to disk. For Trash items, it shows their original paths so you can restore them manually. Finder's Put Back option may not be available.

## Storage numbers

The overview distinguishes immediately free space from space macOS reports as available for important use. The difference is shown as potentially reclaimable space. macOS decides when to reclaim purgeable space. This estimate is not a measurement of snapshot sizes or a guarantee of space Clean My Mac can free. Local snapshots are listed for information only.

## Run it

Requirements: macOS 13 or later, Node.js 22 or later, pnpm 10.20.0, and the Rust toolchain.

```sh
pnpm install --frozen-lockfile
pnpm desktop
```

Build the frontend with `pnpm build`. Run project checks with `pnpm typecheck` and `pnpm test`. Build and open the local Mac app with `pnpm desktop:app`. Build an app bundle or disk image with `pnpm desktop:build`.

See [the build and release guide](docs/RELEASE.md) for local builds and download packaging.

## Privacy and safety

Cleanup scans inspect known locations under your home folder. You can also choose a folder manually. A manually chosen folder is reviewed as one item, and all its contents move to Trash if you confirm. The scanner does not follow symbolic links. Clean My Mac does not request administrator access, use `sudo`, or erase files directly. It does not scan the whole disk or clean operating system folders. See [the privacy and cleanup model](docs/PRIVACY.md) for details.

## Downloading

The manual GitHub Actions workflow builds Apple silicon and Intel DMG files and attaches them to the workflow run. An ad-hoc signed build is for local testing and is not ready for public download. Public distribution requires an Apple Developer ID signature and notarization. Once Apple signing credentials are configured in GitHub Actions, select the signed and notarized option in the workflow.

## Development preview

Run `pnpm dev` for a browser preview with labeled sample data. Browser preview cannot read or change files. The native app reads real filesystem metadata. With the preview running, `pnpm --filter @clean-my-mac/desktop exec node qa/smoke.mjs` checks the review flow, protected files, search, and minimum window size.
