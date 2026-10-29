# Clean My Mac

Clean My Mac is a native macOS storage cleaner built with Tauri 2, Rust, React 19, TypeScript, Vite, and pnpm. It helps people find old agent sessions and other replaceable local clutter, then review each item before moving it to the Mac's Trash.

The scan runs locally. It does not upload file names or contents, and the app has no analytics. Settings and credentials are not scanned. Older inactive caches can be recommended. Recent or in-use histories and caches, plus files directly in Downloads, can be selected after an explicit risk acknowledgement. Nothing is removed during a scan.

The storage view shows a volume summary and grouped findings, with clear sizes and reasons for each suggestion. Selected items move to Trash only after the user confirms. After cleanup, an in-app receipt lists original paths until the app closes or another cleanup runs. To restore a file, drag it from Trash to its original folder. Finder's Put Back option may be unavailable.

## Run it

Requirements: macOS 13 or later, Node.js 22 or later, pnpm 10.20.0, and the Rust toolchain.

```sh
pnpm install --frozen-lockfile
pnpm desktop
```

Build the frontend with `pnpm build`. Run the project checks with `pnpm typecheck` and `pnpm test`. Build and open the local Mac app with `pnpm desktop:app`. Build an app bundle or disk image with `pnpm desktop:build`.

See [the build and release guide](docs/RELEASE.md) for local builds and download packaging.

## Privacy and safety

Automatic scans read only known user-owned folders. You can also add a folder manually. The selected folder is reviewed as one item, and all its contents move to Trash if you confirm. The scanner follows neither symbolic links nor aliases. A changed path, symbolic link, or path outside an approved root is rejected before cleanup. See [the privacy and cleanup model](docs/PRIVACY.md) for details.

Clean My Mac does not request administrator access, use `sudo`, or erase files directly. It asks macOS to move confirmed items to Trash. It does not clean operating system folders or scan the whole disk. These limits keep the app's recommendations understandable and protect personal data.

## Downloading

The manual GitHub Actions workflow builds Apple silicon and Intel DMG files and attaches them to the workflow run. An ad-hoc signed build is for local testing and is not ready for public download. Public distribution requires an Apple Developer ID signature and notarization. Once Apple signing credentials are configured in GitHub Actions, select the signed and notarized option in the workflow.

## Development preview

Run `pnpm dev` for a browser preview with labeled sample data. Browser preview cannot read or change files. The native app reads real filesystem metadata. With the preview running, `pnpm --filter @clean-my-mac/desktop exec node qa/smoke.mjs` checks the review flow, protected files, search, and minimum window size.
