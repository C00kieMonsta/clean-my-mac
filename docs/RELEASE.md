# Build and release

Clean My Mac uses the Talos Labs desktop stack: pnpm, Node.js 22, React 19, TypeScript, Vite, Tauri 2, and Rust. The desktop bundle targets macOS 13 and later.

## Local development

Install dependencies and launch the Tauri window:

```sh
pnpm install --frozen-lockfile
pnpm desktop
```

Run the frontend checks and create a development app bundle:

```sh
pnpm typecheck
pnpm test
pnpm build
pnpm desktop:app
```

`pnpm desktop:app` builds an ad-hoc signed local app bundle and opens it. To create a DMG, run `pnpm desktop:build --bundles dmg`. Set `APPLE_SIGNING_IDENTITY` when building with an installed Developer ID Application certificate.

## CI artifacts

The **Build macOS downloads** GitHub Actions workflow has a manual trigger. It builds one DMG on an Apple silicon runner and another on an Intel runner. It runs the frontend build, type check, and test suite first. The workflow only attaches the two DMGs to its run as artifacts. It does not make a GitHub Release or publish a download page.

The default artifact is ad-hoc signed. This build helps maintainers review the package and test local installation. Gatekeeper may prevent a user from opening a downloaded ad-hoc app without changing macOS security settings. Do not publish this as a public download.

### Public distribution

Public direct downloads require an Apple Developer ID Application certificate, code signing, and notarization. Add these Actions secrets to the repository before running the signed workflow option:

- `APPLE_CERTIFICATE`: base64-encoded `.p12` Developer ID Application certificate.
- `APPLE_CERTIFICATE_PASSWORD`: password for that `.p12` file.
- `APPLE_SIGNING_IDENTITY`: exact Developer ID Application identity name.
- `APPLE_ID`: Apple account used for notarization.
- `APPLE_PASSWORD`: app-specific password for that account.
- `APPLE_TEAM_ID`: Apple Developer team identifier.

The signed option checks that each secret is present and imports the certificate into the temporary runner keychain before building. Tauri uses the signing identity for the app and submits the signed DMG for Apple notarization. If credentials are absent or invalid, the workflow fails rather than labeling the artifact ready for public download.

After a signed workflow succeeds, maintainers should verify the notarization and test the DMG on both architectures before linking it from a download page or publishing it as a release. Publishing is a separate, deliberate step.

See Tauri's official guides for [macOS code signing and notarization](https://v2.tauri.app/distribute/sign/macos/) and [DMG packaging](https://v2.tauri.app/distribute/dmg/) for the platform-specific setup and distribution steps.
