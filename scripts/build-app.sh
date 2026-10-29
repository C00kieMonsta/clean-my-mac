#!/bin/sh
set -eu

# Seal the local app bundle, icon, and executable for macOS. Use an ad-hoc
# identity only when no Developer ID identity or imported certificate exists.
if [ "$(uname -s)" = Darwin ] && [ -z "${APPLE_SIGNING_IDENTITY+x}" ] && [ -z "${APPLE_CERTIFICATE+x}" ]; then
  export APPLE_SIGNING_IDENTITY=-
fi

pnpm --filter @clean-my-mac/desktop tauri build --debug --bundles app "$@"
open "apps/desktop/src-tauri/target/debug/bundle/macos/Clean My Mac.app"
