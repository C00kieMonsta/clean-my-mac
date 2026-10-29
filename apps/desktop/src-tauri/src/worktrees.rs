//! Locate an installed Git executable for read-only source verification.
use std::path::Path;

pub(crate) fn git_binary() -> Option<&'static str> {
    [
        "/Library/Developer/CommandLineTools/usr/bin/git",
        "/Applications/Xcode.app/Contents/Developer/usr/bin/git",
        "/opt/homebrew/bin/git",
        "/usr/local/bin/git",
    ]
    .into_iter()
    .find(|path| Path::new(path).is_file())
}
