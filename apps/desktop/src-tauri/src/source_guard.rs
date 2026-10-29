//! Guards cleanup candidates that contain source code or belong to a Git repo.
//!
//! The scanner supplies the two content flags so this module does not perform
//! another recursive walk over large build and dependency directories.

use std::{
    fs,
    path::{Component, Path, PathBuf},
    time::Duration,
};

const GIT_TIMEOUT: Duration = Duration::from_secs(8);

/// Rejects source-bearing candidates and any candidate that contains a Git
/// repository. Tracked files are checked through Git even for generated paths.
pub(crate) fn check(
    path: &Path,
    generated: bool,
    contains_source_code: bool,
    contains_repository: bool,
) -> Result<(), String> {
    let canonical = fs::canonicalize(path)
        .map_err(|_| "This item is no longer available for cleanup.".to_string())?;

    if (canonical.is_dir() && exists_checked(&canonical.join(".git"))?)
        || is_bare_repository_root(&canonical)
        || contains_repository
        || canonical
            .file_name()
            .is_some_and(|name| matches!(name.to_str(), Some(".git" | ".hg" | ".svn")))
    {
        return Err("Folders containing a repository are protected from cleanup.".into());
    }

    if !generated && (contains_source_code || is_source_path(&canonical)) {
        return Err("Source code and project folders are protected from cleanup.".into());
    }
    if canonical.is_dir()
        && [
            "Cargo.toml",
            "package.json",
            "pyproject.toml",
            "setup.py",
            "go.mod",
            "Gemfile",
            "composer.json",
            "pubspec.yaml",
        ]
        .iter()
        .any(|manifest| canonical.join(manifest).is_file())
    {
        return Err(
            "This folder is a project root and is protected, even if its name resembles a cache."
                .into(),
        );
    }

    if let Some((root, relative)) = git_ancestor_and_relative(&canonical)? {
        let binary = crate::worktrees::git_binary().ok_or_else(|| {
            "Git is unavailable, so tracked files cannot be checked safely.".to_string()
        })?;
        let root = root
            .to_str()
            .ok_or_else(|| "The repository path is not valid UTF-8.".to_string())?;
        let relative = relative
            .to_str()
            .ok_or_else(|| "The selected path is not valid UTF-8.".to_string())?;
        let output = crate::insights::run_command(
            binary,
            &[
                "--literal-pathspecs",
                "--no-optional-locks",
                "-C",
                root,
                "-c",
                "core.fsmonitor=false",
                "ls-files",
                "--cached",
                "-z",
                "--",
                relative,
            ],
            GIT_TIMEOUT,
        )
        .map_err(|_| {
            "Git could not verify whether this item contains tracked files.".to_string()
        })?;
        if !output.is_empty() {
            return Err(
                "This item contains Git-tracked files and is protected from cleanup.".into(),
            );
        }
    }

    Ok(())
}

/// Cheap name-only source recognition for the existing bounded scan walker.
pub(crate) fn is_source_path(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let name = name.to_ascii_lowercase();
    if matches!(
        name.as_str(),
        "src"
            | "source"
            | "lib"
            | "app"
            | "apps"
            | "packages"
            | "components"
            | "scripts"
            | "tests"
            | "test"
            | "migrations"
            | "include"
            | "vendor"
            | "public"
            | "assets"
            | "resources"
            | "static"
            | "config"
            | "configs"
            | "cargo.toml"
            | "package.json"
            | "pyproject.toml"
            | "setup.py"
            | "setup.cfg"
            | "makefile"
            | "justfile"
            | "go.mod"
            | "go.work"
            | "gemfile"
            | "podfile"
            | "composer.json"
            | "build.gradle"
            | "build.gradle.kts"
            | "cmakelists.txt"
            | "meson.build"
            | "mix.exs"
            | "pubspec.yaml"
            | "deno.json"
            | "deno.jsonc"
            | "dockerfile"
            | "containerfile"
            | ".env"
            | ".gitignore"
            | ".gitattributes"
            | ".gitmodules"
    ) {
        return true;
    }

    if name.starts_with(".env.") {
        return true;
    }
    let extension = Path::new(&name)
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("");
    matches!(
        extension,
        "rs" | "c"
            | "h"
            | "cc"
            | "cpp"
            | "cxx"
            | "hpp"
            | "hh"
            | "m"
            | "mm"
            | "swift"
            | "kt"
            | "kts"
            | "java"
            | "go"
            | "py"
            | "pyi"
            | "rb"
            | "php"
            | "js"
            | "jsx"
            | "mjs"
            | "cjs"
            | "ts"
            | "tsx"
            | "vue"
            | "svelte"
            | "html"
            | "css"
            | "scss"
            | "sass"
            | "less"
            | "sql"
            | "sh"
            | "bash"
            | "zsh"
            | "fish"
            | "lua"
            | "pl"
            | "pm"
            | "ex"
            | "exs"
            | "erl"
            | "hrl"
            | "hs"
            | "lhs"
            | "scala"
            | "sc"
            | "clj"
            | "cljs"
            | "cljc"
            | "edn"
            | "fs"
            | "fsx"
            | "vb"
            | "cs"
            | "csx"
            | "r"
            | "rmd"
            | "jl"
            | "dart"
            | "sol"
            | "tf"
            | "hcl"
            | "nix"
            | "proto"
            | "graphql"
            | "gql"
            | "xml"
            | "yaml"
            | "yml"
            | "toml"
            | "ini"
            | "cfg"
            | "conf"
            | "json"
            | "jsonc"
            | "md"
            | "rst"
            | "tex"
            | "gradle"
            | "dockerfile"
            | "ipynb"
            | "asm"
            | "s"
            | "f"
            | "f90"
            | "f95"
            | "pas"
            | "zig"
            | "nim"
            | "groovy"
            | "elm"
            | "ps1"
            | "bat"
            | "cmd"
            | "zip"
            | "tar"
            | "tgz"
            | "gz"
            | "bz2"
            | "xz"
            | "7z"
            | "rar"
    )
}

/// Identifies repository metadata without reading file contents or walking it.
pub(crate) fn is_repository_marker(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if matches!(name, ".git" | ".hg" | ".svn") {
        return true;
    }
    name == "HEAD" && path.parent().is_some_and(is_bare_repository_root)
}

fn is_bare_repository_root(path: &Path) -> bool {
    path.join("HEAD").is_file() && path.join("objects").is_dir() && path.join("refs").is_dir()
}

fn git_ancestor_and_relative(path: &Path) -> Result<Option<(PathBuf, PathBuf)>, String> {
    let selected = if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent()
            .ok_or_else(|| "The selected path has no parent folder.".to_string())?
            .to_path_buf()
    };
    for ancestor in selected.ancestors() {
        if exists_checked(&ancestor.join(".hg"))? || exists_checked(&ancestor.join(".svn"))? {
            return Err(
                "This folder belongs to a source repository that cannot be safely checked.".into(),
            );
        }
        if exists_checked(&ancestor.join(".git"))? {
            let relative = path
                .strip_prefix(ancestor)
                .map_err(|_| "The selected path is outside its Git repository.".to_string())?;
            return Ok(Some((ancestor.to_path_buf(), normalize_relative(relative))));
        }
        if is_bare_repository_root(ancestor) {
            return Err("Repository roots are protected from cleanup.".into());
        }
    }
    Ok(None)
}

fn exists_checked(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(false)
        }
        Err(_) => Err("Source protection could not inspect this location. It was kept.".into()),
    }
}

fn normalize_relative(path: &Path) -> PathBuf {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        path::Path,
        time::{SystemTime, UNIX_EPOCH},
    };

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!("clean-my-mac-source-guard-{nonce}"));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn git(binary: &str, cwd: &Path, args: &[&str]) {
        let status = std::process::Command::new(binary)
            .args(args)
            .current_dir(cwd)
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn source_names_and_extensions_are_recognized() {
        for name in ["src", "vendor.rs", "main.swift", "package.json", "Makefile"] {
            assert!(is_source_path(Path::new(name)), "{name}");
        }
        assert!(!is_source_path(Path::new("cache.bin")));
    }

    #[test]
    fn source_and_repository_flags_protect_candidates() {
        let temp = TempDir::new();
        let candidate = temp.0.join("cache");
        fs::create_dir(&candidate).unwrap();
        assert!(check(&candidate, false, true, false).is_err());
        assert!(check(&candidate, true, true, true).is_err());
        assert!(check(&candidate, true, true, false).is_ok());
        fs::write(candidate.join("Cargo.toml"), "[package]").unwrap();
        assert!(check(&candidate, true, true, false).is_err());
    }

    #[test]
    fn git_metadata_marks_repository_roots() {
        let temp = TempDir::new();
        let repo = temp.0.join("repo");
        fs::create_dir(&repo).unwrap();
        fs::create_dir(repo.join(".git")).unwrap();
        assert!(is_repository_marker(&repo.join(".git")));
        assert!(check(&repo, true, false, false).is_err());
    }

    #[test]
    fn bare_git_roots_are_protected() {
        let temp = TempDir::new();
        let repo = temp.0.join("bare");
        fs::create_dir_all(repo.join("objects")).unwrap();
        fs::create_dir_all(repo.join("refs")).unwrap();
        fs::write(repo.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        assert!(is_repository_marker(&repo.join("HEAD")));
        assert!(check(&repo, true, false, false).is_err());
    }

    #[test]
    fn tracked_files_inside_generated_candidates_are_protected() {
        let Some(binary) = crate::worktrees::git_binary() else {
            return;
        };
        let temp = TempDir::new();
        let repo = temp.0.join("repo");
        let candidate = repo.join("dist");
        fs::create_dir_all(&candidate).unwrap();
        fs::write(
            candidate.join("bundle.js"),
            "tracked generated-looking file",
        )
        .unwrap();
        git(binary, &repo, &["init", "-q"]);
        git(binary, &repo, &["add", "dist/bundle.js"]);
        assert!(check(&candidate, true, false, false).is_err());
    }

    #[test]
    fn untracked_generated_cache_inside_repo_can_be_removed() {
        let Some(binary) = crate::worktrees::git_binary() else {
            return;
        };
        let temp = TempDir::new();
        let repo = temp.0.join("repo");
        let candidate = repo.join("target");
        fs::create_dir_all(&candidate).unwrap();
        git(binary, &repo, &["init", "-q"]);
        fs::write(candidate.join("output.rs"), "generated").unwrap();
        assert!(check(&candidate, true, true, false).is_ok());
    }
}
