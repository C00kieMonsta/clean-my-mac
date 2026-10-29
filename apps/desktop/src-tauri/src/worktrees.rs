//! Git worktrees need Git removal, not a filesystem Trash operation.
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

#[derive(Clone, Debug)]
pub(crate) struct WorktreeInfo {
    pub(crate) main: PathBuf,
    pub(crate) branch: Option<String>,
    pub(crate) reason: Option<String>,
}

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

fn git(path: &Path, args: &[&str], timeout: Duration) -> Result<String, String> {
    let binary = git_binary().ok_or("Git is unavailable. Install Git to inspect worktrees.")?;
    let folder = path
        .to_str()
        .ok_or("The worktree path is not valid UTF-8.")?;
    let mut all = vec![
        "--no-optional-locks",
        "-C",
        folder,
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
    ];
    all.extend_from_slice(args);
    crate::insights::run_command(binary, &all, timeout)
}

#[derive(Debug)]
struct Record {
    path: PathBuf,
    branch: Option<String>,
    locked: bool,
}
fn records(text: &str) -> Vec<Record> {
    text.split("\0\0")
        .filter_map(|entry| {
            let mut path = None;
            let mut branch = None;
            let mut locked = false;
            for line in entry.split('\0') {
                if let Some(value) = line.strip_prefix("worktree ") {
                    path = Some(PathBuf::from(value));
                }
                if let Some(value) = line.strip_prefix("branch ") {
                    branch = Some(value.to_owned());
                }
                if line == "locked" || line.starts_with("locked ") {
                    locked = true;
                }
            }
            path.map(|path| Record {
                path,
                branch,
                locked,
            })
        })
        .collect()
}

fn generated(path: &str) -> bool {
    path.split('/').any(|part| {
        matches!(
            part,
            "node_modules"
                | "target"
                | "target-check"
                | "build"
                | "dist"
                | ".next"
                | ".nuxt"
                | ".turbo"
                | ".cache"
                | "coverage"
                | "test-results"
                | "playwright-report"
                | "__pycache__"
                | ".venv"
                | "venv"
                | ".gradle"
                | ".dart_tool"
                | "cdk.out"
        ) || part.starts_with("target-")
    }) || path.ends_with(".log")
        || path.ends_with(".tsbuildinfo")
        || path.ends_with(".pyc")
        || path.ends_with(".DS_Store")
}

fn is_active(path: &Path) -> bool {
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing()
            .with_cwd(UpdateKind::Always)
            .with_exe(UpdateKind::Always),
    );
    system.processes().values().any(|process| {
        process.cwd().is_some_and(|cwd| cwd.starts_with(path))
            || process.exe().is_some_and(|exe| exe.starts_with(path))
    })
}

pub(crate) fn inspect(path: &Path) -> Result<WorktreeInfo, String> {
    let text = git(
        path,
        &["worktree", "list", "--porcelain", "-z"],
        Duration::from_secs(5),
    )?;
    let rows = records(&text);
    let main = rows
        .first()
        .ok_or("Git did not return a main working tree.")?
        .path
        .clone();
    let record = rows
        .iter()
        .find(|row| row.path == path)
        .ok_or("This folder is not a registered Git worktree.")?;
    let mut reason = if main == path {
        Some("This is the main repository, not an extra worktree.".into())
    } else if record.locked {
        Some("This worktree is locked in Git.".into())
    } else if record.branch.is_none() {
        Some("Detached worktree. Preserve its commits on a branch before removal.".into())
    } else {
        None
    };
    if reason.is_none() {
        let status = git(
            path,
            &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
            Duration::from_secs(8),
        )?;
        if !status.is_empty() {
            reason = Some(
                "This worktree has uncommitted or untracked changes. Keep or back them up first."
                    .into(),
            );
        }
    }
    if reason.is_none() {
        let ignored = git(
            path,
            &[
                "ls-files",
                "--others",
                "--ignored",
                "--exclude-standard",
                "--directory",
                "--no-empty-directory",
                "-z",
            ],
            Duration::from_secs(8),
        )?;
        if ignored
            .split('\0')
            .any(|entry| !entry.is_empty() && !generated(entry))
        {
            reason = Some("This worktree contains ignored local files, such as configuration. Back them up before removal.".into());
        }
    }
    if reason.is_none() && is_active(path) {
        reason = Some("A process is using this worktree. Close it before removal.".into());
    }
    Ok(WorktreeInfo {
        main,
        branch: record.branch.clone(),
        reason,
    })
}

pub(crate) fn remove(path: &Path) -> Result<(), String> {
    let info = inspect(path)?;
    if let Some(reason) = info.reason {
        return Err(reason);
    }
    let branch = info
        .branch
        .ok_or("The worktree has no persistent branch.")?;
    git(
        &info.main,
        &["show-ref", "--verify", "--quiet", &branch],
        Duration::from_secs(5),
    )?;
    let target = path
        .to_str()
        .ok_or("The worktree path is not valid UTF-8.")?;
    // Never --force: Git performs its own final dirty/locked checks.
    git(
        &info.main,
        &["worktree", "remove", "--", target],
        Duration::from_secs(600),
    )?;
    if path.exists() {
        return Err(
            "Git returned without removing the worktree. Inspect it before retrying.".into(),
        );
    }
    Ok(())
}

pub(crate) fn contains_repository(path: &Path) -> bool {
    if path.join(".git").exists() {
        return true;
    }
    if path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(generated)
    {
        return false;
    }
    let mut pending = vec![(path.to_path_buf(), 0)];
    let mut visited = 0;
    while let Some((folder, depth)) = pending.pop() {
        if depth >= 3 {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(folder) else {
            continue;
        };
        for entry in entries.flatten() {
            visited += 1;
            if visited > 5000 {
                return true;
            }
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if !kind.is_dir() || kind.is_symlink() {
                continue;
            }
            let child = entry.path();
            if generated(child.file_name().and_then(|v| v.to_str()).unwrap_or("")) {
                continue;
            }
            if child.join(".git").exists() {
                return true;
            }
            pending.push((child, depth + 1));
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn worktree_records_keep_lock_and_branch_boundaries() {
        let rows = records(
            "worktree /main\0HEAD abc\0branch refs/heads/main\0\0worktree /extra with space\0HEAD def\0branch refs/heads/topic\0locked busy\0\0",
        );
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].path, Path::new("/extra with space"));
        assert!(rows[1].locked);
        assert_eq!(rows[1].branch.as_deref(), Some("refs/heads/topic"));
    }
    #[test]
    fn local_configuration_is_never_treated_as_generated() {
        assert!(!generated("apps/backend/.env"));
        assert!(!generated("plan/notes.md"));
        assert!(generated("apps/web/node_modules/"));
        assert!(generated("infrastructure/cdk.out/"));
    }
}
