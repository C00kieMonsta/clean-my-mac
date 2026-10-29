//! Read-only discovery of less obvious storage consumers.
//!
//! This module only returns candidate roots. The caller measures them and applies
//! the app's cleanup policy. `Sensitive` candidates describe data that may be
//! valuable or required to keep an app working.

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const MAX_SECONDS: u64 = 20;
const MAX_VISITED: usize = 50_000;
const MAX_CANDIDATES: usize = 1_500;
const MAX_DEPTH: usize = 7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Handling {
    Cache,
    Developer,
    Sensitive,
}

#[derive(Clone, Debug)]
pub(crate) struct Candidate {
    pub(crate) path: PathBuf,
    pub(crate) category: &'static str,
    pub(crate) source: String,
    pub(crate) description: String,
    pub(crate) handling: Handling,
}

#[derive(Default)]
pub(crate) struct DiscoveryOutput {
    pub(crate) candidates: Vec<Candidate>,
    pub(crate) warnings: Vec<String>,
    pub(crate) detector_count: usize,
}

struct Scan<'a> {
    home: &'a Path,
    started: Instant,
    visited: usize,
    output: DiscoveryOutput,
    seen: HashSet<PathBuf>,
    repos: HashSet<PathBuf>,
    stopped: bool,
}

impl<'a> Scan<'a> {
    fn push(&mut self, path: PathBuf, category: &'static str, source: &str, desc: &str, handling: Handling) {
        if self.stopped || self.output.candidates.len() >= MAX_CANDIDATES {
            self.limit_warning("candidate");
            return;
        }
        let Ok(canonical) = fs::canonicalize(&path) else { return };
        if !canonical.starts_with(self.home) || canonical == self.home || excluded(&canonical, self.home) {
            return;
        }
        let Ok(meta) = fs::symlink_metadata(&path) else { return };
        if meta.file_type().is_symlink() || !meta.is_dir() || canonical != path {
            return;
        }
        self.output.detector_count += 1;
        if self.seen.insert(canonical.clone()) {
            self.output.candidates.push(Candidate {
                path: canonical,
                category,
                source: source.to_owned(),
                description: desc.to_owned(),
                handling,
            });
        }
    }

    fn limit_warning(&mut self, kind: &str) {
        if !self.stopped {
            self.output.warnings.push(format!(
                "Deep discovery stopped at its {kind} safety limit. Some locations may not be listed."
            ));
            self.stopped = true;
        }
    }

    fn tick(&mut self) -> bool {
        if self.stopped { return false; }
        self.visited += 1;
        if self.visited > MAX_VISITED {
            self.limit_warning("entry");
            return false;
        }
        if self.started.elapsed() > Duration::from_secs(MAX_SECONDS) {
            self.limit_warning("time");
            return false;
        }
        true
    }
}

fn excluded(path: &Path, home: &Path) -> bool {
    let rel = path.strip_prefix(home).unwrap_or(path);
    let parts: Vec<_> = rel.components().filter_map(|c| c.as_os_str().to_str()).collect();
    let blocked = [
        ".ssh", ".gnupg", ".aws", ".azure", ".config/gcloud", ".kube",
        ".codex/auth", ".claude/credentials", "Library/Keychains", "Library/Accounts",
        "Library/Mail", "Library/Messages", "Library/Safari", "Library/Cookies",
        "Library/Application Support/Google/Chrome/Default", // handled by narrower cache roots below
    ];
    blocked.iter().any(|prefix| {
        let p: Vec<_> = Path::new(prefix).components().filter_map(|c| c.as_os_str().to_str()).collect();
        parts.len() >= p.len() && parts.iter().zip(p.iter()).all(|(a,b)| a == b)
    }) || parts.iter().any(|part| matches!(*part, "Cookies" | "Keychains" | "credentials" | "secrets"))
}

fn named_roots(home: &Path) -> Vec<(PathBuf, &'static str, &'static str, &'static str, Handling)> {
    let mut roots = Vec::new();
    let mut add = |path: PathBuf, category, source, desc, handling| roots.push((path, category, source, desc, handling));
    let caches = home.join("Library/Caches");
    for (name, label) in [
        ("pip", "pip wheel cache"), ("uv", "uv package cache"), ("npm", "npm package cache"),
        ("pnpm", "pnpm package store"), ("yarn", "Yarn package cache"), ("bun", "Bun package cache"),
        ("deno", "Deno dependency cache"), ("go-build", "Go build cache"),
        ("gradle", "Gradle build and dependency cache"), ("maven", "Maven dependency cache"),
        ("nuget", "NuGet package cache"), ("pre-commit", "pre-commit hook cache"),
        ("playwright", "Playwright browser cache"), ("ms-playwright", "Playwright browser cache"),
        ("puppeteer", "Puppeteer browser cache"), ("Cypress", "Cypress binary cache"),
        ("CocoaPods", "CocoaPods download cache"), ("Homebrew", "Homebrew download cache"),
        ("com.apple.dt.Xcode", "Xcode cache"), ("com.spotify.client", "Spotify cache"),
        ("com.microsoft.VSCode.ShipIt", "VS Code update cache"),
    ] {
        add(home.join(".cache").join(name), "caches", "Known cache", label, Handling::Cache);
        add(caches.join(name), "caches", "Known cache", label, Handling::Cache);
    }
    for (path, label) in [
        (".npm/_cacache", "npm package cache"), (".bun/install/cache", "Bun package cache"),
        (".deno", "Deno cache, modules, and metadata"), (".gradle/caches", "Gradle dependency cache"),
        (".m2/repository", "Maven downloaded dependencies"), (".nuget/packages", "NuGet package cache"),
        (".cache/go-build", "Go build cache"), (".cache/pip", "pip wheel cache"),
        (".cache/uv", "uv package cache"), (".cache/pre-commit", "pre-commit hook cache"),
        (".cache/puppeteer", "Puppeteer browser cache"), (".cache/ms-playwright", "Playwright browser cache"),
        (".cache/Cypress", "Cypress binary cache"),
        ("Library/Caches/SwiftPM", "Swift Package Manager cache"),
        ("Library/Developer/Xcode/DerivedData", "Xcode build products"),
        ("Library/Developer/Xcode/Archives", "Xcode archives. May contain release builds and dSYMs"),
        ("Library/Developer/Xcode/iOS DeviceSupport", "Xcode device support symbols"),
        ("Library/Developer/CoreSimulator/Caches", "CoreSimulator cache"),
        ("Library/Developer/Xcode/DocumentationCache", "Xcode documentation cache"),
        ("Library/iTunes/iPhone Software Updates", "Downloaded iOS update packages"),
        ("Library/Application Support/Spotify/PersistentCache", "Spotify persistent cache"),
        ("Library/Application Support/stremio-server/stremio-cache", "Stremio media cache"),
        ("Library/Logs/DiagnosticReports", "Application crash reports"),
    ] {
        add(home.join(path), "developer", "Known storage location", label, Handling::Developer);
    }
    for (path, label) in [
        (".cache/huggingface", "Hugging Face models and datasets. Removing these may require large downloads"),
        (".ollama/models", "Ollama model files. Removing these requires downloading models again"),
        (".lmstudio/models", "LM Studio model files. These may be needed offline"),
        (".cache/llama.cpp", "Local language model files"),
        ("Library/Android/sdk", "Android SDK platforms, tools, and system images"),
        (".android/avd", "Android virtual devices and their disks"),
        ("Library/Application Support/MobileSync/Backup", "iPhone and iPad backups. Removing one loses that restore point"),
        ("Library/Application Support/MobileSync/Backups", "iPhone and iPad backups. Removing one loses that restore point"),
        ("Library/Developer/Xcode/iOS Device Logs", "Xcode device logs"),
        ("Library/Application Support/Cursor", "Cursor application state and databases. This is not a cache"),
    ] {
        add(home.join(path), "large", "Sensitive app data", label, Handling::Sensitive);
    }
    // Browser profiles can contain private history, cookies, passwords, and session data.
    // Only known cache subdirectories are ever returned.
    for (base, browser) in [
        ("Library/Application Support/Google/Chrome", "Chrome"),
        ("Library/Application Support/Firefox/Profiles", "Firefox"),
        ("Library/Application Support/Microsoft Edge", "Edge"),
        ("Library/Safari", "Safari"),
    ] {
        let root = home.join(base);
        for cache in ["Cache", "Code Cache", "GPUCache", "Service Worker/CacheStorage"] {
            add(root.join(cache), "caches", "Browser cache", match browser { "Chrome" => "Chrome profile cache files", "Firefox" => "Firefox profile cache files", "Edge" => "Edge profile cache files", _ => "Safari cache files" }, Handling::Cache);
        }
    }
    roots
}

fn walk_projects(scan: &mut Scan<'_>, root: &Path, depth: usize) {
    if depth > MAX_DEPTH || !scan.tick() { return; }
    let Ok(meta) = fs::symlink_metadata(root) else { return };
    if !meta.is_dir() || meta.file_type().is_symlink() { return; }
    if root.join(".git").exists() {
        if let Ok(repo) = fs::canonicalize(root) { scan.repos.insert(repo); }
    }
    let Ok(entries) = fs::read_dir(root) else { return };
    let mut dirs = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else { continue };
        if name == ".git" || name == "node_modules" || name == "target" || name == "target-check" || name == ".next" || name == ".nuxt" || name == ".turbo" || name == ".venv" || name == "__pycache__" || name == "coverage" || name == "dist" || name == "build" {
            if scan.tick() { detect_project_artifact(scan, &path, name); }
            continue;
        }
        if name.starts_with('.') { continue; }
        if fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink()) { dirs.push(path); }
    }
    dirs.sort();
    for dir in dirs {
        if scan.stopped { break; }
        // A repository root is identified by .git, file or directory. Keep walking
        // into it because linked worktrees often live in nested project groups.
        walk_projects(scan, &dir, depth + 1);
    }
}

fn detect_project_artifact(scan: &mut Scan<'_>, path: &Path, name: &str) {
    let Ok(meta) = fs::symlink_metadata(path) else { return };
    if meta.file_type().is_symlink() || !meta.is_dir() { return; }
    let parent = path.parent().unwrap_or(Path::new("/"));
    let category = "developer";
    match name {
        "target" | "target-check" => {
            if path.join(".rustc_info.json").is_file() || path.join("CACHEDIR.TAG").is_file() {
                scan.push(path.to_path_buf(), category, "Rust project build output", "Cargo build artifacts. Removing them requires recompilation", Handling::Developer);
            }
        }
        "node_modules" => {
            if parent.join("package.json").is_file() {
                scan.push(path.to_path_buf(), category, "JavaScript project dependency tree", "Installed project dependencies. They can be restored from the lockfile", Handling::Developer);
            }
        }
        ".next" | ".nuxt" | ".turbo" => {
            if ["package.json", "pnpm-lock.yaml", "yarn.lock", "package-lock.json"].iter().any(|f| parent.join(f).is_file()) {
                scan.push(path.to_path_buf(), category, "JavaScript framework build output", "Generated framework build cache", Handling::Developer);
            }
        }
        ".venv" => {
            if path.join("pyvenv.cfg").is_file() {
                scan.push(path.to_path_buf(), category, "Python project environment", "Virtual environment. Recreate it from project requirements", Handling::Developer);
            }
        }
        "__pycache__" => scan.push(path.to_path_buf(), category, "Python bytecode", "Regenerable Python bytecode cache", Handling::Cache),
        "coverage" => {
            if parent.join("package.json").is_file() || parent.join("pyproject.toml").is_file() {
                scan.push(path.to_path_buf(), category, "Test coverage output", "Generated test coverage reports", Handling::Developer);
            }
        }
        "dist" | "build" => {
            if parent.join("package.json").is_file() && (parent.join("vite.config.ts").exists() || parent.join("webpack.config.js").exists() || parent.join("tsconfig.json").exists()) {
                scan.push(path.to_path_buf(), category, "Project build output", "Generated project output. Review before clearing", Handling::Sensitive);
            }
        }
        _ => {}
    }
}

fn run_git(args: &[&str], timeout: Duration) -> Option<String> {
    let mut child = Command::new("git").args(args).env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(Stdio::null()).stderr(Stdio::null()).stdout(Stdio::piped()).spawn().ok()?;
    let started = Instant::now();
    loop {
        if child.try_wait().ok()?.is_some() { break; }
        if started.elapsed() >= timeout { let _ = child.kill(); let _ = child.wait(); return None; }
        thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output().ok()?;
    output.status.success().then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

fn discover_worktrees(scan: &mut Scan<'_>, repo: &Path) {
    let Some(list) = run_git(&["-C", repo.to_str().unwrap_or(""), "worktree", "list", "--porcelain"], Duration::from_millis(800)) else { return };
    let canonical_repo = fs::canonicalize(repo).unwrap_or_else(|_| repo.to_path_buf());
    for record in list.split("\n\n") {
        let Some(raw) = record.lines().find_map(|line| line.strip_prefix("worktree ")) else { continue };
        let path = PathBuf::from(raw);
        let Ok(canonical) = fs::canonicalize(&path) else { continue };
        if canonical == canonical_repo || !canonical.starts_with(scan.home) || excluded(&canonical, scan.home) { continue; }
        let fields: Vec<_> = record.lines().collect();
        if fields.iter().any(|field| *field == "locked" || *field == "bare") { continue; }
        if !fs::symlink_metadata(&canonical).is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink()) { continue; }
        let clean = run_git(&["-C", canonical.to_str().unwrap_or(""), "status", "--porcelain", "--untracked-files=normal"], Duration::from_millis(600)).is_some_and(|s| s.trim().is_empty());
        let (description, source) = if clean {
            ("Git-linked worktree with no tracked or untracked changes. Review branch and repository state before removing", "Git worktree, clean")
        } else {
            ("Git-linked worktree has changes or could not be checked. Keep it unless you have reviewed its contents", "Git worktree, changed or unknown")
        };
        scan.push(canonical, "developer", source, description, Handling::Sensitive);
    }
}

pub(crate) fn discover(home: &Path, deep: bool) -> DiscoveryOutput {
    let home = fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
    let mut scan = Scan { home: &home, started: Instant::now(), visited: 0, output: DiscoveryOutput::default(), seen: HashSet::new(), repos: HashSet::new(), stopped: false };
    for (path, category, source, desc, handling) in named_roots(&home) {
        if scan.stopped { break; }
        scan.push(path, category, source, desc, handling);
    }
    if deep && !scan.stopped {
        let roots = ["Developer", "Projects", "Code", "src"].map(|name| home.join(name));
        for root in roots {
            if root.is_dir() { walk_projects(&mut scan, &root, 0); }
        }
        // Enumerate repository roots already visited. A short, read-only Git query
        // reveals linked worktrees outside the project tree without scanning them.
        let repos: Vec<_> = scan.repos.iter().cloned().collect();
        for repo in repos {
            if scan.stopped { break; }
            discover_worktrees(&mut scan, &repo);
        }
    }
    scan.output.candidates.sort_by(|a, b| a.category.cmp(b.category).then_with(|| a.path.cmp(&b.path)));
    scan.output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn finds_known_cache_and_marks_models_sensitive() {
        let home = tempdir().unwrap();
        for path in [".cache/uv", ".cache/huggingface", "Library/Developer/Xcode/DerivedData"] {
            fs::create_dir_all(home.path().join(path)).unwrap();
        }
        let result = discover(home.path(), false);
        assert!(result.candidates.iter().any(|c| c.path.ends_with(".cache/uv") && c.handling == Handling::Cache));
        assert!(result.candidates.iter().any(|c| c.path.ends_with(".cache/huggingface") && c.handling == Handling::Sensitive));
        assert!(result.candidates.iter().any(|c| c.path.ends_with("DerivedData") && c.handling == Handling::Developer));
    }

    #[test]
    fn deep_scan_recognizes_project_markers_and_skips_symlinked_builds() {
        let home = tempdir().unwrap();
        let repo = home.path().join("Projects/demo");
        fs::create_dir_all(repo.join("target")).unwrap();
        fs::write(repo.join("target/CACHEDIR.TAG"), "generated").unwrap();
        fs::create_dir_all(repo.join("node_modules")).unwrap();
        fs::write(repo.join("package.json"), "{}").unwrap();
        let outside = tempdir().unwrap();
        fs::create_dir_all(outside.path().join("target")).unwrap();
        #[cfg(unix)] std::os::unix::fs::symlink(outside.path().join("target"), repo.join("linked-target")).unwrap();
        let result = discover(home.path(), true);
        assert!(result.candidates.iter().any(|c| c.path == repo.join("target")));
        assert!(result.candidates.iter().any(|c| c.path == repo.join("node_modules")));
        assert!(!result.candidates.iter().any(|c| c.path.ends_with("linked-target")));
    }

    #[test]
    fn never_returns_credentials_or_items_outside_home() {
        let home = tempdir().unwrap();
        fs::create_dir_all(home.path().join(".ssh")).unwrap();
        fs::create_dir_all(home.path().join("Library/Keychains")).unwrap();
        let result = discover(home.path(), false);
        assert!(result.candidates.iter().all(|c| !c.path.starts_with(home.path().join(".ssh")) && !c.path.starts_with(home.path().join("Library/Keychains"))));
    }
}
