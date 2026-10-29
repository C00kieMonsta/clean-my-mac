//! Read-only discovery of less obvious storage consumers.
//!
//! This module only returns candidate roots. The caller measures them and applies
//! the app's cleanup policy. `Sensitive` candidates describe data that may be
//! valuable or required to keep an app working.

use std::{
    collections::{HashSet, VecDeque},
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const MAX_SECONDS: u64 = 20;
const MAX_VISITED: usize = 50_000;
const MAX_CANDIDATES: usize = 2_500;
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
    candidate_limited: bool,
}

impl<'a> Scan<'a> {
    fn push(
        &mut self,
        path: PathBuf,
        category: &'static str,
        source: &str,
        desc: &str,
        handling: Handling,
    ) {
        if self.stopped {
            return;
        }
        let Ok(canonical) = fs::canonicalize(&path) else {
            return;
        };
        if !canonical.starts_with(self.home)
            || canonical == self.home
            || excluded(&canonical, self.home)
        {
            return;
        }
        let Ok(meta) = fs::symlink_metadata(&path) else {
            return;
        };
        if meta.file_type().is_symlink()
            || (!meta.is_dir() && !(handling == Handling::Sensitive && meta.is_file()))
            || canonical != path
        {
            return;
        }
        self.output.detector_count += 1;
        if self.seen.insert(canonical.clone()) {
            let candidate = Candidate {
                path: canonical,
                category,
                source: source.to_owned(),
                description: desc.to_owned(),
                handling,
            };
            if self.output.candidates.len() < MAX_CANDIDATES {
                self.output.candidates.push(candidate);
            } else {
                self.candidate_limited = true;
                let candidate_priority = priority(&candidate);
                if let Some((index, _)) = self
                    .output
                    .candidates
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, current)| priority(current))
                    && priority(&self.output.candidates[index]) < candidate_priority
                {
                    self.output.candidates[index] = candidate;
                }
            }
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
        if self.stopped {
            return false;
        }
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

fn priority(candidate: &Candidate) -> u8 {
    if candidate.source.starts_with("Git worktree") {
        8
    } else if candidate.source == "QA screenshot output"
        || candidate.source == "Rust project build output"
        || candidate.source == "Project build output"
        || candidate.source == "JavaScript framework build output"
    {
        7
    } else if candidate.handling == Handling::Sensitive {
        6
    } else if candidate.source == "JavaScript project dependency tree"
        || candidate.source == "Python project environment"
    {
        5
    } else if candidate.source == "Unclassified cache folder" {
        1
    } else {
        3
    }
}

pub(crate) fn is_excluded(path: &Path, home: &Path) -> bool {
    let rel = path.strip_prefix(home).unwrap_or(path);
    let parts: Vec<_> = rel
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect();
    let blocked = [
        ".ssh",
        ".gnupg",
        ".aws",
        ".azure",
        ".config/gcloud",
        ".kube",
        ".codex/auth",
        ".claude/credentials",
        "Library/Keychains",
        "Library/Accounts",
        "Library/Mail",
        "Library/Messages",
        "Library/Safari",
        "Library/Cookies",
    ];
    blocked.iter().any(|prefix| {
        let p: Vec<_> = Path::new(prefix)
            .components()
            .filter_map(|c| c.as_os_str().to_str())
            .collect();
        parts.len() >= p.len() && parts.iter().zip(p.iter()).all(|(a, b)| a == b)
    }) || parts
        .iter()
        .any(|part| matches!(*part, "Cookies" | "Keychains" | "credentials" | "secrets"))
}

fn excluded(path: &Path, home: &Path) -> bool {
    is_excluded(path, home)
}

fn named_roots(home: &Path) -> Vec<(PathBuf, &'static str, &'static str, &'static str, Handling)> {
    let mut roots = Vec::new();
    let mut add = |path: PathBuf, category, source, desc, handling| {
        roots.push((path, category, source, desc, handling))
    };
    let caches = home.join("Library/Caches");
    for (name, label) in [
        ("pip", "pip wheel cache"),
        ("uv", "uv package cache"),
        ("npm", "npm package cache"),
        ("pnpm", "pnpm package store"),
        ("yarn", "Yarn package cache"),
        ("bun", "Bun package cache"),
        ("deno", "Deno dependency cache"),
        ("go-build", "Go build cache"),
        ("gradle", "Gradle build and dependency cache"),
        ("maven", "Maven dependency cache"),
        ("nuget", "NuGet package cache"),
        ("pre-commit", "pre-commit hook cache"),
        ("playwright", "Playwright browser cache"),
        ("ms-playwright", "Playwright browser cache"),
        ("puppeteer", "Puppeteer browser cache"),
        ("Cypress", "Cypress binary cache"),
        ("CocoaPods", "CocoaPods download cache"),
        ("Homebrew", "Homebrew download cache"),
        ("com.apple.dt.Xcode", "Xcode cache"),
        ("com.spotify.client", "Spotify cache"),
        ("com.microsoft.VSCode.ShipIt", "VS Code update cache"),
    ] {
        add(
            home.join(".cache").join(name),
            "caches",
            "Known cache",
            label,
            Handling::Cache,
        );
        add(
            caches.join(name),
            "caches",
            "Known cache",
            label,
            Handling::Cache,
        );
    }
    for (path, label) in [
        (".npm/_cacache", "npm package cache"),
        (".bun/install/cache", "Bun package cache"),
        (".deno", "Deno cache, modules, and metadata"),
        (".gradle/caches", "Gradle dependency cache"),
        (".m2/repository", "Maven downloaded dependencies"),
        (".nuget/packages", "NuGet package cache"),
        (".cache/go-build", "Go build cache"),
        (".cache/pip", "pip wheel cache"),
        (".cache/uv", "uv package cache"),
        (".cache/pre-commit", "pre-commit hook cache"),
        (".cache/puppeteer", "Puppeteer browser cache"),
        (".cache/ms-playwright", "Playwright browser cache"),
        (".cache/Cypress", "Cypress binary cache"),
        ("Library/Caches/SwiftPM", "Swift Package Manager cache"),
        (
            "Library/Developer/Xcode/DerivedData",
            "Xcode build products",
        ),
        (
            "Library/Developer/Xcode/Archives",
            "Xcode archives. May contain release builds and dSYMs",
        ),
        (
            "Library/Developer/Xcode/iOS DeviceSupport",
            "Xcode device support symbols",
        ),
        (
            "Library/Developer/CoreSimulator/Caches",
            "CoreSimulator cache",
        ),
        (
            "Library/Developer/Xcode/DocumentationCache",
            "Xcode documentation cache",
        ),
        (
            "Library/iTunes/iPhone Software Updates",
            "Downloaded iOS update packages",
        ),
        (
            "Library/Application Support/Spotify/PersistentCache",
            "Spotify persistent cache",
        ),
        (
            "Library/Application Support/stremio-server/stremio-cache",
            "Stremio media cache",
        ),
        (
            "Library/Logs/DiagnosticReports",
            "Application crash reports",
        ),
    ] {
        add(
            home.join(path),
            "developer",
            "Known storage location",
            label,
            Handling::Developer,
        );
    }
    for (path, label) in [
        (
            ".cache/huggingface",
            "Hugging Face models and datasets. Removing these may require large downloads",
        ),
        (
            ".ollama/models",
            "Ollama model files. Removing these requires downloading models again",
        ),
        (
            ".lmstudio/models",
            "LM Studio model files. These may be needed offline",
        ),
        (".cache/llama.cpp", "Local language model files"),
        (
            "Library/Android/sdk",
            "Android SDK platforms, tools, and system images",
        ),
        (".android/avd", "Android virtual devices and their disks"),
        (
            "Library/Application Support/MobileSync/Backup",
            "iPhone and iPad backups. Removing one loses that restore point",
        ),
        (
            "Library/Application Support/MobileSync/Backups",
            "iPhone and iPad backups. Removing one loses that restore point",
        ),
        (
            "Library/Developer/Xcode/iOS Device Logs",
            "Xcode device logs",
        ),
        (
            "Library/Application Support/Cursor",
            "Cursor application state and databases. This is not a cache",
        ),
        (
            "Library/Containers/com.docker.docker/Data/vms/0/Docker.raw",
            "Docker virtual machine disk. It may contain active containers, images, and volumes",
        ),
        (
            "Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw",
            "Docker virtual machine disk. It may contain active containers, images, and volumes",
        ),
    ] {
        add(
            home.join(path),
            "large",
            "Sensitive app data",
            label,
            Handling::Sensitive,
        );
    }
    add(
        home.join("Library/Caches/com.apple.Safari"),
        "caches",
        "Browser cache",
        "Safari cache files",
        Handling::Cache,
    );
    roots
}

fn browser_cache_roots(home: &Path) -> Vec<Candidate> {
    let mut found = Vec::new();
    for (base, browser) in [
        ("Library/Application Support/Google/Chrome", "Chrome"),
        ("Library/Application Support/Firefox/Profiles", "Firefox"),
        ("Library/Application Support/Microsoft Edge", "Edge"),
    ] {
        let profiles = home.join(base);
        let Ok(entries) = fs::read_dir(&profiles) else {
            continue;
        };
        for entry in entries.flatten() {
            let profile = entry.path();
            if !fs::symlink_metadata(&profile)
                .is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink())
            {
                continue;
            }
            for rel in [
                "Cache",
                "Code Cache",
                "GPUCache",
                "Service Worker/CacheStorage",
            ] {
                let path = profile.join(rel);
                let Ok(canonical) = fs::canonicalize(&path) else {
                    continue;
                };
                if !canonical.starts_with(home)
                    || is_excluded(&canonical, home)
                    || canonical != path
                {
                    continue;
                }
                if !fs::symlink_metadata(&path)
                    .is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink())
                {
                    continue;
                }
                found.push(Candidate {
                    path: canonical,
                    category: "caches",
                    source: format!("{browser} browser profile cache"),
                    description: format!("{browser} cache files only. Cookies, passwords, and browsing history are excluded"),
                    handling: Handling::Cache,
                });
            }
        }
    }
    found
}

fn unclassified_cache_roots(home: &Path) -> Vec<Candidate> {
    let mut found = Vec::new();
    for root in [home.join("Library/Caches"), home.join(".cache")] {
        let Ok(entries) = fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if [
                "huggingface",
                "lerobot",
                "datasets",
                "credentials",
                "secrets",
                "Keychains",
            ]
            .contains(&name)
            {
                continue;
            }
            if !fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink())
            {
                continue;
            }
            let Ok(canonical) = fs::canonicalize(&path) else {
                continue;
            };
            if canonical != path || is_excluded(&canonical, home) {
                continue;
            }
            found.push(Candidate {
                path: canonical,
                category: "caches",
                source: "Unclassified cache folder".into(),
                description: "App cache folder not matched to a known cleaner rule. Inspect its contents before clearing".into(),
                handling: Handling::Cache,
            });
        }
    }
    found
}

fn walk_projects(scan: &mut Scan<'_>, roots: &[PathBuf]) {
    let mut pending: VecDeque<_> = roots
        .iter()
        .filter(|root| root.is_dir())
        .cloned()
        .map(|root| (root, 0))
        .collect();
    let mut bytecode_candidates = 0;
    while let Some((root, depth)) = pending.pop_front() {
        if scan.stopped {
            break;
        }
        if depth > MAX_DEPTH {
            continue;
        }
        if !scan.tick() {
            break;
        }
        let Ok(meta) = fs::symlink_metadata(&root) else {
            continue;
        };
        if !meta.is_dir() || meta.file_type().is_symlink() {
            continue;
        }
        if root.join(".git").exists()
            && let Ok(repo) = fs::canonicalize(&root)
        {
            scan.repos.insert(repo);
        }
        let Ok(entries) = fs::read_dir(&root) else {
            continue;
        };
        let mut dirs = Vec::new();
        for entry in entries.flatten() {
            if !scan.tick() {
                break;
            }
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            if name == ".git" || is_prunable_artifact(&path, name) {
                let is_bytecode = name == "__pycache__";
                if (!is_bytecode || bytecode_candidates < 64)
                    && let Some(_) = fs::symlink_metadata(&path)
                        .ok()
                        .filter(|m| m.is_dir() && !m.file_type().is_symlink())
                {
                    detect_project_artifact(scan, &path, name);
                    if is_bytecode {
                        bytecode_candidates += 1;
                    }
                }
                continue;
            }
            if name.starts_with('.') {
                continue;
            }
            if fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink())
            {
                dirs.push(path);
            }
        }
        dirs.sort();
        if depth < MAX_DEPTH {
            pending.extend(dirs.into_iter().map(|dir| (dir, depth + 1)));
        }
        if scan.stopped {
            break;
        }
    }
}

fn is_prunable_artifact(path: &Path, name: &str) -> bool {
    let parent = path.parent().unwrap_or(Path::new("/"));
    match name {
        name if name == "target" || name.starts_with("target-") => {
            path.join(".rustc_info.json").is_file() || path.join("CACHEDIR.TAG").is_file()
        }
        "node_modules" => parent.join("package.json").is_file(),
        ".next" | ".nuxt" | ".turbo" | ".parcel-cache" | ".vite" | ".webpack" | ".angular"
        | ".svelte-kit" => parent.join("package.json").is_file(),
        ".venv" => path.join("pyvenv.cfg").is_file(),
        "__pycache__" => true,
        "coverage" => {
            parent.join("package.json").is_file() || parent.join("pyproject.toml").is_file()
        }
        "screenshots" => is_test_output_dir(parent),
        "dist" | "build" => {
            parent.join("package.json").is_file()
                && (parent.join("vite.config.ts").exists()
                    || parent.join("webpack.config.js").exists()
                    || parent.join("tsconfig.json").exists())
        }
        "vendor" => ["composer.json", "Gemfile", "go.mod", "Cargo.toml"]
            .iter()
            .any(|marker| parent.join(marker).is_file()),
        "Pods" => parent.join("Podfile").is_file(),
        ".gradle" => {
            parent.join("settings.gradle").exists() || parent.join("settings.gradle.kts").exists()
        }
        ".dart_tool" => parent.join("pubspec.yaml").is_file(),
        ".terraform" => fs::read_dir(parent).is_ok_and(|entries| {
            entries
                .flatten()
                .any(|entry| entry.path().extension().is_some_and(|ext| ext == "tf"))
        }),
        "playwright-report" | "test-results" | "storybook-static" => {
            parent.join("package.json").is_file()
        }
        _ => false,
    }
}

fn is_test_output_dir(parent: &Path) -> bool {
    let mut ancestor = Some(parent);
    (0..4).any(|_| {
        let Some(path) = ancestor else { return false };
        let matched = path
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|name| {
                matches!(
                    name.to_ascii_lowercase().as_str(),
                    "qa" | "test-results" | "playwright-report"
                )
            });
        ancestor = path.parent();
        matched
    })
}

fn detect_project_artifact(scan: &mut Scan<'_>, path: &Path, name: &str) {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return;
    };
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return;
    }
    let parent = path.parent().unwrap_or(Path::new("/"));
    let category = "developer";
    match name {
        name if name == "target" || name.starts_with("target-") => {
            if path.join(".rustc_info.json").is_file() || path.join("CACHEDIR.TAG").is_file() {
                scan.push(
                    path.to_path_buf(),
                    category,
                    "Rust project build output",
                    "Cargo build artifacts. Removing them requires recompilation",
                    Handling::Developer,
                );
            }
        }
        "node_modules" => {
            if parent.join("package.json").is_file() {
                scan.push(
                    path.to_path_buf(),
                    category,
                    "JavaScript project dependency tree",
                    "Installed project dependencies. They can be restored from the lockfile",
                    Handling::Developer,
                );
            }
        }
        ".next" | ".nuxt" | ".turbo" => {
            if [
                "package.json",
                "pnpm-lock.yaml",
                "yarn.lock",
                "package-lock.json",
            ]
            .iter()
            .any(|f| parent.join(f).is_file())
            {
                scan.push(
                    path.to_path_buf(),
                    category,
                    "JavaScript framework build output",
                    "Generated framework build cache",
                    Handling::Developer,
                );
            }
        }
        ".venv" => {
            if path.join("pyvenv.cfg").is_file() {
                scan.push(
                    path.to_path_buf(),
                    category,
                    "Python project environment",
                    "Virtual environment. Recreate it from project requirements",
                    Handling::Developer,
                );
            }
        }
        "vendor" => {
            let dependency_marker = ["composer.json", "Gemfile", "go.mod", "Cargo.toml"]
                .iter()
                .any(|marker| parent.join(marker).is_file());
            if dependency_marker {
                scan.push(
                    path.to_path_buf(),
                    category,
                    "Project dependency directory",
                    "Vendored project dependencies. Review before clearing because projects may store source files here",
                    Handling::Developer,
                );
            }
        }
        "Pods" => {
            if parent.join("Podfile").is_file() {
                scan.push(
                    path.to_path_buf(),
                    category,
                    "CocoaPods project dependencies",
                    "Installed iOS project dependencies. Recreate them with CocoaPods if needed",
                    Handling::Developer,
                );
            }
        }
        ".gradle" => {
            if parent.join("settings.gradle").exists()
                || parent.join("settings.gradle.kts").exists()
            {
                scan.push(
                    path.to_path_buf(),
                    category,
                    "Gradle project cache",
                    "Project-local Gradle state and caches. Review before clearing",
                    Handling::Developer,
                );
            }
        }
        ".dart_tool" => {
            if parent.join("pubspec.yaml").is_file() {
                scan.push(
                    path.to_path_buf(),
                    category,
                    "Flutter or Dart build metadata",
                    "Generated Dart package configuration and build metadata",
                    Handling::Developer,
                );
            }
        }
        ".terraform" => {
            if fs::read_dir(parent).is_ok_and(|entries| {
                entries
                    .flatten()
                    .any(|entry| entry.path().extension().is_some_and(|ext| ext == "tf"))
            }) {
                scan.push(
                    path.to_path_buf(),
                    category,
                    "Terraform local state and providers",
                    "Terraform data may contain local state or credentials. Inspect in Terraform and do not clear automatically",
                    Handling::Sensitive,
                );
            }
        }
        ".parcel-cache" | ".vite" | ".webpack" | ".angular" | ".svelte-kit" => {
            if parent.join("package.json").is_file() {
                scan.push(
                    path.to_path_buf(),
                    category,
                    "JavaScript tool build cache",
                    "Generated frontend tool cache. Review before clearing",
                    Handling::Developer,
                );
            }
        }
        "playwright-report" | "test-results" | "storybook-static" => {
            if parent.join("package.json").is_file() {
                scan.push(
                    path.to_path_buf(),
                    category,
                    "Test or preview output",
                    "Generated test or preview output. Review before clearing because it may contain useful screenshots",
                    Handling::Developer,
                );
            }
        }
        "__pycache__" => scan.push(
            path.to_path_buf(),
            category,
            "Python bytecode",
            "Regenerable Python bytecode cache",
            Handling::Cache,
        ),
        "coverage" => {
            if parent.join("package.json").is_file() || parent.join("pyproject.toml").is_file() {
                scan.push(
                    path.to_path_buf(),
                    category,
                    "Test coverage output",
                    "Generated test coverage reports",
                    Handling::Developer,
                );
            }
        }
        "screenshots" => {
            let mut ancestor = Some(parent);
            let in_test_output = (0..4).any(|_| {
                let Some(path) = ancestor else { return false };
                let matched = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|name| {
                        matches!(
                            name.to_ascii_lowercase().as_str(),
                            "qa" | "test-results" | "playwright-report"
                        )
                    });
                ancestor = path.parent();
                matched
            });
            if in_test_output {
                scan.push(
                    path.to_path_buf(),
                    category,
                    "QA screenshot output",
                    "Screenshots from tests or QA runs. Review before clearing because they may be useful evidence",
                    Handling::Developer,
                );
            }
        }
        "dist" | "build"
            if parent.join("package.json").is_file()
                && (parent.join("vite.config.ts").exists()
                    || parent.join("webpack.config.js").exists()
                    || parent.join("tsconfig.json").exists()) =>
        {
            scan.push(
                path.to_path_buf(),
                category,
                "Project build output",
                "Generated project output. Review before clearing",
                Handling::Sensitive,
            );
        }
        _ => {}
    }
}

fn run_git(args: &[&str], timeout: Duration) -> Option<String> {
    let program = git_program()?;
    let mut child = Command::new(program)
        .args(args)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .ok()?;
    let started = Instant::now();
    loop {
        if child.try_wait().ok()?.is_some() {
            break;
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

fn git_program() -> Option<&'static str> {
    [
        "/Library/Developer/CommandLineTools/usr/bin/git",
        "/Applications/Xcode.app/Contents/Developer/usr/bin/git",
        "/opt/homebrew/bin/git",
        "/usr/local/bin/git",
    ]
    .into_iter()
    .find(|path| Path::new(path).is_file())
}

fn discover_worktrees(scan: &mut Scan<'_>, repo: &Path) {
    let Some(list) = run_git(
        &[
            "-C",
            repo.to_str().unwrap_or(""),
            "worktree",
            "list",
            "--porcelain",
        ],
        Duration::from_millis(800),
    ) else {
        return;
    };
    let canonical_repo = fs::canonicalize(repo).unwrap_or_else(|_| repo.to_path_buf());
    for (index, record) in list.split("\n\n").enumerate() {
        if !scan.tick() {
            break;
        }
        // The first worktree in porcelain output is the repository's primary
        // checkout. It is never a cleanup candidate.
        if index == 0 {
            continue;
        }
        let Some(raw) = record
            .lines()
            .find_map(|line| line.strip_prefix("worktree "))
        else {
            continue;
        };
        let path = PathBuf::from(raw);
        let Ok(canonical) = fs::canonicalize(&path) else {
            continue;
        };
        if canonical == canonical_repo
            || !canonical.starts_with(scan.home)
            || excluded(&canonical, scan.home)
        {
            continue;
        }
        let fields: Vec<_> = record.lines().collect();
        if fields
            .iter()
            .any(|field| *field == "locked" || *field == "bare")
        {
            continue;
        }
        if !fs::symlink_metadata(&canonical)
            .is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink())
        {
            continue;
        }
        let clean = run_git(
            &[
                "-C",
                canonical.to_str().unwrap_or(""),
                "status",
                "--porcelain",
                "--untracked-files=normal",
            ],
            Duration::from_millis(600),
        )
        .is_some_and(|s| s.trim().is_empty());
        let (description, source) = if clean {
            (
                "Git-linked worktree with no tracked or untracked changes. Review branch and repository state before removing",
                "Git worktree, clean",
            )
        } else {
            (
                "Git-linked worktree has changes or could not be checked. Keep it unless you have reviewed its contents",
                "Git worktree, changed or unknown",
            )
        };
        scan.push(
            canonical,
            "developer",
            source,
            description,
            Handling::Sensitive,
        );
    }
}

pub(crate) fn discover(home: &Path, deep: bool) -> DiscoveryOutput {
    let home = fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
    let mut scan = Scan {
        home: &home,
        started: Instant::now(),
        visited: 0,
        output: DiscoveryOutput::default(),
        seen: HashSet::new(),
        repos: HashSet::new(),
        stopped: false,
        candidate_limited: false,
    };
    for (path, category, source, desc, handling) in named_roots(&home) {
        if scan.stopped {
            break;
        }
        scan.push(path, category, source, desc, handling);
    }
    for candidate in browser_cache_roots(&home) {
        scan.push(
            candidate.path,
            candidate.category,
            &candidate.source,
            &candidate.description,
            candidate.handling,
        );
    }
    for candidate in unclassified_cache_roots(&home) {
        scan.push(
            candidate.path,
            candidate.category,
            &candidate.source,
            &candidate.description,
            candidate.handling,
        );
    }
    if deep && !scan.stopped {
        let roots = ["Developer", "Projects", "Code", "src"].map(|name| home.join(name));
        walk_projects(&mut scan, &roots);
        // Enumerate repository roots already visited. A short, read-only Git query
        // reveals linked worktrees outside the project tree without scanning them.
        let repos: Vec<_> = scan.repos.iter().cloned().collect();
        // Finish worktree discovery for repositories already found even when
        // the filesystem traversal reached its separate budget.
        scan.stopped = false;
        scan.started = Instant::now();
        scan.visited = 0;
        if !repos.is_empty() && git_program().is_none() {
            scan.output.warnings.push(
                "Git worktree discovery is unavailable because no installed Git binary was found."
                    .into(),
            );
        }
        for repo in repos {
            if !scan.tick() {
                break;
            }
            discover_worktrees(&mut scan, &repo);
        }
    }
    scan.output
        .candidates
        .sort_by(|a, b| a.category.cmp(b.category).then_with(|| a.path.cmp(&b.path)));
    if scan.candidate_limited {
        scan.output.warnings.push(
            "Deep discovery found more locations than can be shown at once. Higher priority build outputs, databases, and worktrees are shown first.".into(),
        );
    }
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
        for path in [
            ".cache/uv",
            ".cache/huggingface",
            "Library/Developer/Xcode/DerivedData",
        ] {
            fs::create_dir_all(home.path().join(path)).unwrap();
        }
        let docker_disk = home
            .path()
            .join("Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw");
        fs::create_dir_all(docker_disk.parent().unwrap()).unwrap();
        fs::write(&docker_disk, b"vm disk fixture").unwrap();
        let result = discover(home.path(), false);
        assert!(
            result
                .candidates
                .iter()
                .any(|c| c.path.ends_with(".cache/uv") && c.handling == Handling::Cache)
        );
        assert!(
            result.candidates.iter().any(
                |c| c.path.ends_with(".cache/huggingface") && c.handling == Handling::Sensitive
            )
        );
        assert!(
            result
                .candidates
                .iter()
                .any(|c| c.path.ends_with("DerivedData") && c.handling == Handling::Developer)
        );
        assert!(
            result
                .candidates
                .iter()
                .any(|c| { c.path == docker_disk && c.handling == Handling::Sensitive })
        );
    }

    #[test]
    fn deep_scan_recognizes_project_markers_and_skips_symlinked_builds() {
        let home = tempdir().unwrap();
        let repo = home.path().join("Projects/demo");
        fs::create_dir_all(repo.join("target")).unwrap();
        fs::write(repo.join("target/CACHEDIR.TAG"), "generated").unwrap();
        fs::create_dir_all(repo.join("node_modules")).unwrap();
        fs::write(repo.join("package.json"), "{}").unwrap();
        let canonical_repo = fs::canonicalize(&repo).unwrap();
        let outside = tempdir().unwrap();
        fs::create_dir_all(outside.path().join("target")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.path().join("target"), repo.join("linked-target"))
            .unwrap();
        let result = discover(home.path(), true);
        assert!(
            result
                .candidates
                .iter()
                .any(|c| c.path == canonical_repo.join("target"))
        );
        assert!(
            result
                .candidates
                .iter()
                .any(|c| c.path == canonical_repo.join("node_modules"))
        );
        assert!(
            !result
                .candidates
                .iter()
                .any(|c| c.path.ends_with("linked-target"))
        );
    }

    #[test]
    fn never_returns_credentials_or_items_outside_home() {
        let home = tempdir().unwrap();
        fs::create_dir_all(home.path().join(".ssh")).unwrap();
        fs::create_dir_all(home.path().join("Library/Keychains")).unwrap();
        let result = discover(home.path(), false);
        assert!(
            result
                .candidates
                .iter()
                .all(|c| !c.path.starts_with(home.path().join(".ssh"))
                    && !c.path.starts_with(home.path().join("Library/Keychains")))
        );
        assert!(is_excluded(&home.path().join(".ssh/config"), home.path()));
        assert!(is_excluded(
            &home
                .path()
                .join("Library/Application Support/Google/Chrome/Default/Cookies"),
            home.path()
        ));
    }
}
