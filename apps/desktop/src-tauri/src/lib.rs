use chrono::Utc;
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet},
    fs::{self, Metadata},
    hash::{DefaultHasher, Hash, Hasher},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use sysinfo::{ProcessesToUpdate, System};
use tauri::State;

const DAY: u64 = 86_400;
const CACHE_MIN_AGE: u64 = 7 * DAY;
const SESSION_MIN_AGE: u64 = 30 * DAY;
const LARGE_FILE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_SCAN_SECONDS: u64 = 12;
const MAX_VISITED: usize = 100_000;
const MAX_TRASH_SELECTION: usize = 200;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Volume {
    name: String,
    total_bytes: u64,
    available_bytes: u64,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Item {
    id: String,
    category: String,
    name: String,
    path: String,
    bytes: u64,
    file_count: u64,
    modified_at: u64,
    description: String,
    source: String,
    risk: String,
    cleanable: bool,
    reason: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanReport {
    id: String,
    scanned_at: u64,
    volume: Volume,
    items: Vec<Item>,
    warnings: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CleanupFailure {
    id: String,
    message: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CleanupResult {
    trashed_ids: Vec<String>,
    reclaimed_bytes: u64,
    failures: Vec<CleanupFailure>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Policy {
    Cache,
    Session,
    Developer,
    ReadOnly,
}

#[derive(Clone)]
struct Snapshot {
    path: PathBuf,
    policy: Policy,
    cleanable: bool,
    fingerprint: Fingerprint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Fingerprint {
    bytes: u64,
    file_count: u64,
    modified_secs: u64,
    root_dev: u64,
    root_ino: u64,
    digest: u64,
}

#[derive(Default)]
struct Registry {
    scan_id: String,
    entries: HashMap<String, Snapshot>,
}

#[derive(Clone, Default)]
struct AppState {
    registry: Arc<Mutex<Registry>>,
}

fn lock_registry(state: &AppState) -> std::sync::MutexGuard<'_, Registry> {
    state
        .registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn modified_secs(meta: &Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs())
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

fn metadata_identity(meta: &Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (meta.dev(), meta.ino())
}

fn metadata_digest(path: &Path, meta: &Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    let (dev, ino) = metadata_identity(meta);
    let mut hasher = DefaultHasher::new();
    path.hash(&mut hasher);
    dev.hash(&mut hasher);
    ino.hash(&mut hasher);
    meta.len().hash(&mut hasher);
    meta.file_type().is_symlink().hash(&mut hasher);
    meta.file_type().is_dir().hash(&mut hasher);
    meta.mtime().hash(&mut hasher);
    meta.mtime_nsec().hash(&mut hasher);
    meta.ctime().hash(&mut hasher);
    meta.ctime_nsec().hash(&mut hasher);
    hasher.finish()
}

fn measure_tree(path: &Path, started: Instant, budget: &mut usize) -> Result<Fingerprint, String> {
    let root_meta =
        fs::symlink_metadata(path).map_err(|e| format!("Item is no longer available: {e}"))?;
    if root_meta.file_type().is_symlink() {
        return Err("Item changed into a symbolic link. Run a new scan.".to_string());
    }
    let (root_dev, root_ino) = metadata_identity(&root_meta);
    let mut digest = metadata_digest(path, &root_meta);
    *budget = (*budget).saturating_add(1);
    if root_meta.is_file() {
        return Ok(Fingerprint {
            bytes: root_meta.len(),
            file_count: 1,
            modified_secs: modified_secs(&root_meta),
            root_dev,
            root_ino,
            digest,
        });
    }
    if !root_meta.is_dir() {
        return Err("Item is no longer a regular file or folder.".into());
    }
    let mut stack = vec![path.to_path_buf()];
    let mut total = 0_u64;
    let mut count = 0_u64;
    let mut newest = modified_secs(&root_meta);
    while let Some(dir) = stack.pop() {
        if started.elapsed() > Duration::from_secs(MAX_SCAN_SECONDS) || *budget >= MAX_VISITED {
            return Err(
                "The scan reached its safety limit. Run a new scan before cleaning this item."
                    .into(),
            );
        }
        let entries = fs::read_dir(&dir).map_err(|e| format!("Could not verify the item: {e}"))?;
        for entry in entries {
            if started.elapsed() > Duration::from_secs(MAX_SCAN_SECONDS) || *budget >= MAX_VISITED {
                return Err(
                    "The scan reached its safety limit. Run a new scan before cleaning this item."
                        .into(),
                );
            }
            let entry = entry.map_err(|e| format!("Could not verify the item: {e}"))?;
            *budget += 1;
            let child_path = entry.path();
            let meta = fs::symlink_metadata(&child_path)
                .map_err(|e| format!("Could not verify the item: {e}"))?;
            digest ^= metadata_digest(&child_path, &meta);
            if meta.file_type().is_symlink() {
                continue;
            }
            newest = newest.max(modified_secs(&meta));
            if meta.is_dir() {
                stack.push(child_path);
            } else if meta.is_file() {
                total = total.saturating_add(meta.len());
                count = count.saturating_add(1);
            }
        }
    }
    Ok(Fingerprint {
        bytes: total,
        file_count: count,
        modified_secs: newest,
        root_dev,
        root_ino,
        digest,
    })
}

fn fingerprint(path: &Path) -> Result<Fingerprint, String> {
    measure_tree(path, Instant::now(), &mut 0)
}

fn inspect_tree(path: &Path, started: Instant, budget: &mut usize) -> Result<Fingerprint, String> {
    measure_tree(path, started, budget)
}

fn no_symlink_path(path: &Path, home: &Path) -> bool {
    if !path.starts_with(home) {
        return false;
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if current == home || current.starts_with(home) {
            let Ok(meta) = fs::symlink_metadata(&current) else {
                return false;
            };
            if meta.file_type().is_symlink() {
                return false;
            }
        }
    }
    true
}

fn cache_roots(home: &Path) -> Vec<(PathBuf, String)> {
    let caches = home.join("Library/Caches");
    let recognized = [
        ("com.apple.dt.Xcode", "Xcode cache files"),
        ("Homebrew", "Homebrew download cache"),
        ("npm", "npm package cache"),
        ("pnpm", "pnpm package cache"),
        ("yarn", "Yarn package cache"),
        ("pip", "Python package cache"),
        ("uv", "uv package cache"),
        ("playwright", "Playwright browser download cache"),
        ("Cypress", "Cypress binary cache"),
    ];
    let mut roots: Vec<_> = recognized
        .into_iter()
        .map(|(name, desc)| (caches.join(name), desc.to_string()))
        .filter(|(path, _)| path.exists())
        .collect();
    roots.push((home.join(".npm/_cacache"), "npm package cache".into()));
    roots.push((
        home.join(".cache/Homebrew"),
        "Homebrew download cache".into(),
    ));
    roots.push((
        home.join("Library/Logs/DiagnosticReports"),
        "Old app crash reports".into(),
    ));
    roots.retain(|(path, _)| path.exists());
    roots
}

fn cache_candidates(
    home: &Path,
    started: Instant,
    budget: &mut usize,
    warnings: &mut Vec<String>,
) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    for (root, description) in cache_roots(home) {
        for entry in read_entries(
            &root,
            started,
            budget,
            warnings,
            "The scan reached its safety limit. Some items may be missing.",
        ) {
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                note_scan_warning(
                    warnings,
                    "Some cache files could not be inspected. Check macOS privacy permissions.",
                );
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            if path.file_name().is_some_and(|name| name == "_cacache") && meta.is_dir() {
                for child in read_entries(
                    &path,
                    started,
                    budget,
                    warnings,
                    "The scan reached its safety limit. Some items may be missing.",
                ) {
                    let child_path = child.path();
                    let Ok(child_meta) = fs::symlink_metadata(&child_path) else {
                        continue;
                    };
                    if child_meta.file_type().is_symlink() {
                        continue;
                    }
                    if child_path
                        .file_name()
                        .is_some_and(|name| name == "content-v2")
                        && child_meta.is_dir()
                    {
                        for shard in read_entries(
                            &child_path,
                            started,
                            budget,
                            warnings,
                            "The scan reached its safety limit. Some items may be missing.",
                        ) {
                            out.push((shard.path(), format!("{description} content shard")));
                        }
                    } else {
                        out.push((child_path, description.clone()));
                    }
                }
            } else {
                out.push((path, description.clone()));
            }
        }
    }
    out
}

fn running_agent_names() -> Vec<String> {
    let mut system = System::new();
    system.refresh_processes(ProcessesToUpdate::All, true);
    let needles = [
        "claude",
        "codex",
        "gemini",
        "cursor",
        "windsurf",
        "opencode",
        "xcode",
        "xcodebuild",
        "simulator",
        "node",
        "npm",
        "pnpm",
        "yarn",
        "brew",
    ];
    system
        .processes()
        .values()
        .map(|process| process.name().to_string_lossy().to_lowercase())
        .filter(|name| needles.iter().any(|needle| name.contains(needle)))
        .collect::<HashSet<_>>()
        .into_iter()
        .collect()
}

fn volume_info(home: &Path) -> Result<Volume, String> {
    let cpath = std::ffi::CString::new(home.as_os_str().as_encoded_bytes())
        .map_err(|_| "Could not read the startup disk location".to_string())?;
    // statvfs only reads filesystem capacity for the selected path.
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `cpath` is NUL-terminated and `stats` points to writable storage for statvfs.
    let status = unsafe { libc::statvfs(cpath.as_ptr(), stats.as_mut_ptr()) };
    if status != 0 {
        return Err("macOS could not report startup disk capacity.".into());
    }
    // SAFETY: statvfs returned success and initialized the output structure.
    let stats = unsafe { stats.assume_init() };
    let block = stats.f_frsize as u64;
    Ok(Volume {
        name: "Macintosh HD".into(),
        total_bytes: block.saturating_mul(stats.f_blocks as u64),
        available_bytes: block.saturating_mul(stats.f_bavail as u64),
    })
}

fn push_candidate(
    category: &str,
    policy: Policy,
    path: PathBuf,
    description: String,
    source: String,
    active_agents: &[String],
    started: Instant,
    budget: &mut usize,
    items: &mut Vec<Item>,
    snapshots: &mut HashMap<String, Snapshot>,
    warnings: &mut Vec<String>,
) {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    let Ok(meta) = fs::symlink_metadata(&path) else {
        return;
    };
    if meta.file_type().is_symlink() {
        return;
    }
    let fp = match inspect_tree(&path, started, budget) {
        Ok(fp) => fp,
        Err(message) => {
            if !warnings.contains(&message) {
                warnings.push(message);
            }
            return;
        }
    };
    let age = now_secs().saturating_sub(fp.modified_secs);
    let process_reason = active_process_reason(policy, active_agents);
    let (cleanable, risk, reason) = if let Some(reason) = process_reason {
        (false, "protected", Some(reason))
    } else {
        match policy {
            Policy::Cache if is_old_enough(policy, age) => (true, "safe", None),
            Policy::Cache => (
                false,
                "review",
                Some("Used within the last 7 days. Wait before clearing it."),
            ),
            Policy::Session if is_old_enough(policy, age) => (
                true,
                "review",
                Some(
                    "Old agent history may contain prompts and file paths. Review it before clearing.",
                ),
            ),
            Policy::Session => (
                false,
                "review",
                Some("Session history must be at least 30 days old."),
            ),
            Policy::Developer if is_old_enough(policy, age) => (true, "review", None),
            Policy::Developer => (
                false,
                "review",
                Some("Used within the last 7 days. Wait before clearing it."),
            ),
            Policy::ReadOnly => (
                false,
                "protected",
                Some("Large files are listed for review. Open Finder to remove them."),
            ),
        }
    };
    let id = format!("item-{}", items.len());
    let item = Item {
        id: id.clone(),
        category: category.into(),
        name,
        path: path.display().to_string(),
        bytes: fp.bytes,
        file_count: fp.file_count,
        modified_at: fp.modified_secs.saturating_mul(1000),
        description,
        source,
        risk: risk.into(),
        cleanable,
        reason: reason.map(str::to_string),
    };
    snapshots.insert(
        id,
        Snapshot {
            path,
            policy,
            cleanable,
            fingerprint: fp,
        },
    );
    items.push(item);
}

fn note_scan_warning(warnings: &mut Vec<String>, message: &str) {
    if !warnings.iter().any(|warning| warning == message) {
        warnings.push(message.to_string());
    }
}

fn budget_one(
    started: Instant,
    budget: &mut usize,
    warnings: &mut Vec<String>,
    label: &str,
) -> bool {
    if started.elapsed() > Duration::from_secs(MAX_SCAN_SECONDS) || *budget >= MAX_VISITED {
        note_scan_warning(warnings, label);
        return false;
    }
    *budget += 1;
    true
}

fn read_entries(
    path: &Path,
    started: Instant,
    budget: &mut usize,
    warnings: &mut Vec<String>,
    limit_warning: &str,
) -> Vec<fs::DirEntry> {
    let Ok(entries) = fs::read_dir(path) else {
        note_scan_warning(
            warnings,
            "Some folders could not be read. Check macOS privacy permissions.",
        );
        return Vec::new();
    };
    let mut found = Vec::new();
    for entry in entries {
        if !budget_one(started, budget, warnings, limit_warning) {
            break;
        }
        match entry {
            Ok(entry) => found.push(entry),
            Err(_) => note_scan_warning(
                warnings,
                "Some files could not be inspected. Check macOS privacy permissions.",
            ),
        }
    }
    found
}

fn build_scan(home: &Path) -> Result<(ScanReport, HashMap<String, Snapshot>), String> {
    let started = Instant::now();
    let active_processes = running_agent_names();
    let mut items = Vec::new();
    let mut snapshots = HashMap::new();
    let mut warnings = Vec::new();
    let mut budget = 0;
    let limit_warning = "The scan reached its safety limit. Some items may be missing.";

    // Agent transcripts are the primary target, so scan them before broad cache folders.
    let session_roots = [
        home.join(".codex/sessions"),
        home.join(".codex/archived_sessions"),
        home.join(".claude/projects"),
    ];
    for root in session_roots {
        if !no_symlink_path(&root, home) || !root.is_dir() {
            continue;
        }
        let mut stack = vec![root.clone()];
        while let Some(dir) = stack.pop() {
            if started.elapsed() > Duration::from_secs(MAX_SCAN_SECONDS) || budget >= MAX_VISITED {
                note_scan_warning(&mut warnings, limit_warning);
                break;
            }
            for entry in read_entries(&dir, started, &mut budget, &mut warnings, limit_warning) {
                let path = entry.path();
                let Ok(meta) = fs::symlink_metadata(&path) else {
                    note_scan_warning(
                        &mut warnings,
                        "Some files could not be inspected. Check macOS privacy permissions.",
                    );
                    continue;
                };
                if meta.file_type().is_symlink() {
                    continue;
                }
                if meta.is_dir() {
                    stack.push(path);
                } else if meta.is_file()
                    && path.extension().is_some_and(|ext| ext == "jsonl")
                    && no_symlink_path(&path, home)
                {
                    let source = if root.ends_with(".claude/projects") {
                        "Claude Code transcript"
                    } else {
                        "Codex transcript"
                    };
                    push_candidate(
                        "agents",
                        Policy::Session,
                        path,
                        "Conversation transcript. It may contain prompts and paths.".into(),
                        source.into(),
                        &active_processes,
                        started,
                        &mut budget,
                        &mut items,
                        &mut snapshots,
                        &mut warnings,
                    );
                }
            }
        }
    }

    let derived_data = home.join("Library/Developer/Xcode/DerivedData");
    if no_symlink_path(&derived_data, home) {
        for entry in read_entries(
            &derived_data,
            started,
            &mut budget,
            &mut warnings,
            limit_warning,
        ) {
            let path = entry.path();
            if no_symlink_path(&path, home) {
                push_candidate(
                    "developer",
                    Policy::Developer,
                    path,
                    "Xcode build products that Xcode can recreate".into(),
                    "Xcode DerivedData".into(),
                    &active_processes,
                    started,
                    &mut budget,
                    &mut items,
                    &mut snapshots,
                    &mut warnings,
                );
            }
        }
    }

    for (path, description) in
        cache_candidates(home, started, &mut budget, &mut warnings, limit_warning)
    {
        if no_symlink_path(&path, home) {
            push_candidate(
                "caches",
                Policy::Cache,
                path,
                description,
                "Application caches and logs".into(),
                &active_processes,
                started,
                &mut budget,
                &mut items,
                &mut snapshots,
                &mut warnings,
            );
        }
    }

    let downloads = home.join("Downloads");
    if no_symlink_path(&downloads, home) {
        for entry in read_entries(
            &downloads,
            started,
            &mut budget,
            &mut warnings,
            limit_warning,
        ) {
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                note_scan_warning(
                    &mut warnings,
                    "Some files could not be inspected. Check macOS privacy permissions.",
                );
                continue;
            };
            if meta.is_file() && !meta.file_type().is_symlink() && meta.len() >= LARGE_FILE_BYTES {
                push_candidate(
                    "large",
                    Policy::ReadOnly,
                    path,
                    "Large download taking up space".into(),
                    "Downloads".into(),
                    &active_processes,
                    started,
                    &mut budget,
                    &mut items,
                    &mut snapshots,
                    &mut warnings,
                );
            }
        }
    }

    if active_process_reason(Policy::Session, &active_processes).is_some() {
        note_scan_warning(
            &mut warnings,
            "AI coding tools are open. Session transcripts are protected until those apps are closed.",
        );
    }
    let report = ScanReport {
        id: format!(
            "scan-{}-{}",
            now_millis(),
            Utc::now().timestamp_subsec_nanos()
        ),
        scanned_at: now_millis(),
        volume: volume_info(home)?,
        items,
        warnings,
    };
    Ok((report, snapshots))
}

#[tauri::command(rename_all = "camelCase")]
async fn scan_system(state: State<'_, AppState>) -> Result<ScanReport, String> {
    let state = state.inner().clone();
    let home =
        home_dir().ok_or_else(|| "Could not find the current user's home folder.".to_string())?;
    let (report, entries) = tauri::async_runtime::spawn_blocking(move || build_scan(&home))
        .await
        .map_err(|_| "The storage scan could not finish.".to_string())??;
    let mut registry = lock_registry(&state);
    registry.scan_id = report.id.clone();
    registry.entries = entries;
    Ok(report)
}

fn policy_root_allows(path: &Path, home: &Path, policy: Policy) -> bool {
    match policy {
        Policy::Cache => cache_roots(home).iter().any(|(root, _)| {
            let Ok(relative) = path.strip_prefix(root) else {
                return false;
            };
            let components = relative.components().count();
            let direct_child = components == 1
                && !(root.file_name().is_some_and(|name| name == "_cacache")
                    && relative == Path::new("content-v2"));
            let cacache_index = components == 2
                && relative
                    .components()
                    .next()
                    .is_some_and(|part| part.as_os_str() == "_cacache");
            let content_shard = path
                .parent()
                .is_some_and(|parent| parent.file_name().is_some_and(|name| name == "content-v2"))
                && path.parent().and_then(Path::parent).is_some_and(|parent| {
                    parent.file_name().is_some_and(|name| name == "_cacache")
                });
            direct_child || cacache_index || content_shard
        }),
        Policy::Developer => path
            .parent()
            .is_some_and(|p| p == home.join("Library/Developer/Xcode/DerivedData")),
        Policy::Session => {
            path.extension().is_some_and(|ext| ext == "jsonl")
                && [
                    home.join(".codex/sessions"),
                    home.join(".codex/archived_sessions"),
                    home.join(".claude/projects"),
                ]
                .iter()
                .any(|root| path.starts_with(root))
        }
        Policy::ReadOnly => path.parent().is_some_and(|p| p == home.join("Downloads")),
    }
}

fn policy_allows(path: &Path, home: &Path, policy: Policy) -> bool {
    policy_root_allows(path, home, policy) && no_symlink_path(path, home)
}

fn is_old_enough(policy: Policy, age_secs: u64) -> bool {
    match policy {
        Policy::Cache => age_secs >= CACHE_MIN_AGE,
        Policy::Session => age_secs >= SESSION_MIN_AGE,
        Policy::Developer => age_secs >= CACHE_MIN_AGE,
        Policy::ReadOnly => false,
    }
}

fn active_process_reason(policy: Policy, active: &[String]) -> Option<&'static str> {
    let has = |needles: &[&str]| {
        active
            .iter()
            .any(|name| needles.iter().any(|needle| name.contains(needle)))
    };
    match policy {
        Policy::Session
            if has(&[
                "claude", "codex", "gemini", "cursor", "windsurf", "opencode",
            ]) =>
        {
            Some("An AI coding tool is open. Close it before clearing session history.")
        }
        Policy::Developer if has(&["xcode", "xcodebuild", "simulator"]) => {
            Some("Xcode or Simulator is open. Close it before clearing build files.")
        }
        Policy::Cache if has(&["node", "npm", "pnpm", "yarn", "brew"]) => {
            Some("A package manager or build process is open. Close it before clearing caches.")
        }
        _ => None,
    }
}

#[tauri::command(rename_all = "camelCase")]
async fn trash_items(
    state: State<'_, AppState>,
    scan_id: String,
    item_ids: Vec<String>,
) -> CleanupResult {
    let state = state.inner().clone();
    let (scan, selected) = {
        let registry = lock_registry(&state);
        (
            registry.scan_id.clone(),
            item_ids
                .iter()
                .filter_map(|id| registry.entries.get(id).cloned().map(|s| (id.clone(), s)))
                .collect::<Vec<_>>(),
        )
    };
    let mut result = CleanupResult {
        trashed_ids: Vec::new(),
        reclaimed_bytes: 0,
        failures: Vec::new(),
    };
    if scan_id != scan {
        result.failures.push(CleanupFailure {
            id: String::new(),
            message: "This scan has expired. Scan again before cleaning.".into(),
        });
        return result;
    }
    if item_ids.is_empty() || item_ids.len() > MAX_TRASH_SELECTION {
        result.failures.push(CleanupFailure {
            id: String::new(),
            message: "Choose between 1 and 200 items.".into(),
        });
        return result;
    }
    let home = match home_dir() {
        Some(path) => path,
        None => {
            result.failures.push(CleanupFailure {
                id: String::new(),
                message: "Could not find the current user's home folder.".into(),
            });
            return result;
        }
    };
    let selected_ids: HashSet<_> = item_ids.iter().cloned().collect();
    let available_ids: HashSet<_> = selected.iter().map(|(id, _)| id.clone()).collect();
    for id in selected_ids {
        if !available_ids.contains(&id) {
            result.failures.push(CleanupFailure {
                id,
                message: "This item was not part of the current scan. Scan again.".into(),
            });
        }
    }
    for (id, snapshot) in selected {
        if !item_ids.contains(&id) {
            continue;
        }
        let error = if !snapshot.cleanable {
            Some(
                "This item is protected. Only items marked as cleanable can be moved to Trash."
                    .into(),
            )
        } else if !policy_allows(&snapshot.path, &home, snapshot.policy) {
            Some("This location is protected and cannot be moved to Trash.".into())
        } else if snapshot.policy == Policy::Session && !running_agent_names().is_empty() {
            Some("An AI coding tool is open. Close it before clearing session history.".into())
        } else {
            match fingerprint(&snapshot.path) {
                Ok(current) if current == snapshot.fingerprint => None,
                Ok(_) => Some(
                    "This item changed since the scan. Run a new scan before cleaning it.".into(),
                ),
                Err(message) => Some(message),
            }
        };
        if let Some(message) = error {
            result.failures.push(CleanupFailure { id, message });
            continue;
        }
        let bytes = snapshot.fingerprint.bytes;
        let path = snapshot.path.clone();
        let moved = tauri::async_runtime::spawn_blocking(move || trash::delete(path))
            .await
            .map_err(|_| "The Trash operation could not finish.".to_string())
            .and_then(|result| result.map_err(|e| e.to_string()));
        match moved {
            Ok(()) => {
                result.trashed_ids.push(id);
                result.reclaimed_bytes = result.reclaimed_bytes.saturating_add(bytes);
            }
            Err(message) => result.failures.push(CleanupFailure {
                id,
                message: format!("Could not move this item to Trash: {message}"),
            }),
        }
    }
    result
}

#[tauri::command(rename_all = "camelCase")]
fn reveal_item(state: State<'_, AppState>, scan_id: String, item_id: String) -> Result<(), String> {
    let snapshot = {
        let registry = lock_registry(&state);
        if scan_id != registry.scan_id {
            return Err("This scan has expired. Scan again before opening Finder.".into());
        }
        registry
            .entries
            .get(&item_id)
            .cloned()
            .ok_or_else(|| "This item was not part of the current scan.".to_string())?
    };
    let home =
        home_dir().ok_or_else(|| "Could not find the current user's home folder.".to_string())?;
    if !policy_root_allows(&snapshot.path, &home, snapshot.policy)
        || !no_symlink_path(&snapshot.path, &home)
    {
        return Err("This location is outside the scan's safe paths.".into());
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("/usr/bin/open")
            .arg("-R")
            .arg(&snapshot.path)
            .spawn()
            .map_err(|e| format!("Could not open Finder: {e}"))?;
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("Finder reveal is only available on macOS.".into())
    }
}

pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            scan_system,
            trash_items,
            reveal_item
        ])
        .run(tauri::generate_context!())
        .expect("error while running Clean My Mac");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::File, io::Write};
    use tempfile::TempDir;

    #[test]
    fn scan_skips_symlinks_and_sums_regular_files() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new()?;
        let dir = tmp.path().join("cache");
        fs::create_dir(&dir)?;
        let mut file = File::create(dir.join("a"))?;
        file.write_all(b"hello")?;
        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc/passwd", dir.join("link"))?;
        let mut budget = 0;
        let fp = inspect_tree(&dir, Instant::now(), &mut budget)
            .map_err(|e| std::io::Error::other(e))?;
        assert_eq!(fp.bytes, 5);
        assert_eq!(fp.file_count, 1);
        Ok(())
    }

    #[test]
    fn cleanup_policy_is_allowlisted_and_downloads_are_never_removable() {
        let home = Path::new("/Users/tester");
        assert!(!policy_allows(
            &home.join("Downloads/movie.mov"),
            home,
            Policy::ReadOnly
        ));
        assert!(!policy_allows(
            &home.join(".claude/settings.json"),
            home,
            Policy::Session
        ));
        assert!(policy_root_allows(
            &home.join(".claude/projects/project/session.jsonl"),
            home,
            Policy::Session
        ));
        assert!(!policy_root_allows(
            &home.join(".claude/projects/project/settings.json"),
            home,
            Policy::Session
        ));
        assert!(policy_root_allows(
            &home.join("Library/Developer/Xcode/DerivedData/project"),
            home,
            Policy::Developer
        ));
    }

    #[test]
    fn age_thresholds_keep_recent_caches_and_sessions_protected() {
        assert!(!is_old_enough(Policy::Cache, CACHE_MIN_AGE - 1));
        assert!(is_old_enough(Policy::Cache, CACHE_MIN_AGE));
        assert!(!is_old_enough(Policy::Session, SESSION_MIN_AGE - 1));
        assert!(is_old_enough(Policy::Session, SESSION_MIN_AGE));
        assert!(!is_old_enough(Policy::ReadOnly, u64::MAX));
    }

    #[test]
    fn fingerprint_changes_when_file_content_size_changes() -> Result<(), Box<dyn std::error::Error>>
    {
        let tmp = TempDir::new()?;
        let path = tmp.path().join("item.jsonl");
        fs::write(&path, "one")?;
        let before = fingerprint(&path).map_err(std::io::Error::other)?;
        fs::write(&path, "a longer transcript")?;
        let after = fingerprint(&path).map_err(std::io::Error::other)?;
        assert_ne!(before, after);
        Ok(())
    }
}
