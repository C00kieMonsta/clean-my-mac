mod discovery;
mod insights;
mod worktrees;

use chrono::Utc;
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet},
    fs::{self, Metadata},
    hash::{DefaultHasher, Hash, Hasher},
    io::ErrorKind,
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
const MAX_SCAN_SECONDS: u64 = 30;
const MAX_VISITED: usize = 500_000;
const MAX_TEMP_SCAN_SECONDS: u64 = 10;
const MAX_TEMP_VISITED: usize = 200_000;
const DEEP_SCAN_SECONDS: u64 = 60;
const DEEP_SCAN_VISITED: usize = 3_000_000;
const MAX_SCAN_ITEMS: usize = 5_000;
const MAX_AGENT_ITEMS: usize = 1_500;
const MAX_AGENT_VISITED: usize = 30_000;
const MAX_AGENT_SCAN_SECONDS: u64 = 5;
const MAX_TRASH_SELECTION: usize = MAX_SCAN_ITEMS;

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Volume {
    name: String,
    total_bytes: u64,
    available_bytes: u64,
    free_bytes: u64,
    purgeable_bytes: u64,
    available_for_important_usage_bytes: u64,
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
    requires_ack: bool,
    reason: Option<String>,
    cleanup_kind: Option<String>,
    allocated_bytes: Option<u64>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanReport {
    id: String,
    scanned_at: u64,
    volume: Volume,
    items: Vec<Item>,
    warnings: Vec<String>,
    coverage: ScanCoverage,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanCoverage {
    mode: String,
    detectors: usize,
    visited_entries: usize,
    elapsed_ms: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CleanupReport {
    #[serde(flatten)]
    result: CleanupResult,
    moved_bytes: u64,
    free_bytes_before: Option<u64>,
    free_bytes_after: Option<u64>,
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
    Temporary,
    Manual,
    ReadOnly,
    Discovered,
    Sensitive,
    Worktree,
}

#[derive(Clone)]
struct Snapshot {
    path: PathBuf,
    policy: Policy,
    cleanable: bool,
    requires_ack: bool,
    guard_hint: String,
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
    allocated_bytes: u64,
}

#[derive(Default)]
struct Registry {
    scan_id: String,
    entries: HashMap<String, Snapshot>,
    items: HashMap<String, Item>,
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

fn current_user_temp_root() -> Option<PathBuf> {
    let root = fs::canonicalize(std::env::temp_dir()).ok()?;
    let metadata = fs::symlink_metadata(&root).ok()?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: getuid does not take pointers or mutate process state.
        if metadata.uid() != unsafe { libc::getuid() } {
            return None;
        }
    }
    Some(root)
}

fn is_generated_temp_name(name: &std::ffi::OsStr) -> bool {
    let name = name.to_string_lossy();
    name.starts_with("cdk.out") || name.starts_with("jest_")
}

fn temporary_path_is_allowlisted(path: &Path, root: &Path) -> bool {
    path.parent() == Some(root)
        && path.file_name().is_some_and(is_generated_temp_name)
        && fs::symlink_metadata(path)
            .is_ok_and(|meta| meta.is_dir() && !meta.file_type().is_symlink())
        && no_symlink_path(path, root)
}

fn manual_path_is_allowlisted(path: &Path, home: &Path) -> bool {
    let Ok(canonical_path) = fs::canonicalize(path) else {
        return false;
    };
    if canonical_path != path {
        return false;
    }
    let Ok(canonical_home) = fs::canonicalize(home) else {
        return false;
    };
    if !fs::symlink_metadata(&canonical_path)
        .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
    {
        return false;
    }
    let temp_root = current_user_temp_root();
    let home_descendant =
        canonical_path != canonical_home && canonical_path.starts_with(&canonical_home);
    let temp_descendant = temp_root
        .as_ref()
        .is_some_and(|root| canonical_path != *root && canonical_path.starts_with(root));
    if temp_root
        .as_ref()
        .is_some_and(|root| canonical_path == *root)
    {
        return false;
    }
    if !home_descendant && !temp_descendant {
        return false;
    }
    if canonical_path == canonical_home.join("Library") {
        return false;
    }
    let protected_roots = [
        canonical_home.join(".ssh"),
        canonical_home.join(".gnupg"),
        canonical_home.join(".aws"),
        canonical_home.join("Library/Keychains"),
        canonical_home.join("Library/Accounts"),
        canonical_home.join(".codex/auth"),
        canonical_home.join(".claude/credentials"),
        canonical_home.join(".claude/credentials.json"),
    ];
    if protected_roots.iter().any(|protected| {
        canonical_path.starts_with(protected) || protected.starts_with(&canonical_path)
    }) {
        return false;
    }
    let boundary = if home_descendant {
        canonical_home.as_path()
    } else {
        temp_root.as_deref().unwrap_or(Path::new("/"))
    };
    no_symlink_path(&canonical_path, boundary)
}

fn allocated_size(meta: &Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.blocks().saturating_mul(512)
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

fn measure_tree(
    path: &Path,
    started: Instant,
    budget: &mut usize,
    max_seconds: u64,
    max_entries: usize,
) -> Result<Fingerprint, String> {
    use std::os::unix::fs::MetadataExt;
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
            allocated_bytes: allocated_size(&root_meta),
        });
    }
    if !root_meta.is_dir() {
        return Err("Item is no longer a regular file or folder.".into());
    }
    let mut stack = vec![path.to_path_buf()];
    let mut total = 0_u64;
    let mut allocated = 0_u64;
    let mut count = 0_u64;
    let mut newest = modified_secs(&root_meta);
    let mut linked_files = HashSet::new();
    while let Some(dir) = stack.pop() {
        if started.elapsed() > Duration::from_secs(max_seconds) || *budget >= max_entries {
            return Err(
                "The scan reached its safety limit. Run a new scan before cleaning this item."
                    .into(),
            );
        }
        let entries = fs::read_dir(&dir).map_err(|e| format!("Could not verify the item: {e}"))?;
        for entry in entries {
            if started.elapsed() > Duration::from_secs(max_seconds) || *budget >= max_entries {
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
                // Build tools frequently hard-link artifacts into several folders.
                // Fingerprint every path, but count the shared inode only once.
                if meta.nlink() <= 1 || linked_files.insert(metadata_identity(&meta)) {
                    total = total.saturating_add(meta.len());
                    allocated = allocated.saturating_add(allocated_size(&meta));
                }
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
        allocated_bytes: allocated,
    })
}

fn fingerprint(path: &Path) -> Result<Fingerprint, String> {
    measure_tree(
        path,
        Instant::now(),
        &mut 0,
        DEEP_SCAN_SECONDS,
        DEEP_SCAN_VISITED,
    )
}

fn inspect_tree(
    path: &Path,
    started: Instant,
    budget: &mut usize,
    max_seconds: u64,
    max_entries: usize,
) -> Result<Fingerprint, String> {
    measure_tree(path, started, budget, max_seconds, max_entries)
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
    let mut roots = vec![
        (
            home.join("Library/Application Support/Spotify/PersistentCache"),
            "Spotify persistent cache".into(),
        ),
        (
            home.join("Library/Application Support/stremio-server/stremio-cache"),
            "Stremio server cache".into(),
        ),
        (
            home.join("Library/iTunes/iPhone Software Updates"),
            "iPhone software update files".into(),
        ),
        (
            home.join(".cache/huggingface/hub"),
            "Hugging Face downloaded model cache. Removing it may make models unavailable offline."
                .into(),
        ),
        (
            home.join(".cache/puppeteer"),
            "Puppeteer browser download cache".into(),
        ),
    ];
    let recognized = [
        ("com.apple.dt.Xcode", "Xcode cache files"),
        ("Homebrew", "Homebrew download cache"),
        ("npm", "npm package cache"),
        ("pnpm", "pnpm package cache"),
        ("yarn", "Yarn package cache"),
        ("pip", "Python package cache"),
        ("uv", "uv package cache"),
        ("playwright", "Playwright browser download cache"),
        ("ms-playwright", "Playwright browser download cache"),
        ("Cypress", "Cypress binary cache"),
        ("CocoaPods", "CocoaPods package cache"),
        ("com.spotify.client", "Spotify app cache"),
        ("com.microsoft.VSCode.ShipIt", "VS Code update cache"),
    ];
    roots.extend(
        recognized
            .into_iter()
            .map(|(name, desc)| (caches.join(name), desc.to_string())),
    );
    roots.push((home.join(".npm/_cacache"), "npm package cache".into()));
    roots.push((
        home.join(".cache/Homebrew"),
        "Homebrew download cache".into(),
    ));
    roots.extend([
        (home.join(".cache/uv"), "uv package cache".into()),
        (
            home.join(".cache/pre-commit"),
            "pre-commit hook cache".into(),
        ),
    ]);
    roots.push((
        home.join("Library/Logs/DiagnosticReports"),
        "Old app crash reports".into(),
    ));
    roots
}

fn cache_candidates(
    home: &Path,
    started: Instant,
    budget: &mut usize,
    warnings: &mut Vec<String>,
) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    let limit = "The scan reached its safety limit. Some items may be missing.";
    for (root, description) in cache_roots(home) {
        if !no_symlink_path(&root, home) {
            continue;
        }
        for entry in read_entries(
            &root,
            started,
            budget,
            warnings,
            limit,
            MAX_SCAN_SECONDS,
            MAX_VISITED,
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
            let is_cacache =
                path.file_name().is_some_and(|name| name == "_cacache") && meta.is_dir();
            let is_content = path.file_name().is_some_and(|name| name == "content-v2")
                && path.parent().is_some_and(|parent| {
                    parent.file_name().is_some_and(|name| name == "_cacache")
                })
                && meta.is_dir();
            if is_cacache || is_content {
                for child in read_entries(
                    &path,
                    started,
                    budget,
                    warnings,
                    limit,
                    MAX_SCAN_SECONDS,
                    MAX_VISITED,
                ) {
                    let child_path = child.path();
                    let Ok(child_meta) = fs::symlink_metadata(&child_path) else {
                        continue;
                    };
                    if child_meta.file_type().is_symlink() {
                        continue;
                    }
                    let is_content = child_path
                        .file_name()
                        .is_some_and(|name| name == "content-v2")
                        && child_path.parent().is_some_and(|parent| {
                            parent.file_name().is_some_and(|name| name == "_cacache")
                        })
                        && child_meta.is_dir();
                    if is_content {
                        for shard in read_entries(
                            &child_path,
                            started,
                            budget,
                            warnings,
                            limit,
                            MAX_SCAN_SECONDS,
                            MAX_VISITED,
                        ) {
                            if let Ok(shard_meta) = fs::symlink_metadata(shard.path())
                                && !shard_meta.file_type().is_symlink()
                            {
                                out.push((shard.path(), format!("{description} content shard")));
                            }
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
        "python",
        "playwright",
        "cypress",
        "pip",
        "uv",
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
    let block = stats.f_frsize;
    let free = block.saturating_mul(stats.f_bavail as u64);
    let capacity = insights::storage_capacity(home);
    Ok(Volume {
        name: "Macintosh HD".into(),
        total_bytes: block.saturating_mul(stats.f_blocks as u64),
        available_bytes: free,
        free_bytes: free,
        purgeable_bytes: capacity.as_ref().map_or(0, |value| value.purgeable_bytes),
        available_for_important_usage_bytes: capacity
            .as_ref()
            .map_or(free, |value| value.available_for_important_usage_bytes),
    })
}

// Keep policy evaluation and registration together with the shared scan buffers.
#[allow(clippy::too_many_arguments)]
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
    if items.len() >= MAX_SCAN_ITEMS {
        note_scan_warning(
            warnings,
            "The scan reached its item limit. Some items may be missing.",
        );
        return;
    }
    let Ok(meta) = fs::symlink_metadata(&path) else {
        return;
    };
    if meta.file_type().is_symlink() {
        return;
    }
    let (max_seconds, max_entries) = if policy == Policy::Session {
        (MAX_AGENT_SCAN_SECONDS, MAX_AGENT_VISITED)
    } else if policy == Policy::Temporary {
        (MAX_TEMP_SCAN_SECONDS, MAX_TEMP_VISITED)
    } else {
        (MAX_SCAN_SECONDS, MAX_VISITED)
    };
    register_candidate(
        category,
        policy,
        path,
        description,
        source,
        active_agents,
        started,
        budget,
        items,
        snapshots,
        warnings,
        max_seconds,
        max_entries,
    );
}

#[allow(clippy::too_many_arguments)]
fn register_candidate(
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
    max_seconds: u64,
    max_entries: usize,
) {
    if items.len() >= MAX_SCAN_ITEMS {
        note_scan_warning(
            warnings,
            "The scan reached its item limit. Some items may be missing.",
        );
        return;
    }
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    let fp = match inspect_tree(&path, started, budget, max_seconds, max_entries) {
        Ok(fp) => fp,
        Err(message) => {
            if !warnings.contains(&message) {
                warnings.push(message);
            }
            return;
        }
    };
    // Empty build and cache folders take no file space and should not crowd out
    // the large findings the user needs to review.
    if fp.bytes == 0 {
        return;
    }
    let age = now_secs().saturating_sub(fp.modified_secs);
    let process_reason = active_process_reason(policy, active_agents, &description);
    let guard_hint = description.clone();
    let (cleanable, requires_ack, risk, reason) = match policy {
        Policy::Cache
            if process_reason.is_none()
                && is_old_enough(policy, age)
                && !is_offline_model_cache(&description) =>
        {
            (true, false, "safe", None)
        }
        Policy::Cache => (
            true,
            true,
            "review",
            Some(process_reason.unwrap_or(if is_offline_model_cache(&description) {
                "This cache contains downloaded models. Removing them may make models unavailable offline. Review before clearing."
            } else {
                "Used within the last 7 days. Review before clearing."
            })),
        ),
        Policy::Session => (
            true,
            true,
            "review",
            Some(process_reason.unwrap_or(if is_old_enough(policy, age) {
                "Session history may contain prompts and file paths. Review before clearing."
            } else {
                "Recent session history may contain prompts and file paths. Review before clearing."
            })),
        ),
        Policy::Developer => (
            true,
            true,
            "review",
            Some(process_reason.unwrap_or(
                "Build files can belong to recent or active work. Review before clearing.",
            )),
        ),
        Policy::Temporary => (
            true,
            true,
            "review",
            Some("Temporary build or test data may belong to active work. Review before clearing."),
        ),
        Policy::Manual => (
            true,
            true,
            "review",
            Some("This folder and all its contents will move to Trash. It may contain personal files. Review it carefully."),
        ),
        Policy::Discovered | Policy::Worktree => (
            true, true, "review", Some("Review this discovered location and its contents before cleanup."),
        ),
        Policy::Sensitive => (
            false, false, "protected", Some("This contains app state, backups, or model data. Inspect it in Finder or manage it in the owning app."),
        ),
        Policy::ReadOnly => (
            true,
            true,
            "review",
            Some("This is a file in Downloads. Review it before moving it to Trash."),
        ),
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
        requires_ack,
        reason: reason.map(str::to_string),
        cleanup_kind: if policy == Policy::Worktree {
            Some("git".into())
        } else {
            None
        },
        allocated_bytes: Some(fp.allocated_bytes),
    };
    snapshots.insert(
        id,
        Snapshot {
            path,
            policy,
            cleanable,
            requires_ack,
            guard_hint,
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

fn budget_one_for(
    started: Instant,
    budget: &mut usize,
    warnings: &mut Vec<String>,
    label: &str,
    max_seconds: u64,
    max_entries: usize,
) -> bool {
    if started.elapsed() > Duration::from_secs(max_seconds) || *budget >= max_entries {
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
    max_seconds: u64,
    max_entries: usize,
) -> Vec<fs::DirEntry> {
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Vec::new(),
        Err(_) => {
            note_scan_warning(
                warnings,
                "Some folders could not be read. Check macOS privacy permissions.",
            );
            return Vec::new();
        }
    };
    let mut found = Vec::new();
    for entry in entries {
        if !budget_one_for(
            started,
            budget,
            warnings,
            limit_warning,
            max_seconds,
            max_entries,
        ) {
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

fn temporary_candidates(
    root: &Path,
    started: Instant,
    budget: &mut usize,
    warnings: &mut Vec<String>,
) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let limit = "The scan reached its safety limit. Some items may be missing.";
    for entry in read_entries(
        root,
        started,
        budget,
        warnings,
        limit,
        MAX_TEMP_SCAN_SECONDS,
        MAX_TEMP_VISITED,
    ) {
        if started.elapsed() > Duration::from_secs(MAX_TEMP_SCAN_SECONDS)
            || *budget >= MAX_TEMP_VISITED
            || candidates.len() >= MAX_SCAN_ITEMS
        {
            note_scan_warning(warnings, limit);
            break;
        }
        let path = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && path.parent() == Some(root)
            && path.file_name().is_some_and(is_generated_temp_name)
            && no_symlink_path(&path, root)
        {
            candidates.push(path);
        }
    }
    candidates
}

fn build_scan(home: &Path) -> Result<(ScanReport, HashMap<String, Snapshot>), String> {
    build_scan_mode(home, false)
}

fn build_scan_mode(
    home: &Path,
    deep: bool,
) -> Result<(ScanReport, HashMap<String, Snapshot>), String> {
    let started = Instant::now();
    let active_processes = running_agent_names();
    let mut items = Vec::new();
    let mut snapshots = HashMap::new();
    let mut warnings = Vec::new();
    let mut budget: usize = 0;
    let limit_warning = "The scan reached its safety limit. Some items may be missing.";
    let agent_limit_warning =
        "The agent session scan reached its safety limit. Some sessions may be missing.";
    let mut agent_budget = 0;
    let mut temp_visited = 0;
    let (deep_seconds, deep_entries) = if deep {
        (DEEP_SCAN_SECONDS, DEEP_SCAN_VISITED)
    } else {
        (MAX_TEMP_SCAN_SECONDS, MAX_TEMP_VISITED)
    };

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
            if started.elapsed() > Duration::from_secs(MAX_AGENT_SCAN_SECONDS)
                || agent_budget >= MAX_AGENT_VISITED
                || items.len() >= MAX_AGENT_ITEMS
            {
                note_scan_warning(&mut warnings, agent_limit_warning);
                break;
            }
            for entry in read_entries(
                &dir,
                started,
                &mut agent_budget,
                &mut warnings,
                agent_limit_warning,
                MAX_AGENT_SCAN_SECONDS,
                MAX_AGENT_VISITED,
            ) {
                if started.elapsed() > Duration::from_secs(MAX_AGENT_SCAN_SECONDS)
                    || agent_budget >= MAX_AGENT_VISITED
                    || items.len() >= MAX_AGENT_ITEMS
                {
                    note_scan_warning(&mut warnings, agent_limit_warning);
                    break;
                }
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
                        &mut agent_budget,
                        &mut items,
                        &mut snapshots,
                        &mut warnings,
                    );
                }
            }
        }
    }

    // Keep this allowlist narrow and bounded. Run it after transcript discovery so
    // repeated scans can surface additional direct-child temp folders.
    if let Some(temp_root) = current_user_temp_root() {
        let temp_started = Instant::now();
        let mut temp_budget = 0;
        let temp_paths =
            temporary_candidates(&temp_root, temp_started, &mut temp_budget, &mut warnings);
        for path in temp_paths {
            if temp_started.elapsed() > Duration::from_secs(deep_seconds)
                || temp_budget >= deep_entries
                || items.len() >= MAX_SCAN_ITEMS
            {
                note_scan_warning(
                    &mut warnings,
                    "Temporary cache scan reached its limit. Some cdk.out or jest_ folders may be missing.",
                );
                break;
            }
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            let (description, source) = if name.starts_with("cdk.out") {
                (
                    "Cloud Development Kit staging output that can be regenerated",
                    "Temporary Cloud Development Kit output",
                )
            } else {
                (
                    "Jest transform cache that can be regenerated",
                    "Temporary Jest output",
                )
            };
            register_candidate(
                "developer",
                Policy::Temporary,
                path,
                description.into(),
                source.into(),
                &active_processes,
                temp_started,
                &mut temp_budget,
                &mut items,
                &mut snapshots,
                &mut warnings,
                deep_seconds,
                deep_entries,
            );
        }
        if temp_started.elapsed() > Duration::from_secs(deep_seconds) || temp_budget >= deep_entries
        {
            note_scan_warning(
                &mut warnings,
                "Temporary cache scan reached its limit. Some cdk.out or jest_ folders may be missing.",
            );
        }
        temp_visited = temp_budget;
    }

    let cache_started = Instant::now();
    let derived_data = home.join("Library/Developer/Xcode/DerivedData");
    if no_symlink_path(&derived_data, home) {
        for entry in read_entries(
            &derived_data,
            cache_started,
            &mut budget,
            &mut warnings,
            limit_warning,
            MAX_SCAN_SECONDS,
            MAX_VISITED,
        ) {
            if cache_started.elapsed() > Duration::from_secs(MAX_SCAN_SECONDS)
                || budget >= MAX_VISITED
                || items.len() >= MAX_SCAN_ITEMS
            {
                note_scan_warning(&mut warnings, limit_warning);
                break;
            }
            let path = entry.path();
            if no_symlink_path(&path, home) {
                push_candidate(
                    "developer",
                    Policy::Developer,
                    path,
                    "Xcode build products that Xcode can recreate".into(),
                    "Xcode DerivedData".into(),
                    &active_processes,
                    cache_started,
                    &mut budget,
                    &mut items,
                    &mut snapshots,
                    &mut warnings,
                );
            }
        }
    }

    for (path, description) in cache_candidates(home, cache_started, &mut budget, &mut warnings) {
        if cache_started.elapsed() > Duration::from_secs(MAX_SCAN_SECONDS)
            || budget >= MAX_VISITED
            || items.len() >= MAX_SCAN_ITEMS
        {
            note_scan_warning(&mut warnings, limit_warning);
            break;
        }
        if no_symlink_path(&path, home) {
            push_candidate(
                "caches",
                Policy::Cache,
                path,
                description,
                "Application caches and logs".into(),
                &active_processes,
                cache_started,
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
            cache_started,
            &mut budget,
            &mut warnings,
            limit_warning,
            MAX_SCAN_SECONDS,
            MAX_VISITED,
        ) {
            if cache_started.elapsed() > Duration::from_secs(MAX_SCAN_SECONDS)
                || budget >= MAX_VISITED
                || items.len() >= MAX_SCAN_ITEMS
            {
                note_scan_warning(&mut warnings, limit_warning);
                break;
            }
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
                    cache_started,
                    &mut budget,
                    &mut items,
                    &mut snapshots,
                    &mut warnings,
                );
            }
        }
    }

    if active_process_reason(Policy::Session, &active_processes, "").is_some() {
        note_scan_warning(
            &mut warnings,
            "AI coding tools are open. Session history may be changing. Review files before clearing them.",
        );
    }
    let found = discovery::discover(home, deep);
    let detector_count = cache_roots(home).len() + 5 + found.detector_count;
    for warning in found.warnings {
        note_scan_warning(&mut warnings, &warning);
    }
    let extra_started = Instant::now();
    let mut extra_budget = 0;
    let mut candidates = found.candidates;
    candidates.sort_by_key(|candidate| {
        if candidate.source.starts_with("Git worktree") {
            2
        } else if candidate.handling == discovery::Handling::Sensitive {
            0
        } else if candidate.source.starts_with("Rust") || candidate.source.starts_with("QA") {
            1
        } else if candidate.handling == discovery::Handling::Developer {
            3
        } else {
            4
        }
    });
    let extra_seconds = if deep {
        DEEP_SCAN_SECONDS
    } else {
        MAX_SCAN_SECONDS
    };
    let extra_entries = if deep { DEEP_SCAN_VISITED } else { MAX_VISITED };
    for candidate in candidates {
        if extra_started.elapsed() > Duration::from_secs(extra_seconds)
            || extra_budget >= extra_entries
            || items.len() >= MAX_SCAN_ITEMS
        {
            note_scan_warning(
                &mut warnings,
                "Additional discovery reached its measurement limit. Results are partial.",
            );
            break;
        }
        if snapshots.values().any(|snapshot| {
            candidate.path == snapshot.path
                || candidate.path.starts_with(&snapshot.path)
                || snapshot.path.starts_with(&candidate.path)
        }) {
            continue;
        }
        let is_worktree = candidate.source.starts_with("Git worktree");
        let policy = if is_worktree {
            Policy::Worktree
        } else {
            match candidate.handling {
                discovery::Handling::Sensitive => Policy::Sensitive,
                discovery::Handling::Cache | discovery::Handling::Developer => Policy::Discovered,
            }
        };
        if policy != Policy::Sensitive && !discovered_path_is_allowlisted(&candidate.path, home) {
            continue;
        }
        let old_len = items.len();
        register_candidate(
            candidate.category,
            policy,
            candidate.path.clone(),
            candidate.description,
            candidate.source,
            &active_processes,
            extra_started,
            &mut extra_budget,
            &mut items,
            &mut snapshots,
            &mut warnings,
            extra_seconds,
            extra_entries,
        );
        if is_worktree && items.len() > old_len {
            let reason = match worktrees::inspect(&candidate.path) {
                Ok(info) => info.reason,
                Err(error) => Some(error),
            };
            if let Some(reason) = reason {
                if let Some(item) = items.last_mut() {
                    item.cleanable = false;
                    item.risk = "protected".into();
                    item.reason = Some(reason);
                    if let Some(snapshot) = snapshots.get_mut(&item.id) {
                        snapshot.cleanable = false;
                    }
                }
            } else if let Some(item) = items.last_mut() {
                item.reason = Some("Git will remove this clean worktree and retain its branch. It will not go to Trash.".into());
            }
        }
    }
    let report = ScanReport {
        coverage: ScanCoverage {
            mode: if deep { "deep" } else { "quick" }.into(),
            detectors: detector_count,
            visited_entries: budget + temp_visited + agent_budget + extra_budget,
            elapsed_ms: started.elapsed().as_millis() as u64,
        },
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
async fn scan_system(state: State<'_, AppState>, deep: Option<bool>) -> Result<ScanReport, String> {
    let state = state.inner().clone();
    let home =
        home_dir().ok_or_else(|| "Could not find the current user's home folder.".to_string())?;
    let (report, entries) = tauri::async_runtime::spawn_blocking(move || {
        if deep.unwrap_or(false) {
            build_scan_mode(&home, true)
        } else {
            build_scan(&home)
        }
    })
    .await
    .map_err(|_| "The storage scan could not finish.".to_string())??;
    let mut registry = lock_registry(&state);
    registry.scan_id = report.id.clone();
    registry.entries = entries;
    registry.items = report
        .items
        .iter()
        .map(|item| (item.id.clone(), item.clone()))
        .collect();
    Ok(report)
}

#[tauri::command(rename_all = "camelCase")]
async fn pick_cleanup_folder(
    state: State<'_, AppState>,
    scan_id: String,
) -> Result<Option<Item>, String> {
    let state = state.inner().clone();
    {
        let registry = lock_registry(&state);
        if registry.scan_id != scan_id {
            return Err("This scan has expired. Scan again before choosing a folder.".into());
        }
    }
    let Some(selected_path) = rfd::FileDialog::new()
        .set_title("Choose a folder to review")
        .pick_folder()
    else {
        return Ok(None);
    };
    let home =
        home_dir().ok_or_else(|| "Could not find the current user's home folder.".to_string())?;
    let path = fs::canonicalize(&selected_path)
        .map_err(|error| format!("Could not resolve the selected folder: {error}"))?;
    if worktrees::contains_repository(&path) {
        return Err("This folder contains a Git repository. Use Deep scan for linked worktrees, or choose a build-cache subfolder.".into());
    }
    if !manual_path_is_allowlisted(&path, &home) {
        return Err("Choose a folder inside your home folder or user temporary folder. Protected folders cannot be selected.".into());
    }
    {
        let registry = lock_registry(&state);
        if registry.scan_id != scan_id {
            return Err("This scan has expired. Scan again before choosing a folder.".into());
        }
        if let Some((id, _)) = registry.entries.iter().find(|(_, snapshot)| {
            fs::canonicalize(&snapshot.path).is_ok_and(|existing| existing == path)
        }) && let Some(item) = registry.items.get(id)
        {
            return Ok(Some(item.clone()));
        }
    }
    let path_for_scan = path.clone();
    let fingerprint = tauri::async_runtime::spawn_blocking(move || {
        let mut budget: usize = 0;
        inspect_tree(
            &path_for_scan,
            Instant::now(),
            &mut budget,
            MAX_SCAN_SECONDS,
            MAX_VISITED,
        )
    })
    .await
    .map_err(|_| "The selected folder could not be inspected.".to_string())??;
    if !manual_path_is_allowlisted(&path, &home) {
        return Err("The selected folder changed during inspection. Choose it again.".into());
    }
    let name = path
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    let mut item = Item {
        id: format!("manual-{}-{}", now_millis(), Utc::now().timestamp_subsec_nanos()),
        category: "developer".into(),
        name,
        path: path.display().to_string(),
        bytes: fingerprint.bytes,
        file_count: fingerprint.file_count,
        modified_at: fingerprint.modified_secs.saturating_mul(1000),
        description: "This folder and all its contents will move to Trash. It may contain personal files. Review it carefully.".into(),
        cleanup_kind: None,
        allocated_bytes: Some(fingerprint.allocated_bytes),
        source: "Added by you".into(),
        risk: "review".into(),
        cleanable: true,
        requires_ack: true,
        reason: Some("This folder may contain personal files. Review all contents before moving it to Trash.".into()),
    };
    let mut registry = lock_registry(&state);
    if registry.scan_id != scan_id {
        return Err("This scan has expired. Scan again before choosing a folder.".into());
    }
    if let Some((id, _)) = registry.entries.iter().find(|(_, snapshot)| {
        fs::canonicalize(&snapshot.path).is_ok_and(|existing| existing == path)
    }) && let Some(existing) = registry.items.get(id)
    {
        return Ok(Some(existing.clone()));
    }
    let base_id = item.id.clone();
    let mut suffix = 1_u64;
    while registry.entries.contains_key(&item.id) {
        item.id = format!("{base_id}-{suffix}");
        suffix = suffix.saturating_add(1);
    }
    let snapshot = Snapshot {
        path,
        policy: Policy::Manual,
        cleanable: true,
        requires_ack: true,
        guard_hint: item.description.clone(),
        fingerprint,
    };
    registry.entries.insert(item.id.clone(), snapshot);
    registry.items.insert(item.id.clone(), item.clone());
    Ok(Some(item))
}

fn discovered_path_is_allowlisted(path: &Path, home: &Path) -> bool {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    if discovery::is_excluded(path, home) || meta.file_type().is_symlink() {
        return false;
    }
    if meta.is_dir() {
        return manual_path_is_allowlisted(path, home);
    }
    meta.is_file()
        && path
            .parent()
            .is_some_and(|parent| manual_path_is_allowlisted(parent, home))
}

fn policy_root_allows(path: &Path, home: &Path, policy: Policy) -> bool {
    match policy {
        Policy::Discovered => discovered_path_is_allowlisted(path, home),
        Policy::Sensitive => false,
        Policy::Worktree => path.starts_with(home) && path.join(".git").is_file(),
        Policy::Cache => cache_roots(home).iter().any(|(root, _)| {
            let Ok(relative) = path.strip_prefix(root) else {
                return false;
            };
            let components = relative.components().count();
            let direct_child = components == 1
                && relative.file_name().is_some_and(|name| name != "_cacache")
                && !(root.file_name().is_some_and(|name| name == "_cacache")
                    && relative == Path::new("content-v2"));
            let cacache_index = components == 2
                && relative
                    .components()
                    .next()
                    .is_some_and(|part| part.as_os_str() == "_cacache")
                && relative
                    .file_name()
                    .is_some_and(|name| name != "content-v2");
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
        Policy::Temporary => {
            current_user_temp_root().is_some_and(|root| temporary_path_is_allowlisted(path, &root))
        }
        Policy::Manual => manual_path_is_allowlisted(path, home),
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
        Policy::ReadOnly => {
            path.parent().is_some_and(|p| p == home.join("Downloads"))
                && fs::symlink_metadata(path)
                    .is_ok_and(|meta| meta.is_file() && !meta.file_type().is_symlink())
        }
    }
}

fn policy_allows(path: &Path, home: &Path, policy: Policy) -> bool {
    if policy == Policy::Temporary {
        return current_user_temp_root().is_some_and(|root| {
            policy_root_allows(path, home, policy) && no_symlink_path(path, &root)
        });
    }
    if policy == Policy::Manual {
        return manual_path_is_allowlisted(path, home);
    }
    policy_root_allows(path, home, policy) && no_symlink_path(path, home)
}

fn is_old_enough(policy: Policy, age_secs: u64) -> bool {
    match policy {
        Policy::Cache => age_secs >= CACHE_MIN_AGE,
        Policy::Session => age_secs >= SESSION_MIN_AGE,
        Policy::Developer => age_secs >= CACHE_MIN_AGE,
        Policy::Temporary => false,
        Policy::Manual => false,
        Policy::ReadOnly | Policy::Discovered | Policy::Sensitive | Policy::Worktree => false,
    }
}

fn is_offline_model_cache(description: &str) -> bool {
    let description = description.to_lowercase();
    description.contains("hugging face") && description.contains("model cache")
}

fn active_process_reason(policy: Policy, active: &[String], hint: &str) -> Option<&'static str> {
    let has = |needles: &[&str]| {
        active
            .iter()
            .any(|name| needles.iter().any(|needle| name.contains(needle)))
    };
    let hint = hint.to_lowercase();
    match policy {
        Policy::Session
            if has(&[
                "claude", "codex", "gemini", "cursor", "windsurf", "opencode",
            ]) =>
        {
            Some(
                "An AI coding tool is open. Session history may be changing. Review before clearing.",
            )
        }
        Policy::Developer if has(&["xcode", "xcodebuild", "simulator"]) => {
            Some("Xcode or Simulator is open. Build files may be in use. Review before clearing.")
        }
        Policy::Cache if hint.contains("xcode") && has(&["xcode", "xcodebuild", "simulator"]) => {
            Some("Xcode or Simulator is open. This cache may be in use. Review before clearing.")
        }
        Policy::Cache if hint.contains("homebrew") && has(&["brew", "homebrew"]) => {
            Some("Homebrew is running. This cache may be in use. Review before clearing.")
        }
        Policy::Cache
            if ["npm", "pnpm", "yarn", "playwright", "cypress"]
                .iter()
                .any(|name| hint.contains(name))
                && has(&["node", "npm", "pnpm", "yarn", "playwright", "cypress"]) =>
        {
            Some(
                "A package manager or browser build is open. This cache may be in use. Review before clearing.",
            )
        }
        Policy::Cache
            if ["python", "pip", "uv"]
                .iter()
                .any(|name| hint.contains(name))
                && has(&["python", "pip", "uv"]) =>
        {
            Some(
                "A Python package process is open. This cache may be in use. Review before clearing.",
            )
        }
        _ => None,
    }
}

fn move_to_os_trash(path: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        use trash::macos::{DeleteMethod, TrashContextExtMacos};
        let mut context = trash::TrashContext::new();
        context.set_delete_method(DeleteMethod::NsFileManager);
        context.delete(path).map_err(|e| e.to_string())
    }
    #[cfg(not(target_os = "macos"))]
    {
        trash::delete(path).map_err(|e| e.to_string())
    }
}

fn cleanup_selected(
    home: &Path,
    item_ids: Vec<String>,
    selected: Vec<(String, Snapshot)>,
    acknowledge_risk: bool,
) -> CleanupResult {
    let mut result = CleanupResult {
        trashed_ids: Vec::new(),
        reclaimed_bytes: 0,
        failures: Vec::new(),
    };
    let mut unique_ids = Vec::new();
    let mut seen = HashSet::new();
    for id in item_ids {
        if seen.insert(id.clone()) {
            unique_ids.push(id);
        }
    }
    if unique_ids.is_empty() || unique_ids.len() > MAX_TRASH_SELECTION {
        result.failures.push(CleanupFailure {
            id: String::new(),
            message: "Choose between 1 and 5,000 items.".into(),
        });
        return result;
    }
    let selected_by_id: HashMap<_, _> = selected.into_iter().collect();
    let mut paths_by_id = HashMap::<PathBuf, String>::new();
    let mut aliases = HashMap::<String, String>::new();
    unique_ids.retain(|id| {
        let Some(snapshot) = selected_by_id.get(id) else {
            return true;
        };
        if let Some(existing_id) = paths_by_id.get(&snapshot.path) {
            aliases.insert(id.clone(), existing_id.clone());
            false
        } else {
            paths_by_id.insert(snapshot.path.clone(), id.clone());
            true
        }
    });
    let selected_paths: Vec<_> = unique_ids
        .iter()
        .filter_map(|id| selected_by_id.get(id).map(|snapshot| &snapshot.path))
        .collect();
    if selected_paths.iter().enumerate().any(|(index, path)| {
        selected_paths
            .iter()
            .skip(index + 1)
            .any(|other| path != other && (path.starts_with(other) || other.starts_with(path)))
    }) {
        result.failures.push(CleanupFailure {
            id: String::new(),
            message: "Select the folder or its contents, not both.".into(),
        });
        return result;
    }
    let active_processes = running_agent_names();
    for id in unique_ids {
        let Some(snapshot) = selected_by_id.get(&id) else {
            result.failures.push(CleanupFailure {
                id,
                message: "This item was not part of the current scan. Scan again.".into(),
            });
            continue;
        };
        if snapshot.policy == Policy::Worktree {
            let removed = if !acknowledge_risk {
                Err("Confirm the Git worktree removal warning first.".into())
            } else if !snapshot.cleanable || !policy_allows(&snapshot.path, home, snapshot.policy) {
                Err("This worktree is protected or no longer available.".into())
            } else {
                worktrees::remove(&snapshot.path)
            };
            match removed {
                Ok(()) => {
                    result.trashed_ids.push(id);
                    result.reclaimed_bytes = result
                        .reclaimed_bytes
                        .saturating_add(snapshot.fingerprint.bytes);
                }
                Err(message) => result.failures.push(CleanupFailure { id, message }),
            }
            continue;
        }
        let active_reason =
            active_process_reason(snapshot.policy, &active_processes, &snapshot.guard_hint);
        let failure = if !snapshot.cleanable {
            Some(
                "This item is protected. Only items marked as cleanable can be moved to Trash."
                    .into(),
            )
        } else if (snapshot.requires_ack || active_reason.is_some()) && !acknowledge_risk {
            Some(
                "Review the selected items and confirm that you want to move them to Trash.".into(),
            )
        } else if !policy_allows(&snapshot.path, home, snapshot.policy) {
            Some("This location is protected and cannot be moved to Trash.".into())
        } else {
            match fingerprint(&snapshot.path) {
                Ok(current) if current == snapshot.fingerprint => None,
                Ok(_) => Some(
                    "This item changed since the scan. Run a new scan before cleaning it.".into(),
                ),
                Err(message) => Some(message),
            }
        };
        if let Some(message) = failure {
            result.failures.push(CleanupFailure { id, message });
            continue;
        }
        // Recheck path safety and active processes after the full snapshot walk, immediately before Trash.
        if !policy_allows(&snapshot.path, home, snapshot.policy) {
            result.failures.push(CleanupFailure {
                id,
                message: "This location changed during cleanup. Scan again.".into(),
            });
            continue;
        }
        if !acknowledge_risk
            && let Some(reason) = active_process_reason(
                snapshot.policy,
                &running_agent_names(),
                &snapshot.guard_hint,
            )
        {
            result.failures.push(CleanupFailure {
                id,
                message: reason.into(),
            });
            continue;
        }
        match move_to_os_trash(&snapshot.path) {
            Ok(()) => {
                result.trashed_ids.push(id);
                result.reclaimed_bytes = result
                    .reclaimed_bytes
                    .saturating_add(snapshot.fingerprint.bytes);
            }
            Err(message) => result.failures.push(CleanupFailure {
                id,
                message: format!("Could not move this item to Trash: {message}"),
            }),
        }
    }
    for (alias_id, owner_id) in aliases {
        if result.trashed_ids.contains(&owner_id) {
            result.trashed_ids.push(alias_id);
        } else if let Some(message) = result
            .failures
            .iter()
            .find(|failure| failure.id == owner_id)
            .map(|failure| failure.message.clone())
        {
            result.failures.push(CleanupFailure {
                id: alias_id,
                message,
            });
        }
    }
    result
}

#[tauri::command(rename_all = "camelCase")]
async fn trash_items(
    state: State<'_, AppState>,
    scan_id: String,
    item_ids: Vec<String>,
    acknowledge_risk: Option<bool>,
) -> Result<CleanupReport, String> {
    let home = home_dir().ok_or("Could not find the current user's home folder.")?;
    let before = volume_info(&home).ok().map(|volume| volume.free_bytes);
    let (scan, selected) = {
        let registry = lock_registry(&state);
        (
            registry.scan_id.clone(),
            item_ids
                .iter()
                .filter_map(|id| {
                    registry
                        .entries
                        .get(id)
                        .cloned()
                        .map(|snapshot| (id.clone(), snapshot))
                })
                .collect::<Vec<_>>(),
        )
    };
    let result = if scan_id != scan {
        CleanupResult {
            trashed_ids: Vec::new(),
            reclaimed_bytes: 0,
            failures: vec![CleanupFailure {
                id: String::new(),
                message: "This scan has expired. Scan again before cleaning.".into(),
            }],
        }
    } else {
        let worker_home = home.clone();
        tauri::async_runtime::spawn_blocking(move || {
            cleanup_selected(
                &worker_home,
                item_ids,
                selected,
                acknowledge_risk.unwrap_or(false),
            )
        })
        .await
        .map_err(|error| format!("The cleanup could not finish: {error}"))?
    };
    let after = volume_info(&home).ok().map(|volume| volume.free_bytes);
    let mut registry = lock_registry(&state);
    let moved_bytes = result.trashed_ids.iter().fold(0_u64, |total, id| {
        total.saturating_add(
            registry
                .entries
                .get(id)
                .filter(|snapshot| snapshot.policy != Policy::Worktree)
                .map_or(0, |snapshot| snapshot.fingerprint.bytes),
        )
    });
    if registry.scan_id == scan_id {
        for id in &result.trashed_ids {
            registry.entries.remove(id);
            registry.items.remove(id);
        }
    }
    Ok(CleanupReport {
        moved_bytes,
        result,
        free_bytes_before: before,
        free_bytes_after: after,
    })
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
    let allowed = if snapshot.policy == Policy::Sensitive {
        fs::symlink_metadata(&snapshot.path).is_ok_and(|meta| {
            !meta.file_type().is_symlink()
                && metadata_identity(&meta)
                    == (snapshot.fingerprint.root_dev, snapshot.fingerprint.root_ino)
        })
    } else {
        policy_allows(&snapshot.path, &home, snapshot.policy)
    };
    if !allowed {
        return Err("This location is outside the scan's safe paths or has changed.".into());
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

#[tauri::command]
async fn get_system_insights() -> Result<insights::SystemInsights, String> {
    let home = home_dir().ok_or("Could not find your home folder.")?;
    tauri::async_runtime::spawn_blocking(move || insights::collect(&home))
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command(rename_all = "camelCase")]
fn open_system_settings(section: String) -> Result<(), String> {
    let target = match section.as_str() {
        "storage" => "x-apple.systempreferences:com.apple.settings.Storage",
        "diskUtility" => "/System/Applications/Utilities/Disk Utility.app",
        "docker" => "/Applications/Docker.app",
        "timeMachine" => "x-apple.systempreferences:com.apple.Time-Machine-Settings.extension",
        "loginItems" => "x-apple.systempreferences:com.apple.LoginItems-Settings.extension",
        "trash" => {
            let home = home_dir().ok_or("Could not find your home folder.")?;
            return std::process::Command::new("/usr/bin/open")
                .arg(home.join(".Trash"))
                .spawn()
                .map(|_| ())
                .map_err(|e| e.to_string());
        }
        _ => return Err("Unknown settings section.".into()),
    };
    std::process::Command::new("/usr/bin/open")
        .arg(target)
        .spawn()
        .map(|_| ())
        .map_err(|error| error.to_string())
}

pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            scan_system,
            get_system_insights,
            open_system_settings,
            pick_cleanup_folder,
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
        let mut budget: usize = 0;
        let fp = inspect_tree(
            &dir,
            Instant::now(),
            &mut budget,
            MAX_SCAN_SECONDS,
            MAX_VISITED,
        )
        .map_err(std::io::Error::other)?;
        assert_eq!(fp.bytes, 5);
        assert_eq!(fp.file_count, 1);
        Ok(())
    }

    #[test]
    fn cleanup_policy_is_allowlisted_and_downloads_are_direct_files_only()
    -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new()?;
        let home_path = tmp.path().join("home");
        fs::create_dir_all(&home_path)?;
        let home = fs::canonicalize(home_path)?;
        let download = home.join("Downloads/movie.mov");
        fs::create_dir_all(download.parent().ok_or("missing Downloads")?)?;
        fs::write(&download, "movie")?;
        assert!(policy_allows(&download, &home, Policy::ReadOnly));
        assert!(!policy_root_allows(
            &home.join("Downloads/folder/movie.mov"),
            &home,
            Policy::ReadOnly
        ));
        #[cfg(unix)]
        {
            let external = tmp.path().join("external.mov");
            fs::write(&external, "outside")?;
            std::os::unix::fs::symlink(&external, home.join("Downloads/link.mov"))?;
            assert!(!policy_allows(
                &home.join("Downloads/link.mov"),
                &home,
                Policy::ReadOnly
            ));
        }
        assert!(!policy_allows(
            &home.join(".claude/settings.json"),
            &home,
            Policy::Session
        ));
        assert!(policy_root_allows(
            &home.join(".claude/projects/project/session.jsonl"),
            &home,
            Policy::Session
        ));
        assert!(!policy_root_allows(
            &home.join(".claude/projects/project/settings.json"),
            &home,
            Policy::Session
        ));
        assert!(policy_root_allows(
            &home.join("Library/Developer/Xcode/DerivedData/project"),
            &home,
            Policy::Developer
        ));
        Ok(())
    }

    #[test]
    fn cache_candidates_are_allowlisted_and_never_include_cacache_parent()
    -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new()?;
        let home = tmp.path().join("home");
        let cache = home.join(".npm/_cacache");
        fs::create_dir_all(cache.join("content-v2/aa"))?;
        fs::write(cache.join("content-v2/aa/chunk"), "cached")?;
        fs::create_dir_all(cache.join("index-v5"))?;
        fs::write(cache.join("index-v5/index"), "index")?;
        let mut budget: usize = 0;
        let mut warnings = Vec::new();
        let found = cache_candidates(&home, Instant::now(), &mut budget, &mut warnings);
        assert!(!found.is_empty());
        for (path, _) in found {
            assert_ne!(path, cache.join("content-v2"));
            assert!(
                policy_root_allows(&path, &home, Policy::Cache),
                "cache candidate escaped the cleanup allowlist"
            );
        }
        Ok(())
    }

    #[test]
    fn additional_cache_roots_are_specific_and_model_cache_requires_review() {
        let home = Path::new("/Users/tester");
        let roots = cache_roots(home);
        for (relative, description) in [
            (".cache/uv", "uv package cache"),
            (".cache/puppeteer", "Puppeteer browser download cache"),
            (".cache/pre-commit", "pre-commit hook cache"),
            (
                ".cache/huggingface/hub",
                "Hugging Face downloaded model cache. Removing it may make models unavailable offline.",
            ),
            (
                "Library/Application Support/Spotify/PersistentCache",
                "Spotify persistent cache",
            ),
            (
                "Library/Application Support/stremio-server/stremio-cache",
                "Stremio server cache",
            ),
            (
                "Library/iTunes/iPhone Software Updates",
                "iPhone software update files",
            ),
            (
                "Library/Caches/ms-playwright",
                "Playwright browser download cache",
            ),
            ("Library/Caches/CocoaPods", "CocoaPods package cache"),
            ("Library/Caches/com.spotify.client", "Spotify app cache"),
            (
                "Library/Caches/com.microsoft.VSCode.ShipIt",
                "VS Code update cache",
            ),
        ] {
            assert!(roots.contains(&(home.join(relative), description.into())));
        }
        assert!(
            !roots
                .iter()
                .any(|(path, _)| { path == &home.join(".cache/huggingface/lerobot") })
        );
        let model_hub = home.join(".cache/huggingface/hub");
        assert!(policy_root_allows(
            &model_hub.join("models--example"),
            home,
            Policy::Cache
        ));
        assert!(is_offline_model_cache(
            "Hugging Face downloaded model cache. Removing it may make models unavailable offline."
        ));
    }

    #[test]
    fn temporary_candidates_are_direct_named_directories_and_require_review()
    -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new()?;
        let root = fs::canonicalize(tmp.path())?;
        let cdk = root.join("cdk.out-example");
        let jest = root.join("jest_transform_example");
        let generic = root.join("DockerDesktopUpdates");
        let nested_parent = root.join("nested");
        fs::create_dir(&cdk)?;
        fs::write(cdk.join("artifact"), "generated")?;
        fs::create_dir(&jest)?;
        fs::create_dir(&generic)?;
        fs::create_dir(&nested_parent)?;
        fs::create_dir(nested_parent.join("cdk.out-nested"))?;

        assert!(temporary_path_is_allowlisted(&cdk, &root));
        assert!(temporary_path_is_allowlisted(&jest, &root));
        assert!(!temporary_path_is_allowlisted(&generic, &root));
        assert!(!temporary_path_is_allowlisted(
            &nested_parent.join("cdk.out-nested"),
            &root
        ));
        assert!(current_user_temp_root().is_some_and(|temp_root| {
            fs::canonicalize(std::env::temp_dir()).is_ok_and(|expected| temp_root == expected)
        }));

        let mut budget: usize = 0;
        let mut items = Vec::new();
        let mut snapshots = HashMap::new();
        let mut warnings = Vec::new();
        push_candidate(
            "developer",
            Policy::Temporary,
            cdk,
            "Cloud Development Kit staging output that can be regenerated".into(),
            "Temporary Cloud Development Kit output".into(),
            &[],
            Instant::now(),
            &mut budget,
            &mut items,
            &mut snapshots,
            &mut warnings,
        );
        assert_eq!(items.len(), 1);
        assert!(items[0].cleanable);
        assert!(items[0].requires_ack);
        assert_eq!(items[0].risk, "review");
        assert!(
            items[0]
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("Review"))
        );
        Ok(())
    }

    #[test]
    fn manual_folder_policy_allows_home_descendants_and_rejects_protected_roots()
    -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new()?;
        let home_path = tmp.path().join("home");
        fs::create_dir_all(&home_path)?;
        let home = fs::canonicalize(home_path)?;
        let safe = home.join("Developer/project/build");
        let library = home.join("Library");
        let ssh = home.join(".ssh");
        let gnupg = home.join(".gnupg");
        let aws = home.join(".aws");
        let keychains = library.join("Keychains");
        let accounts = library.join("Accounts");
        let codex = home.join(".codex");
        let auth = codex.join("auth");
        let sessions = codex.join("sessions");
        let claude_credentials = home.join(".claude/credentials");
        let outside = tmp.path().join("outside");
        fs::create_dir_all(&safe)?;
        fs::create_dir_all(&keychains)?;
        fs::create_dir_all(&accounts)?;
        fs::create_dir_all(&ssh)?;
        fs::create_dir_all(&auth)?;
        fs::create_dir_all(&sessions)?;
        fs::create_dir_all(&gnupg)?;
        fs::create_dir_all(&aws)?;
        fs::create_dir_all(&claude_credentials)?;
        fs::create_dir_all(&outside)?;
        let outside = fs::canonicalize(outside)?;
        assert!(manual_path_is_allowlisted(&safe, &home));
        assert!(policy_root_allows(&safe, &home, Policy::Manual));
        assert!(!manual_path_is_allowlisted(&home, &home));
        assert!(!manual_path_is_allowlisted(&library, &home));
        assert!(!manual_path_is_allowlisted(&ssh, &home));
        assert!(!manual_path_is_allowlisted(&gnupg, &home));
        assert!(!manual_path_is_allowlisted(&aws, &home));
        assert!(!manual_path_is_allowlisted(&keychains, &home));
        assert!(!manual_path_is_allowlisted(&accounts, &home));
        assert!(!manual_path_is_allowlisted(&auth, &home));
        assert!(!manual_path_is_allowlisted(&codex, &home));
        assert!(!manual_path_is_allowlisted(&claude_credentials, &home));
        assert!(manual_path_is_allowlisted(&sessions, &home));
        // The sibling fixture is still inside the current user's allowed temp folder.
        assert!(manual_path_is_allowlisted(&outside, &home));
        assert!(!manual_path_is_allowlisted(Path::new("/System"), &home));
        assert!(!manual_path_is_allowlisted(Path::new("/"), &home));
        assert!(
            TempDir::new_in(std::env::temp_dir())
                .ok()
                .is_some_and(|temp_folder| fs::canonicalize(temp_folder.path())
                    .is_ok_and(|path| manual_path_is_allowlisted(&path, &home)))
        );
        Ok(())
    }

    #[test]
    fn cleanup_rejects_overlapping_folder_and_child_before_moving_anything()
    -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new()?;
        let home_path = tmp.path().join("home");
        fs::create_dir_all(&home_path)?;
        let home = fs::canonicalize(home_path)?;
        let parent = home.join("selected");
        let child = parent.join("child");
        fs::create_dir_all(&child)?;
        fs::write(parent.join("keep"), "parent data")?;
        fs::write(child.join("keep"), "child data")?;
        let snapshot = |path: &Path| -> Result<Snapshot, Box<dyn std::error::Error>> {
            Ok(Snapshot {
                path: path.to_path_buf(),
                policy: Policy::Manual,
                cleanable: true,
                requires_ack: true,
                guard_hint: "Manually selected folder".into(),
                fingerprint: fingerprint(path).map_err(std::io::Error::other)?,
            })
        };
        let result = cleanup_selected(
            &home,
            vec!["parent".into(), "child".into()],
            vec![
                ("parent".into(), snapshot(&parent)?),
                ("child".into(), snapshot(&child)?),
            ],
            true,
        );
        assert!(result.trashed_ids.is_empty());
        assert_eq!(result.failures.len(), 1);
        assert!(
            result.failures[0]
                .message
                .contains("folder or its contents")
        );
        assert!(parent.join("keep").exists());
        assert!(child.join("keep").exists());

        let stale_fingerprint = fingerprint(&parent).map_err(std::io::Error::other)?;
        fs::write(parent.join("changed"), "changed after the scan")?;
        let duplicate_result = cleanup_selected(
            &home,
            vec!["manual-first".into(), "manual-duplicate".into()],
            vec![
                (
                    "manual-first".into(),
                    Snapshot {
                        path: parent.clone(),
                        policy: Policy::Manual,
                        cleanable: true,
                        requires_ack: true,
                        guard_hint: "Manually selected folder".into(),
                        fingerprint: stale_fingerprint,
                    },
                ),
                (
                    "manual-duplicate".into(),
                    Snapshot {
                        path: parent.clone(),
                        policy: Policy::Manual,
                        cleanable: true,
                        requires_ack: true,
                        guard_hint: "Manually selected folder".into(),
                        fingerprint: stale_fingerprint,
                    },
                ),
            ],
            true,
        );
        assert!(duplicate_result.trashed_ids.is_empty());
        assert_eq!(duplicate_result.failures.len(), 2);
        assert!(parent.join("keep").exists());
        Ok(())
    }

    #[test]
    fn cleanup_requires_acknowledgement_and_preserves_changed_file()
    -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new()?;
        let home = tmp.path().join("home");
        let downloads = home.join("Downloads/large.mov");
        fs::create_dir_all(downloads.parent().ok_or("missing parent")?)?;
        fs::write(&downloads, "keep")?;
        let scanned_fingerprint = fingerprint(&downloads).map_err(std::io::Error::other)?;
        let snapshot = Snapshot {
            path: downloads.clone(),
            policy: Policy::ReadOnly,
            cleanable: true,
            requires_ack: true,
            guard_hint: "Large download taking up space".into(),
            fingerprint: scanned_fingerprint,
        };
        let unacknowledged = cleanup_selected(
            &home,
            vec!["read-only".into()],
            vec![("read-only".into(), snapshot)],
            false,
        );
        assert_eq!(unacknowledged.trashed_ids.len(), 0);
        assert_eq!(unacknowledged.failures.len(), 1);
        assert!(unacknowledged.failures[0].message.contains("Review"));
        assert!(downloads.exists());
        fs::write(&downloads, "changed since scan")?;
        let acknowledged = cleanup_selected(
            &home,
            vec!["read-only".into()],
            vec![(
                "read-only".into(),
                Snapshot {
                    path: downloads.clone(),
                    policy: Policy::ReadOnly,
                    cleanable: true,
                    requires_ack: true,
                    guard_hint: "Large download taking up space".into(),
                    fingerprint: scanned_fingerprint,
                },
            )],
            true,
        );
        assert_eq!(acknowledged.trashed_ids.len(), 0);
        assert_eq!(acknowledged.failures.len(), 1);
        assert!(
            acknowledged.failures[0]
                .message
                .contains("changed since the scan")
        );
        assert!(downloads.exists());
        let unknown = cleanup_selected(&home, vec!["unknown".into()], Vec::new(), false);
        assert_eq!(unknown.trashed_ids.len(), 0);
        assert_eq!(unknown.failures.len(), 1);
        assert!(downloads.exists());
        Ok(())
    }

    #[test]
    fn recent_sessions_remain_selectable_but_require_review()
    -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new()?;
        let home = tmp.path().join("home");
        let session = home.join(".codex/sessions/recent.jsonl");
        fs::create_dir_all(session.parent().ok_or("missing session parent")?)?;
        fs::write(&session, "session data")?;
        let mut budget: usize = 0;
        let mut items = Vec::new();
        let mut snapshots = HashMap::new();
        let mut warnings = Vec::new();
        push_candidate(
            "agents",
            Policy::Session,
            session,
            "Conversation transcript. It may contain prompts and paths.".into(),
            "Codex transcript".into(),
            &["claude".into()],
            Instant::now(),
            &mut budget,
            &mut items,
            &mut snapshots,
            &mut warnings,
        );
        assert_eq!(items.len(), 1);
        assert!(items[0].cleanable);
        assert!(items[0].requires_ack);
        assert_eq!(items[0].risk, "review");
        assert!(
            items[0]
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("open"))
        );
        assert!(snapshots[&items[0].id].cleanable);
        assert!(snapshots[&items[0].id].requires_ack);
        Ok(())
    }

    #[test]
    fn process_guards_are_scoped_to_the_matching_cleanup_category() {
        assert!(active_process_reason(Policy::Session, &["node".into()], "").is_none());
        assert!(
            active_process_reason(Policy::Cache, &["node".into()], "npm package cache").is_some()
        );
        assert!(
            active_process_reason(Policy::Cache, &["node".into()], "Homebrew download cache")
                .is_none()
        );
        assert!(
            active_process_reason(Policy::Cache, &["brew".into()], "Homebrew download cache")
                .is_some()
        );
        assert!(active_process_reason(Policy::Developer, &["xcode".into()], "").is_some());
        assert!(active_process_reason(Policy::Session, &["claude".into()], "").is_some());
    }

    #[test]
    fn allowlist_rejects_symlinked_agent_roots() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new()?;
        let home = tmp.path().join("home");
        let external = tmp.path().join("external");
        fs::create_dir_all(external.join("projects/project"))?;
        fs::write(external.join("projects/project/session.jsonl"), "history")?;
        fs::create_dir_all(&home)?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(&external, home.join(".claude"))?;
        assert!(!policy_allows(
            &home.join(".claude/projects/project/session.jsonl"),
            &home,
            Policy::Session
        ));
        Ok(())
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
        fs::write(&path, "a longer transcript")?;
        let same_size = fingerprint(&path).map_err(std::io::Error::other)?;
        assert_eq!(after.bytes, same_size.bytes);
        assert_ne!(after.digest, same_size.digest);
        Ok(())
    }

    #[test]
    fn hard_linked_build_files_are_counted_once() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDir::new()?;
        let original = tmp.path().join("artifact");
        fs::write(&original, "build")?;
        fs::hard_link(&original, tmp.path().join("linked-artifact"))?;
        let measured = fingerprint(tmp.path()).map_err(std::io::Error::other)?;
        assert_eq!(measured.bytes, 5);
        assert_eq!(measured.file_count, 2);
        assert_eq!(
            measured.allocated_bytes,
            allocated_size(&fs::metadata(original)?)
        );
        Ok(())
    }

    #[test]
    #[ignore = "reads one explicitly chosen folder for storage accounting verification"]
    fn native_folder_accounting() -> Result<(), Box<dyn std::error::Error>> {
        let path = PathBuf::from(
            std::env::var_os("CLEAN_MY_MAC_MEASURE_PATH").ok_or("Set CLEAN_MY_MAC_MEASURE_PATH")?,
        );
        let measured = fingerprint(&path).map_err(std::io::Error::other)?;
        println!(
            "Folder accounting: logical={}, allocated={}, files={}",
            measured.bytes, measured.allocated_bytes, measured.file_count
        );
        Ok(())
    }

    #[test]
    #[ignore = "reads the current user's home; run explicitly for native smoke"]
    fn native_home_scan_smoke_reports_counts_without_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        let Some(home) = home_dir() else {
            return Ok(());
        };
        let (report, _snapshots) = build_scan(&home).map_err(std::io::Error::other)?;
        assert!(report.volume.total_bytes > 0);
        let mut counts = HashMap::<String, usize>::new();
        for item in &report.items {
            *counts.entry(item.category.clone()).or_default() += 1;
        }
        assert!(
            counts.len() > 1,
            "the scan should reserve capacity for multiple categories"
        );
        println!(
            "Read-only storage scan smoke: agents={}, caches={}, developer={}, large={}, warnings={}",
            counts.get("agents").copied().unwrap_or(0),
            counts.get("caches").copied().unwrap_or(0),
            counts.get("developer").copied().unwrap_or(0),
            counts.get("large").copied().unwrap_or(0),
            report.warnings.len()
        );
        Ok(())
    }

    #[test]
    #[ignore = "reads current home metadata; run explicitly for deep scan verification"]
    fn native_deep_scan_report() -> Result<(), Box<dyn std::error::Error>> {
        let home = home_dir().ok_or("Home folder is unavailable")?;
        let (report, _) = build_scan_mode(&home, true).map_err(std::io::Error::other)?;
        assert!(report.volume.total_bytes > 0);
        assert_eq!(report.coverage.mode, "deep");
        assert!(report.items.iter().any(|item| item.category != "agents"));
        if let Some(output) = std::env::var_os("CLEAN_MY_MAC_SCAN_REPORT") {
            fs::write(output, serde_json::to_vec_pretty(&report)?)?;
        }
        let system = insights::collect(&home);
        if let Some(output) = std::env::var_os("CLEAN_MY_MAC_INSIGHTS_REPORT") {
            fs::write(output, serde_json::to_vec_pretty(&system)?)?;
        }
        println!(
            "Deep scan: {} findings, {} warnings, {} visited entries, {} ms; {} snapshots, {} launch agents",
            report.items.len(),
            report.warnings.len(),
            report.coverage.visited_entries,
            report.coverage.elapsed_ms,
            system.snapshots.len(),
            system.launch_agents.len()
        );
        Ok(())
    }
}
