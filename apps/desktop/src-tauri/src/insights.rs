//! Read-only inspection of macOS storage and background activity.
//!
//! This module never changes snapshots, processes, launch services, or files.

use serde::Serialize;
use serde_json::Value;
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_CAPTURE: usize = 512 * 1024;
const MAX_LAUNCH_AGENTS: usize = 100;
const MAX_INSPECTION_TIME: Duration = Duration::from_secs(8);

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SystemInsights {
    pub(crate) snapshots: Vec<SnapshotInfo>,
    pub(crate) processes: Vec<ProcessInfo>,
    pub(crate) launch_agents: Vec<LaunchAgentInfo>,
    pub(crate) deleted_open_files: Vec<OpenFileInfo>,
    pub(crate) warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SnapshotInfo {
    pub(crate) name: String,
    pub(crate) volume: String,
    pub(crate) purgeable: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProcessInfo {
    pub(crate) pid: u32,
    pub(crate) name: String,
    pub(crate) memory_bytes: u64,
    pub(crate) cpu_percent: f32,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LaunchAgentInfo {
    pub(crate) path: String,
    pub(crate) label: String,
    pub(crate) program: Option<String>,
    pub(crate) program_exists: Option<bool>,
    pub(crate) system: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenFileInfo {
    pub(crate) pid: u32,
    pub(crate) process: String,
    pub(crate) path: String,
    pub(crate) bytes: u64,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StorageCapacity {
    pub(crate) free_bytes: u64,
    pub(crate) available_for_important_usage_bytes: u64,
    pub(crate) purgeable_bytes: u64,
}

struct CommandOutput {
    status_success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    timed_out: bool,
}

/// Runs only fixed, read-only tools. Output is drained on reader threads so a
/// full pipe cannot stall the timeout loop. Each retained stream is bounded.
fn run_command(program: &str, args: &[&str], timeout: Duration) -> Option<CommandOutput> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    let stderr = child.stderr.take()?;
    let out_reader = thread::spawn(move || read_bounded(stdout, MAX_CAPTURE));
    let err_reader = thread::spawn(move || read_bounded(stderr, 16 * 1024));
    let start = Instant::now();
    let (status, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (Some(status), false),
            Ok(None) if start.elapsed() < timeout => thread::sleep(Duration::from_millis(25)),
            Ok(None) => {
                let _ = child.kill();
                break (child.wait().ok(), true);
            }
            Err(_) => {
                let _ = child.kill();
                break (child.wait().ok(), false);
            }
        }
    };
    let stdout = out_reader.join().ok().unwrap_or_default();
    let stderr = err_reader.join().ok().unwrap_or_default();
    Some(CommandOutput {
        status_success: status.is_some_and(|s| s.success()),
        stdout,
        stderr,
        timed_out,
    })
}

fn read_bounded(mut reader: impl Read, limit: usize) -> Vec<u8> {
    let mut retained = Vec::with_capacity(limit.min(8192));
    let mut buffer = [0u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(count) => {
                let remaining = limit.saturating_sub(retained.len());
                retained.extend_from_slice(&buffer[..count.min(remaining)]);
            }
        }
    }
    retained
}

pub(crate) fn collect(home: &Path) -> SystemInsights {
    let started = Instant::now();
    let mut result = SystemInsights::default();
    collect_snapshots(&mut result);
    result.processes = top_processes();
    if started.elapsed() < MAX_INSPECTION_TIME {
        collect_launch_agents(home, started, &mut result);
    } else {
        result.warnings.push("Launch agent inspection was skipped to keep the scan responsive.".into());
    }
    if started.elapsed() < MAX_INSPECTION_TIME {
        collect_deleted_open_files(&mut result);
    }
    result
}

fn collect_snapshots(result: &mut SystemInsights) {
    // tmutil names the Data volume snapshots; diskutil provides APFS snapshot
    // metadata, including whether macOS considers a snapshot purgeable.
    if let Some(output) = run_command("/usr/bin/tmutil", &["listlocalsnapshots", "/"], COMMAND_TIMEOUT) {
        if output.timed_out {
            result.warnings.push("Time Machine snapshot listing timed out.".into());
        } else if output.status_success {
            result.snapshots.extend(parse_tmutil_snapshots(&String::from_utf8_lossy(&output.stdout)));
        } else {
            result.warnings.push("Time Machine snapshots could not be listed. macOS may have denied access.".into());
        }
    } else {
        result.warnings.push("Time Machine snapshot listing is unavailable.".into());
    }

    if let Some(output) = run_command("/usr/sbin/diskutil", &["apfs", "listSnapshots", "/System/Volumes/Data"], COMMAND_TIMEOUT) {
        if output.timed_out {
            result.warnings.push("APFS snapshot metadata listing timed out.".into());
        } else if output.status_success {
            let metadata = parse_diskutil_snapshots(&String::from_utf8_lossy(&output.stdout));
            for snapshot in &mut result.snapshots {
                if let Some((volume, purgeable)) = metadata.get(&snapshot.name) {
                    snapshot.volume = volume.clone();
                    snapshot.purgeable = *purgeable;
                }
            }
            for (name, (volume, purgeable)) in metadata {
                if !result.snapshots.iter().any(|s| s.name == name) {
                    result.snapshots.push(SnapshotInfo { name, volume, purgeable });
                }
            }
        } else {
            result.warnings.push("APFS snapshot metadata is unavailable. Purgeability is unknown.".into());
        }
    }
}

fn parse_tmutil_snapshots(text: &str) -> Vec<SnapshotInfo> {
    text.lines()
        .filter_map(|line| {
            let name = line.trim().strip_prefix("com.apple.TimeMachine.")?;
            if name.is_empty() || name.chars().any(char::is_control) { return None; }
            Some(SnapshotInfo {
                name: format!("com.apple.TimeMachine.{name}"),
                volume: "/".into(),
                purgeable: None,
            })
        })
        .take(256)
        .collect()
}

fn parse_diskutil_snapshots(text: &str) -> std::collections::HashMap<String, (String, Option<bool>)> {
    let mut parsed = std::collections::HashMap::new();
    let mut name: Option<String> = None;
    let mut purgeable = None;
    for line in text.lines().chain(std::iter::once("")) {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("Name:") {
            if let Some(previous) = name.replace(value.trim().to_string()) {
                parsed.insert(previous, ("/System/Volumes/Data".into(), purgeable));
            }
            purgeable = None;
        } else if let Some(value) = trimmed.strip_prefix("Purgeable:") {
            purgeable = match value.trim() { "Yes" => Some(true), "No" => Some(false), _ => None };
        } else if trimmed.is_empty() {
            if let Some(previous) = name.take() {
                parsed.insert(previous, ("/System/Volumes/Data".into(), purgeable));
                purgeable = None;
            }
        }
    }
    parsed
}

fn top_processes() -> Vec<ProcessInfo> {
    use sysinfo::{ProcessesToUpdate, System};
    let mut system = System::new();
    system.refresh_processes(ProcessesToUpdate::All, true);
    let mut processes: Vec<_> = system.processes().iter().map(|(pid, process)| ProcessInfo {
        pid: pid.as_u32(),
        name: process.name().to_string_lossy().chars().take(160).collect(),
        memory_bytes: process.memory(),
        cpu_percent: process.cpu_usage(),
    }).collect();
    processes.sort_by(|a, b| b.memory_bytes.cmp(&a.memory_bytes));
    processes.truncate(20);
    processes
}

fn collect_launch_agents(home: &Path, started: Instant, result: &mut SystemInsights) {
    let roots = [
        (home.join("Library/LaunchAgents"), false),
        (PathBuf::from("/Library/LaunchAgents"), true),
        (PathBuf::from("/Library/LaunchDaemons"), true),
    ];
    let mut count = 0;
    for (root, system) in roots {
        let entries = match fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                result.warnings.push(format!("Could not inspect launch agent folder {}.", root.display()));
                continue;
            }
        };
        for entry in entries.flatten() {
            if count >= MAX_LAUNCH_AGENTS || started.elapsed() >= MAX_INSPECTION_TIME { break; }
            let path = entry.path();
            if path.extension().is_none_or(|ext| ext != "plist")
                || fs::symlink_metadata(&path).is_err_and(|_| true)
                || !fs::symlink_metadata(&path).is_ok_and(|m| m.is_file() && !m.file_type().is_symlink())
            { continue; }
            count += 1;
            match parse_launch_agent(&path, system) {
                Some(agent) => result.launch_agents.push(agent),
                None => result.warnings.push(format!("Could not read launch agent metadata from {}.", path.display())),
            }
        }
        if count >= MAX_LAUNCH_AGENTS || started.elapsed() >= MAX_INSPECTION_TIME { break; }
    }
    if count >= MAX_LAUNCH_AGENTS {
        result.warnings.push("Launch agent results are limited to the first 100 plist files.".into());
    }
}

fn parse_launch_agent(path: &Path, system: bool) -> Option<LaunchAgentInfo> {
    let path_string = path.to_str()?;
    let output = run_command("/usr/bin/plutil", &["-convert", "json", "-o", "-", path_string], COMMAND_TIMEOUT)?;
    if !output.status_success || output.timed_out { return None; }
    let value: Value = serde_json::from_slice(&output.stdout).ok()?;
    let label = value.get("Label").and_then(Value::as_str)
        .filter(|s| !s.is_empty()).map(str::to_owned)
        .or_else(|| path.file_stem().map(|s| s.to_string_lossy().into_owned()))?;
    let program = value.get("Program").and_then(Value::as_str)
        .or_else(|| value.get("ProgramArguments").and_then(Value::as_array).and_then(|a| a.first()).and_then(Value::as_str))
        .map(str::to_owned);
    // Only absolute paths can be checked without resolving launchd's context,
    // PATH, or substitutions. Keep uncertainty explicit for all other values.
    let program_exists = program.as_deref().and_then(|p| {
        let candidate = Path::new(p);
        if candidate.is_absolute() { Some(candidate.exists()) } else { None }
    });
    Some(LaunchAgentInfo { path: path_string.to_owned(), label, program, program_exists, system })
}

fn collect_deleted_open_files(result: &mut SystemInsights) {
    let Some(output) = run_command("/usr/sbin/lsof", &["-nP", "+L1", "-Fpcnks"], COMMAND_TIMEOUT) else {
        result.warnings.push("Deleted open files could not be inspected. lsof may be unavailable.".into());
        return;
    };
    if output.timed_out {
        result.warnings.push("Deleted open file inspection timed out.".into());
        return;
    }
    if !output.status_success && output.stdout.is_empty() {
        result.warnings.push("Some deleted open files may be hidden because macOS denied process inspection.".into());
    }
    result.deleted_open_files = parse_lsof(&String::from_utf8_lossy(&output.stdout));
}

fn parse_lsof(text: &str) -> Vec<OpenFileInfo> {
    let (mut pid, mut process, mut path, mut bytes) = (None, String::new(), String::new(), 0u64);
    let mut files = Vec::new();
    let flush = |pid: Option<u32>, process: &str, path: &str, bytes: u64, files: &mut Vec<OpenFileInfo>| {
        if let Some(pid) = pid.filter(|_| !path.is_empty()) {
            files.push(OpenFileInfo { pid, process: process.to_owned(), path: path.to_owned(), bytes });
        }
    };
    for line in text.lines().chain(std::iter::once("f")) {
        let Some((field, value)) = line.split_at_checked(1) else { continue };
        if field == "f" {
            flush(pid, &process, &path, bytes, &mut files);
            path.clear(); bytes = 0;
        } else if let Some(value) = value.strip_prefix('p') {
            pid = value.parse().ok();
        } else if let Some(value) = value.strip_prefix('c') {
            process = value.chars().take(160).collect();
        } else if let Some(value) = value.strip_prefix('n') {
            if value.contains(" (deleted)") || value.contains(" (deleted)") || value.ends_with(" (deleted)") {
                path = value.chars().take(2048).collect();
            }
        } else if let Some(value) = value.strip_prefix('s') {
            bytes = value.parse().unwrap_or(0);
        }
    }
    files.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    files.truncate(100);
    files
}

/// Uses Foundation's NSURL volume resource values on macOS. The important-
/// usage capacity includes space macOS may purge automatically; it is not a
/// promise that all of that space can be reclaimed by this app.
#[cfg(target_os = "macos")]
pub(crate) fn storage_capacity(_home: &Path) -> Option<StorageCapacity> {
    use objc2_foundation::{NSDictionary, NSNumber, NSString, NSURL};

    let url = NSURL::fileURLWithPath(&NSString::from_str("/"));
    let keys = [
        NSString::from_str("NSURLVolumeAvailableCapacityKey"),
        NSString::from_str("NSURLVolumeAvailableCapacityForImportantUsageKey"),
        NSString::from_str("NSURLVolumeTotalCapacityKey"),
    ];
    let keys = objc2_foundation::NSArray::from_retained_slice(&keys.map(|key| key));
    // SAFETY: All resource keys are NSString instances and the Foundation API
    // returns an autoreleased dictionary retained by the generated wrapper.
    let values = unsafe { url.resourceValuesForKeys_error(&keys) }.ok()?;
    let number = |key: &str| -> Option<u64> {
        let key = NSString::from_str(key);
        let value = values.objectForKey(&key)?;
        let number = value.downcast::<NSNumber>().ok()?;
        let amount = unsafe { number.as_i64() };
        u64::try_from(amount).ok()
    };
    let free_bytes = number("NSURLVolumeAvailableCapacityKey")?;
    let important = number("NSURLVolumeAvailableCapacityForImportantUsageKey")?;
    let total = number("NSURLVolumeTotalCapacityKey")?;
    Some(StorageCapacity {
        free_bytes,
        available_for_important_usage_bytes: important,
        purgeable_bytes: important.saturating_sub(free_bytes).min(total),
    })
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn storage_capacity(_home: &Path) -> Option<StorageCapacity> { None }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_time_machine_snapshot_names() {
        let snapshots = parse_tmutil_snapshots("Snapshots for disk /:\ncom.apple.TimeMachine.2026-10-29-035400.local\ninvalid\n");
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].name, "com.apple.TimeMachine.2026-10-29-035400.local");
        assert_eq!(snapshots[0].purgeable, None);
    }

    #[test]
    fn parses_diskutil_purgeability() {
        let parsed = parse_diskutil_snapshots("Snapshot UUID: abc\nName: com.apple.TimeMachine.2026-10-29-035400.local\nPurgeable: Yes\n\nName: com.apple.os.update-x\nPurgeable: No\n");
        assert_eq!(parsed.get("com.apple.TimeMachine.2026-10-29-035400.local").unwrap().1, Some(true));
        assert_eq!(parsed.get("com.apple.os.update-x").unwrap().1, Some(false));
    }

    #[test]
    fn parses_deleted_lsof_records_only() {
        let files = parse_lsof("p10\ncworker\nf3\nk0\ns100\nn/tmp/a (deleted)\nf4\nk0\ns900\nn/tmp/live\n");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].pid, 10);
        assert_eq!(files[0].bytes, 100);
        assert_eq!(files[0].path, "/tmp/a (deleted)");
    }

    #[test]
    fn launch_agent_parse_does_not_claim_relative_program_existence() {
        let dir = tempfile::tempdir().unwrap();
        let plist = dir.path().join("sample.plist");
        let mut file = fs::File::create(&plist).unwrap();
        file.write_all(br#"<?xml version="1.0"?><plist version="1.0"><dict><key>Label</key><string>sample.agent</string><key>ProgramArguments</key><array><string>node</string><string>secret-argument</string></array></dict></plist>"#).unwrap();
        let Some(agent) = parse_launch_agent(&plist, false) else { return; };
        assert_eq!(agent.program.as_deref(), Some("node"));
        assert_eq!(agent.program_exists, None);
        assert!(!serde_json::to_string(&agent).unwrap().contains("secret-argument"));
    }
}
