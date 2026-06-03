use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const DEFAULT_MAX_SCAN_FILES: usize = 50_000;
const DEFAULT_MAX_TEXT_FILE_BYTES: u64 = 1_048_576;
const DEFAULT_TEXT_FINDING_LIMIT: usize = 8;
const GIT_TIMEOUT_MS: u64 = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanReport {
    pub root: String,
    pub passed: bool,
    pub scanned_files: usize,
    pub skipped_files: usize,
    pub duration_ms: u128,
    pub blocker_findings: usize,
    pub warning_findings: usize,
    pub detector_counts: BTreeMap<String, usize>,
    pub checks: Vec<ScanCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub path: String,
    pub line: Option<usize>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    Blocker,
    Warning,
}

#[derive(Debug, Default, Deserialize)]
struct CloseEnvConfig {
    closeenv: Option<CloseEnvPolicy>,
    allow_value_env_paths: Option<Vec<String>>,
    ignore_paths: Option<Vec<String>>,
    ignore_detectors: Option<Vec<String>>,
    max_files: Option<usize>,
    max_file_bytes: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
struct CloseEnvPolicy {
    allow_value_env_paths: Option<Vec<String>>,
    ignore_paths: Option<Vec<String>>,
    ignore_detectors: Option<Vec<String>>,
    max_files: Option<usize>,
    max_file_bytes: Option<u64>,
}

#[derive(Debug, Default)]
struct ScanPolicy {
    allow_value_env_paths: Vec<String>,
    ignore_paths: Vec<String>,
    ignore_detectors: BTreeSet<String>,
    max_files: usize,
    max_file_bytes: u64,
}

#[derive(Debug)]
struct ScanInput {
    root: PathBuf,
    files: Vec<String>,
    tracked_files: BTreeSet<String>,
    skipped_files: usize,
    policy: ScanPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PatternDetection {
    name: &'static str,
    line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanOptions {
    pub mode: ScanMode,
    pub include_ignored: bool,
    pub max_files: Option<usize>,
    pub max_file_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    WorkingTree,
    Staged,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            mode: ScanMode::WorkingTree,
            include_ignored: false,
            max_files: None,
            max_file_bytes: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Text,
    Json,
    Sarif,
}

pub fn run_cli(args: Vec<String>) -> Result<u8, String> {
    let mut args = args.into_iter().skip(1).collect::<Vec<_>>();
    if args
        .first()
        .is_some_and(|arg| arg == "help" || arg == "--help" || arg == "-h")
    {
        println!("{}", help_text());
        return Ok(0);
    }
    if args
        .first()
        .is_some_and(|arg| arg == "--version" || arg == "-V")
    {
        println!("closeenv {}", env!("CARGO_PKG_VERSION"));
        return Ok(0);
    }
    if args.first().is_some_and(|arg| arg == "scan") {
        args.remove(0);
    }

    let mut output_format = OutputFormat::Text;
    let mut fail_on_findings = true;
    let mut text_finding_limit = DEFAULT_TEXT_FINDING_LIMIT;
    let mut options = ScanOptions::default();
    let mut root = PathBuf::from(".");
    let mut saw_path = false;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "--json" => output_format = OutputFormat::Json,
            "--sarif" => output_format = OutputFormat::Sarif,
            "--no-fail" => fail_on_findings = false,
            "--staged" => options.mode = ScanMode::Staged,
            "--include-ignored" => options.include_ignored = true,
            "--max-files" => {
                index += 1;
                options.max_files = Some(parse_usize_arg(&args, index, "--max-files")?);
            }
            "--max-file-bytes" => {
                index += 1;
                options.max_file_bytes = Some(parse_u64_arg(&args, index, "--max-file-bytes")?);
            }
            "--limit" => {
                index += 1;
                text_finding_limit = parse_usize_arg(&args, index, "--limit")?;
            }
            "--help" | "-h" => {
                println!("{}", help_text());
                return Ok(0);
            }
            "--version" | "-V" => {
                println!("closeenv {}", env!("CARGO_PKG_VERSION"));
                return Ok(0);
            }
            candidate if candidate.starts_with('-') => {
                return Err(format!("unknown flag: {candidate}"));
            }
            candidate => {
                if saw_path {
                    return Err("only one scan path is supported".to_string());
                }
                root = PathBuf::from(candidate);
                saw_path = true;
            }
        }
        index += 1;
    }

    let report = scan_path_with_options(&root, options).map_err(|err| err.to_string())?;
    match output_format {
        OutputFormat::Text => print!("{}", report_text_with_limit(&report, text_finding_limit)),
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|err| err.to_string())?
        ),
        OutputFormat::Sarif => println!(
            "{}",
            serde_json::to_string_pretty(&sarif_report(&report)).map_err(|err| err.to_string())?
        ),
    }
    Ok(if fail_on_findings && !report.passed {
        1
    } else {
        0
    })
}

fn parse_usize_arg(args: &[String], index: usize, flag: &str) -> Result<usize, String> {
    args.get(index)
        .ok_or_else(|| format!("{flag} requires a value"))?
        .parse::<usize>()
        .map_err(|_| format!("{flag} requires a positive integer"))
}

fn parse_u64_arg(args: &[String], index: usize, flag: &str) -> Result<u64, String> {
    args.get(index)
        .ok_or_else(|| format!("{flag} requires a value"))?
        .parse::<u64>()
        .map_err(|_| format!("{flag} requires a positive integer"))
}

pub fn scan_path(root: &Path) -> std::io::Result<ScanReport> {
    scan_path_with_options(root, ScanOptions::default())
}

pub fn scan_path_with_options(root: &Path, options: ScanOptions) -> std::io::Result<ScanReport> {
    let started = Instant::now();
    let root = root.canonicalize()?;
    let mut policy = read_policy(&root)?;
    if let Some(max_files) = options.max_files {
        policy.max_files = max_files;
    }
    if let Some(max_file_bytes) = options.max_file_bytes {
        policy.max_file_bytes = max_file_bytes;
    }
    let (files, skipped_files) = collect_files(&root, &policy, &options)?;
    let tracked_files = git_tracked_files(&root).unwrap_or_default();
    let input = ScanInput {
        root: root.clone(),
        files,
        tracked_files,
        skipped_files,
        policy,
    };
    let checks = vec![
        check_tracked_dotenv(&input),
        check_working_tree_dotenv(&input),
        check_example_files(&input)?,
        check_sensitive_file_names(&input),
        check_raw_secret_patterns(&input)?,
        check_repo_secret_state(&input),
        check_package_scripts(&input)?,
        check_compose_env_files(&input)?,
    ];
    let passed = checks.iter().all(|check| check.passed);
    let scanned_files = input.files.len();
    let blocker_findings = checks
        .iter()
        .flat_map(|check| &check.findings)
        .filter(|finding| finding.severity == Severity::Blocker)
        .count();
    let warning_findings = checks
        .iter()
        .flat_map(|check| &check.findings)
        .filter(|finding| finding.severity == Severity::Warning)
        .count();
    let detector_counts = detector_counts(&checks);
    Ok(ScanReport {
        root: root.display().to_string(),
        passed,
        scanned_files,
        skipped_files: input.skipped_files,
        duration_ms: started.elapsed().as_millis(),
        blocker_findings,
        warning_findings,
        detector_counts,
        checks,
    })
}

pub fn report_text(report: &ScanReport) -> String {
    report_text_with_limit(report, DEFAULT_TEXT_FINDING_LIMIT)
}

pub fn report_text_with_limit(report: &ScanReport, finding_limit: usize) -> String {
    let mut output = String::new();
    output.push_str(&format!(
        "CloseEnv scan: {}\n",
        if report.passed { "passed" } else { "failed" }
    ));
    output.push_str(&format!("Root: {}\n", report.root));
    output.push_str(&format!(
        "Files: scanned={} skipped={}\n",
        report.scanned_files, report.skipped_files
    ));
    output.push_str(&format!(
        "Findings: blockers={} warnings={} duration_ms={}\n",
        report.blocker_findings, report.warning_findings, report.duration_ms
    ));
    for check in &report.checks {
        output.push_str(&format!(
            "- {}: {}\n",
            check.name,
            if check.passed {
                check.detail.clone()
            } else {
                format!("{} ({})", check.detail, check.findings.len())
            }
        ));
        for finding in check.findings.iter().take(finding_limit) {
            let line = finding
                .line
                .map(|line| format!(":{line}"))
                .unwrap_or_default();
            output.push_str(&format!(
                "  - {:?}: {}{}: {}\n",
                finding.severity, finding.path, line, finding.detail
            ));
        }
        if check.findings.len() > finding_limit {
            output.push_str(&format!(
                "  - ... {} more findings omitted\n",
                check.findings.len() - finding_limit
            ));
        }
    }
    output
}

fn help_text() -> &'static str {
    "CloseEnv\n\nUsage:\n  closeenv scan [path] [--json|--sarif] [--staged] [--include-ignored]\n                [--max-files <n>] [--max-file-bytes <bytes>] [--limit <n>] [--no-fail]\n\nChecks whether a repository is safe to publish without printing secret values.\n"
}

fn read_policy(root: &Path) -> std::io::Result<ScanPolicy> {
    let mut config = CloseEnvConfig::default();
    for name in ["closeenv.yml", ".closeenv.yml"] {
        let path = root.join(name);
        if !path.exists() {
            continue;
        }
        let body = read_text_limited(&path)?;
        config = serde_yaml::from_str(&body).unwrap_or_default();
        break;
    }
    let mut allow_value_env_paths = Vec::new();
    let mut ignore_paths = Vec::new();
    let mut ignore_detectors = Vec::new();
    let mut max_files = None;
    let mut max_file_bytes = None;
    if let Some(paths) = config.allow_value_env_paths {
        allow_value_env_paths.extend(paths);
    }
    if let Some(paths) = config.ignore_paths {
        ignore_paths.extend(paths);
    }
    if let Some(detectors) = config.ignore_detectors {
        ignore_detectors.extend(detectors);
    }
    if config.max_files.is_some() {
        max_files = config.max_files;
    }
    if config.max_file_bytes.is_some() {
        max_file_bytes = config.max_file_bytes;
    }
    if let Some(policy) = config.closeenv {
        if let Some(paths) = policy.allow_value_env_paths {
            allow_value_env_paths.extend(paths);
        }
        if let Some(paths) = policy.ignore_paths {
            ignore_paths.extend(paths);
        }
        if let Some(detectors) = policy.ignore_detectors {
            ignore_detectors.extend(detectors);
        }
        if policy.max_files.is_some() {
            max_files = policy.max_files;
        }
        if policy.max_file_bytes.is_some() {
            max_file_bytes = policy.max_file_bytes;
        }
    }
    Ok(ScanPolicy {
        allow_value_env_paths: allow_value_env_paths
            .into_iter()
            .filter(|path| !looks_like_secret_value(path))
            .collect(),
        ignore_paths,
        ignore_detectors: ignore_detectors
            .into_iter()
            .filter(|detector| is_safe_detector_name(detector))
            .collect(),
        max_files: max_files.unwrap_or(DEFAULT_MAX_SCAN_FILES),
        max_file_bytes: max_file_bytes.unwrap_or(DEFAULT_MAX_TEXT_FILE_BYTES),
    })
}

fn detector_counts(checks: &[ScanCheck]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for finding in checks.iter().flat_map(|check| &check.findings) {
        *counts.entry(finding.detail.clone()).or_insert(0) += 1;
    }
    counts
}

fn sarif_report(report: &ScanReport) -> serde_json::Value {
    let results = report
        .checks
        .iter()
        .flat_map(|check| {
            check.findings.iter().map(move |finding| {
                serde_json::json!({
                    "ruleId": finding.detail,
                    "level": match finding.severity {
                        Severity::Blocker => "error",
                        Severity::Warning => "warning",
                    },
                    "message": { "text": format!("{}: {}", check.name, finding.detail) },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": { "uri": finding.path },
                            "region": { "startLine": finding.line.unwrap_or(1) }
                        }
                    }]
                })
            })
        })
        .collect::<Vec<_>>();
    let rules = report
        .detector_counts
        .keys()
        .map(|detector| {
            serde_json::json!({
                "id": detector,
                "name": detector,
                "shortDescription": { "text": detector }
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "CloseEnv",
                    "informationUri": "https://github.com/once0811-arch/CloseEnv",
                    "rules": rules
                }
            },
            "results": results
        }]
    })
}

fn collect_files(
    root: &Path,
    policy: &ScanPolicy,
    options: &ScanOptions,
) -> std::io::Result<(Vec<String>, usize)> {
    if !options.include_ignored {
        if let Some(files) = git_scan_files(root, options.mode)? {
            return filter_candidate_files(files, policy);
        }
    }
    collect_files_recursively(root, policy)
}

fn git_scan_files(root: &Path, mode: ScanMode) -> std::io::Result<Option<Vec<String>>> {
    if !root.join(".git").exists() {
        return Ok(None);
    }
    let args = match mode {
        ScanMode::WorkingTree => vec!["ls-files", "-co", "--exclude-standard"],
        ScanMode::Staged => vec!["diff", "--name-only", "--cached", "--diff-filter=ACMR"],
    };
    let files = git_file_list(root, &args)?;
    Ok(Some(files))
}

fn collect_files_recursively(
    root: &Path,
    policy: &ScanPolicy,
) -> std::io::Result<(Vec<String>, usize)> {
    let mut files = Vec::new();
    let mut skipped = 0;
    let mut stack = vec![PathBuf::new()];
    while let Some(relative_dir) = stack.pop() {
        let absolute_dir = root.join(&relative_dir);
        let mut entries = fs::read_dir(&absolute_dir)?.collect::<Result<Vec<_>, _>>()?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let file_name = entry.file_name();
            let path = relative_dir.join(file_name);
            let relative = normalize_path(&path);
            if path_is_ignored(&relative, policy) {
                skipped += 1;
                continue;
            }
            let file_type = entry.file_type()?;
            if file_type.is_symlink() {
                skipped += 1;
                continue;
            }
            if file_type.is_dir() {
                if is_pruned_dir(&entry.file_name()) {
                    skipped += 1;
                } else {
                    stack.push(path);
                }
                continue;
            }
            if file_type.is_file() {
                files.push(relative);
                if files.len() > policy.max_files {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "repo has too many files to scan safely",
                    ));
                }
            }
        }
    }
    files.sort();
    Ok((files, skipped))
}

fn filter_candidate_files(
    candidates: Vec<String>,
    policy: &ScanPolicy,
) -> std::io::Result<(Vec<String>, usize)> {
    let mut files = Vec::new();
    let mut skipped = 0;
    for path in candidates {
        if path_is_ignored(&path, policy) || path.split('/').any(is_pruned_dir_name) {
            skipped += 1;
            continue;
        }
        files.push(path);
        if files.len() > policy.max_files {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "repo has too many files to scan safely",
            ));
        }
    }
    files.sort();
    files.dedup();
    Ok((files, skipped))
}

fn check_tracked_dotenv(input: &ScanInput) -> ScanCheck {
    let findings = input
        .tracked_files
        .iter()
        .filter(|path| {
            is_dotenv_value_path(path) && !policy_allows_value_env_path(path, &input.policy)
        })
        .map(|path| finding(path, "tracked dotenv value file"))
        .collect::<Vec<_>>();
    check(
        "tracked dotenv files",
        "none",
        "remove tracked dotenv files",
        findings,
    )
}

fn check_working_tree_dotenv(input: &ScanInput) -> ScanCheck {
    let findings = input
        .files
        .iter()
        .filter(|path| {
            is_dotenv_value_path(path) && !policy_allows_value_env_path(path, &input.policy)
        })
        .map(|path| finding(path, "dotenv value file in working tree"))
        .collect::<Vec<_>>();
    check(
        "working tree dotenv files",
        "none",
        "remove dotenv value files",
        findings,
    )
}

fn check_example_files(input: &ScanInput) -> std::io::Result<ScanCheck> {
    let mut findings = Vec::new();
    for path in input
        .files
        .iter()
        .filter(|path| is_dotenv_example_path(path))
    {
        let body = read_text_limited_with_cap(&input.root.join(path), input.policy.max_file_bytes)?;
        for (key, value) in parse_dotenv_pairs(&body) {
            if !example_value_is_safe(&key, &value) {
                findings.push(finding(
                    path,
                    &format!("{key} has a concrete value in an example env file"),
                ));
                break;
            }
        }
    }
    Ok(check(
        "example env files",
        "safe placeholders",
        "replace concrete example values with placeholders",
        findings,
    ))
}

fn check_raw_secret_patterns(input: &ScanInput) -> std::io::Result<ScanCheck> {
    let mut findings = Vec::new();
    for path in &input.files {
        if !is_text_scan_candidate(path) {
            continue;
        }
        let absolute = input.root.join(path);
        let Some(body) = read_text_if_small(&absolute, input.policy.max_file_bytes)? else {
            continue;
        };
        let detectors = detect_secret_patterns(&body);
        for detector in detectors {
            if input.policy.ignore_detectors.contains(detector.name) {
                continue;
            }
            findings.push(raw_finding(path, detector.name, detector.line));
        }
    }
    Ok(check(
        "raw secret patterns",
        "none",
        "remove or replace high-confidence secret-like text",
        findings,
    ))
}

fn check_sensitive_file_names(input: &ScanInput) -> ScanCheck {
    let findings = input
        .files
        .iter()
        .filter_map(|path| {
            sensitive_file_name_detector(path)
                .filter(|detector| !input.policy.ignore_detectors.contains(*detector))
                .map(|detector| finding(path, detector))
        })
        .collect::<Vec<_>>();
    check(
        "sensitive file names",
        "none",
        "remove private key, credential, or environment state files",
        findings,
    )
}

fn check_repo_secret_state(input: &ScanInput) -> ScanCheck {
    let state_paths = [
        ".envforge/token",
        ".envforge/session.json",
        ".envforge/tokens.json",
        ".envforge/tokens",
        ".closeenv/tmp",
        ".closeenv/session.json",
        ".envrc",
        ".direnv",
    ];
    let existing = state_paths
        .iter()
        .filter(|path| input.root.join(path).exists())
        .map(|path| finding(path, "repo-local secret or environment state"))
        .collect::<Vec<_>>();
    check(
        "repo-local secret state",
        "none",
        "move secret state outside the repository",
        existing,
    )
}

fn check_package_scripts(input: &ScanInput) -> std::io::Result<ScanCheck> {
    let mut findings = Vec::new();
    for path in input
        .files
        .iter()
        .filter(|path| path.ends_with("package.json"))
    {
        let body = read_text_limited_with_cap(&input.root.join(path), input.policy.max_file_bytes)?;
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&body) else {
            continue;
        };
        let Some(scripts) = value.get("scripts").and_then(|value| value.as_object()) else {
            continue;
        };
        for (name, script) in scripts {
            let Some(script) = script.as_str() else {
                continue;
            };
            if script_loads_dotenv_value(script) {
                findings.push(finding(
                    path,
                    &format!("script {name} loads a dotenv value file"),
                ));
            }
        }
    }
    Ok(check(
        "package scripts",
        "no plaintext dotenv loaders",
        "remove dotenv value loaders from package scripts",
        findings,
    ))
}

fn check_compose_env_files(input: &ScanInput) -> std::io::Result<ScanCheck> {
    let mut findings = Vec::new();
    for path in input.files.iter().filter(|path| is_compose_file(path)) {
        let body = read_text_limited_with_cap(&input.root.join(path), input.policy.max_file_bytes)?;
        if body
            .lines()
            .any(|line| line.trim_start().starts_with("env_file:"))
        {
            findings.push(finding(
                path,
                "Docker Compose env_file can point at plaintext env",
            ));
        }
    }
    Ok(check(
        "Docker Compose env_file",
        "none",
        "remove env_file references or document a safe allowlist",
        findings,
    ))
}

fn check(name: &str, ok: &str, fail: &str, findings: Vec<Finding>) -> ScanCheck {
    ScanCheck {
        name: name.to_string(),
        passed: findings.is_empty(),
        detail: if findings.is_empty() { ok } else { fail }.to_string(),
        findings,
    }
}

fn finding(path: &str, detail: &str) -> Finding {
    Finding {
        severity: Severity::Blocker,
        path: path.to_string(),
        line: None,
        detail: detail.to_string(),
    }
}

fn raw_finding(path: &str, detail: &str, line: usize) -> Finding {
    Finding {
        severity: Severity::Blocker,
        path: path.to_string(),
        line: Some(line),
        detail: detail.to_string(),
    }
}

fn git_tracked_files(root: &Path) -> std::io::Result<BTreeSet<String>> {
    if !root.join(".git").exists() {
        return Ok(BTreeSet::new());
    }
    Ok(git_file_list(root, &["ls-files"])?.into_iter().collect())
}

fn git_file_list(root: &Path, args: &[&str]) -> std::io::Result<Vec<String>> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_clear()
        .env("PATH", safe_path_value())
        .spawn()?;
    let stdout = child.stdout.take().map(read_child_stdout_limited);
    if !wait_child_with_timeout(&mut child)? {
        return Ok(Vec::new());
    }
    let output = stdout
        .map(|stdout| {
            stdout
                .join()
                .unwrap_or_else(|_| Err(std::io::Error::other("git stdout reader failed")))
        })
        .transpose()?
        .unwrap_or_default();
    Ok(String::from_utf8_lossy(&output)
        .lines()
        .map(str::to_string)
        .collect())
}

fn read_child_stdout_limited<R: Read + Send + 'static>(
    reader: R,
) -> std::thread::JoinHandle<std::io::Result<Vec<u8>>> {
    std::thread::spawn(move || {
        let mut output = Vec::new();
        reader
            .take(DEFAULT_MAX_TEXT_FILE_BYTES.saturating_add(1))
            .read_to_end(&mut output)?;
        Ok(output)
    })
}

fn wait_child_with_timeout(child: &mut Child) -> std::io::Result<bool> {
    let deadline = Instant::now() + Duration::from_millis(GIT_TIMEOUT_MS);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status.success());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn read_text_limited(path: &Path) -> std::io::Result<String> {
    read_text_limited_with_cap(path, DEFAULT_MAX_TEXT_FILE_BYTES)
}

fn read_text_limited_with_cap(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} exceeds scan read cap", path.display()),
        ));
    }
    let bytes = fs::read(path)?;
    if bytes.len() as u64 > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} exceeds scan read cap", path.display()),
        ));
    }
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

fn read_text_if_small(path: &Path, max_bytes: u64) -> std::io::Result<Option<String>> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > max_bytes {
        return Ok(None);
    }
    let bytes = fs::read(path)?;
    if bytes.contains(&0) {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(&bytes).to_string()))
}

fn parse_dotenv_pairs(body: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for line in body.lines() {
        let line = line.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if !is_env_key(key) {
            continue;
        }
        let value = strip_inline_comment(raw_value)
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string();
        pairs.push((key.to_string(), value));
    }
    pairs
}

fn strip_inline_comment(value: &str) -> &str {
    value.split(" #").next().unwrap_or(value)
}

fn example_value_is_safe(key: &str, value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || (trimmed.starts_with('<') && trimmed.ends_with('>'))
        || (trimmed.starts_with("${") && trimmed.ends_with('}'))
    {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    if [
        "example",
        "example-value",
        "changeme",
        "change-me",
        "dummy",
        "your-value",
    ]
    .contains(&lower.as_str())
        || lower.starts_with("your_")
        || lower.contains("replace")
    {
        return true;
    }
    is_public_env_key(key)
        && !detect_secret_patterns(trimmed).iter().any(|detector| {
            matches!(
                detector.name,
                "private-key" | "envforge-token" | "openai-token" | "github-token" | "database-url"
            )
        })
}

fn sensitive_file_name_detector(path: &str) -> Option<&'static str> {
    let normalized = path.replace('\\', "/");
    let name = normalized.rsplit('/').next().unwrap_or(&normalized);
    match name {
        "id_rsa" | "id_dsa" | "id_ecdsa" | "id_ed25519" => Some("ssh-private-key-file"),
        ".npmrc" => Some("npm-token-file"),
        ".pypirc" => Some("pypi-token-file"),
        ".netrc" => Some("netrc-credential-file"),
        ".envrc" => Some("direnv-state-file"),
        _ if normalized.ends_with(".aws/credentials") => Some("aws-credentials-file"),
        _ if normalized.ends_with(".kube/config") => Some("kubeconfig-file"),
        _ if name.eq_ignore_ascii_case("serviceAccountKey.json") => {
            Some("google-service-account-file")
        }
        _ if name.to_ascii_lowercase().contains("service-account") && name.ends_with(".json") => {
            Some("service-account-file")
        }
        _ => None,
    }
}

fn detect_secret_patterns(body: &str) -> Vec<PatternDetection> {
    let mut detectors = BTreeMap::<&'static str, usize>::new();
    for (line_index, line) in body.lines().enumerate() {
        let line_number = line_index + 1;
        if contains_prefixed_token(line, &["efp__", "eft__", "efu__"], 32) {
            detectors.entry("envforge-token").or_insert(line_number);
        }
        if contains_prefixed_token(line, &["sk-"], 24) {
            detectors.entry("openai-token").or_insert(line_number);
        }
        if contains_prefixed_token(line, &["ghp_", "gho_", "ghu_", "ghs_", "github_pat_"], 32) {
            detectors.entry("github-token").or_insert(line_number);
        }
        if contains_prefixed_token(line, &["xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"], 24) {
            detectors.entry("slack-token").or_insert(line_number);
        }
        if contains_prefixed_token(line, &["npm_"], 32) {
            detectors.entry("npm-token").or_insert(line_number);
        }
        if contains_prefixed_token(line, &["sk_live_", "rk_live_"], 24) {
            detectors.entry("stripe-secret-key").or_insert(line_number);
        }
        if contains_google_api_key(line) {
            detectors.entry("google-api-key").or_insert(line_number);
        }
        if contains_database_url(line) {
            detectors.entry("database-url").or_insert(line_number);
        }
        if contains_private_key_header(line) {
            detectors.entry("private-key").or_insert(line_number);
        }
        if contains_bearer_token(line) {
            detectors.entry("bearer-token").or_insert(line_number);
        }
        if contains_signed_url_secret(line) {
            detectors.entry("signed-url").or_insert(line_number);
        }
        if contains_aws_access_key_id(line) {
            detectors.entry("aws-access-key-id").or_insert(line_number);
        }
        if contains_jwt_like_token(line) {
            detectors.entry("jwt-like-token").or_insert(line_number);
        }
        if contains_sensitive_assignment(line) {
            detectors
                .entry("sensitive-assignment")
                .or_insert(line_number);
        }
        if contains_google_service_account_marker(line) {
            detectors
                .entry("google-service-account")
                .or_insert(line_number);
        }
    }
    detectors
        .into_iter()
        .map(|(name, line)| PatternDetection { name, line })
        .collect()
}

fn contains_prefixed_token(body: &str, prefixes: &[&str], min_len: usize) -> bool {
    token_candidates(body).any(|token| {
        token.len() >= min_len && prefixes.iter().any(|prefix| token.starts_with(prefix))
    })
}

fn contains_google_api_key(body: &str) -> bool {
    token_candidates(body).any(|token| {
        token.len() == 39
            && token.starts_with("AIza")
            && token
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
    })
}

fn contains_sensitive_assignment(line: &str) -> bool {
    let Some((key, value)) = line.split_once('=') else {
        return false;
    };
    if !is_sensitive_key(key) {
        return false;
    }
    let value = value.trim().trim_matches('"').trim_matches('\'');
    value.len() >= 20
        && token_variety(value) >= 3
        && shannon_entropy(value.as_bytes()) >= 3.5
        && !example_value_is_safe(key.trim(), value)
}

fn contains_google_service_account_marker(line: &str) -> bool {
    line.contains("\"type\"") && line.contains("service_account")
        || line.contains("\"private_key_id\"")
        || line.contains("\"client_email\"") && line.contains("iam.gserviceaccount.com")
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized = key
        .trim()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    [
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "API_KEY",
        "APIKEY",
        "DATABASE_URL",
        "PRIVATE_KEY",
        "ACCESS_KEY",
        "AUTHORIZATION",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

fn token_variety(token: &str) -> usize {
    let mut lower = false;
    let mut upper = false;
    let mut digit = false;
    let mut symbol = false;
    for ch in token.chars() {
        if ch.is_ascii_lowercase() {
            lower = true;
        } else if ch.is_ascii_uppercase() {
            upper = true;
        } else if ch.is_ascii_digit() {
            digit = true;
        } else {
            symbol = true;
        }
    }
    [lower, upper, digit, symbol]
        .into_iter()
        .filter(|present| *present)
        .count()
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    let mut counts = [0_usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .into_iter()
        .filter(|count| *count > 0)
        .map(|count| {
            let probability = count as f64 / len;
            -probability * probability.log2()
        })
        .sum()
}

fn token_candidates(body: &str) -> impl Iterator<Item = &str> {
    body.split(|ch: char| {
        !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '+' | '/' | '~'))
    })
    .filter(|token| !token.is_empty())
}

fn contains_database_url(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    ["postgres://", "postgresql://", "mysql://", "mongodb://"]
        .iter()
        .any(|scheme| {
            url_like_values(&lower).any(|value| {
                value.starts_with(scheme) && value.contains('@') && value.len() >= scheme.len() + 8
            })
        })
}

fn url_like_values(body: &str) -> impl Iterator<Item = &str> {
    body.split(|ch: char| ch.is_whitespace() || matches!(ch, '"' | '\'' | '<' | '>' | ')' | '('))
        .filter(|value| !value.is_empty())
}

fn contains_private_key_header(body: &str) -> bool {
    ["", "RSA ", "EC ", "OPENSSH "]
        .iter()
        .any(|kind| body.contains(&format!("-----BEGIN {kind}PRIVATE KEY-----")))
}

fn contains_bearer_token(body: &str) -> bool {
    body.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        let Some(index) = lower.find("bearer ") else {
            return false;
        };
        let token = line[index + "bearer ".len()..]
            .split(|ch: char| {
                !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '+' | '/' | '='))
            })
            .next()
            .unwrap_or_default();
        token.len() >= 24
            && token.chars().any(|ch| ch.is_ascii_digit())
            && token.chars().any(|ch| ch.is_ascii_alphabetic())
    })
}

fn contains_signed_url_secret(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    ["x-amz-signature=", "sig="].iter().any(|needle| {
        let Some(index) = lower.find(needle) else {
            return false;
        };
        let value = &body[index + needle.len()..];
        let signature = value
            .split(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '%')))
            .next()
            .unwrap_or_default();
        signature.len() >= 16
    })
}

fn contains_aws_access_key_id(body: &str) -> bool {
    body.split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|token| {
            token.len() == 20
                && (token.starts_with("AKIA") || token.starts_with("ASIA"))
                && token
                    .chars()
                    .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit())
        })
}

fn contains_jwt_like_token(body: &str) -> bool {
    body.split_whitespace().any(|token| {
        let parts = token.split('.').collect::<Vec<_>>();
        parts.len() == 3
            && token.len() >= 60
            && parts
                .iter()
                .all(|part| part.len() >= 10 && part.chars().all(is_base64_url_char))
    })
}

fn is_base64_url_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '=')
}

fn is_text_scan_candidate(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    ![
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tar", ".lock",
        ".woff", ".woff2", ".ttf",
    ]
    .iter()
    .any(|suffix| lower.ends_with(suffix))
}

fn script_loads_dotenv_value(script: &str) -> bool {
    script
        .split(|ch: char| ch.is_whitespace() || matches!(ch, '"' | '\'' | '='))
        .any(is_dotenv_value_path)
}

fn is_compose_file(path: &str) -> bool {
    matches!(
        path.rsplit('/').next().unwrap_or(path),
        "compose.yaml" | "compose.yml" | "docker-compose.yaml" | "docker-compose.yml"
    )
}

fn is_dotenv_value_path(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    (name == ".env" || name.starts_with(".env."))
        && !is_dotenv_example_path(path)
        && !name.contains("template")
}

fn is_dotenv_example_path(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    (name == ".env.example" || name == ".env.sample")
        || name.contains(".example")
        || name.contains(".sample")
}

fn policy_allows_value_env_path(path: &str, policy: &ScanPolicy) -> bool {
    policy
        .allow_value_env_paths
        .iter()
        .any(|pattern| pattern_matches(path, pattern))
}

fn path_is_ignored(path: &str, policy: &ScanPolicy) -> bool {
    policy
        .ignore_paths
        .iter()
        .any(|pattern| pattern_matches(path, pattern))
}

fn is_safe_detector_name(detector: &str) -> bool {
    !detector.is_empty()
        && detector.len() <= 64
        && detector
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
}

fn pattern_matches(path: &str, pattern: &str) -> bool {
    let path = path.replace('\\', "/");
    let pattern = pattern.replace('\\', "/");
    if let Some(prefix) = pattern.strip_suffix("/**") {
        path == prefix || path.starts_with(&format!("{prefix}/"))
    } else {
        path == pattern
    }
}

fn is_pruned_dir_name(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | ".hg"
            | ".svn"
            | "node_modules"
            | "target"
            | "dist"
            | "build"
            | ".next"
            | ".nuxt"
            | ".turbo"
            | "coverage"
            | ".cache"
            | "vendor"
    )
}

fn is_pruned_dir(name: &OsString) -> bool {
    is_pruned_dir_name(&name.to_string_lossy())
}

fn is_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(first) if first == '_' || first.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn is_public_env_key(key: &str) -> bool {
    key.starts_with("PUBLIC_")
        || key.starts_with("VITE_")
        || key.starts_with("NEXT_PUBLIC_")
        || key.starts_with("REACT_APP_")
}

fn looks_like_secret_value(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    value.starts_with("efp__")
        || value.starts_with("eft__")
        || value.starts_with("efu__")
        || value.starts_with("sk-")
        || lower.starts_with("bearer ")
        || lower.contains("x-amz-signature=")
        || lower.contains("sig=")
        || value.contains("-----BEGIN ")
}

fn normalize_path(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn safe_path_value() -> &'static str {
    if cfg!(windows) {
        r"C:\Windows\System32;C:\Windows;C:\Windows\System32\WindowsPowerShell\v1.0"
    } else {
        "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_repo_passes_without_secret_values() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name":"clean","scripts":{"dev":"vite"}}"#,
        )
        .unwrap();
        fs::write(dir.path().join(".env.example"), "DATABASE_URL=<value>\n").unwrap();

        let report = scan_path(dir.path()).unwrap();

        assert!(report.passed);
        assert!(report_text(&report).contains("CloseEnv scan: passed"));
    }

    #[test]
    fn detects_dotenv_and_token_without_printing_token_value() {
        let dir = tempfile::tempdir().unwrap();
        let fake_value = format!("{}{}{}", "sk", "-test-do-not-print-", "1234567890");
        fs::write(
            dir.path().join(".env.local"),
            format!("OPENAI_API_KEY={fake_value}\n"),
        )
        .unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"scripts":{"dev":"dotenv -e .env.local -- vite"}}"#,
        )
        .unwrap();

        let report = scan_path(dir.path()).unwrap();
        let text = report_text(&report);

        assert!(!report.passed);
        assert!(text.contains("working tree dotenv files"));
        assert!(text.contains("raw secret patterns"));
        assert!(text.contains("package scripts"));
        assert!(!text.contains(&fake_value));
    }

    #[test]
    fn policy_can_allow_local_test_env_paths() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("closeenv.yml"),
            "closeenv:\n  allow_value_env_paths:\n    - .env.test\n",
        )
        .unwrap();
        fs::write(dir.path().join(".env.test"), "LOCAL_ONLY=1\n").unwrap();

        let report = scan_path(dir.path()).unwrap();
        let dotenv = report
            .checks
            .iter()
            .find(|check| check.name == "working tree dotenv files")
            .unwrap();

        assert!(dotenv.passed);
    }

    #[test]
    fn detects_common_open_source_publish_blockers() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".aws")).unwrap();
        fs::write(dir.path().join(".aws/credentials"), "[default]\n").unwrap();
        let slack = format!("{}{}{}", "xox", "b-123456789012-", "abcdefghijklmnop");
        let npm = format!("{}{}", "npm", "_abcdefghijklmnopqrstuvwxyz123456");
        let stripe = format!("{}{}", "sk", "_live_abcdefghijklmnopqrstuvwxyz");
        let google = format!("{}{}", "AI", "zaabcdefghijklmnopqrstuvwxyz123456789");
        let sample = format!("{}{}", "AbCdEfGhIjKlMnOpQrStUvWxYz", "123456+/");
        fs::write(
            dir.path().join("config.js"),
            [
                format!("SLACK_TOKEN={slack}"),
                format!("NPM_TOKEN={npm}"),
                format!("STRIPE_SECRET={stripe}"),
                format!("GOOGLE_API_KEY={google}"),
                format!("PASSWORD={sample}"),
            ]
            .join("\n"),
        )
        .unwrap();

        let report = scan_path(dir.path()).unwrap();

        assert!(!report.passed);
        assert!(report.detector_counts.contains_key("aws-credentials-file"));
        assert!(report.detector_counts.contains_key("slack-token"));
        assert!(report.detector_counts.contains_key("npm-token"));
        assert!(report.detector_counts.contains_key("stripe-secret-key"));
        assert!(report.detector_counts.contains_key("google-api-key"));
        assert!(report.detector_counts.contains_key("sensitive-assignment"));
    }

    #[test]
    fn config_can_ignore_detector_and_limit_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("closeenv.yml"),
            "closeenv:\n  ignore_detectors:\n    - openai-token\n  max_files: 10\n  max_file_bytes: 2048\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("token.txt"),
            format!("{}{}{}\n", "sk", "-test-do-not-print-", "1234567890"),
        )
        .unwrap();

        let report = scan_path(dir.path()).unwrap();

        assert!(report.passed);
        assert_eq!(report.scanned_files, 2);
    }

    #[test]
    fn sarif_output_uses_detector_rule_ids_without_values() {
        let dir = tempfile::tempdir().unwrap();
        let fake_value = format!("{}{}{}", "sk", "-test-do-not-print-", "1234567890");
        fs::write(
            dir.path().join("token.txt"),
            format!("OPENAI_API_KEY={fake_value}\n"),
        )
        .unwrap();
        let report = scan_path(dir.path()).unwrap();

        let sarif = sarif_report(&report).to_string();

        assert!(sarif.contains("openai-token"));
        assert!(sarif.contains("token.txt"));
        assert!(!sarif.contains(&fake_value));
    }

    #[test]
    fn staged_mode_limits_scan_to_staged_files() {
        let dir = tempfile::tempdir().unwrap();
        let init = Command::new("git")
            .arg("init")
            .current_dir(dir.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        if !init.success() {
            return;
        }
        fs::write(dir.path().join("clean.txt"), "hello\n").unwrap();
        fs::write(
            dir.path().join("staged.txt"),
            format!("{}{}{}\n", "sk", "-test-do-not-print-", "1234567890"),
        )
        .unwrap();
        let add = Command::new("git")
            .args(["add", "staged.txt"])
            .current_dir(dir.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        if !add.success() {
            return;
        }

        let report = scan_path_with_options(
            dir.path(),
            ScanOptions {
                mode: ScanMode::Staged,
                ..ScanOptions::default()
            },
        )
        .unwrap();

        assert_eq!(report.scanned_files, 1);
        assert!(report.detector_counts.contains_key("openai-token"));
    }
}
