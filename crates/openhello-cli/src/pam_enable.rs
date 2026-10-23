use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const PAM_USAGE: &str = "usage: openhello-cli pam <enable [service...] | disable [service...] | status | migrate> [--root DIR] [--arg flag|key=value]... [--no-fingerprint]";

const MODULE: &str = "pam_openhello.so";
const FPRINTD_MODULE: &str = "pam_fprintd.so";
const FPRINTD_MARKER: &str = "# added by open-hello";
const FPRINTD_LINE: &str = "auth sufficient pam_fprintd.so max-tries=3 timeout=10";
const INCLUDE_DEPTH: usize = 8;
const LEGACY_SERVICES_PATH: &str = "/etc/openhello/pam-services";
const LEGACY_SERVICES_HEADER: &str = "# Services where pam_openhello may use the camera";
const FALLBACK: &str =
    "per-service fallback: sudo openhello-cli pam enable <service>... (one service per file in /etc/pam.d)";
const STACK_DISCOVERY_SERVICE: &str = "sudo";
const OLD_STACK_FILES: &[&str] = &["sudo-openhello", "openhello-lockscreen"];
const OLD_INCLUDES: &[&str] = &["sudo-openhello", "openhello-lockscreen"];
const BACKUP_SUFFIX: &str = ".openhello.bak";

#[derive(Debug)]
pub struct PamFailure {
    pub code: u8,
    pub message: String,
}

fn usage(message: impl Into<String>) -> PamFailure {
    PamFailure {
        code: 2,
        message: format!("{}\n{PAM_USAGE}", message.into()),
    }
}

fn failed(message: impl Into<String>) -> PamFailure {
    PamFailure {
        code: 3,
        message: message.into(),
    }
}

#[derive(Debug, PartialEq)]
enum Action {
    Enable,
    Disable,
    Status,
    Migrate,
}

struct Request {
    action: Action,
    root: Option<PathBuf>,
    module_args: Vec<String>,
    services: Vec<String>,
    fingerprint: bool,
}

struct Dirs {
    root: PathBuf,
    etc: PathBuf,
    vendor: PathBuf,
}

fn parse(args: &[String]) -> Result<Request, PamFailure> {
    let mut iter = args.iter();
    let action = match iter.next().map(String::as_str) {
        Some("enable") => Action::Enable,
        Some("disable") => Action::Disable,
        Some("status") => Action::Status,
        Some("migrate") => Action::Migrate,
        Some(other) => return Err(usage(format!("unknown pam command `{other}`"))),
        None => return Err(usage("a pam command is required")),
    };
    let mut root = None;
    let mut module_args = Vec::new();
    let mut services = Vec::new();
    let mut fingerprint = true;
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                root = Some(PathBuf::from(
                    iter.next()
                        .ok_or_else(|| usage("--root needs a directory"))?,
                ))
            }
            "--no-fingerprint" => fingerprint = false,
            "--arg" => {
                let pair = iter
                    .next()
                    .ok_or_else(|| usage("--arg needs a flag or key=value"))?;
                validate_module_arg(pair)?;
                module_args.push(pair.clone());
            }
            flag if flag.starts_with("--") => {
                return Err(usage(format!("unexpected option `{flag}`")))
            }
            name => services.push(name.to_string()),
        }
    }
    if matches!(action, Action::Status | Action::Migrate) && !services.is_empty() {
        return Err(usage("this command takes no service names"));
    }
    Ok(Request {
        action,
        root,
        module_args,
        services,
        fingerprint,
    })
}

fn validate_module_arg(pair: &str) -> Result<(), PamFailure> {
    let keyed = pair.split_once('=').is_some_and(|(key, _)| !key.is_empty());
    let flag = !pair.is_empty()
        && pair
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    let well_formed = (keyed || flag) && !pair.chars().any(|c| c.is_whitespace() || c.is_control());
    if well_formed {
        Ok(())
    } else {
        Err(usage(format!(
            "module argument `{pair}` must be a flag or key=value, without spaces"
        )))
    }
}

fn validate_service(dirs: &Dirs, name: &str) -> Result<(), String> {
    let valid_chars = name
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'));
    if name.is_empty() || name.starts_with('.') || !valid_chars {
        return Err(format!(
            "`{name}` is not a valid service name (only a-z, 0-9, `.`, `_`, `-`; no `/`)"
        ));
    }
    if is_shared_stack(dirs, name) {
        return Err(format!("`{name}` is a shared stack (another service includes it); shared stacks are never edited by name, enable the services that include it instead"));
    }
    Ok(())
}

pub fn run(args: &[String], out: &mut dyn Write) -> Result<(), PamFailure> {
    let request = parse(args)?;
    let injected = request.root.is_some();
    let root = request.root.clone().unwrap_or_else(|| PathBuf::from("/"));
    let dirs = Dirs {
        root: root.clone(),
        etc: root.join("etc/pam.d"),
        vendor: root.join("usr/lib/pam.d"),
    };
    if request.action != Action::Status && !injected && unsafe { libc::geteuid() } != 0 {
        return Err(failed("changing /etc/pam.d requires root; run with sudo"));
    }
    let mut say = |text: String| {
        let _ = writeln!(out, "{text}");
    };
    match request.action {
        Action::Status => status(&dirs, &mut say).map_err(failed),
        Action::Migrate => migrate(&dirs, &mut say).map(|_| ()).map_err(failed),
        Action::Enable | Action::Disable => {
            if request.action == Action::Enable {
                migrate(&dirs, &mut say).map_err(failed)?;
            }
            if request.services.is_empty() {
                let result = match request.action {
                    Action::Enable => {
                        enable_common(&dirs, &request.module_args, request.fingerprint, &mut say)
                    }
                    _ => disable_everywhere(&dirs, &mut say),
                };
                return result.map_err(failed);
            }
            let mut problems = Vec::new();
            for service in &request.services {
                let outcome = validate_service(&dirs, service).and_then(|_| match request.action {
                    Action::Enable => enable_one(&dirs, service, &request.module_args),
                    _ => disable_one(&dirs, service),
                });
                match outcome {
                    Ok(message) => say(message),
                    Err(problem) => problems.push(format!("{service}: {problem}")),
                }
            }
            if problems.is_empty() {
                Ok(())
            } else {
                Err(failed(problems.join("\n")))
            }
        }
    }
}

fn first_token(line: &str) -> Option<&str> {
    line.split_whitespace()
        .next()
        .filter(|t| !t.starts_with('#'))
}

fn is_our_line(line: &str) -> bool {
    let mut tokens = line.split_whitespace();
    tokens.next() == Some("auth")
        && tokens.next() == Some("sufficient")
        && tokens.next() == Some(MODULE)
}

fn is_fprintd_line(line: &str) -> bool {
    let code = line.split('#').next().unwrap_or("");
    let mut tokens = code.split_whitespace();
    matches!(tokens.next(), Some("auth" | "-auth"))
        && tokens.any(|t| {
            Path::new(t)
                .file_name()
                .is_some_and(|n| n == FPRINTD_MODULE)
        })
}

fn is_our_fprintd_line(line: &str) -> bool {
    is_fprintd_line(line) && line.contains(FPRINTD_MARKER)
}

fn is_old_include(line: &str) -> bool {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    matches!(tokens.as_slice(), ["auth", "include", name] if OLD_INCLUDES.contains(name))
}

fn insert_line(content: &str, line: &str) -> String {
    insert_before(content, line, &["auth", "-auth", "@include"])
}

fn insert_before(content: &str, line: &str, anchors: &[&str]) -> String {
    let lines: Vec<&str> = content.split_inclusive('\n').collect();
    let at = lines
        .iter()
        .position(|l| first_token(l).is_some_and(|t| anchors.contains(&t)))
        .unwrap_or(lines.len());
    let mut result = String::with_capacity(content.len() + line.len() + 2);
    for (index, existing) in lines.iter().enumerate() {
        if index == at {
            result.push_str(line);
            result.push('\n');
        }
        result.push_str(existing);
    }
    if at == lines.len() {
        if !result.is_empty() && !result.ends_with('\n') {
            result.push('\n');
        }
        result.push_str(line);
        result.push('\n');
    }
    result
}

fn insert_after_our_line(content: &str, line: &str) -> String {
    let mut result = String::with_capacity(content.len() + line.len() + 2);
    let mut placed = false;
    for existing in content.split_inclusive('\n') {
        result.push_str(existing);
        if !placed && is_our_line(existing) {
            if !existing.ends_with('\n') {
                result.push('\n');
            }
            result.push_str(line);
            result.push('\n');
            placed = true;
        }
    }
    result
}

fn remove_lines(content: &str, matches: impl Fn(&str) -> bool) -> (String, usize) {
    let mut removed = 0;
    let kept: String = content
        .split_inclusive('\n')
        .filter(|l| {
            let drop = matches(l);
            removed += usize::from(drop);
            !drop
        })
        .collect();
    (kept, removed)
}

fn our_line(module_args: &[String]) -> String {
    let mut line = format!("auth sufficient {MODULE}");
    for arg in module_args {
        line.push(' ');
        line.push_str(arg);
    }
    line
}

fn write_atomic(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    owner: Option<(u32, u32)>,
) -> Result<(), String> {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("pam");
    let temp = path.with_file_name(format!(".{name}.openhello.tmp"));
    let attempt = || -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.set_permissions(fs::Permissions::from_mode(mode & 0o7777))?;
        if let Some((uid, gid)) = owner {
            let own = file.metadata()?;
            if own.uid() != uid || own.gid() != gid {
                std::os::unix::fs::fchown(&file, Some(uid), Some(gid))?;
            }
        }
        file.sync_all()?;
        fs::rename(&temp, path)
    };
    attempt().map_err(|e| {
        let _ = fs::remove_file(&temp);
        format!("cannot write {}: {e}", path.display())
    })?;
    if let Some(dir) = path.parent().and_then(|d| File::open(d).ok()) {
        let _ = dir.sync_all();
    }
    Ok(())
}

fn ensure_backup(path: &Path, service: &str) -> Result<(), String> {
    let backup = path.with_file_name(format!("{service}{BACKUP_SUFFIX}"));
    if fs::symlink_metadata(&backup).is_ok() {
        return Ok(());
    }
    let meta = fs::metadata(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let bytes = fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    write_atomic(&backup, &bytes, meta.mode(), Some((meta.uid(), meta.gid())))
}

fn read_text(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| format!("cannot read {} as text: {e}", path.display()))
}

fn refuse_symlink(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(format!(
            "{} is a symlink (probably into a tree owned by a configuration manager); it is not edited, replace it with a regular file first",
            path.display()
        )),
        _ => Ok(()),
    }
}

fn materialize(dirs: &Dirs, service: &str) -> Result<PathBuf, String> {
    let target = dirs.etc.join(service);
    refuse_symlink(&target)?;
    if target.exists() {
        return Ok(target);
    }
    let vendor = dirs.vendor.join(service);
    let meta = fs::metadata(&vendor).map_err(|_| {
        format!(
            "no PAM service file for `{service}` in {} or {}",
            dirs.etc.display(),
            dirs.vendor.display()
        )
    })?;
    let bytes = fs::read(&vendor).map_err(|e| format!("cannot read {}: {e}", vendor.display()))?;
    write_atomic(&target, &bytes, meta.mode(), Some((meta.uid(), meta.gid())))?;
    Ok(target)
}

fn rewrite(path: &Path, service: &str, content: &str) -> Result<(), String> {
    ensure_backup(path, service)?;
    let meta = fs::metadata(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    write_atomic(
        path,
        content.as_bytes(),
        meta.mode(),
        Some((meta.uid(), meta.gid())),
    )
}

fn enable_one(dirs: &Dirs, service: &str, module_args: &[String]) -> Result<String, String> {
    let path = materialize(dirs, service)?;
    let content = read_text(&path)?;
    if content.lines().any(is_our_line) {
        return Ok(format!("{service}: already enabled"));
    }
    rewrite(
        &path,
        service,
        &insert_line(&content, &our_line(module_args)),
    )?;
    Ok(format!("{service}: enabled in {}", path.display()))
}

fn disable_one(dirs: &Dirs, service: &str) -> Result<String, String> {
    let path = dirs.etc.join(service);
    refuse_symlink(&path)?;
    if !path.exists() {
        return Ok(format!(
            "{service}: not enabled (no file in {})",
            dirs.etc.display()
        ));
    }
    let content = read_text(&path)?;
    let (kept, removed) = remove_lines(&content, is_our_line);
    if removed == 0 {
        return Ok(format!("{service}: not enabled"));
    }
    rewrite(&path, service, &kept)?;
    Ok(format!("{service}: disabled, removed {removed} line(s)"))
}

fn include_target(line: &str) -> Option<&str> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    match tokens.as_slice() {
        ["@include", name] | ["auth" | "-auth", "include" | "substack", name] => Some(name),
        _ => None,
    }
}

fn any_include_target(line: &str) -> Option<&str> {
    if let Some(name) = include_target(line) {
        return Some(name);
    }
    let tokens: Vec<&str> = line.split_whitespace().collect();
    match tokens.as_slice() {
        ["account" | "-account" | "session" | "-session" | "password" | "-password", "include" | "substack", name] => {
            Some(name)
        }
        _ => None,
    }
}

fn is_shared_stack(dirs: &Dirs, name: &str) -> bool {
    let mut others = list_names(&dirs.etc).unwrap_or_default();
    others.extend(list_names(&dirs.vendor).unwrap_or_default());
    others.retain(|n| n != name && !n.ends_with(BACKUP_SUFFIX) && !n.starts_with('.'));
    others.sort();
    others.dedup();
    others.iter().any(|other| {
        read_service(dirs, other).is_some_and(|text| {
            text.lines()
                .filter_map(any_include_target)
                .any(|t| t == name)
        })
    })
}

fn has_auth_line(text: &str) -> bool {
    text.lines()
        .any(|l| matches!(first_token(l), Some("auth" | "-auth")))
}

fn read_service(dirs: &Dirs, name: &str) -> Option<String> {
    fs::read_to_string(dirs.etc.join(name))
        .or_else(|_| fs::read_to_string(dirs.vendor.join(name)))
        .ok()
}

fn discover_common_stack(dirs: &Dirs) -> Result<String, String> {
    let sudo = read_service(dirs, STACK_DISCOVERY_SERVICE).ok_or_else(|| {
        format!("no PAM service file for `{STACK_DISCOVERY_SERVICE}`, so the common auth stack cannot be discovered")
    })?;
    sudo.lines()
        .filter_map(include_target)
        .filter(|name| !name.contains('/'))
        .find(|name| read_service(dirs, name).is_some_and(|t| has_auth_line(&t)))
        .map(str::to_string)
        .ok_or_else(|| format!("{STACK_DISCOVERY_SERVICE} includes no common auth stack (no `@include X` or `auth include X` pointing to a file with `auth` lines)"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum FingerprintLine {
    Absent,
    System,
    Ours,
}

fn fingerprint_line_reached(dirs: &Dirs, text: &str, depth: usize) -> FingerprintLine {
    let own = text
        .lines()
        .map(|l| match (is_our_fprintd_line(l), is_fprintd_line(l)) {
            (true, _) => FingerprintLine::Ours,
            (_, true) => FingerprintLine::System,
            _ => FingerprintLine::Absent,
        })
        .max()
        .unwrap_or(FingerprintLine::Absent);
    if depth == 0 {
        return own;
    }
    text.lines()
        .filter_map(include_target)
        .filter(|name| !name.contains('/'))
        .filter_map(|name| read_service(dirs, name))
        .map(|included| fingerprint_line_reached(dirs, &included, depth - 1))
        .fold(own, FingerprintLine::max)
}

pub fn security_dir() -> Option<PathBuf> {
    let listing = ["ldconfig", "/sbin/ldconfig"]
        .iter()
        .find_map(|program| Command::new(program).arg("-p").output().ok())?;
    let text = String::from_utf8_lossy(&listing.stdout);
    let libpam = text
        .lines()
        .find(|l| l.contains("libpam.so.0"))?
        .rsplit("=> ")
        .next()?
        .trim();
    Some(fs::canonicalize(libpam).ok()?.parent()?.join("security"))
}

fn fprintd_module_present(dirs: &Dirs) -> bool {
    security_dir().is_some_and(|dir| {
        let relative = dir.strip_prefix("/").unwrap_or(&dir);
        is_regular(&dirs.root.join(relative).join(FPRINTD_MODULE))
    })
}

fn fingerprint_report(dirs: &Dirs, updated: &mut String, requested: bool) -> &'static str {
    if !requested {
        return "fingerprint login not switched on: --no-fingerprint was given";
    }
    match fingerprint_line_reached(dirs, updated, INCLUDE_DEPTH) {
        FingerprintLine::Ours => {
            "fingerprint login already switched on (pam_fprintd after the open-hello line)"
        }
        FingerprintLine::System => {
            "the system already uses pam_fprintd in the common auth stack; it was left as it is"
        }
        FingerprintLine::Absent if !fprintd_module_present(dirs) => {
            "fingerprint login not switched on: pam_fprintd.so is not installed on this machine"
        }
        FingerprintLine::Absent => {
            let line = format!("{FPRINTD_LINE} {FPRINTD_MARKER}");
            *updated = insert_after_our_line(updated, &line);
            "fingerprint login switched on: pam_fprintd was added right after the open-hello line (face first, finger second)"
        }
    }
}

fn enable_common(
    dirs: &Dirs,
    module_args: &[String],
    fingerprint: bool,
    say: &mut dyn FnMut(String),
) -> Result<(), String> {
    let with_fallback = |e: String| format!("{e}\n{FALLBACK}");
    let name = discover_common_stack(dirs).map_err(with_fallback)?;
    let path = materialize(dirs, &name).map_err(with_fallback)?;
    let content = read_text(&path)?;
    let already = content.lines().any(is_our_line);
    let mut updated = if already {
        content.clone()
    } else {
        insert_before(&content, &our_line(module_args), &["auth", "-auth"])
    };
    let fingerprint_note = fingerprint_report(dirs, &mut updated, fingerprint);
    if updated != content {
        rewrite(&path, &name, &updated)?;
    }
    let verb = if already {
        "already enabled in"
    } else {
        "enabled in"
    };
    say(format!("{name}: {verb} {}", path.display()));
    say(fingerprint_note.to_string());
    for service in editable_names(dirs)? {
        if service != name {
            remove_service_lines(dirs, &service, say)?;
        }
    }
    Ok(())
}

fn legacy_services_file(dirs: &Dirs) -> PathBuf {
    let root = dirs
        .etc
        .parent()
        .and_then(Path::parent)
        .unwrap_or(Path::new("/"));
    root.join(LEGACY_SERVICES_PATH.trim_start_matches('/'))
}

fn has_legacy_allowlist(line: &str) -> bool {
    is_our_line(line) && line.split_whitespace().any(|t| t.starts_with("allowlist="))
}

fn without_legacy_allowlist(line: &str) -> String {
    let (body, ending) = match line.strip_suffix('\n') {
        Some(body) => (body, "\n"),
        None => (line, ""),
    };
    let mut kept: Vec<&str> = body
        .split_whitespace()
        .filter(|t| !t.starts_with("allowlist="))
        .collect();
    if kept.is_empty() {
        kept.push(MODULE);
    }
    format!("{}{ending}", kept.join(" "))
}

fn is_regular(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.is_file())
}

fn remove_service_lines(
    dirs: &Dirs,
    service: &str,
    say: &mut dyn FnMut(String),
) -> Result<(), String> {
    let path = dirs.etc.join(service);
    if !is_regular(&path) {
        return Ok(());
    }
    let Ok(content) = fs::read_to_string(&path) else {
        return Ok(());
    };
    let (kept, removed) = remove_lines(&content, is_our_line);
    if removed > 0 {
        rewrite(&path, service, &kept)?;
        say(format!(
            "{service}: removed {removed} per-service line(s), the common stack covers it"
        ));
    }
    Ok(())
}

fn editable_names(dirs: &Dirs) -> Result<Vec<String>, String> {
    let mut names = list_names(&dirs.etc)?;
    names.retain(|n| !n.ends_with(BACKUP_SUFFIX) && !n.starts_with('.'));
    names.sort();
    Ok(names)
}

fn disable_everywhere(dirs: &Dirs, say: &mut dyn FnMut(String)) -> Result<(), String> {
    let mut touched = 0;
    for name in editable_names(dirs)? {
        let path = dirs.etc.join(&name);
        let Some(content) = is_regular(&path)
            .then(|| fs::read_to_string(&path).ok())
            .flatten()
        else {
            continue;
        };
        let (kept, removed) = remove_lines(&content, |l| is_our_line(l) || is_our_fprintd_line(l));
        if removed > 0 {
            rewrite(&path, &name, &kept)?;
            say(format!("{name}: disabled, removed {removed} line(s)"));
            touched += 1;
        }
    }
    if touched == 0 {
        say("not enabled anywhere".to_string());
    }
    Ok(())
}

fn report_common_stack(dirs: &Dirs, say: &mut dyn FnMut(String)) {
    match discover_common_stack(dirs) {
        Ok(name) => {
            let path = dirs.etc.join(&name);
            let state = match fs::symlink_metadata(&path) {
                Ok(m) if m.file_type().is_symlink() => "symlink (not editable)",
                Ok(_) if read_service(dirs, &name).is_some_and(|t| t.lines().any(is_our_line)) => {
                    "line present"
                }
                _ => "line absent",
            };
            say(format!("common stack: {name}, {state}"));
            let fingerprint = match read_service(dirs, &name)
                .map(|t| fingerprint_line_reached(dirs, &t, INCLUDE_DEPTH))
            {
                Some(FingerprintLine::Ours) => "present, added by open-hello",
                Some(FingerprintLine::System) => "present, not added by open-hello",
                _ => "absent",
            };
            say(format!("fingerprint line (pam_fprintd): {fingerprint}"));
        }
        Err(reason) => say(format!("common stack: not found ({reason})")),
    }
}

fn status(dirs: &Dirs, say: &mut dyn FnMut(String)) -> Result<(), String> {
    report_common_stack(dirs, say);
    let common = discover_common_stack(dirs).ok();
    let mut names = list_names(&dirs.etc)?;
    names.sort();
    for name in names {
        let path = dirs.etc.join(&name);
        let state = match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => "symlink (not editable)",
            Ok(meta) if meta.is_file() => match fs::read_to_string(&path) {
                Ok(text) if text.lines().any(is_our_line) => "enabled",
                Ok(_) => "disabled",
                Err(_) => "unreadable",
            },
            _ => continue,
        };
        let note = if state == "enabled" && common.as_deref() != Some(name.as_str()) {
            " (per-service line)"
        } else {
            ""
        };
        say(format!("{name}: {state}{note}"));
    }
    Ok(())
}

fn list_names(dir: &Path) -> Result<Vec<String>, String> {
    let entries = fs::read_dir(dir).map_err(|e| format!("cannot list {}: {e}", dir.display()))?;
    Ok(entries
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .collect())
}

fn is_ours(text: &str) -> bool {
    text.contains(MODULE)
}

fn migrate(dirs: &Dirs, say: &mut dyn FnMut(String)) -> Result<usize, String> {
    let mut changes = 0;
    let Ok(_) = fs::read_dir(&dirs.etc) else {
        return Ok(0);
    };
    let mut names = list_names(&dirs.etc)?;
    names.sort();
    for name in names.iter().filter(|n| {
        !OLD_STACK_FILES.contains(&n.as_str()) && !n.ends_with(BACKUP_SUFFIX) && !n.starts_with('.')
    }) {
        let path = dirs.etc.join(name);
        let regular = fs::symlink_metadata(&path).is_ok_and(|m| m.is_file());
        let Some(content) = regular.then(|| fs::read_to_string(&path).ok()).flatten() else {
            continue;
        };
        let (kept, removed) = remove_lines(&content, is_old_include);
        if removed > 0 {
            rewrite(&path, name, &kept)?;
            say(format!(
                "migrated: removed {removed} old `auth include` line(s) from {}",
                path.display()
            ));
            changes += removed;
        }
    }
    for name in &names {
        let path = dirs.etc.join(name);
        let regular = fs::symlink_metadata(&path).is_ok_and(|m| m.is_file());
        let Some(content) = regular.then(|| fs::read_to_string(&path).ok()).flatten() else {
            continue;
        };
        if name.ends_with(BACKUP_SUFFIX)
            || name.starts_with('.')
            || !content.lines().any(has_legacy_allowlist)
        {
            continue;
        }
        let migrated: String = content
            .split_inclusive('\n')
            .map(|l| {
                if has_legacy_allowlist(l) {
                    without_legacy_allowlist(l)
                } else {
                    l.to_string()
                }
            })
            .collect();
        rewrite(&path, name, &migrated)?;
        say(format!(
            "migrated: dropped the retired `allowlist=` argument from {}",
            path.display()
        ));
        changes += 1;
    }
    remove_legacy_services_file(dirs, say, &mut changes)?;
    for name in OLD_STACK_FILES {
        let path = dirs.etc.join(name);
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        let ours = meta.is_file() && fs::read_to_string(&path).is_ok_and(|t| is_ours(&t));
        if ours {
            fs::remove_file(&path).map_err(|e| format!("cannot remove {}: {e}", path.display()))?;
            say(format!(
                "migrated: removed old stack file {}",
                path.display()
            ));
            changes += 1;
        } else {
            say(format!(
                "kept {}: its content is not an open-hello stack",
                path.display()
            ));
        }
    }
    Ok(changes)
}

fn remove_legacy_services_file(
    dirs: &Dirs,
    say: &mut dyn FnMut(String),
    changes: &mut usize,
) -> Result<(), String> {
    let path = legacy_services_file(dirs);
    let ours = fs::symlink_metadata(&path).is_ok_and(|m| m.is_file())
        && fs::read_to_string(&path).is_ok_and(|t| t.starts_with(LEGACY_SERVICES_HEADER));
    if ours {
        fs::remove_file(&path).map_err(|e| format!("cannot remove {}: {e}", path.display()))?;
        say(format!("migrated: removed retired {}", path.display()));
        *changes += 1;
    }
    Ok(())
}
