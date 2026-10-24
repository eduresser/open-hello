use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const PAM_USAGE: &str = "usage: openhello-cli pam <enable [service...] | disable [service...] | status | migrate | upgrade> [--root DIR] [--arg flag|key=value]...";

const MODULE: &str = "pam_openhello.so";
const CAPTURE_ARG: &str = "capture";
const LEGACY_SERVICES_PATH: &str = "/etc/openhello/pam-services";
const LEGACY_SERVICES_HEADER: &str = "# Services where pam_openhello may use the camera";
const FALLBACK: &str =
    "per-service fallback: sudo openhello-cli pam enable <service>... (one service per file in /etc/pam.d)";
const COMMON_STACKS: &[&str] = &[
    "common-auth",
    "system-auth",
    "password-auth",
    "common-account",
    "common-session",
    "common-password",
    "system-login",
    "postlogin",
];
const OLD_STACK_FILES: &[&str] = &["sudo-openhello", "openhello-lockscreen"];
const OLD_INCLUDES: &[&str] = &["sudo-openhello", "openhello-lockscreen"];
const BACKUP_SUFFIX: &str = ".openhello.bak";
const WRAPPER_HEADER: &str =
    "# open-hello wrapper: `openhello-cli pam disable` restores the symlink to";

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
    Upgrade,
}

struct Request {
    action: Action,
    root: Option<PathBuf>,
    module_args: Vec<String>,
    services: Vec<String>,
}

struct Dirs {
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
        Some("upgrade") => Action::Upgrade,
        Some(other) => return Err(usage(format!("unknown pam command `{other}`"))),
        None => return Err(usage("a pam command is required")),
    };
    let mut root = None;
    let mut module_args = Vec::new();
    let mut services = Vec::new();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                root = Some(PathBuf::from(
                    iter.next()
                        .ok_or_else(|| usage("--root needs a directory"))?,
                ))
            }
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
    if matches!(action, Action::Status | Action::Migrate | Action::Upgrade) && !services.is_empty() {
        return Err(usage("this command takes no service names"));
    }
    Ok(Request {
        action,
        root,
        module_args,
        services,
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

fn validate_service(name: &str) -> Result<(), String> {
    let valid_chars = name
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'));
    if name.is_empty() || name.starts_with('.') || !valid_chars {
        return Err(format!(
            "`{name}` is not a valid service name (only a-z, 0-9, `.`, `_`, `-`; no `/`)"
        ));
    }
    if COMMON_STACKS.contains(&name) {
        return Err(format!("`{name}` is a shared stack; shared stacks are never edited, enable the services that include it instead"));
    }
    Ok(())
}

pub fn run(args: &[String], out: &mut dyn Write) -> Result<(), PamFailure> {
    let request = parse(args)?;
    let injected = request.root.is_some();
    let root = request.root.clone().unwrap_or_else(|| PathBuf::from("/"));
    let dirs = Dirs {
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
        Action::Upgrade => upgrade_common(&dirs, &mut say).map_err(failed),
        Action::Enable | Action::Disable => {
            if request.action == Action::Enable {
                migrate(&dirs, &mut say).map_err(failed)?;
            }
            if request.services.is_empty() {
                let result = match request.action {
                    Action::Enable => enable_common(&dirs, &request.module_args, &mut say),
                    _ => disable_everywhere(&dirs, &mut say),
                };
                return result.map_err(failed);
            }
            let mut problems = Vec::new();
            for service in &request.services {
                let outcome = validate_service(service).and_then(|_| match request.action {
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

fn is_capture_line(line: &str) -> bool {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    matches!(tokens.as_slice(), ["auth", "optional", MODULE, rest @ ..] if rest.contains(&CAPTURE_ARG))
}

fn is_any_line(line: &str) -> bool {
    is_our_line(line) || is_capture_line(line)
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

// Appending after the last auth line keeps every `[success=N]` jump count of the stack valid.
fn insert_after_last_auth(content: &str, line: &str) -> String {
    let lines: Vec<&str> = content.split_inclusive('\n').collect();
    let at = lines
        .iter()
        .rposition(|l| matches!(first_token(l), Some("auth" | "-auth")))
        .map_or(lines.len(), |i| i + 1);
    let mut result = String::with_capacity(content.len() + line.len() + 2);
    for (index, existing) in lines.iter().enumerate() {
        if index == at {
            result.push_str(line);
            result.push('\n');
        }
        result.push_str(existing);
        if index + 1 == at && !existing.ends_with('\n') {
            result.push('\n');
        }
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
    with_args(format!("auth sufficient {MODULE}"), module_args)
}

fn capture_line(module_args: &[String]) -> String {
    with_args(format!("auth optional {MODULE} {CAPTURE_ARG}"), module_args)
}

fn with_args(mut line: String, module_args: &[String]) -> String {
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
    if let Some(message) = unwrap_if_wrapper(dirs, service, &content)? {
        return Ok(message);
    }
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
    let sudo = read_service(dirs, "sudo").ok_or_else(|| {
        "no PAM service file for `sudo`, so the common auth stack cannot be discovered".to_string()
    })?;
    sudo.lines()
        .filter_map(include_target)
        .filter(|name| !name.contains('/'))
        .find(|name| read_service(dirs, name).is_some_and(|t| has_auth_line(&t)))
        .map(str::to_string)
        .ok_or_else(|| "sudo includes no common auth stack (no `@include X` or `auth include X` pointing to a file with `auth` lines)".to_string())
}

fn enable_common(
    dirs: &Dirs,
    module_args: &[String],
    say: &mut dyn FnMut(String),
) -> Result<(), String> {
    let with_fallback = |e: String| format!("{e}\n{FALLBACK}");
    let name = discover_common_stack(dirs).map_err(with_fallback)?;
    if let Some(target) = sibling_symlink_target(dirs, &name) {
        wrap_symlink(dirs, &name, &target, module_args)?;
        say(format!(
            "{name}: enabled through a wrapper that includes {target}, which your PAM tool keeps managing"
        ));
        return remove_other_service_lines(dirs, &name, say);
    }
    let path = materialize(dirs, &name).map_err(with_fallback)?;
    let content = read_text(&path)?;
    let first = content.lines().any(is_our_line);
    let capture = content.lines().any(is_capture_line);
    if first && capture {
        say(format!("{name}: already enabled in {}", path.display()));
    } else {
        let mut updated = content;
        if !first {
            updated = insert_before(&updated, &our_line(module_args), &["auth", "-auth"]);
        }
        if !capture {
            updated = insert_after_last_auth(&updated, &capture_line(module_args));
        }
        rewrite(&path, &name, &updated)?;
        say(if first {
            format!("{name}: added the capture line in {}", path.display())
        } else {
            format!("{name}: enabled in {}", path.display())
        });
    }
    remove_other_service_lines(dirs, &name, say)
}

fn upgrade_common(dirs: &Dirs, say: &mut dyn FnMut(String)) -> Result<(), String> {
    let Ok(name) = discover_common_stack(dirs) else {
        say("common stack: not found, nothing to upgrade".to_string());
        return Ok(());
    };
    let path = dirs.etc.join(&name);
    let content = is_regular(&path)
        .then(|| fs::read_to_string(&path).ok())
        .flatten()
        .unwrap_or_default();
    let Some(first) = content.lines().find(|l| is_our_line(l)) else {
        say(format!("{name}: not enabled, left alone"));
        return Ok(());
    };
    if content.lines().any(is_capture_line) {
        say(format!("{name}: capture line already present"));
        return Ok(());
    }
    let args: Vec<String> = first.split_whitespace().skip(3).map(str::to_string).collect();
    rewrite(
        &path,
        &name,
        &insert_after_last_auth(&content, &capture_line(&args)),
    )?;
    say(format!("{name}: added the capture line in {}", path.display()));
    Ok(())
}

fn remove_other_service_lines(
    dirs: &Dirs,
    common: &str,
    say: &mut dyn FnMut(String),
) -> Result<(), String> {
    for service in editable_names(dirs)? {
        if service != common {
            remove_service_lines(dirs, &service, say)?;
        }
    }
    Ok(())
}

fn sibling_symlink_target(dirs: &Dirs, name: &str) -> Option<String> {
    let target = fs::read_link(dirs.etc.join(name)).ok()?;
    let target = target.to_str()?;
    (!target.contains('/') && is_regular(&dirs.etc.join(target))).then(|| target.to_string())
}

fn wrapper_content(module_args: &[String], target: &str) -> String {
    format!(
        "{WRAPPER_HEADER} {target}\n{}\nauth include {target}\n{}\n",
        our_line(module_args),
        capture_line(module_args)
    )
}

fn wrapped_target(content: &str) -> Option<&str> {
    let lines: Vec<&str> = content.lines().filter(|l| first_token(l).is_some()).collect();
    let include = match lines.as_slice() {
        [ours, include] if is_our_line(ours) => include,
        [ours, include, capture] if is_our_line(ours) && is_capture_line(capture) => include,
        _ => return None,
    };
    match include.split_whitespace().collect::<Vec<_>>()[..] {
        ["auth", "include", target] if !target.contains('/') => Some(target),
        _ => None,
    }
}

fn wrap_symlink(
    dirs: &Dirs,
    name: &str,
    target: &str,
    module_args: &[String],
) -> Result<(), String> {
    let target_path = dirs.etc.join(target);
    let meta = fs::metadata(&target_path)
        .map_err(|e| format!("cannot read {}: {e}", target_path.display()))?;
    write_atomic(
        &dirs.etc.join(name),
        wrapper_content(module_args, target).as_bytes(),
        meta.mode(),
        Some((meta.uid(), meta.gid())),
    )
}

fn restore_symlink(dirs: &Dirs, name: &str, target: &str) -> Result<(), String> {
    let path = dirs.etc.join(name);
    let temp = path.with_file_name(format!(".{name}.openhello.tmp"));
    let _ = fs::remove_file(&temp);
    std::os::unix::fs::symlink(target, &temp)
        .and_then(|_| fs::rename(&temp, &path))
        .map_err(|e| {
            let _ = fs::remove_file(&temp);
            format!("cannot restore {} as a symlink to {target}: {e}", path.display())
        })
}

fn unwrap_if_wrapper(dirs: &Dirs, name: &str, content: &str) -> Result<Option<String>, String> {
    let Some(target) = wrapped_target(content) else {
        return Ok(None);
    };
    if !is_regular(&dirs.etc.join(target)) {
        return Ok(None);
    }
    restore_symlink(dirs, name, target)?;
    Ok(Some(format!("{name}: disabled, restored the symlink to {target}")))
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
        if let Some(message) = unwrap_if_wrapper(dirs, &name, &content)? {
            say(message);
            touched += 1;
            continue;
        }
        let (kept, removed) = remove_lines(&content, is_any_line);
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
            let text = read_service(dirs, &name).unwrap_or_default();
            let capture = if text.lines().any(is_capture_line) {
                "capture line present"
            } else {
                "capture line absent"
            };
            let state = match fs::symlink_metadata(&path) {
                Ok(m) if m.file_type().is_symlink() => "symlink (not editable)".to_string(),
                Ok(_) if text.lines().any(is_our_line) => format!("line present, {capture}"),
                _ => format!("line absent, {capture}"),
            };
            say(format!("common stack: {name}, {state}"));
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
