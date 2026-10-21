use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const PAM_USAGE: &str = "usage: openhello-cli pam <enable [service...] | disable <service>... | status | migrate> [--root DIR] [--arg flag|key=value]...";

const MODULE: &str = "pam_openhello.so";
const DEFAULT_SERVICES: &[&str] = &["sudo"];
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
const OLD_STACK_FILES: &[&str] = &["sudo-openhello", "openhello-lockscreen", "kde-face"];
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
    if matches!(action, Action::Status | Action::Migrate) && !services.is_empty() {
        return Err(usage("this command takes no service names"));
    }
    if action == Action::Disable && services.is_empty() {
        return Err(usage("disable needs at least one service name"));
    }
    if action == Action::Enable && services.is_empty() {
        services = DEFAULT_SERVICES.iter().map(|s| s.to_string()).collect();
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
        Action::Enable | Action::Disable => {
            if request.action == Action::Enable {
                migrate(&dirs, &mut say).map_err(failed)?;
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

fn is_old_include(line: &str) -> bool {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    matches!(tokens.as_slice(), ["auth", "include", name] if OLD_INCLUDES.contains(name))
}

fn insert_line(content: &str, line: &str) -> String {
    let lines: Vec<&str> = content.split_inclusive('\n').collect();
    let at = lines
        .iter()
        .position(|l| matches!(first_token(l), Some("auth" | "-auth" | "@include")))
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

fn status(dirs: &Dirs, say: &mut dyn FnMut(String)) -> Result<(), String> {
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
        say(format!("{name}: {state}"));
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
    text.contains(MODULE) || text.contains("include openhello-lockscreen")
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
