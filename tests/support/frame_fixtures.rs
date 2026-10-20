use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureFrame {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u8>,
}

#[derive(Debug)]
pub struct FixtureIdentity {
    pub name: String,
    pub frames: Vec<FixtureFrame>,
}

pub fn write_pgm(path: &Path, frame: &FixtureFrame) -> std::io::Result<()> {
    let mut bytes = format!("P5\n{} {}\n255\n", frame.width, frame.height).into_bytes();
    bytes.extend(&frame.pixels);
    fs::write(path, bytes)
}

pub fn read_pgm(path: &Path) -> Result<FixtureFrame, String> {
    let bytes = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut cursor = 0;
    let mut token = |bytes: &[u8]| -> Result<String, String> {
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let start = cursor;
        while cursor < bytes.len() && !bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if start == cursor {
            return Err(format!("{}: truncated PGM header", path.display()));
        }
        Ok(String::from_utf8_lossy(&bytes[start..cursor]).into_owned())
    };
    if token(&bytes)? != "P5" {
        return Err(format!("{}: not a binary PGM (P5)", path.display()));
    }
    let parse = |text: String| text.parse::<u32>().map_err(|_| format!("{}: invalid PGM header number `{text}`", path.display()));
    let width = parse(token(&bytes)?)?;
    let height = parse(token(&bytes)?)?;
    if parse(token(&bytes)?)? != 255 {
        return Err(format!("{}: only 8-bit PGM is supported", path.display()));
    }
    let pixels = bytes[cursor + 1..].to_vec();
    if pixels.len() != (width as usize) * (height as usize) {
        return Err(format!("{}: expected {} pixel bytes, found {}", path.display(), width * height, pixels.len()));
    }
    Ok(FixtureFrame { width, height, pixels })
}

pub fn load_identity(directory: &Path) -> Result<FixtureIdentity, String> {
    let mut files: Vec<PathBuf> = fs::read_dir(directory)
        .map_err(|e| format!("{}: {e}", directory.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "pgm"))
        .collect();
    files.sort();
    if files.is_empty() {
        return Err(format!("{}: no .pgm frames found", directory.display()));
    }
    let frames = files.iter().map(|f| read_pgm(f)).collect::<Result<Vec<_>, _>>()?;
    let name = directory.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    Ok(FixtureIdentity { name, frames })
}

pub fn load_all_identities(root: &Path) -> Result<Vec<FixtureIdentity>, String> {
    let mut directories: Vec<PathBuf> = fs::read_dir(root)
        .map_err(|e| format!("{}: {e}", root.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    directories.sort();
    directories.iter().map(|d| load_identity(d)).collect()
}
