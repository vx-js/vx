use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkMode {
    Auto,
    Tree,
    Symlink,
    Junction,
}

pub fn current_link_mode_name() -> String {
    match link_mode() {
        LinkMode::Auto => "auto",
        LinkMode::Tree => "tree",
        LinkMode::Symlink => "symlink",
        LinkMode::Junction => "junction",
    }
    .to_string()
}

fn link_mode() -> LinkMode {
    let raw = std::env::var("VX_LINK_MODE").unwrap_or_default();
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "auto" => default_link_mode(),
        "tree" | "copy" => LinkMode::Tree,
        "symlink" => LinkMode::Symlink,
        "junction" => LinkMode::Junction,
        _ => default_link_mode(),
    }
}

fn default_link_mode() -> LinkMode {
    if cfg!(windows) {
        LinkMode::Junction
    } else {
        LinkMode::Auto
    }
}

pub fn remove_dir_all_if_exists(path: &Path) -> Result<()> {
    if path.exists() {
        fs::remove_dir_all(path).with_context(|| format!("remove {}", path.display()))?;
    }
    Ok(())
}

pub fn ensure_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("create dir {}", path.display()))?;
    Ok(())
}

pub fn link_tree(store_dir: &Path, dest_dir: &Path) -> Result<()> {
    ensure_dir(dest_dir)?;
    for entry in WalkDir::new(store_dir).follow_links(false) {
        let entry = entry?;
        let src = entry.path();
        let rel = src.strip_prefix(store_dir).unwrap();
        if rel.as_os_str().is_empty() {
            continue;
        }
        let dst = dest_dir.join(rel);
        if entry.file_type().is_dir() {
            ensure_dir(&dst)?;
            continue;
        }
        if entry.file_type().is_file() {
            if let Some(parent) = dst.parent() {
                ensure_dir(parent)?;
            }
            if dst.exists() {
                fs::remove_file(&dst).with_context(|| format!("remove file {}", dst.display()))?;
            }
            if fs::hard_link(src, &dst).is_err() {
                fs::copy(src, &dst).with_context(|| {
                    format!("copy {} -> {}", src.display(), dst.display())
                })?;
            }
            continue;
        }
        // Skip special files / symlinks for now (prototype).
    }
    Ok(())
}

pub fn link_dir_fast(store_dir: &Path, dest_dir: &Path) -> Result<bool> {
    if try_link_dir_platform(store_dir, dest_dir, link_mode())? {
        return Ok(true);
    }
    Ok(false)
}

#[cfg(windows)]
fn try_link_dir_platform(store_dir: &Path, dest_dir: &Path, mode: LinkMode) -> Result<bool> {
    use std::os::windows::fs as winfs;
    match mode {
        LinkMode::Tree => Ok(false),
        LinkMode::Symlink => Ok(winfs::symlink_dir(store_dir, dest_dir).is_ok()),
        LinkMode::Junction => {
            if junction::create(store_dir, dest_dir).is_ok() {
                return Ok(true);
            }
            Ok(winfs::symlink_dir(store_dir, dest_dir).is_ok())
        }
        LinkMode::Auto => {
            if winfs::symlink_dir(store_dir, dest_dir).is_ok() {
                return Ok(true);
            }
            Ok(false)
        }
    }
}

#[cfg(not(windows))]
fn try_link_dir_platform(store_dir: &Path, dest_dir: &Path, mode: LinkMode) -> Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs as unixfs;
        match mode {
            LinkMode::Tree => return Ok(false),
            LinkMode::Junction => return Ok(false),
            LinkMode::Symlink | LinkMode::Auto => {
                if unixfs::symlink(store_dir, dest_dir).is_ok() {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

pub fn node_modules_package_dir(node_modules: &Path, name: &str) -> Result<PathBuf> {
    if let Some((scope, pkg)) = name.strip_prefix('@').and_then(|s| s.split_once('/')) {
        Ok(node_modules.join(format!("@{scope}")).join(pkg))
    } else {
        Ok(node_modules.join(name))
    }
}
