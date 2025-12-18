use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

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
    if try_link_dir_platform(store_dir, dest_dir)? {
        return Ok(true);
    }
    Ok(false)
}

#[cfg(windows)]
fn try_link_dir_platform(store_dir: &Path, dest_dir: &Path) -> Result<bool> {
    // Prefer NTFS junctions (no admin required) for very fast installs.
    if junction::create(store_dir, dest_dir).is_ok() {
        return Ok(true);
    }

    // Fall back to symlink if available (requires Developer Mode or elevated privileges).
    use std::os::windows::fs as winfs;
    if winfs::symlink_dir(store_dir, dest_dir).is_ok() {
        return Ok(true);
    }
    Ok(false)
}

#[cfg(not(windows))]
fn try_link_dir_platform(store_dir: &Path, dest_dir: &Path) -> Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs as unixfs;
        if unixfs::symlink(store_dir, dest_dir).is_ok() {
            return Ok(true);
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
