use anyhow::{anyhow, Context, Result};
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
    // Check for symlink first (symlink_metadata doesn't follow symlinks)
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            // Remove symlink (use remove_file for symlinks on Unix)
            fs::remove_file(path).with_context(|| format!("remove symlink {}", path.display()))?;
            return Ok(());
        }
    }

    if path.exists() {
        let result = fs::remove_dir_all(path);
        if let Err(e) = result {
            // Check for path length errors (OS error 36 on Linux, 206 on Windows)
            let is_path_too_long = e
                .raw_os_error()
                .map(|code| code == 36 || code == 206)
                .unwrap_or(false)
                || e.to_string().contains("File name too long")
                || e.to_string().contains("path too long")
                || e.to_string().contains("filename too long");

            if is_path_too_long {
                // If we can't remove due to path length, that's okay - we'll try to overwrite
                // But check the path length before proceeding
                check_path_length(path)?;
            } else {
                return Err(e).with_context(|| format!("remove {}", path.display()));
            }
        }
    }
    Ok(())
}

fn check_path_length(path: &Path) -> Result<()> {
    // Check path length limits
    // Linux: typically 4096 bytes, Windows: 260 chars by default (can be extended)
    // Use the path as bytes for accurate checking on Linux
    let path_bytes = path.as_os_str().len();
    let max_length = if cfg!(windows) {
        // Windows: 260 characters (MAX_PATH)
        260
    } else {
        // Linux: 4096 bytes (PATH_MAX)
        4096
    };

    if path_bytes > max_length {
        return Err(anyhow!(
            "Path too long ({} bytes, max {}): {}\n\
            This usually happens with deeply nested dependencies in nested layout.\n\
            Solution: Use flat layout by setting VX_LAYOUT=flat environment variable,\n\
            or use symlinks by setting VX_LINK_MODE=symlink",
            path_bytes,
            max_length,
            path.display()
        ));
    }
    Ok(())
}

pub fn ensure_dir(path: &Path) -> Result<()> {
    check_path_length(path)?;
    let result = fs::create_dir_all(path);
    if let Err(e) = result {
        // Check for path length errors (OS error 36 on Linux, 206 on Windows)
        let is_path_too_long = e
            .raw_os_error()
            .map(|code| code == 36 || code == 206)
            .unwrap_or(false)
            || e.to_string().contains("File name too long")
            || e.to_string().contains("path too long")
            || e.to_string().contains("filename too long");

        if is_path_too_long {
            return Err(anyhow!(
                "Path too long: {}\n\
                This usually happens with deeply nested dependencies in nested layout.\n\
                Solution: Use flat layout by setting VX_LAYOUT=flat environment variable,\n\
                or use symlinks by setting VX_LINK_MODE=symlink",
                path.display()
            )
            .context(format!("create dir {}", path.display())));
        }
        return Err(e).with_context(|| format!("create dir {}", path.display()));
    }
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
                let copy_result = fs::copy(src, &dst);
                if let Err(e) = copy_result {
                    // Check for path length errors (OS error 36 on Linux, 206 on Windows)
                    let is_path_too_long = e
                        .raw_os_error()
                        .map(|code| code == 36 || code == 206)
                        .unwrap_or(false)
                        || e.to_string().contains("File name too long")
                        || e.to_string().contains("path too long")
                        || e.to_string().contains("filename too long");

                    if is_path_too_long {
                        return Err(anyhow!(
                            "Path too long: {}\n\
                            This usually happens with deeply nested dependencies.\n\
                            Try using flat layout by setting VX_LAYOUT=flat, or use symlinks by setting VX_LINK_MODE=symlink",
                            dst.display()
                        ).context(format!("copy {} -> {}", src.display(), dst.display())));
                    }
                    return Err(e)
                        .with_context(|| format!("copy {} -> {}", src.display(), dst.display()));
                }
            }
            continue;
        }
        // Skip special files / symlinks for now (prototype).
    }
    Ok(())
}

pub fn link_dir_fast(store_dir: &Path, dest_dir: &Path) -> Result<bool> {
    // Ensure parent directory exists (important for scoped packages like @scope/pkg)
    if let Some(parent) = dest_dir.parent() {
        ensure_dir(parent)?;
    }
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
                // Remove existing file/symlink if present
                if dest_dir.exists() || dest_dir.is_symlink() {
                    let _ = fs::remove_file(dest_dir);
                    let _ = fs::remove_dir_all(dest_dir);
                }
                // Verify store_dir exists and is a directory
                if !store_dir.is_dir() {
                    return Ok(false);
                }
                match unixfs::symlink(store_dir, dest_dir) {
                    Ok(()) => return Ok(true),
                    Err(_e) => {
                        // Symlink failed, fall back to copy
                        return Ok(false);
                    }
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (store_dir, dest_dir, mode);
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
