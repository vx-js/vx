use anyhow::{Context, Result, anyhow};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct ProjectPaths {
    pub root: PathBuf,
    pub package_json: PathBuf,
    pub lockfile: PathBuf,
    pub node_modules: PathBuf,
    pub vx_dir: PathBuf,
    pub store_dir: PathBuf,
    pub tmp_dir: PathBuf,
}

impl ProjectPaths {
    pub fn discover() -> Result<Self> {
        let cwd = std::env::current_dir().context("get current dir")?;
        let root = find_project_root(&cwd)
            .ok_or_else(|| anyhow!("no package.json found (run `vx init` first)"))?;
        Self::for_root(root)
    }

    pub fn for_root(root: PathBuf) -> Result<Self> {
        let vx_dir = vx_dir_for_path(&root)?;
        Self::for_root_with_vx(root, vx_dir)
    }

    pub fn for_root_with_vx(root: PathBuf, vx_dir: PathBuf) -> Result<Self> {
        let package_json = root.join("package.json");
        let store_dir = vx_dir.join("store");
        let tmp_dir = vx_dir.join("tmp");
        Ok(Self {
            root: root.clone(),
            package_json,
            lockfile: root.join("vx.lock"),
            node_modules: root.join("node_modules"),
            vx_dir,
            store_dir,
            tmp_dir,
        })
    }
}

fn find_project_root(start: &Path) -> Option<PathBuf> {
    let mut cur = Some(start);
    while let Some(dir) = cur {
        if dir.join("package.json").exists() {
            return Some(dir.to_path_buf());
        }
        cur = dir.parent();
    }
    None
}

pub(crate) fn vx_dir_for_path(path: &Path) -> Result<PathBuf> {
    #[cfg(windows)]
    {
        use std::path::Component;

        let mut comps = path.components();
        let Some(Component::Prefix(prefix)) = comps.next() else {
            // Relative paths or UNC paths: keep per-project directory.
            return Ok(path.join(".vx"));
        };

        let drive = match prefix.kind() {
            std::path::Prefix::Disk(d) | std::path::Prefix::VerbatimDisk(d) => {
                (d as char).to_ascii_uppercase()
            }
            _ => return Ok(path.join(".vx")),
        };

        vx_dir_windows_for_drive(drive, userprofile_dir().ok())
    }
    #[cfg(not(windows))]
    {
        let _ = path; // unused on non-windows
        home_vx_dir()
    }
}

#[cfg(windows)]
fn vx_dir_windows_for_drive(drive: char, userprofile: Option<PathBuf>) -> Result<PathBuf> {
    if drive == 'C' {
        let userprofile = userprofile.ok_or_else(|| anyhow!("USERPROFILE is not set"))?;
        return Ok(userprofile.join(".vx"));
    }
    Ok(PathBuf::from(format!("{drive}:\\")).join(".vx"))
}

#[cfg(windows)]
fn userprofile_dir() -> Result<PathBuf> {
    if let Some(up) = std::env::var_os("USERPROFILE") {
        return Ok(PathBuf::from(up));
    }
    let hd = std::env::var_os("HOMEDRIVE").ok_or_else(|| anyhow!("USERPROFILE is not set"))?;
    let hp = std::env::var_os("HOMEPATH").ok_or_else(|| anyhow!("USERPROFILE is not set"))?;
    let mut p = PathBuf::from(hd);
    p.push(hp);
    Ok(p)
}

#[cfg(not(windows))]
fn home_vx_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?;
    Ok(PathBuf::from(home).join(".vx"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(windows)]
    fn vx_dir_windows_c_goes_to_userprofile() {
        let p = vx_dir_windows_for_drive('C', Some(PathBuf::from(r"C:\Users\TestUser"))).unwrap();
        assert_eq!(p, PathBuf::from(r"C:\Users\TestUser\.vx"));
    }

    #[test]
    #[cfg(windows)]
    fn vx_dir_windows_non_c_goes_to_drive_root() {
        let p = vx_dir_windows_for_drive('D', None).unwrap();
        assert_eq!(p, PathBuf::from(r"D:\.vx"));
    }

    #[test]
    #[cfg(not(windows))]
    fn vx_dir_unix_goes_to_home() {
        // Temporarily set HOME for this test
        std::env::set_var("HOME", "/home/testuser");
        let p = home_vx_dir().unwrap();
        assert_eq!(p, PathBuf::from("/home/testuser/.vx"));
    }
}
