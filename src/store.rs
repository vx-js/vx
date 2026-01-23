use crate::fsutil::{
    ensure_dir, link_dir_fast, link_tree, node_modules_package_dir, remove_dir_all_if_exists,
};
use crate::integrity::{Algo, Integrity, hex};
use crate::lockfile::Lockfile;
use crate::paths::ProjectPaths;
use crate::registry::RegistryClient;
use anyhow::{Context, Result, anyhow};
use futures::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use sha1::{Digest, Sha1};
use sha2::Sha512;
use std::collections::BTreeMap;
use std::fs;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tar::Archive;
use tokio::sync::Semaphore;

pub struct Store {
    paths: ProjectPaths,
    registry: RegistryClient,
}

pub struct InstallOptions {
    pub prune_node_modules: bool,
}

#[derive(Debug, Clone, Copy)]
enum Layout {
    Flat,
    Nested,
}

impl Store {
    pub fn new(paths: ProjectPaths) -> Self {
        Self {
            registry: RegistryClient::from_env().expect("registry client"),
            paths,
        }
    }

    pub fn ensure_bins_from_lock(&self, lock: &Lockfile) -> Result<()> {
        match detect_layout() {
            Layout::Flat => self.ensure_bins_flat(lock),
            Layout::Nested => self.ensure_bins_nested(lock),
        }
    }

    pub async fn install_from_lock(&self, lock: &Lockfile, options: &InstallOptions) -> Result<()> {
        ensure_dir(&self.paths.vx_dir)?;
        ensure_dir(&self.paths.store_dir)?;
        ensure_dir(&self.paths.tmp_dir)?;

        if options.prune_node_modules {
            remove_dir_all_if_exists(&self.paths.node_modules)?;
        }
        ensure_dir(&self.paths.node_modules)?;

        self.ensure_store(lock).await?;

        match detect_layout() {
            Layout::Flat => self.install_flat(lock),
            Layout::Nested => self.install_nested(lock),
        }
    }

    async fn ensure_store(&self, lock: &Lockfile) -> Result<()> {
        let concurrency = suggested_concurrency();
        let sem = Arc::new(Semaphore::new(concurrency));
        let mut tasks = futures::stream::FuturesUnordered::new();

        let mut missing = Vec::new();
        for node in lock.packages.values() {
            let Some(tarball) = node.tarball.clone() else {
                continue;
            };
            let integrity = node.integrity.clone();
            let store_path = self.store_path(integrity.as_deref(), &tarball)?;
            if !store_path.exists() {
                missing.push((store_path, tarball, integrity));
            }
        }

        if missing.is_empty() {
            return Ok(());
        }

        let total = missing.len() as u64;
        let pb = ProgressBar::new(total);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
                .unwrap()
                .progress_chars("=> "),
        );
        pb.set_message("Fetching packages...");
        pb.enable_steady_tick(Duration::from_millis(100));

        let pb = Arc::new(pb);

        for (store_path, tarball, integrity) in missing {
            let permit = sem.clone().acquire_owned().await.unwrap();
            let registry = self.registry.clone();
            let tmp_dir = self.paths.tmp_dir.clone();
            let pb = pb.clone();
            tasks.push(tokio::spawn(async move {
                let _permit = permit;
                let res = ensure_in_store(
                    &registry,
                    &tmp_dir,
                    &store_path,
                    &tarball,
                    integrity.as_deref(),
                )
                .await;
                pb.inc(1);
                res
            }));
        }

        while let Some(res) = tasks.next().await {
            res.context("store task panicked")??;
        }
        pb.finish_with_message("Fetched");
        Ok(())
    }

    fn install_nested(&self, lock: &Lockfile) -> Result<()> {
        let total = lock.packages.len() as u64;
        let pb = ProgressBar::new(total);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
                .unwrap()
                .progress_chars("=> "),
        );
        pb.set_message("Linking packages...");

        for (name, child_key) in &lock.root.requires {
            self.install_tree(lock, &self.paths.root, name, child_key, &pb)?;
        }
        pb.finish_with_message("Linked");
        Ok(())
    }

    fn install_flat(&self, lock: &Lockfile) -> Result<()> {
        let chosen = choose_flat_set(lock);
        let node_modules = &self.paths.node_modules;
        ensure_dir(node_modules)?;

        let total = chosen.len() as u64;
        let pb = ProgressBar::new(total);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
                .unwrap()
                .progress_chars("=> "),
        );
        pb.set_message("Linking packages...");

        for (name, key) in chosen {
            let node = lock
                .packages
                .get(&key)
                .ok_or_else(|| anyhow!("missing lock node {key}"))?;
            let tarball = node
                .tarball
                .as_deref()
                .ok_or_else(|| anyhow!("missing tarball for {key}"))?;
            let store_dir = self.store_path(node.integrity.as_deref(), tarball)?;
            normalize_store_dir_if_needed(&store_dir)?;
            let dest = node_modules_package_dir(node_modules, &name)?;
            remove_dir_all_if_exists(&dest)?;
            if !link_dir_fast(&store_dir, &dest)? {
                ensure_dir(&dest)?;
                link_tree(&store_dir, &dest)?;
            }
            link_bins_for_package(node_modules, &dest)?;
            pb.inc(1);
        }
        pb.finish_with_message("Linked");
        Ok(())
    }

    fn ensure_bins_flat(&self, lock: &Lockfile) -> Result<()> {
        let chosen = choose_flat_set(lock);
        let node_modules = &self.paths.node_modules;
        if !node_modules.exists() {
            return Ok(());
        }
        for (name, _key) in chosen {
            let dest = node_modules_package_dir(node_modules, &name)?;
            if dest.join("package.json").exists() {
                link_bins_for_package(node_modules, &dest)?;
            }
        }
        Ok(())
    }

    fn ensure_bins_nested(&self, lock: &Lockfile) -> Result<()> {
        for (name, child_key) in &lock.root.requires {
            self.ensure_bins_tree(lock, &self.paths.root, name, child_key)?;
        }
        Ok(())
    }

    fn install_tree(
        &self,
        lock: &Lockfile,
        parent_dir: &Path,
        name: &str,
        key: &str,
        pb: &ProgressBar,
    ) -> Result<()> {
        let node = lock
            .packages
            .get(key)
            .ok_or_else(|| anyhow!("missing lock node {key}"))?;
        let tarball = node
            .tarball
            .as_deref()
            .ok_or_else(|| anyhow!("missing tarball for {key}"))?;
        let store_dir = self.store_path(node.integrity.as_deref(), tarball)?;
        normalize_store_dir_if_needed(&store_dir)?;
        if !store_dir.exists() {
            return Err(anyhow!(
                "store entry missing for {key}: {}",
                store_dir.display()
            ));
        }

        let node_modules = parent_dir.join("node_modules");
        ensure_dir(&node_modules)?;
        let dest = node_modules_package_dir(&node_modules, name)?;
        // Check path length early - ensure_dir will validate and provide helpful error
        remove_dir_all_if_exists(&dest)?;
        if !link_dir_fast(&store_dir, &dest)? {
            ensure_dir(&dest)?;
            link_tree(&store_dir, &dest)?;
        }
        link_bins_for_package(&node_modules, &dest)?;
        pb.inc(1);

        for (dep_name, child_key) in &node.requires {
            self.install_tree(lock, &dest, dep_name, child_key, pb)?;
        }
        Ok(())
    }

    fn ensure_bins_tree(
        &self,
        lock: &Lockfile,
        parent_dir: &Path,
        name: &str,
        key: &str,
    ) -> Result<()> {
        let node = lock
            .packages
            .get(key)
            .ok_or_else(|| anyhow!("missing lock node {key}"))?;
        let node_modules = parent_dir.join("node_modules");
        let dest = node_modules_package_dir(&node_modules, name)?;
        if dest.join("package.json").exists() {
            link_bins_for_package(&node_modules, &dest)?;
        }
        for (dep_name, child_key) in &node.requires {
            self.ensure_bins_tree(lock, &dest, dep_name, child_key)?;
        }
        Ok(())
    }

    fn store_path(&self, integrity: Option<&str>, tarball_url: &str) -> Result<PathBuf> {
        if let Some(integrity) = integrity {
            let parsed = Integrity::parse(integrity)?;
            let hex_key = hex(&parsed.expected);
            let algo_dir = match parsed.algo {
                Algo::Sha512 => "sha512",
                Algo::Sha1 | Algo::Sha1Hex => "sha1",
            };
            return Ok(self.paths.store_dir.join(algo_dir).join(hex_key));
        }
        // Fallback: hash the tarball URL so we can still dedupe and keep paths short.
        let mut h = Sha1::new();
        h.update(tarball_url.as_bytes());
        let hex_key = hex(&h.finalize().to_vec());
        Ok(self.paths.store_dir.join("url-sha1").join(hex_key))
    }
}

pub fn current_layout_name() -> &'static str {
    match detect_layout() {
        Layout::Flat => "flat",
        Layout::Nested => "nested",
    }
}

fn detect_layout() -> Layout {
    let v = std::env::var("VX_LAYOUT").unwrap_or_default();
    match v.as_str() {
        "nested" => Layout::Nested,
        "flat" => Layout::Flat,
        _ => Layout::Flat, // Default to flat for better compatibility (Next.js, etc.)
    }
}

fn choose_flat_set(lock: &Lockfile) -> BTreeMap<String, String> {
    let mut chosen: BTreeMap<String, String> = BTreeMap::new();
    for (name, key) in &lock.root.requires {
        chosen.entry(name.clone()).or_insert_with(|| key.clone());
    }
    // Best-effort: fill additional packages without clobbering.
    for (key, node) in &lock.packages {
        let Some(name) = node.name.clone() else {
            continue;
        };
        chosen.entry(name).or_insert_with(|| key.clone());
    }
    chosen
}

fn suggested_concurrency() -> usize {
    let env = std::env::var("VX_CONCURRENCY")
        .ok()
        .and_then(|v| v.parse::<usize>().ok());
    if let Some(v) = env {
        return v.max(1);
    }
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8);
    (cpus * 8).clamp(8, 64)
}

async fn ensure_in_store(
    registry: &RegistryClient,
    tmp_root: &Path,
    store_dir: &Path,
    tarball_url: &str,
    integrity: Option<&str>,
) -> Result<()> {
    if store_dir.exists() {
        return Ok(());
    }

    ensure_dir(store_dir.parent().unwrap_or(store_dir))?;

    let tmp = tempfile::Builder::new()
        .prefix("vx-")
        .tempdir_in(tmp_root)
        .context("create temp dir")?;
    let tgz_path = tmp.path().join("pkg.tgz");

    let (bytes_hash, algo) =
        download_with_hash(registry, tarball_url, &tgz_path, integrity).await?;

    if let Some(integrity) = integrity {
        let parsed = Integrity::parse(integrity)?;
        if parsed.expected != bytes_hash {
            return Err(anyhow!("integrity mismatch for {}", tarball_url));
        }
        if !matches_algo(parsed.algo, algo) {
            // ok for sha1-hex vs sha1
        }
    }

    let extracted = tmp.path().join("extracted");
    ensure_dir(&extracted)?;
    tokio::task::spawn_blocking({
        let tgz_path = tgz_path.clone();
        let extracted = extracted.clone();
        move || extract_tgz(&tgz_path, &extracted)
    })
    .await
    .context("extract task panicked")??;

    if store_dir.exists() {
        return Ok(());
    }

    match fs::rename(&extracted, store_dir) {
        Ok(()) => Ok(()),
        Err(_e) if store_dir.exists() => Ok(()),
        Err(_) => {
            ensure_dir(store_dir)?;
            link_tree(&extracted, store_dir)?;
            Ok(())
        }
    }
}

fn matches_algo(expected: Algo, actual: Algo) -> bool {
    matches!(
        (expected, actual),
        (Algo::Sha1Hex, Algo::Sha1) | (Algo::Sha1Hex, Algo::Sha1Hex)
    ) || expected == actual
}

async fn download_with_hash(
    registry: &RegistryClient,
    url: &str,
    dest: &Path,
    integrity: Option<&str>,
) -> Result<(Vec<u8>, Algo)> {
    let algo = if let Some(s) = integrity {
        Integrity::parse(s)?.algo
    } else {
        Algo::Sha512
    };

    let mut sha512 = Sha512::new();
    let mut sha1 = Sha1::new();

    let mut file = tokio::fs::File::create(dest)
        .await
        .with_context(|| format!("create {}", dest.display()))?;

    let resp = registry.download(url).await?;
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.with_context(|| format!("read chunk from {}", url))?;
        tokio::io::AsyncWriteExt::write_all(&mut file, &chunk).await?;
        match algo {
            Algo::Sha512 => sha512.update(&chunk),
            Algo::Sha1 | Algo::Sha1Hex => sha1.update(&chunk),
        }
    }
    tokio::io::AsyncWriteExt::flush(&mut file).await?;

    let bytes = match algo {
        Algo::Sha512 => sha512.finalize().to_vec(),
        Algo::Sha1 | Algo::Sha1Hex => sha1.finalize().to_vec(),
    };
    Ok((
        bytes,
        match algo {
            Algo::Sha1Hex => Algo::Sha1,
            a => a,
        },
    ))
}

fn extract_tgz(tgz_path: &Path, dest: &Path) -> Result<()> {
    let f = fs::File::open(tgz_path).with_context(|| format!("open {}", tgz_path.display()))?;
    let gz = flate2::read::GzDecoder::new(f);
    let mut archive = Archive::new(gz);
    for entry in archive.entries().context("read tar entries")? {
        let mut entry = entry?;
        let path = entry.path()?;
        let safe_rel = strip_first_component(&path)?;
        if safe_rel.as_os_str().is_empty() {
            continue;
        }
        let out_path = dest.join(&safe_rel);
        if entry.header().entry_type().is_dir() {
            fs::create_dir_all(&out_path)?;
            continue;
        }
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if entry.header().entry_type().is_file() {
            let mut out = fs::File::create(&out_path)?;
            std::io::copy(&mut entry, &mut out)?;
            continue;
        }
        // Skip symlinks/hardlinks/special entries (prototype).
    }
    Ok(())
}

fn strip_first_component(path: &Path) -> Result<PathBuf> {
    let mut comps = path.components();
    let _first = comps.next().ok_or_else(|| anyhow!("empty tar path"))?;
    let rest: PathBuf = comps.collect();
    if rest.as_os_str().is_empty() {
        // No directory prefix; keep the original path.
        return safe_relative_path(path);
    }
    safe_relative_path(&rest)
}

fn safe_relative_path(p: &Path) -> Result<PathBuf> {
    let mut out = PathBuf::new();
    for c in p.components() {
        use std::path::Component;
        match c {
            Component::Normal(n) => out.push(n),
            Component::CurDir => {}
            _ => return Err(anyhow!("unsafe path in tarball: {}", p.display())),
        }
    }
    Ok(out)
}

fn normalize_store_dir_if_needed(store_dir: &Path) -> Result<()> {
    if store_dir.join("package.json").exists() {
        return Ok(());
    }
    if !store_dir.exists() {
        return Ok(());
    }

    let mut entries = fs::read_dir(store_dir)
        .with_context(|| format!("read dir {}", store_dir.display()))?
        .filter_map(|e| e.ok())
        .collect::<Vec<_>>();
    if entries.len() != 1 {
        return Ok(());
    }

    let only = entries.pop().unwrap();
    let ft = only.file_type()?;
    if !ft.is_dir() {
        return Ok(());
    }
    let inner = only.path();
    if !inner.join("package.json").exists() {
        return Ok(());
    }

    for child in fs::read_dir(&inner).with_context(|| format!("read dir {}", inner.display()))? {
        let child = child?;
        let from = child.path();
        let to = store_dir.join(child.file_name());
        let child_ft = child.file_type()?;
        if to.exists() {
            if to.is_dir() {
                fs::remove_dir_all(&to)?;
            } else {
                fs::remove_file(&to)?;
            }
        }
        if fs::rename(&from, &to).is_err() {
            if child_ft.is_dir() {
                ensure_dir(&to)?;
                link_tree(&from, &to)?;
                fs::remove_dir_all(&from)?;
            } else {
                fs::copy(&from, &to)?;
                fs::remove_file(&from)?;
            }
        }
    }
    fs::remove_dir_all(&inner)?;
    Ok(())
}

fn link_bins_for_package(parent_node_modules: &Path, pkg_dir: &Path) -> Result<()> {
    let bins = read_package_bins(pkg_dir)?;
    if bins.is_empty() {
        return Ok(());
    }
    let bin_dir = parent_node_modules.join(".bin");
    ensure_dir(&bin_dir)?;
    for (name, rel_path) in bins {
        let target = pkg_dir.join(rel_path);
        if !target.is_file() {
            continue;
        }
        create_bin_shim(&bin_dir, &name, &target)?;
    }
    Ok(())
}

fn read_package_bins(pkg_dir: &Path) -> Result<Vec<(String, String)>> {
    let pkg_json = pkg_dir.join("package.json");
    if !pkg_json.exists() {
        return Ok(Vec::new());
    }
    let bytes = fs::read(&pkg_json).with_context(|| format!("read {}", pkg_json.display()))?;
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", pkg_json.display()))?;
    let bin_val = match v.get("bin") {
        Some(val) => val,
        None => return Ok(Vec::new()),
    };
    let pkg_name = v
        .get("name")
        .and_then(|v| v.as_str())
        .or_else(|| pkg_dir.file_name().and_then(|s| s.to_str()))
        .unwrap_or("")
        .to_string();

    let mut bins = Vec::new();
    match bin_val {
        serde_json::Value::String(s) => {
            if !pkg_name.is_empty() && !s.trim().is_empty() {
                bins.push((default_bin_name(&pkg_name), s.to_string()));
            }
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                if let Some(s) = v.as_str() {
                    if !k.trim().is_empty() && !s.trim().is_empty() {
                        bins.push((k.clone(), s.to_string()));
                    }
                }
            }
        }
        _ => {}
    }
    Ok(bins)
}

fn default_bin_name(pkg_name: &str) -> String {
    pkg_name.rsplit('/').next().unwrap_or(pkg_name).to_string()
}

#[cfg(windows)]
fn create_bin_shim(bin_dir: &Path, name: &str, target: &Path) -> Result<()> {
    let shim_path = bin_dir.join(format!("{name}.cmd"));
    let target_str = target.to_string_lossy();
    let use_node = should_use_node(target)?;
    let body = if use_node {
        format!(
            "@ECHO OFF\r\nnode --preserve-symlinks --preserve-symlinks-main \"{}\" %*\r\n",
            target_str
        )
    } else {
        format!("@ECHO OFF\r\n\"{}\" %*\r\n", target_str)
    };
    fs::write(&shim_path, body).with_context(|| format!("write {}", shim_path.display()))?;
    Ok(())
}

#[cfg(not(windows))]
fn create_bin_shim(bin_dir: &Path, name: &str, target: &Path) -> Result<()> {
    let shim_path = bin_dir.join(name);
    let target_str = target.to_string_lossy();
    let use_node = should_use_node(target)?;
    let body = if use_node {
        format!(
            "#!/usr/bin/env sh\nexec node --preserve-symlinks --preserve-symlinks-main \"{}\" \"$@\"\n",
            target_str
        )
    } else {
        format!("#!/usr/bin/env sh\nexec \"{}\" \"$@\"\n", target_str)
    };
    fs::write(&shim_path, body).with_context(|| format!("write {}", shim_path.display()))?;
    set_exec(&shim_path)?;
    if !use_node {
        set_exec(target)?;
    }
    Ok(())
}

fn should_use_node(target: &Path) -> Result<bool> {
    let ext = target
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if matches!(ext.as_str(), "js" | "mjs" | "cjs") {
        return Ok(true);
    }
    if let Some(shebang) = read_shebang(target)? {
        let lower = shebang.to_ascii_lowercase();
        if lower.contains("node") {
            return Ok(true);
        }
    }
    Ok(false)
}

fn read_shebang(path: &Path) -> Result<Option<String>> {
    let f = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut reader = std::io::BufReader::new(f);
    let mut buf = Vec::new();
    let _ = reader.read_until(b'\n', &mut buf)?;
    if buf.len() < 2 || &buf[..2] != b"#!" {
        return Ok(None);
    }
    let line = String::from_utf8_lossy(&buf[2..]);
    Ok(Some(line.trim().to_string()))
}

#[cfg(unix)]
fn set_exec(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)
        .with_context(|| format!("metadata {}", path.display()))?
        .permissions();
    let mode = perms.mode();
    perms.set_mode(mode | 0o111);
    fs::set_permissions(path, perms).with_context(|| format!("chmod {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_exec(_path: &Path) -> Result<()> {
    Ok(())
}
