use crate::lockfile::{LockNode, Lockfile, LOCKFILE_VERSION};
use crate::manifest::Manifest;
use crate::npm_semver;
use crate::registry::{Packument, RegistryClient, ResolvedVersion};
use anyhow::{Context, Result, anyhow};
use futures::StreamExt;
use sha1::{Digest, Sha1};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

pub struct ResolveOptions {
    pub include_dev: bool,
    pub frozen_lockfile: bool,
}

pub struct Resolver {
    registry: RegistryClient,
    packuments: HashMap<String, Packument>,
    resolved_versions: HashMap<(String, String), ResolvedVersion>,
    packument_versions: HashMap<String, Vec<(semver::Version, String)>>,
    packument_cache_dir: Option<PathBuf>,
    progress: ResolveProgress,
}

impl Resolver {
    #[allow(dead_code)]
    pub fn new(registry: RegistryClient) -> Self {
        Self::new_with_cache(registry, None)
    }

    pub fn new_with_cache(registry: RegistryClient, packument_cache_dir: Option<PathBuf>) -> Self {
        Self {
            registry,
            packuments: HashMap::new(),
            resolved_versions: HashMap::new(),
            packument_versions: HashMap::new(),
            packument_cache_dir,
            progress: ResolveProgress::new(),
        }
    }

    pub async fn resolve(
        &mut self,
        manifest: &Manifest,
        existing: Option<Lockfile>,
        options: &ResolveOptions,
    ) -> Result<Lockfile> {
        let mut root_deps = manifest.dependencies.clone();
        if options.include_dev {
            root_deps.extend(manifest.dev_dependencies.clone());
        }
        let root_optional = manifest.optional_dependencies.clone();

        if options.frozen_lockfile {
            let lock = existing.ok_or_else(|| anyhow!("--frozen-lockfile requires an existing vx.lock"))?;
            if lock.registry != self.registry.base {
                return Err(anyhow!(
                    "lockfile registry `{}` does not match current registry `{}`",
                    lock.registry,
                    self.registry.base
                ));
            }
            lock.validate_against_manifest(manifest, options.include_dev)?;
            return Ok(lock);
        }

        let mut lock = existing.unwrap_or_else(|| Lockfile::new(self.registry.base.clone()));
        if lock.registry != self.registry.base {
            lock.registry = self.registry.base.clone();
        }
        lock.lockfile_version = LOCKFILE_VERSION;

        lock.root.dependencies = root_deps.clone();
        lock.root.optional_dependencies = root_optional.clone();
        lock.root.requires.retain(|k, _| {
            lock.root.dependencies.contains_key(k) || lock.root.optional_dependencies.contains_key(k)
        });

        let mut queue: VecDeque<(String, BTreeMap<String, String>, BTreeMap<String, String>)> =
            VecDeque::new();
        queue.push_back(("__root__".to_string(), root_deps, root_optional));
        let mut visited_nodes: BTreeSet<String> = BTreeSet::new();
        let _progress_guard = self.progress.start();

        let batch_size = std::env::var("VX_RESOLVE_BATCH")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(256)
            .clamp(1, 2048);

        while !queue.is_empty() {
            let mut batch = Vec::new();
            while batch.len() < batch_size {
                let Some((parent_key, deps, optional_deps)) = queue.pop_front() else { break };
                if parent_key != "__root__" && !visited_nodes.insert(parent_key.clone()) {
                    continue;
                }
                batch.push((parent_key, deps, optional_deps));
            }
            if batch.is_empty() {
                continue;
            }

            let mut names = Vec::new();
            for (parent_key, deps, optional_deps) in &batch {
                for (dep_name, dep_req) in deps {
                    let needs_resolve = match existing_child(&lock, parent_key, dep_name) {
                        Some(child_key) if child_key_ok(dep_req, &child_key) => false,
                        _ => true,
                    };
                    if needs_resolve {
                        names.push(dep_name.clone());
                    }
                }
                // Optional dependencies still need metadata to evaluate platform support.
                names.extend(optional_deps.keys().cloned());
            }
            names.sort();
            names.dedup();
            self.prefetch_packuments(names).await?;

            for (parent_key, deps, optional_deps) in batch {
                if parent_key != "__root__" {
                    if let Some(parent) = lock.packages.get_mut(&parent_key) {
                        parent.requires.retain(|k, _| {
                            deps.contains_key(k) || optional_deps.contains_key(k)
                        });
                    }
                }
                for (dep_name, dep_req) in deps {
                    let child_key = match existing_child(&lock, &parent_key, &dep_name) {
                        Some(k) if child_key_ok(&dep_req, &k) => k,
                        _ => self
                            .resolve_and_upsert(&mut lock, &dep_name, &dep_req)
                            .await
                            .with_context(|| format!("resolve {dep_name}@{dep_req}"))?,
                    };

                    set_requires(&mut lock, &parent_key, &dep_name, &child_key)?;

                    let node = lock
                        .packages
                        .get(&child_key)
                        .ok_or_else(|| anyhow!("missing node for {child_key}"))?;
                    if !node.dependencies.is_empty() || !node.optional_dependencies.is_empty() {
                        queue.push_back((
                            child_key.clone(),
                            node.dependencies.clone(),
                            node.optional_dependencies.clone(),
                        ));
                    }
                }

                for (dep_name, dep_req) in optional_deps {
                    let child_key = self
                        .resolve_optional(&mut lock, &dep_name, &dep_req)
                        .await
                        .with_context(|| format!("resolve optional {dep_name}@{dep_req}"))?;
                    let Some(child_key) = child_key else {
                        continue;
                    };

                    set_requires(&mut lock, &parent_key, &dep_name, &child_key)?;

                    let node = lock
                        .packages
                        .get(&child_key)
                        .ok_or_else(|| anyhow!("missing node for {child_key}"))?;
                    if !node.dependencies.is_empty() || !node.optional_dependencies.is_empty() {
                        queue.push_back((
                            child_key.clone(),
                            node.dependencies.clone(),
                            node.optional_dependencies.clone(),
                        ));
                    }
                }
            }
        }

        prune_unreachable(&mut lock)?;
        Ok(lock)
    }

    async fn resolve_and_upsert(&mut self, lock: &mut Lockfile, name: &str, req: &str) -> Result<String> {
        let resolved = self.resolve_version_cached(name, req).await?;
        Ok(upsert_resolved(lock, &resolved))
    }

    async fn resolve_optional(
        &mut self,
        lock: &mut Lockfile,
        name: &str,
        req: &str,
    ) -> Result<Option<String>> {
        let resolved = match self.resolve_version_cached(name, req).await {
            Ok(resolved) => resolved,
            Err(err) => {
                eprintln!("Skipping optional dependency {}: {}", name, err);
                return Ok(None);
            }
        };
        if !is_supported_optional(&resolved) {
            return Ok(None);
        }
        Ok(Some(upsert_resolved(lock, &resolved)))
    }

    async fn resolve_version_cached(&mut self, name: &str, req: &str) -> Result<ResolvedVersion> {
        let req_key = match req {
            "" | "*" | "latest" => "latest",
            _ => req,
        };
        let key = (name.to_string(), req_key.to_string());
        if let Some(resolved) = self.resolved_versions.get(&key) {
            return Ok(resolved.clone());
        }
        let resolved = if req == "latest" || req == "*" || req.is_empty() {
            let p = self.packument_cached(name).await?;
            let version = p
                .dist_tags
                .get("latest")
                .cloned()
                .ok_or_else(|| anyhow!("no dist-tag latest for {}", name))?;
            let meta = p
                .versions
                .get(&version)
                .ok_or_else(|| anyhow!("missing version metadata for {name}@{version}"))?;
            ResolvedVersion {
                name: meta.name.clone(),
                version: meta.version.clone(),
                tarball: meta.dist.tarball.clone(),
                integrity: meta
                    .dist
                    .integrity
                    .clone()
                    .or_else(|| meta.dist.shasum.as_ref().map(|s| format!("sha1-hex:{s}"))),
                dependencies: meta.dependencies.clone().unwrap_or_default(),
                optional_dependencies: meta.optional_dependencies.clone(),
                os: meta
                    .os
                    .clone()
                    .map(|v| v.into_vec())
                    .unwrap_or_default(),
                cpu: meta
                    .cpu
                    .clone()
                    .map(|v| v.into_vec())
                    .unwrap_or_default(),
            }
        } else {
            let reqs = crate::npm_semver::parse_req_any(req)
                .with_context(|| format!("invalid semver range `{req}` for {name}"))?;
            let cached_version = self
                .packument_versions
                .get(name)
                .and_then(|versions| {
                    versions
                        .iter()
                        .find(|(ver, _)| reqs.iter().any(|r| r.matches(ver)))
                        .map(|(_, ver_str)| ver_str.clone())
                });

            if let Some(version) = cached_version {
                let p = self.packument_cached(name).await?;
                let meta = p
                    .versions
                    .get(&version)
                    .ok_or_else(|| anyhow!("missing version metadata for {name}@{version}"))?;
                ResolvedVersion {
                    name: meta.name.clone(),
                    version: meta.version.clone(),
                    tarball: meta.dist.tarball.clone(),
                    integrity: meta
                        .dist
                        .integrity
                        .clone()
                        .or_else(|| meta.dist.shasum.as_ref().map(|s| format!("sha1-hex:{s}"))),
                    dependencies: meta.dependencies.clone().unwrap_or_default(),
                    optional_dependencies: meta.optional_dependencies.clone(),
                    os: meta
                        .os
                        .clone()
                        .map(|v| v.into_vec())
                        .unwrap_or_default(),
                    cpu: meta
                        .cpu
                        .clone()
                        .map(|v| v.into_vec())
                        .unwrap_or_default(),
                }
            } else {
                let (resolved, versions_cache) = {
                    let p = self.packument_cached(name).await?;
                    let mut versions = Vec::new();
                    for v in p.versions.keys() {
                        let Ok(ver) = semver::Version::parse(v) else { continue };
                        versions.push((ver, v.to_string()));
                    }
                    versions.sort_by(|a, b| b.0.cmp(&a.0));
                    let version = versions
                        .iter()
                        .find(|(ver, _)| reqs.iter().any(|r| r.matches(ver)))
                        .map(|(_, ver_str)| ver_str.clone())
                        .ok_or_else(|| anyhow!("no version for {name} matches `{req}`"))?;
                    let meta = p
                        .versions
                        .get(&version)
                        .ok_or_else(|| anyhow!("missing version metadata for {name}@{version}"))?;
                    let resolved = ResolvedVersion {
                        name: meta.name.clone(),
                        version: meta.version.clone(),
                        tarball: meta.dist.tarball.clone(),
                        integrity: meta
                            .dist
                            .integrity
                            .clone()
                            .or_else(|| meta.dist.shasum.as_ref().map(|s| format!("sha1-hex:{s}"))),
                        dependencies: meta.dependencies.clone().unwrap_or_default(),
                        optional_dependencies: meta.optional_dependencies.clone(),
                        os: meta
                            .os
                            .clone()
                            .map(|v| v.into_vec())
                            .unwrap_or_default(),
                        cpu: meta
                            .cpu
                            .clone()
                            .map(|v| v.into_vec())
                            .unwrap_or_default(),
                    };
                    (resolved, versions)
                };
                self.packument_versions
                    .insert(name.to_string(), versions_cache);
                resolved
            }
        };

        self.resolved_versions.insert(key, resolved.clone());
        Ok(resolved)
    }

    async fn packument_cached(&mut self, name: &str) -> Result<&Packument> {
        if !self.packuments.contains_key(name) {
            let p = self.packument_disk_or_net(name).await?;
            self.packuments.insert(name.to_string(), p);
        }
        Ok(self.packuments.get(name).expect("inserted above"))
    }

    async fn packument_disk_or_net(&mut self, name: &str) -> Result<Packument> {
        self.progress.net_fetch_started(1);
        let Some(dir) = self.packument_cache_dir.as_deref() else {
            let p = self.registry.packument(name).await?;
            self.progress.net_fetch_finished(1);
            return Ok(p);
        };

        crate::fsutil::ensure_dir(dir)?;
        let key = packument_key(name);
        let json_path = dir.join(format!("{key}.json"));
        let etag_path = dir.join(format!("{key}.etag"));

        let max_age = std::env::var("VX_PACKUMENT_MAX_AGE_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(3600);

        if json_path.exists() {
            if let Ok(meta) = tokio::fs::metadata(&json_path).await {
                if let Ok(modified) = meta.modified() {
                    if let Ok(age) = modified.elapsed() {
                        if age.as_secs() <= max_age {
                            let bytes = tokio::fs::read(&json_path)
                                .await
                                .with_context(|| format!("read {}", json_path.display()))?;
                            let p = serde_json::from_slice::<Packument>(&bytes)
                                .with_context(|| format!("parse {}", json_path.display()))?;
                            self.progress.cache_hit(1);
                            self.progress.net_fetch_finished(1);
                            return Ok(p);
                        }
                    }
                }
            }
        }

        let etag = tokio::fs::read_to_string(&etag_path)
            .await
            .ok()
            .map(|s| s.trim().to_string());
        let resp = self.registry.packument_raw(name, etag.as_deref()).await?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_MODIFIED && json_path.exists() {
            self.progress.net_fetch_finished(1);
            let bytes = tokio::fs::read(&json_path)
                .await
                .with_context(|| format!("read {}", json_path.display()))?;
            let p = serde_json::from_slice::<Packument>(&bytes)
                .with_context(|| format!("parse {}", json_path.display()))?;
            return Ok(p);
        }

        let resp = resp
            .error_for_status()
            .with_context(|| format!("packument http error for {}", name))?;
        let new_etag = resp
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let bytes = resp.bytes().await.with_context(|| format!("read packument body for {}", name))?;
        self.progress.net_fetch_finished(1);

        // Best-effort persist.
        let _ = tokio::fs::write(&json_path, &bytes).await;
        if let Some(etag) = new_etag {
            let _ = tokio::fs::write(&etag_path, etag).await;
        }

        let p = serde_json::from_slice::<Packument>(&bytes).with_context(|| format!("parse packument for {}", name))?;
        Ok(p)
    }

    async fn prefetch_packuments(&mut self, names: Vec<String>) -> Result<()> {
        let to_fetch = names
            .into_iter()
            .filter(|n| !self.packuments.contains_key(n))
            .collect::<Vec<_>>();
        if to_fetch.is_empty() {
            return Ok(());
        }

        let concurrency = std::env::var("VX_PACKUMENT_CONCURRENCY")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(128)
            .clamp(1, 256);
        let registry = self.registry.clone();
        let cache_dir = self.packument_cache_dir.clone();
        let progress = self.progress.clone();

        progress.net_fetch_started(to_fetch.len());
        let fetched = futures::stream::iter(to_fetch.into_iter().map(|name| {
            let registry = registry.clone();
            let cache_dir = cache_dir.clone();
            let progress = progress.clone();
            async move {
                let p = fetch_packument_with_cache(&registry, cache_dir.as_deref(), &name, &progress).await?;
                Ok::<(String, Packument), anyhow::Error>((name, p))
            }
        }))
        .buffer_unordered(concurrency)
        .collect::<Vec<_>>()
        .await;

        for item in fetched {
            let (name, p) = item?;
            self.packuments.insert(name, p);
        }
        Ok(())
    }
}

fn upsert_resolved(lock: &mut Lockfile, resolved: &ResolvedVersion) -> String {
    let key = Lockfile::key(&resolved.name, &resolved.version);
    let node = lock.packages.entry(key.clone()).or_insert_with(LockNode::default);
    node.name = Some(resolved.name.clone());
    node.version = Some(resolved.version.clone());
    node.tarball = Some(resolved.tarball.clone());
    node.integrity = resolved.integrity.clone();
    node.dependencies = resolved.dependencies.clone();
    node.optional_dependencies = resolved.optional_dependencies.clone();
    key
}

fn is_supported_optional(resolved: &ResolvedVersion) -> bool {
    if !resolved.os.is_empty() && !matches_platform(&resolved.os, current_os()) {
        return false;
    }
    if !resolved.cpu.is_empty() && !matches_platform(&resolved.cpu, current_cpu()) {
        return false;
    }
    true
}

fn current_os() -> &'static str {
    match std::env::consts::OS {
        "windows" => "win32",
        "macos" => "darwin",
        "linux" => "linux",
        "android" => "android",
        "freebsd" => "freebsd",
        "openbsd" => "openbsd",
        "netbsd" => "netbsd",
        "dragonfly" => "dragonfly",
        "solaris" => "sunos",
        "aix" => "aix",
        other => other,
    }
}

fn current_cpu() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        "x86" | "i686" | "i386" => "ia32",
        "arm" | "armv7" | "armv7l" => "arm",
        "powerpc64" => "ppc64",
        "s390x" => "s390x",
        other => other,
    }
}

fn matches_platform(list: &[String], current: &str) -> bool {
    let mut has_positive = false;
    let mut allowed = false;
    for entry in list {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        if let Some(neg) = entry.strip_prefix('!') {
            if neg == current {
                return false;
            }
        } else {
            has_positive = true;
            if entry == current {
                allowed = true;
            }
        }
    }
    if has_positive {
        allowed
    } else {
        true
    }
}

#[derive(Clone)]
struct ResolveProgress {
    net_total: Arc<AtomicUsize>,
    net_done: Arc<AtomicUsize>,
    cache_hits: Arc<AtomicUsize>,
}

impl ResolveProgress {
    fn new() -> Self {
        Self {
            net_total: Arc::new(AtomicUsize::new(0)),
            net_done: Arc::new(AtomicUsize::new(0)),
            cache_hits: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn start(&self) -> ProgressGuard {
        let net_total = self.net_total.clone();
        let net_done = self.net_done.clone();
        let cache_hits = self.cache_hits.clone();
        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(500));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let total = net_total.load(Ordering::Relaxed);
                        let done = net_done.load(Ordering::Relaxed);
                        let hits = cache_hits.load(Ordering::Relaxed);
                        if total > 0 {
                            eprintln!("Resolving: metadata {done}/{total} (cache hits {hits})");
                        }
                    }
                    _ = &mut rx => break,
                }
            }
        });
        ProgressGuard { stop: Some(tx) }
    }

    fn net_fetch_started(&self, n: usize) {
        self.net_total.fetch_add(n, Ordering::Relaxed);
    }

    fn net_fetch_finished(&self, n: usize) {
        self.net_done.fetch_add(n, Ordering::Relaxed);
    }

    fn cache_hit(&self, n: usize) {
        self.cache_hits.fetch_add(n, Ordering::Relaxed);
    }
}

struct ProgressGuard {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for ProgressGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
    }
}

fn packument_key(name: &str) -> String {
    let mut h = Sha1::new();
    h.update(name.as_bytes());
    crate::integrity::hex(&h.finalize().to_vec())
}

async fn fetch_packument_with_cache(
    registry: &RegistryClient,
    cache_dir: Option<&Path>,
    name: &str,
    progress: &ResolveProgress,
) -> Result<Packument> {
    let Some(cache_dir) = cache_dir else {
        let p = registry.packument(name).await?;
        progress.net_fetch_finished(1);
        return Ok(p);
    };

    crate::fsutil::ensure_dir(cache_dir)?;
    let key = packument_key(name);
    let json_path = cache_dir.join(format!("{key}.json"));
    let etag_path = cache_dir.join(format!("{key}.etag"));
    let max_age = std::env::var("VX_PACKUMENT_MAX_AGE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(3600);

    if json_path.exists() {
        if let Ok(meta) = tokio::fs::metadata(&json_path).await {
            if let Ok(modified) = meta.modified() {
                if let Ok(age) = modified.elapsed() {
                    if age.as_secs() <= max_age {
                        let bytes = tokio::fs::read(&json_path)
                            .await
                            .with_context(|| format!("read {}", json_path.display()))?;
                        let p = serde_json::from_slice::<Packument>(&bytes)
                            .with_context(|| format!("parse {}", json_path.display()))?;
                        progress.cache_hit(1);
                        progress.net_fetch_finished(1);
                        return Ok(p);
                    }
                }
            }
        }
    }

    let etag = tokio::fs::read_to_string(&etag_path)
        .await
        .ok()
        .map(|s| s.trim().to_string());
    let resp = registry.packument_raw(name, etag.as_deref()).await?;
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_MODIFIED && json_path.exists() {
        progress.net_fetch_finished(1);
        let bytes = tokio::fs::read(&json_path)
            .await
            .with_context(|| format!("read {}", json_path.display()))?;
        let p = serde_json::from_slice::<Packument>(&bytes).with_context(|| format!("parse {}", json_path.display()))?;
        return Ok(p);
    }

    let resp = resp
        .error_for_status()
        .with_context(|| format!("packument http error for {}", name))?;
    let new_etag = resp
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let bytes = resp.bytes().await.with_context(|| format!("read packument body for {}", name))?;
    progress.net_fetch_finished(1);

    let _ = tokio::fs::write(&json_path, &bytes).await;
    if let Some(etag) = new_etag {
        let _ = tokio::fs::write(&etag_path, etag).await;
    }

    let p = serde_json::from_slice::<Packument>(&bytes).with_context(|| format!("parse packument for {}", name))?;
    Ok(p)
}

fn existing_child(lock: &Lockfile, parent_key: &str, dep_name: &str) -> Option<String> {
    if parent_key == "__root__" {
        lock.root.requires.get(dep_name).cloned()
    } else {
        lock.packages
            .get(parent_key)
            .and_then(|n| n.requires.get(dep_name).cloned())
    }
}

fn set_requires(lock: &mut Lockfile, parent_key: &str, dep_name: &str, child_key: &str) -> Result<bool> {
    if parent_key == "__root__" {
        Ok(lock
            .root
            .requires
            .insert(dep_name.to_string(), child_key.to_string())
            .as_deref()
            != Some(child_key))
    } else {
        let parent = lock
            .packages
            .get_mut(parent_key)
            .ok_or_else(|| anyhow!("missing parent node {parent_key}"))?;
        Ok(parent
            .requires
            .insert(dep_name.to_string(), child_key.to_string())
            .as_deref()
            != Some(child_key))
    }
}

fn child_key_ok(req: &str, child_key: &str) -> bool {
    if req == "*" || req == "latest" || req.is_empty() {
        return true;
    }
    let Some((_name, version)) = split_key(child_key) else { return false };
    if req == version {
        return true;
    }
    semver::Version::parse(version)
        .ok()
        .map(|v| npm_semver::matches_req(req, &v))
        .unwrap_or(false)
}

fn split_key(key: &str) -> Option<(&str, &str)> {
    let idx = key.rfind('@')?;
    if idx == 0 {
        return None;
    }
    Some((&key[..idx], &key[idx + 1..]))
}

fn prune_unreachable(lock: &mut Lockfile) -> Result<()> {
    let mut queue: VecDeque<String> = lock.root.requires.values().cloned().collect();
    let mut reachable: BTreeSet<String> = BTreeSet::new();
    while let Some(key) = queue.pop_front() {
        if !reachable.insert(key.clone()) {
            continue;
        }
        let Some(node) = lock.packages.get(&key) else { continue };
        for child in node.requires.values() {
            queue.push_back(child.clone());
        }
    }

    lock.root.requires.retain(|_, v| reachable.contains(v));
    lock.packages.retain(|k, _| reachable.contains(k));
    for node in lock.packages.values_mut() {
        node.requires.retain(|_, v| reachable.contains(v));
    }
    Ok(())
}
