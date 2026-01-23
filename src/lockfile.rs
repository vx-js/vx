use crate::manifest::Manifest;
use crate::npm_semver;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lockfile {
    #[serde(rename = "lockfileVersion")]
    pub lockfile_version: u32,
    pub registry: String,
    pub root: LockNode,
    pub packages: BTreeMap<String, LockNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LockNode {
    pub name: Option<String>,
    pub version: Option<String>,
    pub tarball: Option<String>,
    pub integrity: Option<String>,
    #[serde(default)]
    pub dependencies: BTreeMap<String, String>,
    #[serde(rename = "optionalDependencies", default)]
    pub optional_dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub requires: BTreeMap<String, String>,
}

pub const LOCKFILE_VERSION: u32 = 3;

impl Lockfile {
    pub fn new(registry: String) -> Self {
        Self {
            lockfile_version: LOCKFILE_VERSION,
            registry,
            root: LockNode::default(),
            packages: BTreeMap::new(),
        }
    }

    pub fn key(name: &str, version: &str) -> String {
        format!("{name}@{version}")
    }

    pub fn load_if_exists(path: &Path) -> Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        let lock: Self =
            serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
        Ok(Some(lock))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let s = serde_json::to_string_pretty(self)? + "\n";
        fs::write(path, s).with_context(|| format!("write {}", path.display()))?;
        Ok(())
    }

    pub fn validate_against_manifest(&self, manifest: &Manifest, include_dev: bool) -> Result<()> {
        anyhow::ensure!(
            self.lockfile_version >= LOCKFILE_VERSION,
            "lockfile version {} is too old (expected {})",
            self.lockfile_version,
            LOCKFILE_VERSION
        );
        let mut root_deps = manifest.dependencies.clone();
        if include_dev {
            root_deps.extend(manifest.dev_dependencies.clone());
        }
        let root_optional = manifest.optional_dependencies.clone();

        anyhow::ensure!(
            self.root.dependencies == root_deps,
            "lockfile root dependencies do not match package.json"
        );
        anyhow::ensure!(
            self.root.optional_dependencies == root_optional,
            "lockfile root optional dependencies do not match package.json"
        );

        for (name, req) in &root_deps {
            let child =
                self.root.requires.get(name).ok_or_else(|| {
                    anyhow::anyhow!("lockfile missing root resolution for {}", name)
                })?;
            anyhow::ensure!(
                child_key_satisfies(req, child)?,
                "lockfile root resolution {} -> {} does not satisfy `{}`",
                name,
                child,
                req
            );
        }
        for (name, req) in &root_optional {
            if let Some(child) = self.root.requires.get(name) {
                anyhow::ensure!(
                    child_key_satisfies(req, child)?,
                    "lockfile optional root resolution {} -> {} does not satisfy `{}`",
                    name,
                    child,
                    req
                );
            }
        }

        let mut queue: VecDeque<String> = self.root.requires.values().cloned().collect();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        while let Some(key) = queue.pop_front() {
            if !seen.insert(key.clone()) {
                continue;
            }
            let node = self
                .packages
                .get(&key)
                .ok_or_else(|| anyhow::anyhow!("lockfile missing node {}", key))?;

            anyhow::ensure!(
                node.tarball.as_deref().unwrap_or("").len() > 0,
                "lockfile node {} is missing tarball",
                key
            );

            for (dep_name, dep_req) in &node.dependencies {
                let child = node.requires.get(dep_name).ok_or_else(|| {
                    anyhow::anyhow!(
                        "lockfile missing resolution for {} dependency {}",
                        key,
                        dep_name
                    )
                })?;
                anyhow::ensure!(
                    child_key_satisfies(dep_req, child)?,
                    "lockfile resolution {} -> {} does not satisfy `{}`",
                    dep_name,
                    child,
                    dep_req
                );
                queue.push_back(child.clone());
            }
        }
        Ok(())
    }
}

fn child_key_satisfies(req: &str, child_key: &str) -> Result<bool> {
    if req.trim().is_empty() || req == "*" || req == "latest" {
        return Ok(true);
    }
    let Some((_name, version_str)) = split_key(child_key) else {
        return Ok(false);
    };
    if req == version_str {
        return Ok(true);
    }
    let Ok(v) = semver::Version::parse(version_str) else {
        return Ok(false);
    };
    Ok(npm_semver::matches_req(req, &v))
}

fn split_key(key: &str) -> Option<(&str, &str)> {
    let idx = key.rfind('@')?;
    if idx == 0 {
        return None;
    }
    Some((&key[..idx], &key[idx + 1..]))
}
