use anyhow::{Context, Result, anyhow};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::Client;
use semver::Version;
use serde::Deserialize;
use std::collections::BTreeMap;
use crate::npm_semver;

#[derive(Clone)]
pub struct RegistryClient {
    pub base: String,
    client: Client,
}

impl RegistryClient {
    pub fn from_env() -> Result<Self> {
        let base = std::env::var("VX_REGISTRY")
            .unwrap_or_else(|_| "https://registry.npmjs.org".to_string());
        let client = Client::builder()
            .user_agent(format!("vx/{}", env!("CARGO_PKG_VERSION")))
            .pool_max_idle_per_host(256)
            .tcp_nodelay(true)
            .build()
            .context("build http client")?;
        Ok(Self { base, client })
    }

    pub async fn packument(&self, name: &str) -> Result<Packument> {
        let resp = self.packument_raw(name, None).await?;
        let resp = resp
            .error_for_status()
            .with_context(|| format!("packument http error for {}", name))?;
        Ok(resp
            .json::<Packument>()
            .await
            .with_context(|| format!("decode packument for {}", name))?)
    }

    pub async fn packument_raw(&self, name: &str, etag: Option<&str>) -> Result<reqwest::Response> {
        let encoded = utf8_percent_encode(name, NON_ALPHANUMERIC).to_string();
        let url = format!("{}/{}", self.base.trim_end_matches('/'), encoded);
        let mut req = self
            .client
            .get(url)
            // Use the smaller "corgi" packument to reduce network/parse time.
            .header("Accept", "application/vnd.npm.install-v1+json");
        if let Some(etag) = etag {
            req = req.header("If-None-Match", etag);
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("GET packument for {}", name))?;
        Ok(resp)
    }

    pub async fn latest_version(&self, name: &str) -> Result<String> {
        let p = self.packument(name).await?;
        let latest = p
            .dist_tags
            .get("latest")
            .cloned()
            .ok_or_else(|| anyhow!("no dist-tag latest for {}", name))?;
        Ok(latest)
    }

    pub async fn resolve_version(&self, name: &str, req: &str) -> Result<ResolvedVersion> {
        let p = self.packument(name).await?;
        let version = if req == "latest" || req == "*" || req.is_empty() {
            p.dist_tags
                .get("latest")
                .cloned()
                .ok_or_else(|| anyhow!("no dist-tag latest for {}", name))?
        } else if p.versions.contains_key(req) {
            req.to_string()
        } else {
            let reqs = npm_semver::parse_req_any(req)
                .with_context(|| format!("invalid semver range `{req}` for {name}"))?;
            let mut best: Option<Version> = None;
            for v in p.versions.keys() {
                let Ok(ver) = Version::parse(v) else { continue };
                if reqs.iter().any(|r| r.matches(&ver)) {
                    if best.as_ref().map(|b| &ver > b).unwrap_or(true) {
                        best = Some(ver);
                    }
                }
            }
            best.ok_or_else(|| anyhow!("no version for {name} matches `{req}`"))?
                .to_string()
        };

        let meta = p
            .versions
            .get(&version)
            .ok_or_else(|| anyhow!("missing version metadata for {name}@{version}"))?;

        Ok(ResolvedVersion {
            name: meta.name.clone(),
            version: meta.version.clone(),
            tarball: meta.dist.tarball.clone(),
            integrity: meta
                .dist
                .integrity
                .clone()
                .or_else(|| meta.dist.shasum.as_ref().map(|s| format!("sha1-hex:{s}"))),
            dependencies: meta.dependencies.clone().unwrap_or_default(),
        })
    }

    pub async fn download(&self, url: &str) -> Result<reqwest::Response> {
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .with_context(|| format!("GET tarball {}", url))?
            .error_for_status()
            .with_context(|| format!("tarball http error {}", url))?;
        Ok(resp)
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedVersion {
    pub name: String,
    pub version: String,
    pub tarball: String,
    pub integrity: Option<String>,
    pub dependencies: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct Packument {
    #[serde(rename = "dist-tags")]
    pub dist_tags: BTreeMap<String, String>,
    pub versions: BTreeMap<String, PackumentVersion>,
}

#[derive(Debug, Deserialize)]
pub struct PackumentVersion {
    pub name: String,
    pub version: String,
    pub dist: Dist,
    pub dependencies: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
pub struct Dist {
    pub tarball: String,
    pub integrity: Option<String>,
    pub shasum: Option<String>,
}
