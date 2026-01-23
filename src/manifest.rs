use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct PackageSpec {
    pub name: String,
    pub req: Option<String>,
}

impl PackageSpec {
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        if input.is_empty() {
            return Err(anyhow!("empty spec"));
        }

        // Scoped packages: "@scope/name@^1.2.3" (split on the last '@' only if it has "/").
        if input.starts_with('@') {
            if let Some(idx) = input.rfind('@') {
                if idx > 0 && input[..idx].contains('/') && !input[idx + 1..].trim().is_empty() {
                    return Ok(Self {
                        name: input[..idx].to_string(),
                        req: Some(input[idx + 1..].to_string()),
                    });
                }
            }
            return Ok(Self {
                name: input.to_string(),
                req: None,
            });
        }

        // Unscoped: "react@^18"
        if let Some(idx) = input.rfind('@') {
            if idx > 0 && !input[idx + 1..].trim().is_empty() {
                return Ok(Self {
                    name: input[..idx].to_string(),
                    req: Some(input[idx + 1..].to_string()),
                });
            }
        }

        Ok(Self {
            name: input.to_string(),
            req: None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    #[serde(default)]
    pub dependencies: BTreeMap<String, String>,
    #[serde(rename = "devDependencies", default)]
    pub dev_dependencies: BTreeMap<String, String>,
    #[serde(rename = "optionalDependencies", default)]
    pub optional_dependencies: BTreeMap<String, String>,
}

impl Manifest {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        let raw: Value =
            serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
        let dependencies = raw
            .get("dependencies")
            .and_then(|v| v.as_object())
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();
        let dev_dependencies = raw
            .get("devDependencies")
            .and_then(|v| v.as_object())
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();
        let optional_dependencies = raw
            .get("optionalDependencies")
            .and_then(|v| v.as_object())
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();
        Ok(Self {
            dependencies,
            dev_dependencies,
            optional_dependencies,
        })
    }

    pub fn load_raw(path: &Path) -> Result<Value> {
        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        let raw: Value =
            serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
        Ok(raw)
    }

    pub fn save_raw(path: &Path, raw: &Value) -> Result<()> {
        let s = serde_json::to_string_pretty(raw)? + "\n";
        fs::write(path, s).with_context(|| format!("write {}", path.display()))?;
        Ok(())
    }

    pub fn set_dep(raw: &mut Value, dev: bool, name: &str, req: &str) -> Result<()> {
        if !raw.is_object() {
            return Err(anyhow!("package.json root must be an object"));
        }
        let dep_key = if dev {
            "devDependencies"
        } else {
            "dependencies"
        };
        if raw.get(dep_key).is_none() {
            raw[dep_key] = Value::Object(Default::default());
        }
        let obj = raw[dep_key]
            .as_object_mut()
            .ok_or_else(|| anyhow!("{dep_key} must be an object"))?;
        obj.insert(name.to_string(), Value::String(req.to_string()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_unscoped_with_version() {
        let s = PackageSpec::parse("react@^18").unwrap();
        assert_eq!(s.name, "react");
        assert_eq!(s.req.as_deref(), Some("^18"));
    }

    #[test]
    fn parse_unscoped_without_version() {
        let s = PackageSpec::parse("react").unwrap();
        assert_eq!(s.name, "react");
        assert!(s.req.is_none());
    }

    #[test]
    fn parse_scoped_with_version() {
        let s = PackageSpec::parse("@types/node@^20").unwrap();
        assert_eq!(s.name, "@types/node");
        assert_eq!(s.req.as_deref(), Some("^20"));
    }

    #[test]
    fn parse_scoped_without_version() {
        let s = PackageSpec::parse("@types/node").unwrap();
        assert_eq!(s.name, "@types/node");
        assert!(s.req.is_none());
    }
}
