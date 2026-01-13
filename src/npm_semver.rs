use anyhow::{Context, Result, anyhow};
use semver::{Version, VersionReq};

pub(crate) fn matches_req(req: &str, version: &Version) -> bool {
    let req = req.trim();
    if req.is_empty() || req == "*" || req == "latest" {
        return true;
    }
    if req == version.to_string() {
        return true;
    }
    let Ok(reqs) = parse_req_any(req) else {
        return false;
    };
    reqs.iter().any(|r| r.matches(version))
}

pub(crate) fn parse_req_any(req: &str) -> Result<Vec<VersionReq>> {
    let req = req.trim();
    if req.is_empty() {
        return Err(anyhow!("empty version range"));
    }

    let parts = req
        .split("||")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();

    let mut out = Vec::with_capacity(parts.len().max(1));
    for part in parts {
        out.push(parse_req_loose(part).with_context(|| format!("invalid range part `{part}`"))?);
    }

    if out.is_empty() {
        return Err(anyhow!("empty version range"));
    }
    Ok(out)
}

fn parse_req_loose(s: &str) -> Result<VersionReq> {
    let s = s.trim();
    if let Ok(r) = VersionReq::parse(s) {
        return Ok(r);
    }

    // Handle npm hyphen ranges: "1 - 3" means ">=1.0.0 <4.0.0", "1.2.3 - 2.3.4" means ">=1.2.3 <=2.3.4"
    if let Some(hyphen_idx) = s.find(" - ") {
        let low = s[..hyphen_idx].trim();
        let high = s[hyphen_idx + 3..].trim();
        
        // Parse the low version
        let low_ver = if low.is_empty() {
            Version::parse("0.0.0")?
        } else {
            // Normalize partial versions like "1" to "1.0.0"
            let normalized_low = normalize_partial_version(low);
            Version::parse(&normalized_low)
                .with_context(|| format!("invalid lower bound in hyphen range: `{low}`"))?
        };
        
        // Parse the high version
        let high_ver = if high.is_empty() {
            return Err(anyhow!("missing upper bound in hyphen range"));
        } else {
            // Normalize partial versions like "3" to "3.0.0"
            let normalized_high = normalize_partial_version(high);
            Version::parse(&normalized_high)
                .with_context(|| format!("invalid upper bound in hyphen range: `{high}`"))?
        };
        
        // Determine if high is a partial version (e.g., "3" vs "3.0.0")
        let high_is_partial = is_partial_version(high);
        
        // Convert to semver range format (VersionReq uses comma-separated constraints)
        // If high is partial (e.g., "3"), treat as X-range: "1 - 3" -> ">=1.0.0, <4.0.0"
        // If high is full (e.g., "2.3.4"), use inclusive: "1.2.3 - 2.3.4" -> ">=1.2.3, <2.3.5"
        let next_ver = if high_is_partial {
            // Partial version: bump major version
            Version {
                major: high_ver.major + 1,
                minor: 0,
                patch: 0,
                pre: semver::Prerelease::EMPTY,
                build: semver::BuildMetadata::EMPTY,
            }
        } else {
            // Full version: bump patch version for inclusive upper bound
            Version {
                major: high_ver.major,
                minor: high_ver.minor,
                patch: high_ver.patch + 1,
                pre: semver::Prerelease::EMPTY,
                build: semver::BuildMetadata::EMPTY,
            }
        };
        
        let range_str = format!(">={}, <{}", low_ver, next_ver);
        return VersionReq::parse(&range_str)
            .with_context(|| format!("failed to parse hyphen range `{s}`"));
    }

    // npm often uses whitespace to separate AND constraints, while `semver` prefers commas.
    let normalized = s
        .split_whitespace()
        .filter(|t| !t.is_empty())
        .collect::<Vec<_>>()
        .join(", ");
    if normalized != s {
        if let Ok(r) = VersionReq::parse(&normalized) {
            return Ok(r);
        }
    }

    Err(anyhow!("unsupported semver range `{s}`"))
}

fn normalize_partial_version(s: &str) -> String {
    let parts: Vec<&str> = s.split('.').collect();
    match parts.len() {
        1 => format!("{}.0.0", parts[0]),
        2 => format!("{}.{}.0", parts[0], parts[1]),
        _ => s.to_string(),
    }
}

fn is_partial_version(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() < 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn or_ranges_match() {
        let reqs = parse_req_any("^2.4.1 || ^3.0.0").unwrap();
        assert_eq!(reqs.len(), 2);
        assert!(reqs[0].matches(&Version::parse("2.4.1").unwrap()));
        assert!(reqs[1].matches(&Version::parse("3.1.0").unwrap()));
    }

    #[test]
    fn whitespace_and_constraints_are_accepted() {
        let reqs = parse_req_any(">=1.2.3 <2.0.0").unwrap();
        assert_eq!(reqs.len(), 1);
        assert!(reqs[0].matches(&Version::parse("1.9.9").unwrap()));
        assert!(!reqs[0].matches(&Version::parse("2.0.0").unwrap()));
    }

    #[test]
    fn hyphen_ranges_with_partial_versions() {
        // "1 - 3" should mean ">=1.0.0 <4.0.0"
        let reqs = parse_req_any("1 - 3").unwrap();
        assert_eq!(reqs.len(), 1);
        assert!(reqs[0].matches(&Version::parse("1.0.0").unwrap()));
        assert!(reqs[0].matches(&Version::parse("2.5.0").unwrap()));
        assert!(reqs[0].matches(&Version::parse("3.9.9").unwrap()));
        assert!(!reqs[0].matches(&Version::parse("4.0.0").unwrap()));
        assert!(!reqs[0].matches(&Version::parse("0.9.9").unwrap()));
    }

    #[test]
    fn hyphen_ranges_with_full_versions() {
        // "1.2.3 - 2.3.4" should mean ">=1.2.3 <=2.3.4"
        let reqs = parse_req_any("1.2.3 - 2.3.4").unwrap();
        assert_eq!(reqs.len(), 1);
        assert!(reqs[0].matches(&Version::parse("1.2.3").unwrap()));
        assert!(reqs[0].matches(&Version::parse("2.0.0").unwrap()));
        assert!(reqs[0].matches(&Version::parse("2.3.4").unwrap()));
        assert!(!reqs[0].matches(&Version::parse("2.3.5").unwrap()));
        assert!(!reqs[0].matches(&Version::parse("1.2.2").unwrap()));
    }
}

