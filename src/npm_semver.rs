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
}

