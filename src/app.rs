use crate::cli::{CacheCommand, Cli, Command};
use crate::fsutil::{
    current_link_mode_name, ensure_dir, node_modules_package_dir, remove_dir_all_if_exists,
};
use crate::lockfile::{Lockfile, LOCKFILE_VERSION};
use crate::manifest::{Manifest, PackageSpec};
use crate::paths::{ProjectPaths, vx_dir_for_path};
use crate::registry::RegistryClient;
use crate::resolver::{ResolveOptions, Resolver};
use crate::state::InstallState;
use crate::store::{InstallOptions, Store};
use anyhow::{Context, Result, anyhow};
use semver::Version;
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs;
use std::process::{Command as ProcCommand, ExitCode};
use std::time::{Duration, Instant};

pub async fn run(cli: Cli) -> Result<ExitCode> {
    let command = cli.command.unwrap_or(Command::Install {
        production: false,
        frozen_lockfile: false,
        no_prune: false,
    });

    match command {
        Command::Init { name } => cmd_init(name),
        Command::Add {
            specs,
            dev,
            no_install,
        } => cmd_add(specs, dev, no_install).await,
        Command::Install {
            production,
            frozen_lockfile,
            no_prune,
        } => cmd_install(production, frozen_lockfile, no_prune).await,
        Command::Cache { command } => cmd_cache(command),
        Command::X {
            spec,
            bin,
            offline,
            force,
            args,
        } => cmd_x(spec, bin, offline, force, args).await,
        Command::Run { script, args } => cmd_run(script, args),
    }
}

fn cmd_init(name: Option<String>) -> Result<ExitCode> {
    let cwd = std::env::current_dir().context("get current dir")?;
    let package_json = cwd.join("package.json");
    if package_json.exists() {
        return Err(anyhow!(
            "package.json already exists at {}",
            package_json.display()
        ));
    }

    let inferred_name = name.unwrap_or_else(|| {
        cwd.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("vx-project")
            .to_string()
    });

    let value = serde_json::json!({
        "name": inferred_name,
        "private": true,
        "version": "0.0.0",
        "dependencies": {},
        "devDependencies": {},
    });
    fs::write(&package_json, serde_json::to_string_pretty(&value)? + "\n")
        .with_context(|| format!("write {}", package_json.display()))?;
    Ok(ExitCode::SUCCESS)
}

async fn cmd_add(specs: Vec<String>, dev: bool, no_install: bool) -> Result<ExitCode> {
    if specs.is_empty() {
        return Err(anyhow!(
            "vx add expects at least 1 spec, e.g. `vx add react`"
        ));
    }
    let paths = ProjectPaths::discover()?;

    let registry = RegistryClient::from_env()?;
    let mut manifest_json = Manifest::load_raw(&paths.package_json)?;

    for spec in specs {
        let parsed = PackageSpec::parse(&spec)?;
        let req = match parsed.req {
            Some(req) => req,
            None => {
                let latest = registry
                    .latest_version(&parsed.name)
                    .await
                    .with_context(|| format!("resolve latest version for {}", parsed.name))?;
                format!("^{latest}")
            }
        };
        Manifest::set_dep(&mut manifest_json, dev, &parsed.name, &req)?;
    }

    Manifest::save_raw(&paths.package_json, &manifest_json)?;

    if no_install {
        return Ok(ExitCode::SUCCESS);
    }
    cmd_install(false, false, false).await
}

fn cmd_run(script: String, args: Vec<String>) -> Result<ExitCode> {
    let paths = ProjectPaths::discover()?;

    let raw = Manifest::load_raw(&paths.package_json)?;
    let scripts = raw
        .get("scripts")
        .and_then(|v| v.as_object())
        .ok_or_else(|| anyhow!("package.json has no scripts"))?;

    let cmd = scripts
        .get(&script)
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .ok_or_else(|| {
            let available = scripts.keys().map(|s| s.as_str()).collect::<Vec<_>>();
            if available.is_empty() {
                anyhow!("package.json has no scripts")
            } else {
                anyhow!(
                    "unknown script `{}` (available: {})",
                    script,
                    available.join(", ")
                )
            }
        })?;

    if cmd.is_empty() {
        return Err(anyhow!("script `{}` is empty", script));
    }

    let status = run_script_command(&paths, &cmd, &args)?;
    Ok(exitcode_from_status(status))
}

fn run_script_command(
    paths: &ProjectPaths,
    script_cmd: &str,
    args: &[String],
) -> Result<std::process::ExitStatus> {
    // On Windows, npm "bin" shims are typically `.cmd` files in `node_modules/.bin`.
    // `std::process::Command` does not reliably resolve `.cmd` from PATH, so use `cmd.exe`
    // like `npm run` does.
    if cfg!(windows) {
        let mut cmd = shell_command_for_script(script_cmd, args)?;
        cmd.current_dir(&paths.root);
        prepend_node_modules_bin_to_path(&mut cmd, paths);
        return cmd
            .status()
            .with_context(|| format!("run script `{}`", script_cmd));
    }

    let mut cmd = if script_needs_shell(script_cmd) {
        shell_command_for_script(script_cmd, args)?
    } else {
        let words = split_command_words(script_cmd)?;
        let (exe, rest) = words
            .split_first()
            .ok_or_else(|| anyhow!("script command is empty"))?;
        let mut c = ProcCommand::new(exe);
        c.args(rest);
        c.args(args);
        c
    };

    cmd.current_dir(&paths.root);
    prepend_node_modules_bin_to_path(&mut cmd, paths);

    match cmd.status() {
        Ok(status) => Ok(status),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let mut cmd = shell_command_for_script(script_cmd, args)?;
            cmd.current_dir(&paths.root);
            prepend_node_modules_bin_to_path(&mut cmd, paths);
            cmd.status()
        }
        Err(err) => Err(err),
    }
    .with_context(|| format!("run script `{}`", script_cmd))
}

fn prepend_node_modules_bin_to_path(cmd: &mut ProcCommand, paths: &ProjectPaths) {
    let bin_dir = paths.node_modules.join(".bin");
    let sep = if cfg!(windows) { ";" } else { ":" };
    let mut new_path = OsString::new();
    new_path.push(bin_dir.as_os_str());
    if let Some(old) = std::env::var_os("PATH") {
        new_path.push(sep);
        new_path.push(old);
    }
    cmd.env("PATH", new_path);
}

fn script_needs_shell(script_cmd: &str) -> bool {
    let s = script_cmd;
    if s.contains('\n') {
        return true;
    }
    if s.contains("&&")
        || s.contains("||")
        || s.contains('|')
        || s.contains('<')
        || s.contains('>')
        || s.contains(';')
        || s.contains('&')
    {
        return true;
    }
    if cfg!(not(windows)) && starts_with_posix_env_assignments(s) {
        return true;
    }
    false
}

fn starts_with_posix_env_assignments(s: &str) -> bool {
    let mut i = 0usize;
    let bytes = s.as_bytes();

    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            return false;
        }

        if !is_env_key_start(bytes[i]) {
            return false;
        }
        i += 1;
        while i < bytes.len() && is_env_key_continue(bytes[i]) {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            return false;
        }
        i += 1;

        while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }

        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            return true;
        }

        if !is_env_key_start(bytes[i]) {
            return true;
        }
    }

    true
}

fn is_env_key_start(b: u8) -> bool {
    (b as char).is_ascii_alphabetic() || b == b'_'
}

fn is_env_key_continue(b: u8) -> bool {
    (b as char).is_ascii_alphanumeric() || b == b'_'
}

fn shell_command_for_script(script_cmd: &str, args: &[String]) -> Result<ProcCommand> {
    #[cfg(windows)]
    {
        let mut full = script_cmd.to_string();
        if !args.is_empty() {
            full.push(' ');
            full.push_str(
                &args
                    .iter()
                    .map(|a| windows_list2cmdline_arg(a))
                    .collect::<Vec<_>>()
                    .join(" "),
            );
        }
        let mut c = ProcCommand::new("cmd.exe");
        c.args(["/d", "/s", "/c", &full]);
        return Ok(c);
    }
    #[cfg(not(windows))]
    {
        let mut c = ProcCommand::new("sh");
        c.arg("-lc").arg(format!("{script_cmd} \"$@\"")).arg("--");
        c.args(args);
        return Ok(c);
    }
}

fn windows_list2cmdline_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "\"\"".to_string();
    }

    let needs_quotes = arg.bytes().any(|b| b == b' ' || b == b'\t' || b == b'"');
    if !needs_quotes {
        return arg.to_string();
    }

    let mut out = String::new();
    out.push('"');
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                if backslashes > 0 {
                    out.push_str(&"\\".repeat(backslashes));
                    backslashes = 0;
                }
                out.push(ch);
            }
        }
    }
    if backslashes > 0 {
        out.push_str(&"\\".repeat(backslashes * 2));
    }
    out.push('"');
    out
}

fn split_command_words(s: &str) -> Result<Vec<String>> {
    let mut words = Vec::<String>::new();
    let mut cur = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escape = false;

    for ch in s.chars() {
        if escape {
            cur.push(ch);
            escape = false;
            continue;
        }

        match ch {
            '\\' if cfg!(not(windows)) && !in_single => {
                escape = true;
            }
            '\'' if !in_double => {
                in_single = !in_single;
            }
            '"' if !in_single => {
                in_double = !in_double;
            }
            c if c.is_whitespace() && !in_single && !in_double => {
                if !cur.is_empty() {
                    words.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(ch),
        }
    }

    if escape {
        cur.push('\\');
    }
    if in_single || in_double {
        return Err(anyhow!("unclosed quote in script command"));
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    Ok(words)
}

async fn cmd_install(production: bool, frozen_lockfile: bool, no_prune: bool) -> Result<ExitCode> {
    let started = Instant::now();
    let paths = ProjectPaths::discover()?;
    let registry = RegistryClient::from_env()?;
    let manifest = Manifest::load(&paths.package_json)?;

    let include_dev = !production;
    let layout = crate::store::current_layout_name().to_string();
    let node_modules = paths.node_modules.clone();
    let next_cache_dir = if manifest.dependencies.contains_key("next")
        || manifest.dev_dependencies.contains_key("next")
    {
        Some(paths.root.join(".next"))
    } else {
        None
    };

    let existing_lock = load_lock_with_hash(&paths.lockfile)?;
    let mut lock_and_hash = None;

    if let Some((lock, lock_hash)) = existing_lock {
        let valid = lock
            .validate_against_manifest(&manifest, include_dev)
            .is_ok();
        if valid {
            if is_up_to_date(
                &paths,
                &lock,
                &lock_hash,
                include_dev,
                &layout,
                &registry.base,
            )? {
                let store = Store::new(paths.clone());
                store.ensure_bins_from_lock(&lock)?;
                eprintln!("Already up to date in {}", fmt_elapsed(started.elapsed()));
                return Ok(ExitCode::SUCCESS);
            }
            lock_and_hash = Some((lock, lock_hash));
        } else if frozen_lockfile {
            return Err(anyhow!(
                "lockfile is not valid for current package.json (and --frozen-lockfile is set)"
            ));
        }
    } else if frozen_lockfile {
        return Err(anyhow!("--frozen-lockfile requires an existing vx.lock"));
    }

    let lock = if let Some((lock, lock_hash)) = lock_and_hash.take() {
        eprintln!("Using existing lockfile (no network)...");
        (lock, lock_hash)
    } else {
        eprintln!("Resolving dependencies...");
        let resolve_started = Instant::now();
        let existing = Lockfile::load_if_exists(&paths.lockfile)?
            .filter(|lock| lock.lockfile_version >= LOCKFILE_VERSION);
        let packument_cache_dir = paths.vx_dir.join("meta").join("packuments");
        let mut resolver = Resolver::new_with_cache(registry.clone(), Some(packument_cache_dir));
        let resolve_options = ResolveOptions {
            include_dev,
            frozen_lockfile: false,
        };
        let lock = resolver
            .resolve(&manifest, existing, &resolve_options)
            .await?;
        lock.save(&paths.lockfile)?;
        let (saved, hash) = load_lock_with_hash(&paths.lockfile)?
            .ok_or_else(|| anyhow!("failed to read lockfile after saving"))?;
        eprintln!("Resolved in {}", fmt_elapsed(resolve_started.elapsed()));
        (saved, hash)
    };

    let store = Store::new(paths);
    store
        .install_from_lock(
            &lock.0,
            &InstallOptions {
                prune_node_modules: !no_prune,
            },
        )
        .await?;
    if let Some(next_dir) = next_cache_dir {
        if next_dir.exists() {
            // Clear stale Next.js cache after dependency relinking.
            remove_dir_all_if_exists(&next_dir)?;
        }
    }

    crate::state::save(
        &node_modules,
        &InstallState {
            lock_sha256: lock.1.clone(),
            include_dev,
            layout,
            link_mode: current_link_mode_name(),
            registry: registry.base.clone(),
            vx_version: env!("CARGO_PKG_VERSION").to_string(),
        },
    )?;

    eprintln!("Install complete in {}", fmt_elapsed(started.elapsed()));
    Ok(ExitCode::SUCCESS)
}

fn cmd_cache(command: CacheCommand) -> Result<ExitCode> {
    let paths = ProjectPaths::discover()?;
    match command {
        CacheCommand::Dir => {
            println!("{}", paths.store_dir.display());
            Ok(ExitCode::SUCCESS)
        }
        CacheCommand::Clean => {
            if paths.vx_dir.exists() {
                fs::remove_dir_all(&paths.vx_dir)
                    .with_context(|| format!("remove {}", paths.vx_dir.display()))?;
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

async fn cmd_x(
    spec: String,
    bin: Option<String>,
    offline: bool,
    force: bool,
    args: Vec<String>,
) -> Result<ExitCode> {
    let cwd = std::env::current_dir().context("get current dir")?;
    let vx_dir = vx_dir_for_path(&cwd)?;
    ensure_dir(&vx_dir)?;

    let registry = RegistryClient::from_env()?;
    let parsed = PackageSpec::parse(&spec)?;
    let req = parsed.req.clone();

    let (resolved_name, resolved_version) = match (offline, req.as_deref()) {
        (true, Some(r)) => {
            Version::parse(r).map_err(|_| {
                anyhow!(
                    "vx x --offline requires an exact semver version (e.g. `vx x cowsay@1.5.0`)"
                )
            })?;
            (parsed.name, r.to_string())
        }
        (true, None) => {
            return Err(anyhow!(
                "vx x --offline requires an explicit version (e.g. `vx x cowsay@1.5.0`)"
            ));
        }
        (false, Some(r)) if Version::parse(r).is_ok() => (parsed.name, r.to_string()),
        (false, _) => {
            let req = req.unwrap_or_else(|| "latest".to_string());
            let resolved = registry.resolve_version(&parsed.name, &req).await?;
            (resolved.name, resolved.version)
        }
    };

    let dlx_root = dlx_dir(&vx_dir, &resolved_name, &resolved_version)?;
    ensure_dir(&dlx_root)?;

    let package_json = dlx_root.join("package.json");
    if force {
        remove_dir_all_if_exists(&dlx_root.join("node_modules"))?;
        if dlx_root.join("vx.lock").exists() {
            fs::remove_file(dlx_root.join("vx.lock")).ok();
        }
    }

    if !package_json.exists() || force {
        let value = serde_json::json!({
            "name": "vx-dlx",
            "private": true,
            "version": "0.0.0",
            "dependencies": {
                resolved_name.clone(): resolved_version.clone()
            }
        });
        fs::write(&package_json, serde_json::to_string_pretty(&value)? + "\n")
            .with_context(|| format!("write {}", package_json.display()))?;
    }

    let node_modules_dir = dlx_root.join("node_modules");
    let pkg_dir = node_modules_package_dir(&node_modules_dir, &resolved_name)?;

    // Fast path: already installed.
    if !force && pkg_dir.join("package.json").exists() {
        let (bin_name, bin_rel) = select_bin(&pkg_dir, &resolved_name, bin.as_deref())?;
        let bin_path = pkg_dir.join(bin_rel);
        let status = run_bin(&bin_path, &bin_name, &args)?;
        return Ok(exitcode_from_status(status));
    }

    if offline {
        return Err(anyhow!(
            "offline mode requested, but the package is not installed: {}",
            pkg_dir.display()
        ));
    }

    // Install into the dlx root.
    {
        let started = Instant::now();
        let paths = ProjectPaths::for_root_with_vx(dlx_root.clone(), vx_dir.clone())?;
        let manifest = Manifest::load(&paths.package_json)?;
        let existing_lock = Lockfile::load_if_exists(&paths.lockfile)?;
        let packument_cache_dir = vx_dir.join("meta").join("packuments");
        let mut resolver = Resolver::new_with_cache(registry, Some(packument_cache_dir));
        let lock = resolver
            .resolve(
                &manifest,
                existing_lock,
                &ResolveOptions {
                    include_dev: false,
                    frozen_lockfile: false,
                },
            )
            .await?;
        lock.save(&paths.lockfile)?;

        let store = Store::new(paths);
        store
            .install_from_lock(
                &lock,
                &InstallOptions {
                    prune_node_modules: false,
                },
            )
            .await?;
        eprintln!("Ready in {}", fmt_elapsed(started.elapsed()));
    }

    let (bin_name, bin_rel) = select_bin(&pkg_dir, &resolved_name, bin.as_deref())?;
    let bin_path = pkg_dir.join(bin_rel);

    let status = run_bin(&bin_path, &bin_name, &args)?;
    Ok(exitcode_from_status(status))
}

fn dlx_dir(vx_dir: &std::path::Path, name: &str, version: &str) -> Result<std::path::PathBuf> {
    use sha1::Digest;
    let mut h = sha1::Sha1::new();
    h.update(format!("{name}@{version}").as_bytes());
    let hex = crate::integrity::hex(&h.finalize().to_vec());
    Ok(vx_dir.join("dlx").join(hex))
}

fn select_bin(
    pkg_dir: &std::path::Path,
    pkg_name: &str,
    requested: Option<&str>,
) -> Result<(String, String)> {
    let pkg_json = pkg_dir.join("package.json");
    let bytes = fs::read(&pkg_json).with_context(|| format!("read {}", pkg_json.display()))?;
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", pkg_json.display()))?;
    let bin_val = v
        .get("bin")
        .ok_or_else(|| anyhow!("package {} has no `bin` field", pkg_name))?;

    let mut bins: Vec<(String, String)> = Vec::new();
    match bin_val {
        serde_json::Value::String(s) => {
            let default = default_bin_name(pkg_name);
            bins.push((default, s.clone()));
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                if let Some(s) = v.as_str() {
                    bins.push((k.clone(), s.to_string()));
                }
            }
        }
        _ => return Err(anyhow!("invalid `bin` field in {}", pkg_json.display())),
    }

    if bins.is_empty() {
        return Err(anyhow!("package {} exposes no runnable bins", pkg_name));
    }

    if let Some(req) = requested {
        let found = bins
            .into_iter()
            .find(|(k, _)| k == req)
            .ok_or_else(|| anyhow!("bin `{}` not found in {}", req, pkg_name))?;
        return Ok(found);
    }

    if bins.len() == 1 {
        return Ok(bins.remove(0));
    }

    let default = default_bin_name(pkg_name);
    if let Some(found) = bins.iter().find(|(k, _)| k == &default) {
        return Ok(found.clone());
    }

    let choices = bins
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    Err(anyhow!(
        "package {} has multiple bins ({}) - choose with `--bin <name>`",
        pkg_name,
        choices
    ))
}

fn default_bin_name(pkg_name: &str) -> String {
    pkg_name.rsplit('/').next().unwrap_or(pkg_name).to_string()
}

fn run_bin(
    bin_path: &std::path::Path,
    _bin_name: &str,
    args: &[String],
) -> Result<std::process::ExitStatus> {
    let ext = bin_path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if ext == "js" || ext == "mjs" || ext == "cjs" {
        return ProcCommand::new("node")
            .args(["--preserve-symlinks", "--preserve-symlinks-main"])
            .arg(bin_path)
            .args(args)
            .status()
            .with_context(|| format!("run node {}", bin_path.display()));
    }
    ProcCommand::new(bin_path)
        .args(args)
        .status()
        .with_context(|| format!("run {}", bin_path.display()))
}

fn exitcode_from_status(status: std::process::ExitStatus) -> ExitCode {
    if let Some(code) = status.code() {
        ExitCode::from(code as u8)
    } else {
        ExitCode::FAILURE
    }
}

fn fmt_elapsed(d: Duration) -> String {
    let secs = d.as_secs_f64();
    if secs < 60.0 {
        return format!("{secs:.2}s");
    }
    let mins = (secs / 60.0).floor() as u64;
    let rem = secs - (mins as f64) * 60.0;
    format!("{mins}m{rem:.2}s")
}

fn load_lock_with_hash(path: &std::path::Path) -> Result<Option<(Lockfile, String)>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let mut h = Sha256::new();
    h.update(&bytes);
    let hex = crate::integrity::hex(&h.finalize().to_vec());
    let lock: Lockfile =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
    Ok(Some((lock, hex)))
}

#[cfg(test)]
mod run_tests {
    use super::*;

    #[test]
    fn split_command_words_basic() {
        let v = split_command_words("next dev").unwrap();
        assert_eq!(v, vec!["next", "dev"]);
    }

    #[test]
    fn split_command_words_quotes() {
        let v = split_command_words(r#"node -e "console.log(1)""#).unwrap();
        assert_eq!(v, vec!["node", "-e", "console.log(1)"]);
    }

    #[test]
    #[cfg(windows)]
    fn split_command_words_windows_paths() {
        let v = split_command_words(r#"node .\scripts\foo.js"#).unwrap();
        assert_eq!(v, vec!["node", r#".\scripts\foo.js"#]);
    }
}

fn is_up_to_date(
    paths: &ProjectPaths,
    lock: &Lockfile,
    lock_hash: &str,
    include_dev: bool,
    layout: &str,
    registry: &str,
) -> Result<bool> {
    if !paths.node_modules.exists() {
        return Ok(false);
    }
    let Some(state) = crate::state::load(&paths.node_modules)? else {
        return Ok(false);
    };
    if state.lock_sha256 != lock_hash
        || state.include_dev != include_dev
        || state.layout != layout
        || state.link_mode.is_empty()
        || state.link_mode != current_link_mode_name()
        || state.registry != registry
    {
        return Ok(false);
    }
    for name in lock.root.requires.keys() {
        let dir = node_modules_package_dir(&paths.node_modules, name)?;
        if !dir.join("package.json").exists() {
            return Ok(false);
        }
    }
    Ok(true)
}
