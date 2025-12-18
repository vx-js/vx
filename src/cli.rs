use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "vx", version, about = "A fast, cache-first npm package installer (prototype).")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create a minimal package.json
    Init {
        #[arg(long)]
        name: Option<String>,
    },
    /// Add dependencies to package.json (and install by default)
    Add {
        specs: Vec<String>,
        #[arg(long)]
        dev: bool,
        #[arg(long)]
        no_install: bool,
    },
    /// Install dependencies from package.json / vx.lock
    Install {
        #[arg(long)]
        production: bool,
        #[arg(long)]
        frozen_lockfile: bool,
        #[arg(long)]
        no_prune: bool,
    },
    /// Manage vx cache
    Cache {
        #[command(subcommand)]
        command: CacheCommand,
    },
    /// Run a package binary without adding it to your project (pnpm dlx-like)
    X {
        /// Package spec, e.g. `cowsay` or `@biomejs/biome@1.9.4`
        spec: String,
        /// Select which bin to run when the package exposes multiple
        #[arg(long)]
        bin: Option<String>,
        /// Do not hit the network (requires an already-installed dlx dir)
        #[arg(long)]
        offline: bool,
        /// Reinstall even if already present
        #[arg(long)]
        force: bool,
        /// Arguments passed to the binary (use `--` to separate)
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum CacheCommand {
    /// Print cache path
    Dir,
    /// Remove the local content-addressed store
    Clean,
}
