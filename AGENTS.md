# AGENTS.md - Coding Agent Guidelines for vx

This document provides guidelines for AI coding agents working in the `vx` codebase.

## Project Overview

**vx** is a fast, cache-first npm package installer written in Rust (Edition 2024). It aims to be the fastest JavaScript package manager with features like content-addressed storage, parallel downloads, and smart caching.

## Build Commands

```bash
# Build (debug)
cargo build

# Build (release)
cargo build --release

# Build for specific target
cargo build --release --target x86_64-pc-windows-msvc

# Format code
cargo fmt

# Check formatting without changes
cargo fmt -- --check

# Run clippy linter
cargo clippy

# Run clippy with warnings as errors (CI standard)
cargo clippy -- -D warnings
```

## Test Commands

```bash
# Run all tests
cargo test

# Run a single test by name
cargo test test_name

# Run a single test with exact match
cargo test test_name -- --exact

# Run tests in a specific module
cargo test module_name::

# Run tests with output visible
cargo test -- --nocapture

# Run tests matching a pattern
cargo test parse_  # runs all tests containing "parse_"
```

Tests are located inline within source files using `#[cfg(test)]` modules, not in a separate `tests/` directory.

## Project Structure

```
src/
  main.rs         # Entry point
  lib.rs          # Library root, exports public modules
  cli.rs          # CLI definitions (clap derive)
  app.rs          # Command implementations (cmd_init, cmd_add, etc.)
  manifest.rs     # package.json parsing
  lockfile.rs     # vx.lock handling
  resolver.rs     # Dependency resolution
  registry.rs     # npm registry HTTP client
  store.rs        # Content-addressed store & installation
  npm_semver.rs   # npm-compatible semver parsing
  integrity.rs    # SHA verification
  paths.rs        # Project path discovery
  fsutil.rs       # File system utilities
  state.rs        # Install state persistence
npm/              # npm distribution packages
scripts/          # CI/build scripts
```

## Code Style Guidelines

### Import Organization

Imports are generally sorted alphabetically. Group and organize imports as:
```rust
use crate::module::{Type1, Type2};
use external_crate::{Item1, Item2};
use std::collections::BTreeMap;
```

### Naming Conventions

| Element | Convention | Examples |
|---------|------------|----------|
| Functions | snake_case | `cmd_install`, `ensure_dir`, `parse_spec` |
| Variables | snake_case | `resolved_name`, `package_json` |
| Types/Structs | PascalCase | `Lockfile`, `InstallOptions`, `RegistryClient` |
| Enums | PascalCase | `Layout::Flat`, `Algo::Sha512` |
| Constants | SCREAMING_SNAKE_CASE | `LOCKFILE_VERSION` |
| Files/Modules | snake_case | `npm_semver.rs`, `fsutil.rs` |

**Function prefixes:**
- `cmd_*` - CLI command handlers
- `is_*` - Boolean predicates
- `ensure_*` - Idempotent operations
- `load_*` / `save_*` - I/O operations
- `parse_*` - Parsing functions

### Type Patterns

```rust
// Data transfer structs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MyStruct {
    #[serde(rename = "camelCase")]
    pub field_name: String,
    #[serde(default)]
    pub optional_field: Option<String>,
}

// Simple enums
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MyEnum {
    VariantOne,
    VariantTwo,
}
```

**Prefer `BTreeMap`/`BTreeSet` over `HashMap`/`HashSet`** for deterministic serialization.

### Error Handling

Use `anyhow` exclusively. All functions return `anyhow::Result<T>`.

```rust
use anyhow::{Context, Result, anyhow};

// Add context to errors
let data = fs::read(path)
    .with_context(|| format!("read {}", path.display()))?;

// Create errors directly
return Err(anyhow!("invalid input: {}", value));

// Ensure conditions
anyhow::ensure!(condition, "error message");
```

### Platform-Specific Code

```rust
#[cfg(windows)]
fn platform_specific() -> Result<()> {
    // Windows implementation
}

#[cfg(not(windows))]
fn platform_specific() -> Result<()> {
    // Unix implementation
}
```

### Async Patterns

- Runtime: `tokio` with `#[tokio::main]`
- Concurrency: `futures::stream::FuturesUnordered` with `Semaphore`
- Environment variables for tuning: `VX_CONCURRENCY`, `VX_RESOLVE_BATCH`

### Test Structure

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptive_test_name() {
        // Arrange
        let input = "test input";
        
        // Act
        let result = function_under_test(input);
        
        // Assert
        assert_eq!(result, expected);
    }
}
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VX_REGISTRY` | npm registry URL | `https://registry.npmjs.org` |
| `VX_LAYOUT` | `flat` or `nested` | `flat` (Windows), `nested` (Unix) |
| `VX_LINK_MODE` | `auto`, `tree`, `symlink`, `junction` | `auto` |
| `VX_CONCURRENCY` | Download concurrency | 8-64 based on CPU |
| `VX_PACKUMENT_CONCURRENCY` | Packument fetch concurrency | 128 |
| `VX_PACKUMENT_MAX_AGE_SECS` | Cache TTL | 3600 |

## Key Dependencies

- `anyhow` - Error handling
- `clap` - CLI parsing (derive macros)
- `tokio` - Async runtime
- `reqwest` - HTTP client (rustls-tls)
- `serde`/`serde_json` - Serialization
- `semver` - Version handling

## CI/CD

GitHub Actions runs on push to `master` and tags. Builds for:
- Linux x64/arm64
- macOS x64/arm64  
- Windows x64

Releases are created on `v*` tags. Canary versions published on master pushes.

## Common Tasks

**Adding a new CLI command:**
1. Add variant to `Command` enum in `src/cli.rs`
2. Implement `cmd_newcommand()` in `src/app.rs`
3. Add match arm in `run()` function

**Adding a new module:**
1. Create `src/newmodule.rs`
2. Add `mod newmodule;` or `pub mod newmodule;` in `src/lib.rs`
3. Use `pub use` for key types to re-export

**Writing tests:**
- Add `#[cfg(test)]` module at bottom of source file
- Use descriptive test names: `parse_scoped_with_version`
- Run specific test: `cargo test parse_scoped_with_version`
