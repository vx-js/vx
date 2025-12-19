# vx

The fastest JavaScript package manager we've seen.

`vx` is a fast, cache-first npm package installer prototype written in Rust.

## CLI

- `vx install` installs dependencies (default command)
- `vx add <spec...>` adds dependencies
- `vx run <script> -- <args...>` runs a `package.json` script (npm run-like)
- `vx x <pkg> -- <args...>` runs a package binary without adding it

## npm package

This repo includes an npm publish setup under `npm/`:

- `npm/vx` -> `@vx-js/vx` (wrapper that exposes the `vx` CLI)
- `npm/vx-win32-x64-msvc` -> `@vx-js/vx-win32-x64-msvc` (Windows x64 binary)
- `npm/vx-linux-x64-gnu` -> `@vx-js/vx-linux-x64-gnu` (Linux x64 GNU binary)
- `npm/vx-linux-arm64-gnu` -> `@vx-js/vx-linux-arm64-gnu` (Linux arm64 GNU binary)
- `npm/vx-darwin-x64` -> `@vx-js/vx-darwin-x64` (macOS x64 binary)
- `npm/vx-darwin-arm64` -> `@vx-js/vx-darwin-arm64` (macOS arm64 binary)

To create tarballs locally (no publish):

```bash
cd npm/vx-win32-x64-msvc && npm pack
cd ../vx && npm pack
```
