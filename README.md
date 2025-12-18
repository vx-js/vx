# vx

The fastest JavaScript package manager we've seen.

`vx` is a fast, cache-first npm package installer prototype written in Rust.

## npm package

This repo includes an npm publish setup under `npm/`:

- `npm/vx` -> `@vx-js/vx` (wrapper that exposes the `vx` CLI)
- `npm/vx-win32-x64-msvc` -> `@vx-js/vx-win32-x64-msvc` (Windows x64 binary)

To create tarballs locally (no publish):

```bash
cd npm/vx-win32-x64-msvc && npm pack
cd ../vx && npm pack
```
