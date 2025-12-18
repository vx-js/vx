const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

function parseArgs(argv) {
  const args = { out: null, target: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--out") args.out = argv[++i];
    else if (a === "--target") args.target = argv[++i];
    else throw new Error(`Unknown arg: ${a}`);
  }
  if (!args.out) throw new Error("Missing required --out <path>");
  return args;
}

const { out, target } = parseArgs(process.argv.slice(2));
const repoRoot = path.resolve(__dirname, "..");
const pkgCwd = process.cwd();

const cargoArgs = ["build", "--release"];
if (target) cargoArgs.push("--target", target);

const build = spawnSync("cargo", cargoArgs, { cwd: repoRoot, stdio: "inherit" });
if (build.status !== 0) process.exit(build.status ?? 1);

const exe = process.platform === "win32" ? "vx.exe" : "vx";
const builtPath = target
  ? path.join(repoRoot, "target", target, "release", exe)
  : path.join(repoRoot, "target", "release", exe);

if (!fs.existsSync(builtPath)) {
  throw new Error(`Built binary not found: ${builtPath}`);
}

const outPath = path.resolve(pkgCwd, out);
fs.mkdirSync(path.dirname(outPath), { recursive: true });
fs.copyFileSync(builtPath, outPath);
if (process.platform !== "win32") fs.chmodSync(outPath, 0o755);

console.log(`Copied ${builtPath} -> ${outPath}`);

