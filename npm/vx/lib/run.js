const { spawn } = require("node:child_process");

function platformPackage() {
  const { platform, arch } = process;
  if (platform === "win32" && arch === "x64") return "@vx-js/vx-win32-x64-msvc";
  if (platform === "linux" && arch === "x64") return "@vx-js/vx-linux-x64-gnu";
  if (platform === "linux" && arch === "arm64") return "@vx-js/vx-linux-arm64-gnu";
  if (platform === "darwin" && arch === "x64") return "@vx-js/vx-darwin-x64";
  if (platform === "darwin" && arch === "arm64") return "@vx-js/vx-darwin-arm64";
  return null;
}

function resolveBinaryPath() {
  const pkg = platformPackage();
  if (!pkg) {
    throw new Error(
      `@vx-js/vx does not ship binaries for ${process.platform}/${process.arch} yet.`
    );
  }

  try {
    const mod = require(pkg);
    if (!mod || typeof mod.binaryPath !== "string" || mod.binaryPath.length === 0) {
      throw new Error(`Invalid ${pkg} module: expected { binaryPath: string }`);
    }
    return mod.binaryPath;
  } catch (err) {
    const msg = err && err.stack ? err.stack : String(err);
    throw new Error(
      `Failed to load platform binary package (${pkg}).\n` +
        `Make sure optional dependencies are installed (npm install without --omit=optional).\n` +
        msg
    );
  }
}

const binPath = resolveBinaryPath();
const child = spawn(binPath, process.argv.slice(2), {
  stdio: "inherit",
  windowsHide: true,
});

child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 1);
});
