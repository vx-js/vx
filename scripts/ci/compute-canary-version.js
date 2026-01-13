const fs = require('fs');
const pkg = JSON.parse(fs.readFileSync('npm/vx/package.json', 'utf8'));
const base = pkg.version;
const ts = new Date().toISOString().replace(/\D/g, '').slice(0, 14);
const runId = (process.env.GITHUB_RUN_ID || '').trim();
const suffix = runId ? (ts + '-' + runId) : ts;
const v = base + '-canary-' + suffix;
console.log(v);
fs.appendFileSync(process.env.GITHUB_OUTPUT, 'version=' + v + '\n');
