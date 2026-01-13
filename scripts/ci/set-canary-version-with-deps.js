const fs = require('fs');
const p = 'package.json';
const j = JSON.parse(fs.readFileSync(p, 'utf8'));
const v = String(process.env.CANARY_VERSION || '').trim();
j.version = v;
j.optionalDependencies = j.optionalDependencies || {};
for (const k of Object.keys(j.optionalDependencies)) {
  j.optionalDependencies[k] = v;
}
fs.writeFileSync(p, JSON.stringify(j, null, '\t') + '\n');
