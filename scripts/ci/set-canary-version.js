const fs = require('fs');
const p = 'package.json';
const j = JSON.parse(fs.readFileSync(p, 'utf8'));
j.version = String(process.env.CANARY_VERSION || '').trim();
fs.writeFileSync(p, JSON.stringify(j, null, '\t') + '\n');
