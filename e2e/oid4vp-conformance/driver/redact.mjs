// Copyright 2026 HelixIAM contributors
// SPDX-License-Identifier: Apache-2.0
// node redact.mjs <exportDir with json/*.zip> <outDir>
import fs from 'node:fs'; import path from 'node:path'; import { execFileSync } from 'node:child_process';
const [src, dst] = process.argv.slice(2);
const PRIVATE_JWK = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'];
let redactions = 0;
function scrubString(s) {
  return s
    .replace(/(response_code(?:=|\\u003d|%3D))[A-Za-z0-9_-]+/g, (m, p) => { redactions++; return p + '<redacted>'; })
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, () => { redactions++; return '<redacted private key>'; })
    .replace(/(\\*"(?:d|p|q|dp|dq|qi)\\*"\s*:\s*\\*")[A-Za-z0-9_-]{16,}/g, (m, p) => { redactions++; return p + '<redacted>'; });
}
function scrub(v, ctx) {
  if (typeof v === 'string') return scrubString(v);
  if (Array.isArray(v)) return v.map(x => scrub(x, ctx));
  if (v && typeof v === 'object') {
    const out = {};
    const isJwk = 'kty' in v;
    for (const [k, x] of Object.entries(v)) {
      if (isJwk && PRIVATE_JWK.includes(k)) { out[k] = '<redacted>'; redactions++; continue; }
      if (k === 'img' && typeof x === 'string' && x.startsWith('data:image/')) {
        const name = `${ctx.test}-${v._id || 'img'}`.replace(/[^A-Za-z0-9_.-]/g, '_') + '.png';
        fs.mkdirSync(path.join(ctx.dir, 'screenshots'), { recursive: true });
        const png = path.join(ctx.dir, 'screenshots', name);
        fs.writeFileSync(png, Buffer.from(x.split(',')[1], 'base64'));
        const jpg = png.replace(/\.png$/, '.jpg');
        execFileSync('sips', ['-s', 'format', 'jpeg', '-s', 'formatOptions', '60', '-Z', '900', png, '--out', jpg], { stdio: 'ignore' });
        fs.unlinkSync(png);
        out[k] = 'screenshots/' + path.basename(jpg); continue;
      }
      out[k] = scrub(x, ctx);
    }
    return out;
  }
  return v;
}
for (const zip of fs.readdirSync(path.join(src, 'json')).filter(f => f.endsWith('.zip'))) {
  const label = zip.replace(/\.zip$/, '');
  const tmp = fs.mkdtempSync(path.join(src, 'x-'));
  execFileSync('unzip', ['-q', path.join(src, 'json', zip), '-d', tmp]);
  const dir = path.join(dst, label); fs.mkdirSync(dir, { recursive: true });
  for (const f of fs.readdirSync(tmp).filter(f => f.endsWith('.json'))) {
    const test = f.replace(/^test-log-/, '').replace(/\.json$/, '');
    const data = scrub(JSON.parse(fs.readFileSync(path.join(tmp, f), 'utf8')), { dir, test });
    fs.writeFileSync(path.join(dir, f), JSON.stringify(data, null, 1) + '\n');
  }
  fs.rmSync(tmp, { recursive: true });
}
console.log('redactions', redactions);
