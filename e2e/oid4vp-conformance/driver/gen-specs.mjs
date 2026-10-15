// Copyright 2026 HelixIAM contributors
// SPDX-License-Identifier: Apache-2.0
// node gen-specs.mjs <profile: prod|dev> <run label> -> writes specs/<label>/*.json and prints their order
import fs from 'node:fs';
const [profile, run] = process.argv.slice(2);
const S = process.env.OIDF_WORK;
if (!S) throw new Error('source ../env.sh first (OIDF_WORK)');
const out = `${S}/runs/${run}`; const dir = `${S}/specs/${run}-${profile}`; fs.mkdirSync(dir, { recursive: true });
const cf = { sdjwt: 'sd_jwt_vc', mdoc: 'iso_mdl' };
const specs = [];
const add = (name, s) => { fs.writeFileSync(`${dir}/${name}.json`, JSON.stringify({ out, ...s }, null, 1)); specs.push(`${dir}/${name}.json`); };
const HAIP = 'oid4vp-1final-verifier-haip-test-plan', PLAIN = 'oid4vp-1final-verifier-test-plan';
const mode = profile === 'prod' ? 'direct_post.jwt' : 'direct_post';
const modeTag = profile === 'prod' ? 'jwt' : 'directpost';
const suffix = profile === 'prod' ? '' : '-plain';
for (const f of ['sdjwt', 'mdoc']) for (const cid of ['hash', 'san']) {
  const alias = `w-${f}-${cid}${suffix}`;
  const usesHaip = profile === 'prod' && cid === 'hash';
  const planName = usesHaip ? HAIP : PLAIN;
  const variant = usesHaip ? { credential_format: cf[f], response_mode: mode }
    : { vp_profile: 'plain_vp', client_id_prefix: cid === 'hash' ? 'x509_hash' : 'x509_san_dns', request_method: 'request_uri_signed', credential_format: cf[f], response_mode: mode };
  const config = `${S}/pki/${cid === 'hash' ? 'config-haip.json' : 'config-san.json'}`;
  const base = `${usesHaip ? 'haip' : 'plain'}-${cid}-${f}-${modeTag}`;
  const posts = profile === 'prod' ? { 'oid4vp-1final-verifier-request-uri-method-post': `${alias}-post` } : {};
  // 1. link the suite's PID to the test user (account console), so later happy flows end in a real sign-in
  add(`0-link-${alias}`, { planName, variant, config, alias, flow: 'same', label: `${run}-setup-link-${alias}`,
    modules: ['oid4vp-1final-verifier-happy-flow'], linkUser: 'jean.dupont' });
  for (const p of Object.values(posts)) add(`0-link-${p}`, { planName, variant, config, alias: p, flow: 'same',
    label: `${run}-setup-link-${p}`, modules: ['oid4vp-1final-verifier-happy-flow'], linkUser: 'jean.dupont' });
  // 2. the whole plan, same-device
  add(`1-${base}-same`, { planName, variant, config, alias, flow: 'same', label: `${run}-${base}-same`, moduleAlias: posts });
  // 3. cross-device happy flow
  add(`2-${base}-cross`, { planName, variant, config, alias, flow: 'cross', label: `${run}-${base}-cross`, modules: ['oid4vp-1final-verifier-happy-flow'] });
}
console.log(specs.sort().join('\n'));
