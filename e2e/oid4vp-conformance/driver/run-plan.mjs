// Copyright 2026 HelixIAM contributors
// SPDX-License-Identifier: Apache-2.0
// Drives one OIDF conformance-suite verifier plan against HelixIAM.
// usage: node run-plan.mjs <spec.json>
// spec: {planName, variant, config, alias, flow: "same"|"cross", modules?: [..], moduleAlias?: {module: alias},
//        linkUser?: username (start from the account console's "Link wallet" instead of a sign-in), label, out}
// Needs OIDF_WORK (source ../env.sh). For each module: create the test in the plan, open the HelixIAM wallet page in
// Chromium, hand the suite the same-device link (or the decoded cross-device QR), visit the redirect_uri the suite
// received from the bound browser, screenshot the HelixIAM result page and upload it to the suite's placeholder.
import fs from 'node:fs';
import path from 'node:path';
import { chromium } from 'playwright';
import jsQR from 'jsqr';
import { PNG } from 'pngjs';
import { Agent, setGlobalDispatcher } from 'undici';
import crypto from 'node:crypto';
if (!process.env.OIDF_WORK) throw new Error('source ../env.sh first (OIDF_WORK)');
const PKI = `${process.env.OIDF_WORK}/pki`;
// The suite's nginx serves a self-signed certificate (CN=localhost, no SAN): trust exactly that certificate,
// pinned by its SHA-256 fingerprint, for both host names the suite is reached under.
const SUITE_CERT = fs.readFileSync(`${PKI}/suite-nginx.pem`, 'utf8');
const SUITE_FP = new crypto.X509Certificate(SUITE_CERT).fingerprint256;
setGlobalDispatcher(new Agent({ connect: { ca: SUITE_CERT,
  checkServerIdentity: (host, cert) => cert.fingerprint256 === SUITE_FP ? undefined : new Error('suite certificate pin mismatch') } }));

const spec = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const API = `https://localhost:${process.env.OIDF_SUITE_PORT || 18443}/api`;
const HELIX = `https://${process.env.OIDF_HOST || 'helix-oidf.localtest.me'}:${process.env.OIDF_TLS_PORT || 18943}`;
const REALM = spec.realm || 'oidf';
const sleep = ms => new Promise(r => setTimeout(r, ms));
const out = spec.out; fs.mkdirSync(out, { recursive: true });

async function api(method, url, body, type = 'application/json') {
  const res = await fetch(API + url, { method, headers: body ? { 'Content-Type': type } : {}, body });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = text; }
  if (res.status >= 300) throw new Error(`${method} ${url} -> ${res.status} ${text.slice(0, 300)}`);
  return json;
}
const q = o => encodeURIComponent(JSON.stringify(o));

async function waitStatus(id, states, timeoutMs = 60000) {
  const end = Date.now() + timeoutMs;
  let info;
  while (Date.now() < end) {
    info = await api('GET', `/info/${id}`);
    if (states.includes(info.status)) return info;
    await sleep(500);
  }
  return info;
}

async function decodeQr(page) {
  const png = PNG.sync.read(await page.locator('#walletQr').screenshot());
  const code = jsQR(new Uint8ClampedArray(png.data), png.width, png.height);
  if (!code) throw new Error('QR not decodable');
  return code.data;
}

async function runModule(browser, planId, mod) {
  const alias = (spec.moduleAlias && spec.moduleAlias[mod.testModule]) || spec.alias;
  const created = await api('POST', `/runner?test=${mod.testModule}&plan=${planId}&variant=${q(mod.variant || {})}`);
  const id = created.id;
  const rec = { module: mod.testModule, testId: id, alias, notes: [] };
  await waitStatus(id, ['WAITING', 'FINISHED'], 30000);
  const st = await api('GET', `/runner/${id}`);
  const submit = st.exposed && st.exposed.authorization_endpoint;
  const ctx = await browser.newContext({ viewport: { width: 1100, height: 900 } });
  const page = await ctx.newPage();
  try {
    if (spec.linkUser) {
      // account-console link flow: sign in with a password, then press "Link wallet" for this alias
      const pw = fs.readFileSync(`${PKI}/userpw`, 'utf8').trim();
      await page.goto(`${HELIX}/realms/${REALM}/account`);
      await page.fill('input[name=username]', spec.linkUser);
      await page.fill('input[name=password]', pw);
      await Promise.all([page.waitForNavigation(), page.locator('button[type=submit]').first().click()]);
      await Promise.all([page.waitForNavigation(), page.locator(`form[action$="/account/wallet/link"]:has(input[name=alias][value="${alias}"]) button`).click()]);
      rec.notes.push('link flow started from the account console');
    } else {
      await page.goto(`${HELIX}/realms/${REALM}/broker/${alias}`);
    }
    let invocation;
    if (spec.flow === 'cross') invocation = await decodeQr(page);
    else invocation = await page.locator('#walletOpen').getAttribute('href');
    rec.invocation = invocation.replace(/request%2F[^&]+/, 'request%2F<redacted>');
    const query = invocation.substring(invocation.indexOf('?'));
    const res = await fetch(submit + query);
    rec.submitStatus = res.status;
    // wait for the suite to finish its wallet side
    let info;
    for (let i = 0; i < 60; i++) {
      info = await api('GET', `/info/${id}`);
      const br = await api('GET', `/runner/browser/${id}`);
      if (info.status === 'FINISHED') break;
      if ((br.urls && br.urls.length) || info.status === 'WAITING') {
        const log = await api('GET', `/log/${id}`);
        const needsUpload = log.find(e => e.upload && !e.img);
        const done = log.some(e => e.src === 'CallDirectPostEndpoint' || e.src === 'EnsureHttpStatusCodeIs200');
        if (done || needsUpload || (br.urls && br.urls.length)) {
          for (const u of br.urls || []) {
            rec.notes.push('visiting redirect_uri from the bound browser');
            await page.goto(u);
            await api('POST', `/runner/browser/${id}/visit?url=${encodeURIComponent(u)}`);
          }
          if (spec.flow === 'cross') {
            // the wallet page polls the status endpoint and follows "next" by itself
            try { await page.waitForURL(u => !u.toString().includes('/wallet?tx='), { timeout: 20000 }); } catch { rec.notes.push('cross-device page did not move on'); }
          }
          await page.waitForLoadState('load');
          await sleep(1500);
          rec.helixFinalUrl = page.url().replace(/response_code=[^&]+/, 'response_code=<redacted>').replace(/tx=[^&]+/, 'tx=<redacted>');
          // JPEG of the viewport: the suite refuses uploads over 500 KB, which a full-page PNG of an account page
          // with many sessions exceeds
          const shot = await page.screenshot({ type: 'jpeg', quality: 70 });
          fs.writeFileSync(path.join(out, `${spec.label}-${mod.testModule}.jpg`), shot);
          if (needsUpload) {
            await api('POST', `/log/${id}/images/${needsUpload.upload}`, 'data:image/jpeg;base64,' + shot.toString('base64'), 'text/plain');
            rec.notes.push('uploaded HelixIAM result screenshot to placeholder');
          }
          break;
        }
      }
      await sleep(1000);
    }
    info = await waitStatus(id, ['FINISHED'], 60000);
    rec.status = info.status; rec.result = info.result;
  } catch (e) {
    rec.error = e.message;
    const i = await api('GET', `/info/${id}`).catch(() => ({}));
    rec.status = i.status; rec.result = i.result;
  } finally {
    await ctx.close();
  }
  // findings
  const log = await api('GET', `/log/${id}`);
  rec.findings = log.filter(e => ['FAILURE', 'WARNING', 'REVIEW', 'SKIPPED', 'INTERRUPTED'].includes(e.result))
    .map(e => ({ result: e.result, src: e.src, msg: (e.msg || '').slice(0, 400), requirements: e.requirements }));
  return rec;
}

// HelixIAM's TLS certificate is issued by the run's local CA; Chromium accepts exactly that key (SPKI pin).
const SPKI = fs.readFileSync(`${PKI}/tls-spki.txt`, 'utf8').trim();
const browser = await chromium.launch({ args: [`--ignore-certificate-errors-spki-list=${SPKI}`] });
const plan = await api('POST', `/plan?planName=${spec.planName}&variant=${q(spec.variant)}`, fs.readFileSync(spec.config));
const results = { label: spec.label, planName: spec.planName, planId: plan.id, variant: spec.variant, alias: spec.alias, flow: spec.flow, modules: [] };
for (const mod of plan.modules) {
  if (spec.modules && !spec.modules.includes(mod.testModule)) continue;
  const rec = await runModule(browser, plan.id, mod);
  console.log(`${spec.label} ${rec.module}: ${rec.status}/${rec.result} ${rec.error || ''}`);
  for (const f of rec.findings) if (f.result !== 'REVIEW') console.log(`   ${f.result} ${f.src}: ${f.msg.slice(0, 160)}`);
  results.modules.push(rec);
}
await browser.close();
fs.writeFileSync(path.join(out, `${spec.label}-results.json`), JSON.stringify(results, null, 1));
console.log('plan', plan.id);
