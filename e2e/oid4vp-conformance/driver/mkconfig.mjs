// Copyright 2026 HelixIAM contributors
// SPDX-License-Identifier: Apache-2.0
import fs from 'node:fs'; import crypto from 'node:crypto';
const P = process.argv[2];
const jwk = crypto.createPrivateKey(fs.readFileSync(P + '/ids.key')).export({format: 'jwk'});
const der = pem => pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
jwk.alg = 'ES256'; jwk.kid = 'oidf-pid-ds'; jwk.x5c = [der(fs.readFileSync(P + '/ids.pem', 'utf8'))];
const anchor = fs.readFileSync(P + '/vroot.pem', 'utf8');
for (const [name, extra] of [['config-haip.json', {}], ['config-san.json', {client: {client_id: process.env.OIDF_HOST || 'helix-oidf.localtest.me'}}]]) {
  const cfg = {alias: 'helixiam-oidf', description: 'HelixIAM OpenID4VP verifier conformance run',
    client: {request_object_trust_anchor_pem: anchor, ...(extra.client || {})},
    credential: {signing_jwk: jwk}};
  fs.writeFileSync(P + '/' + name, JSON.stringify(cfg, null, 1));
}
