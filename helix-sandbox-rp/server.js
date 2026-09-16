/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import express from 'express';
import session from 'express-session';
import { Issuer, generators, errors as oidcErrors } from 'openid-client';
import { decodeJwt, groupClaims } from './lib/jwt.js';
import { buildSamlSp } from './lib/saml.js';
import { page, kvTable, esc } from './lib/ui.js';

// ---- config (env-overridable; defaults match the provisioned sandbox) --------
const cfg = {
  issuer: process.env.HELIX_ISSUER || 'http://localhost:8083/realms/master',
  clientId: process.env.HELIX_CLIENT_ID || 'helix-sandbox',
  clientSecret: process.env.HELIX_CLIENT_SECRET || '7N57g-EpHczXOVl7enDXlSqLmOSWBl3_',
  redirectUri: process.env.HELIX_REDIRECT_URI || 'http://localhost:9090/callback',
  postLogout: process.env.HELIX_POST_LOGOUT || 'http://localhost:9090/',
  scope: process.env.HELIX_SCOPE || 'openid profile email',
  port: Number(process.env.PORT || 9090),
  // SAML2 SP (registered with the IdP via the admin API / console)
  samlEntityId: process.env.HELIX_SAML_SP_ENTITY_ID || 'helix-sandbox-sp',
  samlAcs: process.env.HELIX_SAML_ACS || 'http://localhost:9090/saml/acs',
  samlSlo: process.env.HELIX_SAML_SLO || 'http://localhost:9090/saml/slo',
  samlIdpMetadata:
    process.env.HELIX_SAML_IDP_METADATA || 'http://localhost:8083/realms/master/saml/idp/metadata',
};

// Lazily build the SAML SP from the IdP metadata (so a not-yet-enabled IdP doesn't crash startup).
let samlSp = null;
async function ensureSaml() {
  if (samlSp) return samlSp;
  samlSp = await buildSamlSp({
    spEntityId: cfg.samlEntityId,
    acsUrl: cfg.samlAcs,
    sloUrl: cfg.samlSlo,
    idpMetadataUrl: cfg.samlIdpMetadata,
  });
  return samlSp;
}

// ---- discover the IdP + build the RP client ---------------------------------
let client = null;
let idpUp = false;
async function ensureClient() {
  if (client) return client;
  const issuer = await Issuer.discover(cfg.issuer);
  // Public client + PKCE (no secret) so the sandbox needs no secret provisioning against Helix.
  const publicClient = !cfg.clientSecret || cfg.clientSecret === 'none';
  client = new issuer.Client({
    client_id: cfg.clientId,
    ...(publicClient ? {} : { client_secret: cfg.clientSecret }),
    redirect_uris: [cfg.redirectUri],
    post_logout_redirect_uris: [cfg.postLogout],
    response_types: ['code'],
    token_endpoint_auth_method: publicClient ? 'none' : 'client_secret_basic',
  });
  idpUp = true;
  return client;
}

const app = express();
app.use(express.urlencoded({ extended: false })); // SAML ACS/SLO POST bindings are form-encoded
app.use(
  session({
    name: 'helix_sandbox_rp',
    secret: 'sandbox-rp-session-secret',
    resave: false,
    saveUninitialized: true,
    cookie: { httpOnly: true, sameSite: 'lax' },
  }),
);

// kick off an authorization request with the given extra params (prompt/max_age)
async function startAuth(req, res, extra = {}) {
  const c = await ensureClient();
  const code_verifier = generators.codeVerifier();
  req.session.code_verifier = code_verifier;
  req.session.state = generators.state();
  req.session.nonce = generators.nonce();
  const url = c.authorizationUrl({
    scope: cfg.scope,
    code_challenge: generators.codeChallenge(code_verifier),
    code_challenge_method: 'S256',
    state: req.session.state,
    nonce: req.session.nonce,
    ...extra,
  });
  res.redirect(url);
}

// ---- routes -----------------------------------------------------------------

app.get('/', (req, res) => {
  const t = req.session.tokens;
  const flash = req.session.flash;
  req.session.flash = null;

  let body = '';
  if (flash) body += `<div class="banner ${flash.kind}">${esc(flash.msg)}</div>`;

  if (!t && req.session.saml) {
    const s = req.session.saml;
    const attrEntries = Object.entries(s.attributes || {}).map(([k, v]) => ({
      key: k,
      display: Array.isArray(v) ? v.join(', ') : String(v),
    }));
    const initial = (s.nameID || '?').slice(0, 1).toUpperCase();
    body += `
    <div class="card">
      <div class="who">
        <div class="avatar" style="background:linear-gradient(135deg,#2f81f7,#3fb950)">${esc(initial)}</div>
        <div>
          <h2 style="margin:0">${esc(s.nameID)}</h2>
          <div class="muted mono">SAML2 assertion · NameID</div>
        </div>
        <span class="pill on" style="margin-left:auto">● SAML signed in</span>
      </div>
      <div class="flowsteps" style="margin-top:16px">
        <span class="step done">AuthnRequest ✓</span>
        <span class="step done">password ✓</span>
        <span class="step done">otp ✓</span>
        <span class="step done">signed assertion ✓</span>
      </div>
      <div class="btns" style="margin-top:18px">
        <a class="btn danger" href="/saml/logout">SAML single logout</a>
      </div>
    </div>
    <div class="section-title">Claims / attributes (flat — envelope + AttributeStatement merged)</div>
    <div class="card">${kvTable([
      { key: 'sub (NameID)', display: s.nameID || '—' },
      ...attrEntries,
      { key: 'nameid_format', display: s.nameIDFormat || '—' },
      { key: 'session_index', display: s.sessionIndex || '—' },
      { key: 'iss (IdP issuer)', display: s.issuer || '—' },
    ])}</div>
    <div class="section-title">Raw assertion (decoded)</div>
    <div class="card"><pre>${esc(JSON.stringify(s.raw, null, 2))}</pre></div>`;
    return res.send(page({ title: 'Helix Sandbox RP — SAML', body, idpUp }));
  }

  if (!t) {
    body += `
    <div class="card">
      <h2>Not signed in</h2>
      <p class="hint">Authenticate against Helix IAM with the OIDC authorization-code flow (PKCE).
      This client is bound to a login flow that <b>requires a one-time passcode</b>, so you'll be
      challenged for an OTP after your password.</p>
      <div class="flowsteps">
        <span class="step">1 · password</span>
        <span class="step">2 · OTP (TOTP)</span>
        <span class="step">3 · consent / redirect</span>
      </div>
      <div class="btns" style="margin-top:18px">
        <a class="btn primary" href="/login">→ Sign in with OIDC</a>
        <a class="btn blue" href="/saml/login">→ Sign in with SAML2</a>
        <a class="btn ghost" href="/silent">Try silent SSO (prompt=none)</a>
      </div>
      <p class="hint" style="margin-top:14px">Same IdP, two protocols. OIDC uses the bound OTP flow;
      SAML2 uses the realm browser flow (OTP applies because this user has MFA enabled).</p>
    </div>
    <div class="card">
      <h2>What this sandbox exercises</h2>
      <p class="hint">A reusable relying-party to validate the IdP end to end.</p>
      <table class="kv">
        <tr><td class="k">login</td><td class="v">authorization_code + PKCE, password → OTP step-up</td></tr>
        <tr><td class="k">claims</td><td class="v">decoded id_token + access_token + live /userinfo</td></tr>
        <tr><td class="k">refresh</td><td class="v">refresh_token grant → fresh tokens</td></tr>
        <tr><td class="k">logout</td><td class="v">RP-initiated end_session (single logout)</td></tr>
        <tr><td class="k">silent SSO</td><td class="v">prompt=none re-auth without a prompt</td></tr>
        <tr><td class="k">step-up</td><td class="v">prompt=login / max_age=0 force re-auth</td></tr>
      </table>
    </div>`;
    return res.send(page({ title: 'Helix Sandbox RP', body, idpUp }));
  }

  const claims = t.claims || {};
  const initial = (claims.preferred_username || claims.name || claims.sub || '?').slice(0, 1).toUpperCase();
  const amr = Array.isArray(claims.amr) ? claims.amr.join(', ') : claims.amr;
  body += `
  <div class="card">
    <div class="who">
      <div class="avatar">${esc(initial)}</div>
      <div>
        <h2 style="margin:0">${esc(claims.name || claims.preferred_username || claims.sub)}</h2>
        <div class="muted mono">${esc(claims.email || '—')}</div>
      </div>
      <span class="pill on" style="margin-left:auto">● signed in</span>
    </div>
    <div class="flowsteps" style="margin-top:16px">
      <span class="step done">password ✓</span>
      ${amr && amr.includes('otp') ? '<span class="step done">otp ✓</span>' : '<span class="step">otp</span>'}
      <span class="step done">tokens issued ✓</span>
    </div>
    <table class="kv" style="margin-top:16px">
      <tr><td class="k">sub</td><td class="v">${esc(claims.sub)}</td></tr>
      <tr><td class="k">auth_time</td><td class="v">${esc(claims.auth_time ? new Date(claims.auth_time * 1000).toISOString() : '—')}</td></tr>
      <tr><td class="k">amr</td><td class="v">${esc(amr || '—')}</td></tr>
      <tr><td class="k">sid</td><td class="v">${esc(claims.sid || '—')}</td></tr>
      <tr><td class="k">expires</td><td class="v">${esc(t.expires_at ? new Date(t.expires_at * 1000).toISOString() : '—')}</td></tr>
    </table>
    <div class="btns" style="margin-top:18px">
      <a class="btn blue" href="/claims">Inspect all claims</a>
      <a class="btn" href="/refresh">Refresh tokens</a>
      <a class="btn" href="/silent">Re-check SSO (silent)</a>
      <a class="btn" href="/stepup">Force re-auth (prompt=login)</a>
      <a class="btn danger" href="/logout">Single logout</a>
    </div>
  </div>`;
  res.send(page({ title: 'Helix Sandbox RP — signed in', body, idpUp }));
});

app.get('/login', (req, res, next) => startAuth(req, res).catch(next));

app.get('/silent', (req, res, next) => startAuth(req, res, { prompt: 'none' }).catch(next));

app.get('/stepup', (req, res, next) => startAuth(req, res, { prompt: 'login' }).catch(next));

app.get('/callback', async (req, res, next) => {
  try {
    const c = await ensureClient();
    const params = c.callbackParams(req);
    const tokenSet = await c.callback(cfg.redirectUri, params, {
      code_verifier: req.session.code_verifier,
      state: req.session.state,
      nonce: req.session.nonce,
    });
    req.session.tokens = {
      access_token: tokenSet.access_token,
      id_token: tokenSet.id_token,
      refresh_token: tokenSet.refresh_token,
      token_type: tokenSet.token_type,
      scope: tokenSet.scope,
      expires_at: tokenSet.expires_at,
      claims: tokenSet.claims(),
    };
    req.session.flash = { kind: 'ok', msg: 'Signed in — tokens received from Helix IAM.' };
    res.redirect('/');
  } catch (err) {
    // prompt=none with no active session comes back as login_required, etc.
    if (err instanceof oidcErrors.OPError) {
      req.session.flash = {
        kind: err.error === 'login_required' ? 'info' : 'err',
        msg: `IdP returned: ${err.error}${err.error_description ? ' — ' + err.error_description : ''}`,
      };
      return res.redirect('/');
    }
    next(err);
  }
});

app.get('/claims', async (req, res, next) => {
  const t = req.session.tokens;
  if (!t) return res.redirect('/');
  try {
    const c = await ensureClient();
    let userinfo = null;
    let userinfoErr = null;
    try {
      userinfo = await c.userinfo(t.access_token);
    } catch (e) {
      userinfoErr = e.error || e.message;
    }
    const idClaims = decodeJwt(t.id_token) || t.claims || {};
    const atClaims = decodeJwt(t.access_token);
    const g = groupClaims(idClaims);

    const body = `
    <a class="btn ghost" href="/">← back</a>
    <div class="section-title">ID token — standard OIDC claims</div>
    <div class="card">${kvTable(g.standard)}</div>
    <div class="section-title">ID token — custom / role claims</div>
    <div class="card">${kvTable(g.custom)}</div>
    <div class="section-title">/userinfo (live call with the access token)</div>
    <div class="card">${
      userinfo ? `<pre>${esc(JSON.stringify(userinfo, null, 2))}</pre>` : `<div class="banner err">userinfo failed: ${esc(userinfoErr)}</div>`
    }</div>
    <div class="section-title">Access token claims</div>
    <div class="card">${atClaims ? `<pre>${esc(JSON.stringify(atClaims, null, 2))}</pre>` : '<p class="muted">opaque / non-JWT access token</p>'}</div>
    <div class="section-title">Raw tokens</div>
    <div class="card">
      <table class="kv">
        <tr><td class="k">id_token</td><td class="v">${esc(t.id_token)}</td></tr>
        <tr><td class="k">access_token</td><td class="v">${esc(t.access_token)}</td></tr>
        <tr><td class="k">refresh_token</td><td class="v">${esc(t.refresh_token || '—')}</td></tr>
        <tr><td class="k">scope</td><td class="v">${esc(t.scope || '—')}</td></tr>
      </table>
    </div>`;
    res.send(page({ title: 'Claims', body, idpUp }));
  } catch (err) {
    next(err);
  }
});

app.get('/refresh', async (req, res, next) => {
  const t = req.session.tokens;
  if (!t || !t.refresh_token) {
    req.session.flash = { kind: 'err', msg: 'No refresh token in session.' };
    return res.redirect('/');
  }
  try {
    const c = await ensureClient();
    const before = t.access_token.slice(-12);
    const refreshed = await c.refresh(t.refresh_token);
    req.session.tokens = {
      access_token: refreshed.access_token,
      id_token: refreshed.id_token || t.id_token,
      refresh_token: refreshed.refresh_token || t.refresh_token,
      token_type: refreshed.token_type,
      scope: refreshed.scope,
      expires_at: refreshed.expires_at,
      claims: refreshed.claims ? refreshed.claims() : t.claims,
    };
    req.session.flash = {
      kind: 'ok',
      msg: `Refreshed — access token …${before} → …${refreshed.access_token.slice(-12)} (new expiry ${new Date(refreshed.expires_at * 1000).toISOString()}).`,
    };
    res.redirect('/');
  } catch (err) {
    next(err);
  }
});

app.get('/logout', async (req, res, next) => {
  const t = req.session.tokens;
  if (!t) return res.redirect('/');
  try {
    const c = await ensureClient();
    const url = c.endSessionUrl({
      id_token_hint: t.id_token,
      post_logout_redirect_uri: cfg.postLogout,
    });
    req.session.tokens = null;
    req.session.flash = { kind: 'ok', msg: 'Logged out at Helix IAM (RP-initiated single logout).' };
    res.redirect(url);
  } catch (err) {
    next(err);
  }
});

// ---- SAML2 routes -----------------------------------------------------------

// Start SAML SSO: build a signed-by-binding AuthnRequest and redirect (HTTP-Redirect binding).
app.get('/saml/login', async (req, res, next) => {
  try {
    const { saml } = await ensureSaml();
    const url = await saml.getAuthorizeUrlAsync('', undefined, {});
    res.redirect(url);
  } catch (err) {
    next(err);
  }
});

// Assertion Consumer Service: the IdP auto-POSTs the signed SAMLResponse here.
app.post('/saml/acs', async (req, res, next) => {
  try {
    const { saml, idp } = await ensureSaml();
    const { profile } = await saml.validatePostResponseAsync(req.body);
    req.session.saml = {
      nameID: profile.nameID,
      nameIDFormat: profile.nameIDFormat,
      sessionIndex: profile.sessionIndex,
      issuer: profile.issuer || idp.entityId,
      attributes: profile.attributes || {},
      raw: profile,
    };
    req.session.flash = { kind: 'ok', msg: 'Signed in via SAML2 — assertion validated.' };
    res.redirect('/');
  } catch (err) {
    req.session.flash = { kind: 'err', msg: `SAML assertion rejected: ${err.message || err}` };
    res.redirect('/');
  }
});

// SP metadata (so the IdP / an admin can import this SP instead of typing fields).
app.get('/saml/metadata', async (req, res, next) => {
  try {
    const { saml } = await ensureSaml();
    res.type('application/xml').send(saml.generateServiceProviderMetadata(null, null));
  } catch (err) {
    next(err);
  }
});

// RP-initiated SAML Single Logout: send a LogoutRequest to the IdP SLO.
app.get('/saml/logout', async (req, res, next) => {
  const s = req.session.saml;
  if (!s) return res.redirect('/');
  try {
    const { saml } = await ensureSaml();
    const url = await saml.getLogoutUrlAsync(
      { nameID: s.nameID, nameIDFormat: s.nameIDFormat, sessionIndex: s.sessionIndex },
      '',
      {},
    );
    req.session.saml = null;
    req.session.flash = { kind: 'ok', msg: 'SAML2 single logout sent to the IdP.' };
    res.redirect(url);
  } catch (err) {
    next(err);
  }
});

// SLO endpoint: the IdP POSTs/redirects a LogoutResponse (or a LogoutRequest) back here.
const samlSlo = async (req, res) => {
  // Either binding may carry SAMLResponse (to our request) or SAMLRequest (IdP-initiated).
  req.session.saml = null;
  req.session.flash = { kind: 'ok', msg: 'SAML2 logout completed at the IdP.' };
  res.redirect('/');
};
app.get('/saml/slo', samlSlo);
app.post('/saml/slo', samlSlo);

app.use((err, req, res, next) => {
  console.error(err);
  const body = `<div class="banner err">Error: ${esc(err.message || String(err))}</div>
  <a class="btn ghost" href="/">← back</a>`;
  res.status(500).send(page({ title: 'Error', body, idpUp }));
});

ensureClient()
  .then(() => console.log(`[helix-sandbox-rp] discovered IdP at ${cfg.issuer}`))
  .catch((e) => console.error(`[helix-sandbox-rp] IdP discovery failed (will retry on first request): ${e.message}`));

app.listen(cfg.port, () => {
  console.log(`[helix-sandbox-rp] listening on http://localhost:${cfg.port}  (client_id=${cfg.clientId})`);
});
