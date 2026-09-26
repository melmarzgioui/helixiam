#!/usr/bin/env python3
# Copyright 2026 HelixIAM contributors
# SPDX-License-Identifier: Apache-2.0
"""
Scripted end-to-end check of a running HelixIAM (1.0 release gate), Python 3 standard library only.

Builds the Monthfold setup over the public HTTP APIs and exercises it:
  master admin -> service account "monthfold-provisioner" (realm role admin, master realm)
  provisioner (bearer) -> realm "monthfold" (requireMfa=true), clients web/portal/ledger, organization
  "harbor-pine", users joe (owner) and maya (client), ledger's token-exchange policy (only web)
  joe: authorization code + PKCE with enforced TOTP (enrolment on first sign-in, TOTP on the next)
  maya: claim-injection reproduction (PUT profile {"attributes":{"sub":<joe>}} must be refused)
  web: token exchange of joe's token to audience=ledger; ledger: client_credentials
Every token is written to out/tokens.json for the Go jwx validator (jwxcheck/).

Usage: python3 run.py --base http://localhost:18080 --admin-password '<master admin password>'
"""
import argparse, base64, hashlib, hmac, http.cookiejar, json, os, re, secrets, struct, sys, time
import urllib.error, urllib.parse, urllib.request

REDIRECT = "http://localhost:9999/cb"
TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
CHECKS = []


def check(cond, what):
    CHECKS.append((bool(cond), what))
    print(("PASS " if cond else "FAIL ") + what)
    if not cond:
        raise SystemExit("e2e failed: " + what)


class InsecureTransportPolicy(http.cookiejar.DefaultCookiePolicy):
    """Send Secure cookies over plain http (the check talks to a port-forward, like a TLS-terminating proxy)."""
    def return_ok_secure(self, cookie, request):
        return True


class PlainHttpJar(http.cookiejar.CookieJar):
    """Keeps Secure cookies received over plain http (Python's jar drops them): the check talks to a port-forward,
    standing in for the TLS-terminating proxy that would sit in front of HelixIAM."""
    def make_cookies(self, response, request):
        cookies = super().make_cookies(response, request)
        for c in cookies:
            c.secure = False
        return cookies


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Resp:
    def __init__(self, status, headers, body, url):
        self.status, self.headers, self.body, self.url = status, headers, body, url

    @property
    def location(self):
        return self.headers.get("Location")

    def json(self):
        return json.loads(self.body or "null")

    def __repr__(self):
        return f"{self.status} {self.url} -> {self.location or ''} {self.body[:300]!r}"


class Browser:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.jar = PlainHttpJar(policy=InsecureTransportPolicy())
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), NoRedirect())

    def url(self, path):
        return path if path.startswith("http") else self.base + path

    def request(self, method, path, form=None, body=None, headers=None):
        data, hdrs = None, {"Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}
        hdrs.update(headers or {})
        if form is not None:
            data = urllib.parse.urlencode(form, doseq=True).encode()
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        elif body is not None:
            data = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        req = urllib.request.Request(self.url(path), data=data, method=method, headers=hdrs)
        try:
            with self.opener.open(req, timeout=30) as r:
                resp = Resp(r.status, r.headers, r.read().decode("utf-8", "replace"), req.full_url)
        except urllib.error.HTTPError as e:
            resp = Resp(e.code, e.headers, e.read().decode("utf-8", "replace"), req.full_url)
        if os.environ.get("TRACE"):
            print(f"  {method} {urllib.parse.urlparse(req.full_url).path} -> {resp.status} {resp.location or ''}"
                  f" cookies={sorted((c.name, c.path) for c in self.jar)}")
        return resp

    def follow(self, resp, stop=lambda r: False, limit=15):
        while resp.status in (301, 302, 303, 307) and not stop(resp) and limit > 0:
            resp = self.request("GET", urllib.parse.urljoin(resp.url, resp.location))
            limit -= 1
        return resp

    def cookie(self, name, path_prefix="/"):
        for c in self.jar:
            if c.name == name and c.path == path_prefix and c.value:
                return c.value
        return None


def form_fields(html, marker):
    for m in re.finditer(r"<form\b([^>]*)>(.*?)</form>", html, re.S | re.I):
        if marker in m.group(0):
            action = re.search(r'action="([^"]*)"', m.group(1)).group(1).replace("&amp;", "&")
            hidden = dict(re.findall(r'<input[^>]*type="hidden"[^>]*name="([^"]+)"[^>]*value="([^"]*)"', m.group(2)))
            return action, hidden
    raise SystemExit(f"no form with {marker!r}")


def login(b, realm, username, password):
    page = b.request("GET", f"/realms/{realm}/login")
    action, fields = form_fields(page.body, 'name="password"')
    fields.update(username=username, password=password)
    return b.request("POST", action, form=fields)


def admin_second_factor(b, base, a):
    """With the default mfa.enabled=true every sign-in needs TOTP, the master admin's too. The first run enrols
    it and keeps the secret next to the output (out/admin-totp-secret) for later runs."""
    secret_file = os.path.join(os.path.dirname(a.out), "admin-totp-secret")
    page = b.request("GET", "/realms/master/mfa/totp")
    probe = b.follow(b.request("GET", "/realms/master/mfa/enable"))
    if probe.status == 200 and "/mfa/enable" in probe.url:
        secret = re.search(r"<code[^>]*>\s*([A-Z2-7]{16,})\s*</code>", probe.body).group(1)
        action, fields = form_fields(probe.body, 'name="code"')
        fields["code"] = totp(secret)
        r = b.request("POST", urllib.parse.urljoin(probe.url, action), form=fields)
        os.makedirs(os.path.dirname(secret_file), exist_ok=True)
        with open(secret_file, "w") as f:
            f.write(secret)
        check(r.status == 200 and "recovery" in r.body.lower(), "master admin enrols TOTP (first run)")
    else:
        with open(secret_file) as f:
            secret = f.read().strip()
        page = b.request("GET", "/realms/master/mfa/totp")
        action, fields = form_fields(page.body, 'name="code"')
        fields["code"] = totp(secret, 30)
        r = b.request("POST", urllib.parse.urljoin(page.url, action), form=fields)
        check(r.status in (200, 302), "master admin passes TOTP")


def totp(secret_b32, offset=0):
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    counter = int(time.time() + offset) // 30
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = digest[-1] & 0x0F
    return "%06d" % ((struct.unpack(">I", digest[o:o + 4])[0] & 0x7FFFFFFF) % 1000000)


def authorize(b, realm, client_id, username, password, scope, on_mfa=None):
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    q = urllib.parse.urlencode({"response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT,
                                "scope": scope, "state": secrets.token_urlsafe(8), "nonce": secrets.token_urlsafe(8),
                                "code_challenge": challenge, "code_challenge_method": "S256"})
    at_cb = lambda r: (r.location or "").startswith(REDIRECT)
    r = b.follow(b.request("GET", f"/realms/{realm}/oauth2/authorize?{q}"), at_cb)
    if not at_cb(r):
        action, fields = form_fields(r.body, 'name="password"')
        fields.update(username=username, password=password)
        r = b.follow(b.request("POST", urllib.parse.urljoin(r.url, action), form=fields), at_cb)
        mfa_pages = []
        while not at_cb(r) and r.status == 200 and "/mfa/" in r.url and on_mfa and len(mfa_pages) < 4:
            mfa_pages.append(urllib.parse.urlparse(r.url).path)
            r = b.follow(on_mfa(b, r), at_cb)
        authorize.mfa_pages = mfa_pages
    if not at_cb(r):
        return None, verifier
    return urllib.parse.parse_qs(urllib.parse.urlparse(r.location).query)["code"][0], verifier


def token(b, realm, client_id, secret, form):
    basic = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
    return b.request("POST", f"/realms/{realm}/oauth2/token", form=form, headers={"Authorization": "Basic " + basic})


def claims(jwt):
    p = jwt.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--admin-user", default="admin")
    ap.add_argument("--admin-password", required=True)
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "out", "tokens.json"))
    a = ap.parse_args()
    base, suffix = a.base.rstrip("/"), secrets.token_hex(3)
    tokens = {}

    # --- master admin (console session + CSRF) creates the provisioner service account ---
    admin = Browser(base)
    check(login(admin, "master", a.admin_user, a.admin_password).status == 302, "master admin signs in (password)")
    admin_second_factor(admin, base, a)
    admin.request("GET", "/admin/realms/master/clients")
    xsrf = {"X-XSRF-TOKEN": admin.cookie("XSRF-TOKEN"), "Accept": "application/json"}
    prov_id = "monthfold-provisioner-" + suffix
    r = admin.request("POST", "/admin/realms/master/clients", body={"clientId": prov_id, "grantTypes": ["client_credentials"]}, headers=xsrf)
    check(r.status == 201, "master admin creates service account " + prov_id)
    prov_secret = r.json()["secret"]
    r = admin.request("POST", f"/admin/realms/master/clients/{prov_id}/service-account/roles", body={"roleName": "admin", "roleType": "REALM"}, headers=xsrf)
    check(r.status == 201, "provisioner gets the master realm role admin")

    api = Browser(base)
    r = token(api, "master", prov_id, prov_secret, {"grant_type": "client_credentials"})
    check(r.status == 200, "provisioner client_credentials token")
    tokens["provisioner (client_credentials, master)"] = {"token": r.json()["access_token"], "issuer": base + "/realms/master"}
    bearer = {"Authorization": "Bearer " + r.json()["access_token"], "Accept": "application/json"}

    # --- provisioner builds realm monthfold over the admin API (bearer, no CSRF) ---
    realm = "monthfold"
    r = api.request("PUT", f"/admin/realms/{realm}/settings", headers=bearer, body={
        "displayName": "Monthfold", "accessTokenTtlSeconds": 300, "refreshTokenTtlSeconds": 86400,
        "enabled": True, "passwordMinLength": 12})
    check(r.status == 200, "service-account token calls the admin API: realm monthfold created/updated")
    r = api.request("PUT", f"/admin/realms/{realm}/settings/mfa", headers=bearer, body={"requireMfa": True})
    check(r.status == 200 and r.json()["requireMfa"] is True, "monthfold requires TOTP")
    secrets_by_client = {}
    grants = ["authorization_code", "refresh_token", TOKEN_EXCHANGE]
    for cid, body in (("web", {"grantTypes": grants, "redirectUris": [REDIRECT], "scopes": ["openid", "profile", "email"]}),
                      ("portal", {"grantTypes": grants, "redirectUris": [REDIRECT], "scopes": ["openid", "profile"]}),
                      ("ledger", {"grantTypes": ["client_credentials"], "scopes": ["openid"]})):
        existing = [c for c in api.request("GET", f"/admin/realms/{realm}/clients", headers=bearer).json() if c["clientId"] == cid]
        if existing:
            r = api.request("POST", f"/admin/realms/{realm}/clients/{existing[0]['id']}/secret", headers=bearer)
        else:
            r = api.request("POST", f"/admin/realms/{realm}/clients", headers=bearer, body=dict(clientId=cid, **body))
        check(r.status in (200, 201), f"client {cid} in monthfold")
        secrets_by_client[cid] = r.json()["secret"]
    r = api.request("PUT", f"/admin/realms/{realm}/clients/ledger/token-exchange", headers=bearer, body={"allowedClients": ["web"]})
    check(r.status == 200, "ledger's token-exchange policy allows only web")

    r = api.request("POST", f"/admin/realms/{realm}/organizations", headers=bearer, body={"name": "harbor-pine-" + suffix})
    check(r.status == 201, "organization harbor-pine")
    org = r.json()["orgId"]
    users = {}
    for name, role in (("joe", "owner"), ("maya", "client")):
        uname = f"{name}-{suffix}"
        r = api.request("POST", f"/admin/realms/{realm}/users", headers=bearer, body={
            "username": uname, "email": f"{uname}@harbor-pine.example", "password": "Monthfold-Passw0rd!", "enabled": True})
        check(r.status == 201, f"user {uname} (admin-created)")
        users[name] = (uname, r.json()["userId"])
        r = api.request("PUT", f"/admin/realms/{realm}/organizations/{org}/members/{users[name][1]}", headers=bearer, body={"role": role})
        check(r.status in (200, 204), f"{uname} is {role} of harbor-pine")

    # --- joe: authorization code + PKCE, TOTP enrolment enforced on first sign-in ---
    state = {}

    def enrol(b, page):
        secret = re.search(r"<code[^>]*>\s*([A-Z2-7]{16,})\s*</code>", page.body).group(1)
        uri = urllib.parse.unquote(re.search(r'href="(otpauth://[^"]+)"', page.body).group(1).replace("&amp;", "&"))
        check("issuer=Monthfold" in uri and uri.startswith("otpauth://totp/Monthfold:"), "otpauth issuer and label = realm name")
        state["secret"] = secret
        action, fields = form_fields(page.body, 'name="code"')
        fields["code"] = totp(secret)
        shown = b.follow(b.request("POST", urllib.parse.urljoin(page.url, action), form=fields))
        state["recovery"] = re.findall(r"\b([A-Z2-9]{4}-[A-Z2-9]{4})\b", shown.body)
        check(len(state["recovery"]) >= 8, "recovery codes shown after enrolment")
        m = re.search(r'href="([^"]*oauth2/authorize[^"]*)"', shown.body)
        if m is None:
            raise SystemExit("recovery page has no link back to /oauth2/authorize; links: "
                             + str(re.findall(r'href="([^"]+)"', shown.body)))
        nxt = m.group(1).replace("&amp;", "&")
        return b.request("GET", nxt)

    joe_b = Browser(base)
    code, verifier = authorize(joe_b, realm, "web", users["joe"][0], "Monthfold-Passw0rd!", "openid profile email", enrol)
    check(authorize.mfa_pages[:1] == [f"/realms/{realm}/mfa/enable"], "joe must enrol TOTP before any code is issued")
    check(code is not None, "joe: authorization code after TOTP enrolment")
    r = token(joe_b, realm, "web", secrets_by_client["web"], {"grant_type": "authorization_code", "code": code,
                                                             "redirect_uri": REDIRECT, "code_verifier": verifier})
    check(r.status == 200, "joe: code + PKCE verifier -> tokens")
    joe_tokens = r.json()
    tokens["joe access token (web)"] = {"token": joe_tokens["access_token"], "issuer": base + "/realms/monthfold"}
    tokens["joe id_token (web)"] = {"token": joe_tokens["id_token"], "issuer": base + "/realms/monthfold"}
    check(claims(joe_tokens["access_token"])["sub"] == users["joe"][1], "joe's sub is joe's id")

    def by_totp(b, page):
        check(urllib.parse.urlparse(page.url).path == f"/realms/{realm}/mfa/totp", "later sign-in asks for a TOTP code")
        action, fields = form_fields(page.body, 'name="code"')
        fields["code"] = totp(state["secret"], 30)
        return b.request("POST", urllib.parse.urljoin(page.url, action), form=fields)

    code2, verifier2 = authorize(Browser(base), realm, "web", users["joe"][0], "Monthfold-Passw0rd!", "openid", by_totp)
    check(code2 is not None, "joe: second sign-in with TOTP")
    replay_b = Browser(base)
    code3, _ = authorize(replay_b, realm, "web", users["joe"][0], "Monthfold-Passw0rd!", "openid", by_totp)
    check(code3 is None, "replayed TOTP code refused")

    # --- token exchange: web exchanges joe's token for ledger ---
    r = token(joe_b, realm, "web", secrets_by_client["web"], {"grant_type": TOKEN_EXCHANGE,
              "subject_token": joe_tokens["access_token"],
              "subject_token_type": "urn:ietf:params:oauth:token-type:access_token", "audience": "ledger"})
    check(r.status == 200, "token exchange web -> ledger")
    ex = claims(r.json()["access_token"])
    aud = ex["aud"] if isinstance(ex["aud"], list) else [ex["aud"]]
    check(aud == ["ledger"] and ex["act"]["sub"] == "web" and ex["sub"] == users["joe"][1], "exchanged: aud=[ledger], act.sub=web, sub=joe")
    check(any(o.get("id") == org and "owner" in o.get("roles", []) for o in ex.get("organizations", [])), "exchanged token keeps joe's organization role")
    tokens["joe exchanged for ledger (token exchange)"] = {"token": r.json()["access_token"], "issuer": base + "/realms/monthfold"}
    r = token(joe_b, realm, "web", secrets_by_client["web"], {"grant_type": TOKEN_EXCHANGE,
              "subject_token": joe_tokens["access_token"],
              "subject_token_type": "urn:ietf:params:oauth:token-type:access_token", "audience": "nobody"})
    check(r.status == 400 and r.json().get("error") == "invalid_target", "unknown audience -> invalid_target")
    r = token(api, realm, "ledger", secrets_by_client["ledger"], {"grant_type": "client_credentials"})
    check(r.status == 200, "ledger client_credentials")
    tokens["ledger (client_credentials)"] = {"token": r.json()["access_token"], "issuer": base + "/realms/monthfold"}

    # --- maya: claim-injection reproduction (1.0 item 1) ---
    maya_b = Browser(base)
    code, verifier = authorize(maya_b, realm, "web", users["maya"][0], "Monthfold-Passw0rd!", "openid profile", enrol)
    r = token(maya_b, realm, "web", secrets_by_client["web"], {"grant_type": "authorization_code", "code": code,
                                                              "redirect_uri": REDIRECT, "code_verifier": verifier})
    maya_b.request("GET", f"/realms/{realm}/account/profile", headers={"Accept": "application/json"})
    xs = maya_b.cookie("XSRF-TOKEN", f"/realms/{realm}")
    r2 = maya_b.request("PUT", f"/realms/{realm}/account/profile", headers={"X-XSRF-TOKEN": xs, "Accept": "application/json"},
                        body={"email": users["maya"][0] + "@harbor-pine.example", "attributes": {"sub": users["joe"][1]}})
    check(r2.status in (400, 403), f"maya cannot set attributes.sub (HTTP {r2.status})")
    code, verifier = authorize(maya_b, realm, "web", users["maya"][0], "Monthfold-Passw0rd!", "openid profile")
    r = token(maya_b, realm, "web", secrets_by_client["web"], {"grant_type": "authorization_code", "code": code,
                                                              "redirect_uri": REDIRECT, "code_verifier": verifier})
    check(r.status == 200 and claims(r.json()["access_token"])["sub"] == users["maya"][1], "maya's token still says maya")
    tokens["maya access token (web)"] = {"token": r.json()["access_token"], "issuer": base + "/realms/monthfold"}

    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w") as f:
        json.dump(tokens, f, indent=2)
    print(f"\n{sum(ok for ok, _ in CHECKS)}/{len(CHECKS)} checks passed; {len(tokens)} tokens written to {a.out}")


if __name__ == "__main__":
    main()
