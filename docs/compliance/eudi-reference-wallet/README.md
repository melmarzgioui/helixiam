# EU reference wallet interop run (2026-10-15)

HelixIAM's OpenID4VP 1.0 / HAIP 1.0 verifier, tested end to end against the **EU Digital Identity Wallet reference
app** (the open-source Android wallet of the `eu-digital-identity-wallet` GitHub organisation) on an Android emulator,
with PIDs issued by the EU reference **test** PID issuer. Both formats (SD-JWT VC and ISO mdoc) and both flows
(same-device and cross-device) signed in. No product change was needed. The mdoc DeviceResponses and SD-JWT VC
presentations the wallet posted are kept as offline test vectors (see "DeviceAuth vector" below).

Screenshots: [`2026-10-15/`](2026-10-15/). They show only the fictitious test PID entered at the test issuer
(Refw Tester, born 1990-01-01, administrative number `REFW-TEST-0001`).

## Result

| Flow | SD-JWT VC PID (`dc+sd-jwt`) | mdoc PID (`mso_mdoc`) |
|---|---|---|
| Same-device (emulator browser → "Open wallet app" → wallet → back to the browser) | **Pass** | **Pass** |
| Cross-device (desktop browser shows the QR code → wallet on the emulator) | **Pass** (QR content passed by `adb` intent, see deviations) | **Pass** (same) |

"Pass" means, for every run: the wallet accepted the signed request object and showed the verifier as **verified**
("HelixIAM Interop Test", green tick); after consent it posted an encrypted `direct_post.jwt` response; HelixIAM verified
the presentation (issuer chain to the PID issuer CA, issuer-certificate revocation by CRL under the default `HARD_FAIL`,
the Token Status List of both PIDs under the default `FAIL_CLOSED`, holder binding: KB-JWT or mdoc DeviceAuth),
resolved the subject by `personal_administrative_number`, and the relying party received an authorization code and
tokens. Server log line for each: `Wallet presentation verified: … formats=[…] decision=Provision|Existing`, audit event
`WALLET_LOGIN_SUCCESS`.

A sixth run checked the decline path: tapping **Cancel** in the wallet. See deviation 5.

## Versions

| Component | Version |
|---|---|
| Wallet app | `eudi-app-android-wallet-ui` release **2026.10.43-Demo** (build 43, tag `Wallet/Demo_Version=2026.10.43-Demo_Build=43`, commit `4b29547`), the released APK `2026.10.43-Demo.apk`, SHA-256 `83eeb2b0a99d195c21e3750f6e9b8d74dcd720dff3385926627cdffe2e645892`, **unmodified**. Wallet core `eudi-lib-android-wallet-core` 0.31.0. Licence: **EUPL-1.2** |
| Wallet flavour | `demo`: issuers `https://issuer.eudiw.dev` and `https://issuer-backend.eudiw.dev`, wallet provider `https://wallet-provider.eudiw.dev`, trusted lists at `https://trustedlist.serviceproviders.eudiw.dev/LOTE/json/*.jwt` (the EU's public test services) |
| PID issuer | `https://issuer.eudiw.dev`, "PID Combined" (one SD-JWT VC `urn:eudi:pid:1` and one mdoc `eu.europa.ec.eudi.pid.1`), country "FormEU" (a form you fill in). Signed by `CN=PID DS - 003`, issued by `CN=PID Issuer CA - UT 02, O=EUDI Wallet Reference Implementation, C=UT` |
| Verifier access certificate | Issued to us by the EU **Testing Relying Party Registration** service (`https://registry.serviceproviders.eudiw.dev`), WRP id 179: `CN=HelixIAM Interop Test, O=HelixIAM interop test (non-production), C=UT`, issued by `CN=WRPAC Issuer CA 01, …, C=UT`, valid to 2028-10-14, EC P-256. Its `x509_hash` is `NDYhYE-at3hRuFy5Uz4K7Wbkx0tVUYJMF0g8c5nuxsY` |
| Android | Emulator 37.2.12, platform-tools 37.0.1, command-line tools 22.0 (Homebrew cask `android-commandlinetools` 15859902), system image `system-images;android-35;google_apis;arm64-v8a` rev 9 (Android 15, Google Play services, `userdebug`), AVD Pixel 7, 6 GB RAM, on an Apple Silicon Mac (macOS 26.6.2). Chrome in the emulator 124.0.6367.219 |
| Desktop browser | Chrome for Testing 153.0.8010.12 (headless, driven by Playwright) |
| HelixIAM | `helix-iam-server` 1.0.0-SNAPSHOT at `master` 298dd452, Java 21.0.11, PostgreSQL 16.14, **no** `dev` profile (production defaults: `HELIX_ALLOWED_HOSTS` enforced, `revocationChecking=HARD_FAIL`, status list `FAIL_CLOSED`, MFA on) |
| Relying party | `helix-sandbox-rp` from the same commit, as an OIDC client of the test realm |

## What the reference wallet accepts (findings)

- **Verifier trust is enforced, with no dev bypass in the released app.** The `demo` (and `dev`) flavour configures
  `configureReaderAuthentication { enforceIfPresent() }` with the reader trust taken from the EU trusted list
  `WRPACProviders.jwt` (`core-logic/src/demo/.../WalletCoreConfigImpl.kt`). Per the app's source, a request signed by a
  certificate that does not chain to a listed WRPAC CA is refused ("Untrusted x5c", shown as "verifier not trusted");
  we did not try one. A self-made verifier
  certificate therefore does not work with the released APK. What made it work: the EU's public **Testing Relying Party
  Registration** service issues access certificates under that list. Authentication there is itself an OpenID4VP
  presentation of a PID, which we made with the test PID in the same wallet; the registration (legal person, legal
  entity, provider, supervisory authority, wallet relying party) and the access certificate are REST calls
  (`workflow_and_endpoints.md` of `eudi-srv-web-relyingparty-registration-py`). The service returns the key pair in a
  PKCS#12 file; its issuing CA is not included in the file (the CA is in `WRPACProviders.jwt`).
- **`client_id` prefixes:** the app enables `x509_san_dns` and `x509_hash` (`ClientIdScheme.X509SanDns`,
  `ClientIdScheme.X509Hash`). We used **`x509_hash`** (HelixIAM's default). `x509_san_dns` was not tested: the access
  certificates the registrar issues carry a URI and e-mail SAN only, no dNSName, so no certificate we could obtain under
  the trusted list would satisfy `x509_san_dns`.
- **Invocation schemes:** the app registers `openid4vp://`, `eudi-openid4vp://`, `mdoc-openid4vp://` and `haip-vp://`
  (any host). HelixIAM's default `haip-vp://` opened it, from both the "Open wallet app" link and the QR content.
- **Formats:** `dc+sd-jwt` and `mso_mdoc`, ES256 only. Encrypted responses: the wallet chose `ECDH-ES` with `A128GCM`
  from HelixIAM's `encrypted_response_enc_values_supported` (`A128GCM`, `A256GCM`).
- **DCQL:** HelixIAM's request (one SD-JWT VC query and one mdoc query, each with `claim_sets`) is shown by the wallet
  as alternatives ("Option 1 of 3": SD-JWT, mdoc, and a third entry for a not-yet-issued deferred mdoc PID the issuer
  had also queued). The wallet disclosed the first claim set (given and family name, birth date,
  `personal_administrative_number`, `issuing_country`).
- **The registration-certificate check is off** in the app by default (Settings, "Check Registration Certificates").
  We did not obtain a registration certificate (WRPRC), so the "intended use" layer was not exercised.
- **TLS:** the wallet's network security config trusts system CAs only (no user CAs), so the verifier needs a server
  certificate from a CA in the device's **system** store.

## Steps to reproduce

All local tooling lives outside the repository; nothing below adds code to the product.

1. **Android tooling.** `brew install --cask android-commandlinetools`; then
   `sdkmanager "platform-tools" "emulator" "system-images;android-35;google_apis;arm64-v8a"`;
   `avdmanager create avd -n refw-api35 -k "system-images;android-35;google_apis;arm64-v8a" -d pixel_7`.
   Use the `google_apis` image (it has Google Play services and allows `adb root`); the `google_apis_playstore` image
   does not allow root, which step 5 needs. Boot with `emulator -avd refw-api35 -writable-system`.
2. **Wallet.** Download `2026.10.43-Demo.apk` from the `eudi-app-android-wallet-ui` GitHub release and
   `adb install` it. Open it and set a PIN.
3. **Test PID.** In the wallet: Documents → Add → From list → **PID Combined**. The issuer opens in the browser:
   choose **FormEU**, fill in the mandatory fields, add the optional `personal_administrative_number` (HelixIAM needs it
   to create the account; without it the wallet can only be linked to an existing account), Submit, **Authorize**. The
   wallet receives one SD-JWT VC and one mdoc PID. (No login is needed. The wallet provider attested the emulator's
   software key without complaint.)
4. **Access certificate.** `GET https://registry.serviceproviders.eudiw.dev/authentication` returns a
   `eudi-openid4vp://` URL and a `presentation_id`; open the URL in the wallet (`adb shell am start -a
   android.intent.action.VIEW -d '<url>'`) and share the mdoc PID; `POST /getpidoid4vp?presentation_id=…` returns a
   `hash_pid`. Then create a law, a legal person, an identifier, a legal entity, a policy, a provider, a supervisory
   authority and a wallet relying party, and `POST /wallet_rp/certificate {hash_pid, wrp_id, password}`: the response
   carries the PKCS#12 (base64). Treat the `hash_pid` and the PKCS#12 password as secrets.
5. **TLS for the emulator.** Make a local CA and a `localhost` server certificate. Put the CA into the emulator's
   **system** trust store (Android 14+ reads it from the Conscrypt APEX: with `adb root`, copy
   `/apex/com.android.conscrypt/cacerts` to a tmpfs over `/system/etc/security/cacerts`, add the CA as
   `<subject_hash_old>.0`, and bind-mount it over the APEX directory in the zygote's and each app's mount namespace).
   Chrome in the emulator uses its own root store and also trusts user-added CAs, so add the CA to
   `/data/misc/user/0/cacerts-added/` as well. Then `adb reverse tcp:8743 tcp:8743` (and the RP's port) so that
   `https://localhost:8743` on the emulator is the Mac's `localhost:8743`, the same URL the desktop browser uses.
6. **HelixIAM.** PostgreSQL in Docker; the server jar on `127.0.0.1:8744` behind a small TLS reverse proxy on
   `localhost:8743` that adds `X-Forwarded-For`/`-Proto`:
   `IDP_BASE_URL=SP_BASE_URL=https://localhost:8743`, `HELIX_TRUSTED_PROXIES=127.0.0.1` (the proxy is the only peer),
   `HELIX_ALLOWED_HOSTS` empty (the IdP host `localhost` is always allowed; a request with any other `Host` got `400`),
   `DB_ENCRYPTION` set, `HELIX_SESSION_STORE=queue`, `helix.admin.dev-open=true` for the seeding calls only (bound to
   loopback). Seed like `e2e/wallet-demo/seed.sh`: realm `refw`; `POST /admin/realms/refw/verifier-keys` with the
   access-certificate key and the chain leaf + `WRPAC Issuer CA 01 (UT)` (HelixIAM keeps the leaf: `chainLength` 1);
   `POST /admin/realms/refw/identity-providers` with protocol `eudi-wallet`, `accessKeyRef`, `credentialFormats`
   `["dc+sd-jwt","mso_mdoc"]`, and as `trustAnchors` the seven self-signed **PID Issuer CA** certificates from
   `PIDProviders.jwt` (one of them, `PID Issuer CA - UT 02`, signed the PIDs). Every other setting stays at its default
   (`x509_hash`, `haip-vp`, `direct_post.jwt`, `HARD_FAIL`, `FAIL_CLOSED`). Register `helix-sandbox-rp` as a client and
   serve it over https too: HelixIAM sends HSTS for `localhost`, which then upgrades the RP's `http://localhost`
   callback in the browser.
7. **Same-device.** In the emulator's Chrome: RP → "Sign in with OIDC" → HelixIAM login → **EU Digital Identity
   Wallet** → **Open wallet app** → choose the option → Share → PIN → Close. The wallet opens the `redirect_uri` from
   HelixIAM's response in the browser, which completes the login.
8. **Cross-device.** On the Mac's browser: RP → login → **EU Digital Identity Wallet**: the page shows the QR code. We
   decoded the QR from a screenshot of the page and passed its content to the wallet with
   `adb shell am start -a android.intent.action.VIEW -d '<qr content>' eu.europa.ec.euidi`; consent in the wallet; the
   desktop page's poll then continued the login.
9. A new account's first login asks it to enrol a TOTP authenticator (realm MFA is on outside `dev`); later logins ask
   for the code. We computed the codes from the enrolment secret.

## DeviceAuth vector

Captured, and checked offline: `helix-iam-server/src/test/resources/wallet/vectors/eudi-reference-wallet/`, test
`EudiReferenceWalletCaptureVectorTest` (17 cases). Four captures (SD-JWT VC and mdoc, same-device and cross-device),
each with:

- `request-object.jwt`: the signed request object the wallet fetched (x5c = our access certificate);
- `response.jwe`: the `response` parameter the wallet posted (`direct_post.jwt`, ECDH-ES + A128GCM);
- `verifier-ephemeral-key.jwk.json`: the verifier's per-transaction decryption key (private). Captured by a test-only
  PostgreSQL trigger on `wallet_transaction` that copied the encrypted `encryption_jwk` column before HelixIAM cleared
  it, decrypted afterwards with the run's `DB_ENCRYPTION`. Nothing in the product was changed for this. The key was
  single-use and its transaction expired long ago;
- `decrypted-response.json`: what the JWE decrypts to;
- `capture.json`: when and how it was captured, the SessionTranscript inputs (`client_id`, `nonce`, `response_uri`,
  JWK thumbprint), the expected SessionTranscript (mdoc), the KB-JWT `iat` (SD-JWT VC) and the status-list reference;
- `pid-issuer-ca-ut-02.crt` and `wrpac-issuer-ca-ut-01.crt`: the two CA certificates, from the EU trusted lists.

Before they were committed, every capture was re-verified with an independent implementation (Python `cryptography`
and `cbor2`): JWE decryption (Concat KDF, AES-GCM), mdoc IssuerAuth with its `x5chain` leaf, mdoc DeviceAuth over
`["DeviceAuthentication", SessionTranscript, docType, DeviceNameSpacesBytes]` with the MSO device key, SD-JWT issuer
signature with its `x5c` leaf, and KB-JWT signature, `sd_hash`, `nonce` and `aud`. That one-off script is not kept in the repository; `EudiReferenceWalletCaptureVectorTest` is the
repeatable check of the same properties.

The Java test runs the production `VpResponseDecryptor`, `MdocPresentationVerifier` and `SdJwtVcPresentationVerifier`
at the capture time against the reference PID CA, and shows that DeviceAuth fails (`HOLDER_BINDING_INVALID`) for any
other `client_id`, `nonce`, `response_uri` or JWK thumbprint, and for a missing thumbprint. Revocation and status are
off in the offline test (they need the network); the live runs checked both.

## Interop fixes

None were needed: every flow passed on the first attempt with `master` 298dd452. The harness needed fixes of its own
(serving the RP over https because of HSTS; forwarding `X-Forwarded-Proto` to the RP), none in HelixIAM.

## Deviations and limits of this run

1. **Cross-device QR by intent, not by camera.** The emulator's virtual-scene camera shows a poster only where the
   scene puts it, and aiming the camera needs interactive keyboard/mouse input to the emulator window, which we could
   not script. The QR content was decoded from the desktop page and handed to the wallet by an Android `VIEW` intent.
   The wallet received exactly the QR's text (`haip-vp://?client_id=x509_hash%3A…&request_uri=…`), and the request and
   response then went over the cross-device path (`flow=CROSS_DEVICE` in the server log), but the wallet's QR scanner
   itself was not exercised.
2. **Emulator trust store changed.** Our local TLS CA was put into the emulator's system store (step 5). The wallet APK
   was not modified and its own trust configuration was not changed.
3. **`x509_san_dns` not tested** (no dNSName in registrar-issued access certificates), only `x509_hash`.
4. **Status list and revocation only live.** Both PIDs carry a Token Status List reference
   (`https://issuer.eudiw.dev/token_status_list/FC/…`; the mdoc MSO also names an `identifier_list`, which HelixIAM
   does not use); HelixIAM fetched and checked the status lists in the live runs. The offline test checks that the
   right reference reaches the status check, stubs its answer, and turns issuer-certificate revocation off.
5. **Decline sends nothing.** When the user taps **Cancel** in the wallet, the reference wallet posts no error response
   to `response_uri` (OpenID4VP defines an `access_denied` error response for this). HelixIAM's page keeps waiting until the
   transaction expires (`transactionTtlSeconds`, default 300 s) and then reports it as expired; the user can go
   "Back to sign in" at any time. Nothing to fix on our side.
6. **MFA after a wallet sign-up.** Under the default realm policy outside `dev` (MFA on), the account a wallet login
   creates must enrol a TOTP authenticator at once, and later wallet logins ask for the code. This is the realm's
   policy, not a wallet problem, but an operator who wants wallet-only sign-in has to adjust the realm's MFA settings.
7. **Not covered:** a national wallet, the W3C Digital Credentials API (`dc_api`; the wallet supports it), the iOS
   reference wallet, the OpenID Foundation conformance suite, and the registration-certificate (WRPRC) layer.
8. **Sandbox RP header label.** The RP result screenshots show "realm master": that header label is static in
   `helix-sandbox-rp/lib/ui.js`. The run itself used realm `refw`.
9. **The test registration** (WRP id 179, legal person "HelixIAM interop test (non-production)", support URI
   `https://github.com/helixiam`) exists in the EU test registry until it is cleaned up there; the access certificate is
   for this test only and its key never left the test machine.

## Licences

- Wallet app (`eudi-app-android-wallet-ui`): EUPL-1.2. Wallet core library (`eudi-lib-android-wallet-core`) and the
  registrar service (`eudi-srv-web-relyingparty-registration-py`): Apache-2.0.
- The captured presentations are machine output of that software, run by the HelixIAM project, over test data we typed
  in ourselves. See `helix-iam-server/src/test/resources/wallet/vectors/SOURCES.md`.
