# Wallet test vectors: sources and licences

Every file here is an unmodified excerpt of a published specification, extracted on 2026-10-11 (line breaks that the
specs added for page width were removed; JSON wrappers name the source section). Each vector was re-verified with an
independent implementation (Python `cryptography` and `cbor2`) before it was committed: signatures, disclosure
digests, `sd_hash`, JWE decryption, CBOR encodings and status-list bit values all match the documented results.

Protocol notes: `docs/eudi-wallet-spec-notes.md`.

## Licences

**These vector files are NOT under the project's Apache-2.0 licence.** Each file keeps the licence of the specification
it was extracted from, as listed below. Downstream packagers must carry these notices with the files.

### IETF-sourced files: Revised BSD License (IETF Trust Legal Provisions §4)

Applies to exactly these files:

- `sd-jwt/rfc9901-5.1-issuer-signed-jwt.txt`, `sd-jwt/rfc9901-5.1-sd-jwt.txt`, `sd-jwt/rfc9901-5.2-sd-jwt-kb.txt`,
  `sd-jwt/rfc9901-5.2-expected.json`, `sd-jwt/rfc9901-A.3-sd-jwt-vc-issued.txt`, `sd-jwt/rfc9901-A.3-sd-jwt-vc-kb.txt`,
  `sd-jwt/rfc9901-A.3-expected.json`, `sd-jwt/rfc9901-A.5-issuer-public-key.jwk.json`: from **RFC 9901**,
  Copyright (c) 2025 IETF Trust and the persons identified as the document authors.
- `sd-jwt/sd-jwt-vc-19-2.3.2-presentation-kb.txt`, `sd-jwt/sd-jwt-vc-19-2.3.2-presentation-no-kb.txt`: from
  **draft-ietf-oauth-sd-jwt-vc-19**, Copyright (c) 2026 IETF Trust and the persons identified as the document authors.
- `status-list/status-list-21-4.1-small-examples.json`, `status-list/status-list-21-C.1-1bit.json`,
  `status-list/status-list-21-C.2-2bit.json`, `status-list/status-list-21-C.3-4bit.json`,
  `status-list/status-list-21-C.4-8bit.json`, `status-list/status-list-21-8.2-status-list-token.jwt`: from
  **draft-ietf-oauth-status-list-21**, Copyright (c) 2026 IETF Trust and the persons identified as the document
  authors.

Each source document states: "Code Components extracted from this document must include Revised BSD License text as
described in Section 4.e of the Trust Legal Provisions and are provided without warranty as described in the Revised
BSD License." These extracted JWTs, JWKs, JSON values and CBOR hex are Code Components. Per TLP §4.e option (1), the
full Revised BSD License text from TLP §4.c (Legal Provisions Relating to IETF Documents, v5.0, corrected 2021,
https://trustee.ietf.org/documents/trust-legal-provisions/) is reproduced here and applies to each file listed above,
with the copyright line given for that file. Per TLP §4.d: these Code Components were derived from IETF RFC 9901,
draft-ietf-oauth-sd-jwt-vc-19 and draft-ietf-oauth-status-list-21 as listed. Please reproduce this note if possible.

```
Copyright (c) <year as listed above> IETF Trust and the persons identified as authors of
the code. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are
permitted provided that the following conditions are met:

- Redistributions of source code must retain the above copyright notice, this list of
  conditions and the following disclaimer.
- Redistributions in binary form must reproduce the above copyright notice, this list of
  conditions and the following disclaimer in the documentation and/or other materials
  provided with the distribution.
- Neither the name of Internet Society, IETF or IETF Trust, nor the names of specific
  contributors, may be used to endorse or promote products derived from this software
  without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

(Only line wrapping and the bullet characters differ from the TLP PDF.)

### OIDF-sourced files: OpenID Foundation terms (field-of-use restricted, NOT Apache-2.0)

Applies to exactly these files: `openid4vp/openid4vp-1.0-B.2.6.1-handover.json`,
`openid4vp/openid4vp-1.0-8.3-encrypted-response.json`, `openid4vp/openid4vp-1.0-dcql-examples.json`. Each is from
**OpenID for Verifiable Presentations 1.0** (Final, 9 July 2025),
https://openid.net/specs/openid-4-verifiable-presentations-1_0.html. Copyright (c) 2025 The OpenID Foundation.

Licence (OpenID4VP 1.0 Appendix G, verbatim): "The OpenID Foundation (OIDF) grants to any Contributor, developer,
implementer, or other interested party a non-exclusive, royalty free, worldwide copyright license to reproduce, prepare
derivative works from, distribute, perform and display, this Implementers Draft, Final Specification, or Final
Specification Incorporating Errata Corrections solely for the purposes of (i) developing specifications, and (ii)
implementing Implementers Drafts, Final Specifications, and Final Specification Incorporating Errata Corrections based
on such documents, provided that attribution be made to the OIDF as the source of the material, but that such
attribution does not indicate an endorsement by the OIDF."

This is a **field-of-use** licence: these files may be used only to develop specifications or implement OpenID4VP. We
use them as test fixtures for this OpenID4VP implementation, with the attribution above. They are **not** offered
under Apache-2.0 and must not be relicensed or repurposed beyond that field of use.

## Files

### `sd-jwt/`

| File | Source | URL |
|---|---|---|
| `rfc9901-5.1-issuer-signed-jwt.txt` | RFC 9901 §5.1, Issuer-signed JWT (`typ` `example+sd-jwt`, so a `dc+sd-jwt` verifier must reject its type) | https://www.rfc-editor.org/rfc/rfc9901#section-5.1 |
| `rfc9901-5.1-sd-jwt.txt` | RFC 9901 §5.1, SD-JWT with all 10 disclosures, no KB-JWT (ends in `~`) | same |
| `rfc9901-5.2-sd-jwt-kb.txt` | RFC 9901 §5.2, SD-JWT+KB with 4 disclosures (object, address object, array element) | https://www.rfc-editor.org/rfc/rfc9901#section-5.2 |
| `rfc9901-5.2-expected.json` | RFC 9901 §5.2, KB-JWT payload and Processed SD-JWT Payload | same |
| `rfc9901-A.3-sd-jwt-vc-issued.txt` | RFC 9901 Appendix A.3, issued SD-JWT VC (`typ` `dc+sd-jwt`, `vct` `urn:eudi:pid:de:1`, 27 disclosures incl. recursive `age_equal_or_over`) | https://www.rfc-editor.org/rfc/rfc9901#appendix-A.3 |
| `rfc9901-A.3-sd-jwt-vc-kb.txt` | RFC 9901 Appendix A.3, SD-JWT+KB disclosing `nationalities` and `age_equal_or_over.18` (recursive disclosure) | same |
| `rfc9901-A.3-expected.json` | RFC 9901 Appendix A.3, KB-JWT payload and Processed SD-JWT Payload | same |
| `rfc9901-A.5-issuer-public-key.jwk.json` | RFC 9901 Appendix A.5, issuer public key for every RFC 9901 and SD-JWT VC draft example (KB keys are the `cnf.jwk` in each payload) | https://www.rfc-editor.org/rfc/rfc9901#appendix-A.5 |
| `sd-jwt-vc-19-2.3.2-presentation-kb.txt` | draft-ietf-oauth-sd-jwt-vc-19 §2.3.2, Figure 8 (SD-JWT+KB; KB `aud` `https://example.com/verifier`, `nonce` `1234567890`) | https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-19.txt |
| `sd-jwt-vc-19-2.3.2-presentation-no-kb.txt` | draft-ietf-oauth-sd-jwt-vc-19 §2.3.2, Figure 10 (presentation without KB-JWT) | same |

None of the official SD-JWT examples carry an `x5c` header. **X.509 issuer chains: none — generated by TestWallet.**

### `status-list/`

| File | Source | URL |
|---|---|---|
| `status-list-21-4.1-small-examples.json` | draft-ietf-oauth-status-list-21 §4.1–§4.3 (1-bit and 2-bit byte arrays, compressed hex, `lst`, CBOR StatusList) | https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.txt |
| `status-list-21-C.1-1bit.json` | Appendix C.1, 2^20-entry 1-bit list: `lst`, CBOR hex, every non-zero index | same |
| `status-list-21-C.2-2bit.json` | Appendix C.2, 2-bit list | same |
| `status-list-21-C.3-4bit.json` | Appendix C.3, 4-bit list | same |
| `status-list-21-C.4-8bit.json` | Appendix C.4, 8-bit list | same |
| `status-list-21-8.2-status-list-token.jwt` | §8.2, example Status List Token response body (`typ` `statuslist+jwt`). **Its signing key is not published, so the signature cannot be verified; use for parsing only.** | same |

In the Appendix C files, `expected_nonzero` lists every index whose status is not 0; all other indices are 0.
**Signed status-list tokens (JWT and CWT): none — generated by TestWallet.**

### `openid4vp/`

| File | Source | URL |
|---|---|---|
| `openid4vp-1.0-B.2.6.1-handover.json` | OpenID4VP 1.0 Appendix B.2.6.1: inputs (client_id, nonce, response_uri, encryption JWK) and expected JWK thumbprint, OpenID4VPHandoverInfo, OpenID4VPHandover and SessionTranscript CBOR hex | https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2.6.1 |
| `openid4vp-1.0-8.3-encrypted-response.json` | OpenID4VP 1.0 §8.3: verifier encryption JWK (with private `d`), encrypted response JWE (ECDH-ES, A128GCM, `kid` `ac`), decoded header and payload | https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.3 |
| `openid4vp-1.0-dcql-examples.json` | OpenID4VP 1.0 §7.4 and Appendix D DCQL query examples (SD-JWT, mdoc, `credential_sets`) | https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-D |
| `x509-hash-known-answer-leaf.crt` | **Generated for HelixIAM (not from a spec).** PEM-encoded public certificate only (`.crt`: the repository ignores `*.pem`). A fixed CA-issued EC P-256 verifier leaf (CN=Helix Verifier KAT, SAN `verifier.example.eu`, issued by a throwaway CA whose key was discarded), made once with OpenSSL on 2026-10-12. Its `x509_hash` (OpenID4VP §5.9.3), computed with `openssl x509 -outform DER \| openssl dgst -sha256 -binary \| base64 \| tr '+/' '-_' \| tr -d '='`, is `7fteuS9uf6D2mMloP0J3jLDcjNtOhIouAw_VOuczFMI`. Known-answer test for `AuthorizationRequestFactory.clientId`. | n/a (generated) |

The decrypted `vp_token` in the §8.3 example is a placeholder string (`eyJhb...YMetA`), not a verifiable presentation.
**A complete signed request object with an `x5c` chain, and full encrypted responses carrying real presentations:
none — generated by TestWallet.**

### mdoc (no files)

**None — generated by TestWallet.** ISO/IEC 18013-5 Annex D test vectors are ISO copyright and are not reproduced.
OpenID4VP 1.0 has no DeviceResponse example. The only official mdoc-related vector is the SessionTranscript in
`openid4vp/openid4vp-1.0-B.2.6.1-handover.json`.

### PID (ARF)

**None — generated by TestWallet.** The PID Rulebook (eudi-doc-attestation-rulebooks-catalog) carries no licence file,
so its example payload is not copied. RFC 9901 A.3 (`vct` `urn:eudi:pid:de:1`) serves as a PID-shaped SD-JWT VC.
