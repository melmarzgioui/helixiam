# EUDI Wallet (OpenID4VP verifier): pinned specification notes

This file is the source of truth for every protocol string, field name, CBOR structure and handover format used by
`io.helixiam.authorization.federation.wallet`. When the implementation plan
(`docs/superpowers/plans/2026-10-09-eudi-wallet-openid4vp.md`) or the feature request
(`docs/superpowers/specs/2026-10-09-eudi-wallet-openid4vp.md`) disagrees with this file, **this file wins**. Record the
deviation in the PR description.

Conventions:

- Text in `>` blocks is quoted **verbatim** from the named section. Pilcrows and line wrapping were removed; nothing
  else was changed.
- **UNVERIFIED:** marks a value that could not be confirmed from a final normative text. Do not treat it as settled.
- Everything outside quotes is our reading, labelled as such where it is an interpretation.
- Test vectors are in `helix-iam-server/src/test/resources/wallet/vectors/` (see `SOURCES.md` there). Every vector
  listed was re-verified with an independent implementation (Python `cryptography` + `cbor2`) on 2026-10-11:
  signatures, digests, `sd_hash`, JWE decryption, CBOR encodings and status-list bit extraction all match.

## 0. Versions pinned (fetched 2026-10-11)

| Spec | Version / status | Date | URL |
|---|---|---|---|
| OpenID for Verifiable Presentations 1.0 | **Final** (errata URL; identical to `-final` apart from one reference date) | 9 July 2025 | https://openid.net/specs/openid-4-verifiable-presentations-1_0.html |
| OpenID4VC High Assurance Interoperability Profile 1.0 | **Final** | 24 December 2025 | https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html |
| Selective Disclosure for JSON Web Tokens | **RFC 9901** (Standards Track) | November 2025 | https://www.rfc-editor.org/rfc/rfc9901 |
| SD-JWT-based Verifiable Digital Credentials (SD-JWT VC) | `draft-ietf-oauth-sd-jwt-vc-19` (Internet-Draft; IESG state "Waiting for AD Go-Ahead") | 31 August 2026 | https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-19.txt |
| Token Status List (TSL) | `draft-ietf-oauth-status-list-21` (Internet-Draft; in the RFC Editor queue) | 21 June 2026 | https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.txt |
| ISO/IEC 18013-5 (mdoc structures) | 2021 edition is paywalled and **was not read**. Structures below come from OpenID4VP 1.0 Annex B and the public **working draft** of the 2nd edition ("CD ballot resolution v4", dated 2025-09-14) | 2025-09-14 | https://github.com/ISOWG10/ISO-18013/tree/main/Working%20Documents |
| ARF | v3.0.0 (Annex 3.01 is now only a pointer to the rulebooks catalog) | 2026-07-23 | https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/tree/v3.0.0 |
| ARF Annex 3.01 PID Rulebook | **v1.7** (catalog commit `6d8f7f84`) | 17 July 2026 | https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog/blob/6d8f7f8422e5bf6c48186005b6835c078f762a67/rulebooks/pid/pid-rulebook.md |
| ARF Annex 2 (high-level requirements, Topic 3 PID, Topic 7 revocation) | ARF v3.0.0 | 2026-07-23 | `docs/annexes/annex-2/annex-2.02-high-level-requirements-by-topic.md` at tag `v3.0.0` |
| IANA COSE / JOSE algorithm registries | live registry | fetched 2026-10-11 | https://www.iana.org/assignments/cose/ , https://www.iana.org/assignments/jose/ |

**Version pinning conflict (read this).** HAIP 1.0 §9.4 pins older drafts than the latest ones:

> Implementers should be aware that this specification uses several specifications that are not yet final
> specifications. Those specifications are:
> - SD-JWT-based Verifiable Credentials (SD-JWT VC) draft -13 [I-D.ietf-oauth-sd-jwt-vc]
> - Token Status List draft -14 [I-D.ietf-oauth-status-list]
>
> While breaking changes to the
> specifications referenced in this specification are not expected, should they occur, implementations compliant with
> this specification should continue to use the specifically referenced versions above in preference to the final
> versions, unless updated by a profile or new version of this specification.

We read SD-JWT VC **-19** and TSL **-21**. Differences that matter for a verifier are flagged inline ("draft-19
only"). We did **not** diff against -13 / -14 line by line. **UNVERIFIED:** that no verifier-relevant breaking change
exists between SD-JWT VC -13 and -19, and between TSL -14 and -21. The format identifiers (`dc+sd-jwt`, `kb+jwt`,
`statuslist+jwt`) and the `status.status_list.{idx,uri}` structure are identical in both, per the change logs.

---

## 1. OpenID for Verifiable Presentations 1.0 (Final)

### 1.1 Request Object (JAR) and request parameters

§5:

> Verifiers MUST include the typ Header Parameter in Request Objects with the value oauth-authz-req+jwt, as defined in
> [RFC9101]. Wallets MUST NOT process Request Objects where the typ Header Parameter is not present or does not have
> the value oauth-authz-req+jwt.

> The client_id claim is required as defined below and would be redundant with a possible iss claim in the Request
> Object which is commonly used in JAR. To avoid breaking existing JAR implementations, the iss claim MAY be present in
> the Request Object. However, if it is present, the Wallet MUST ignore it.

> Additional request parameters, other than those defined in this section, MAY be defined and used, as described in
> [RFC6749]. The Wallet MUST ignore any unrecognized parameters, other than the transaction_data parameter. One
> exception to this rule is the transaction_data parameter. Wallets that do not support this parameter MUST reject
> requests that contain it.

§5.1 (new parameters):

> dcql_query: A JSON object containing a DCQL query as defined in Section 6. Either a dcql_query or a scope parameter
> representing a DCQL Query MUST be present in the Authorization Request, but not both.

> client_metadata: OPTIONAL. A JSON object containing the Verifier metadata values. It MUST be UTF-8 encoded. The
> following metadata parameters MAY be used:
> - jwks: OPTIONAL. A JSON Web Key Set, as defined in [RFC7591], that contains one or more public keys, such as those
>   used by the Wallet as an input to a key agreement that may be used for encryption of the Authorization Response
>   (see Section 8.3), or where the Wallet will require the public key of the Verifier to generate a Verifiable
>   Presentation. This allows the Verifier to pass ephemeral keys specific to this Authorization Request. Public keys
>   included in this parameter MUST NOT be used to verify the signature of signed Authorization Requests. Each JWK in
>   the set MUST have a kid (Key ID) parameter that uniquely identifies the key within the context of the request.
> - encrypted_response_enc_values_supported: OPTIONAL. Non-empty array of strings, where each string is a JWE
>   [RFC7516] enc algorithm that can be used as the content encryption algorithm for encrypting the Response. When a
>   response_mode requiring encryption of the Response (such as dc_api.jwt or direct_post.jwt) is specified, this MUST
>   be present for anything other than the default single value of A128GCM. Otherwise, this SHOULD be absent.
> - vp_formats_supported: REQUIRED when not available to the Wallet via another mechanism. As defined in Section 11.1.
>
> Other metadata parameters MUST be ignored unless a profile of this specification explicitly defines them as usable in
> the client_metadata parameter.

> request_uri_method: OPTIONAL. A string determining the HTTP method to be used when the request_uri parameter is
> included in the same request. Two case-sensitive valid values are defined in this specification: get and post. If
> request_uri_method value is get, the Wallet MUST send the request to retrieve the Request Object using the HTTP GET
> method, i.e., as defined in [RFC9101]. If request_uri_method value is post, a supporting Wallet MUST send the
> request using the HTTP POST method as detailed in Section 5.10. If the request_uri_method parameter is not present,
> the Wallet MUST process the request_uri parameter as defined in [RFC9101]. Wallets not supporting the post method
> will send a GET request to the Request URI (default behavior as defined in [RFC9101]). request_uri_method parameter
> MUST NOT be present if a request_uri parameter is not present.

> verifier_info: OPTIONAL. A non-empty array of attestations about the Verifier relevant to the Credential Request.
> [...] Each object has the following structure:
> - format: REQUIRED. A string that identifies the format of the attestation and how it is encoded. [...]
> - data: REQUIRED. An object or string containing an attestation (e.g. a JWT). [...]
> - credential_ids: OPTIONAL. A non-empty array of strings each referencing a Credential requested by the Verifier for
>   which the attestation is relevant. [...]

§5.2 (existing parameters):

> nonce: REQUIRED. A case-sensitive String representing a value to securely bind Verifiable Presentation(s) provided
> by the Wallet to the particular transaction. The Verifier MUST create a fresh, cryptographically random number with
> sufficient entropy for every Authorization Request, store it with its current session, and pass it in the nonce
> Authorization Request Parameter to the Wallet. See Section 14.1 for details. Values MUST only contain ASCII URL safe
> characters (uppercase and lowercase letters, decimal digits, hyphen, period, underscore, and tilde).

> response_mode: REQUIRED. Defined in [OAuth.Responses]. [...]

> client_id: REQUIRED. Defined in [RFC6749]. [...]

> state: REQUIRED under the conditions defined in Section 5.3. Otherwise, state is OPTIONAL. state values MUST only
> contain ASCII URL safe characters (uppercase and lowercase letters, decimal digits, hyphen, period, underscore, and
> tilde).

§5.8 (`aud` of a Request Object):

> - the aud claim MUST be equal to the iss (issuer) claim value, when Dynamic Discovery is performed.
> - the aud claim MUST be "https://self-issued.me/v2", when Static Discovery metadata is used.
>
> Note: "https://self-issued.me/v2" is a symbolic string and can be used as an aud claim value even when this
> specification is used standalone, without SIOPv2.

**For Helix:** we use static discovery, so `aud = "https://self-issued.me/v2"`. OpenID4VP does not define `iat` /
`exp` for the request object; adding them is allowed (JAR). `iss` may be present but is ignored by wallets.

§5.10 (`request_uri_method=post`):

> The request MUST use the HTTP POST method with the https scheme, and the content type
> application/x-www-form-urlencoded and the Accept header set to application/oauth-authz-req+jwt. The names and values
> in the body MUST be encoded using UTF-8.

> wallet_metadata: OPTIONAL. A string containing a JSON object containing metadata parameters as defined in Section 10.
>
> wallet_nonce: OPTIONAL. A string value used to mitigate replay attacks of the Authorization Request. When received,
> the Verifier MUST use it as the wallet_nonce value in the signed authorization request object. [...]

> Additional parameters MAY be defined and used in the request to the Request URI Endpoint. The Verifier MUST ignore
> any unrecognized parameters.

§5.10.1:

> The Request URI response MUST be an HTTP response with the content type application/oauth-authz-req+jwt and the body
> being a signed, optionally encrypted, request object as defined in [RFC9101].

> The Client Identifier value in the client_id Authorization Request parameter and the Request Object client_id claim
> value MUST be identical, including the Client Identifier Prefix.

§5.10.2:

> If the Verifier responds with any HTTP error response, the Wallet MUST terminate the process.

Spec example of a request-object payload (§5.10.1, non-normative):

```json
{
  "client_id": "x509_san_dns:client.example.org",
  "response_uri": "https://client.example.org/post",
  "response_type": "vp_token",
  "response_mode": "direct_post",
  "dcql_query": {...},
  "nonce": "n-0S6_WzA2Mj",
  "wallet_nonce": "qPmxiNFCR3QTm19POc8u",
  "state" : "eyJhb...6-sVA"
}
```

### 1.2 Client Identifier Prefixes (`x509_san_dns`, `x509_hash`)

§5.9.1:

> In the client_id Authorization Request parameter and other places where the Client Identifier is used, the Client
> Identifier Prefixes are prefixed to the usual Client Identifier, separated by a : (colon) character:
> `<client_id_prefix>:<orig_client_id>`

> The Client Identifier Prefix is defined as the string before the (first) : character.

§5.9.3:

> x509_san_dns: When the Client Identifier Prefix is x509_san_dns, the original Client Identifier (the part after the
> x509_san_dns: prefix) MUST be a DNS name and match a dNSName Subject Alternative Name (SAN) [RFC5280] entry in the
> leaf certificate passed with the request. The request MUST be signed with the private key corresponding to the
> public key in the leaf X.509 certificate of the certificate chain added to the request in the x5c JOSE header
> [RFC7515] of the signed request object. The Wallet MUST validate the signature and the trust chain of the X.509
> certificate. All Verifier metadata other than the public key MUST be obtained from the client_metadata parameter.
> The following requirement applies unless the interaction is using the DC API as defined in Appendix A: If the Wallet
> can establish trust in the Client Identifier authenticated through the certificate, e.g. because the Client
> Identifier is contained in a list of trusted Client Identifiers, it may allow the client to freely choose the
> redirect_uri value. If not, the FQDN of the redirect_uri value MUST match the Client Identifier without the prefix
> x509_san_dns:. Example Client Identifier: x509_san_dns:client.example.org.

> x509_hash: When the Client Identifier Prefix is x509_hash, the original Client Identifier (the part without the
> x509_hash: prefix) MUST be a hash and match the hash of the leaf certificate passed with the request. The request
> MUST be signed with the private key corresponding to the public key in the leaf X.509 certificate of the certificate
> chain added to the request in the x5c JOSE header parameter [RFC7515] of the signed request object. The value of
> x509_hash is the base64url-encoded value of the SHA-256 hash of the DER-encoded X.509 certificate. The Wallet MUST
> validate the signature and the trust chain of the X.509 leaf certificate. All Verifier metadata other than the
> public key MUST be obtained from the client_metadata parameter. Example Client Identifier:
> x509_hash:Uvo3HtuIxuhC92rShpgqcT3YXwrqRxWEviRiA0OZszk

§8.2 ties `response_uri` to the same rule:

> The response_uri value MUST be a value that the client would be permitted to use as redirect_uri when following the
> rules defined in Section 5.9.

**Exact syntax for Helix:**

- `x509_san_dns:<dNSName>`, e.g. `x509_san_dns:id.example.eu`. With `direct_post`/`direct_post.jwt`, the FQDN of
  `response_uri` must equal `<dNSName>` (unless the wallet trusts the client id). The config validator should enforce
  this, not only "SAN matches `clientIdHost`".
- `x509_hash:<base64url(SHA-256(DER(leaf certificate)))>`, unpadded base64url (43 characters for SHA-256).
  OpenID4VP 1.0 §2 (Terminology): "Base64url-encoded denotes the URL-safe base64 encoding without padding defined in
  Section 2 of [RFC7515]."
- The full string, including the prefix, is the value of `aud` in the KB-JWT and the `clientId` in the mdoc handover
  (§14.8: "Wallets MUST always use the full Client Identifier, including the prefix if provided").

### 1.3 `client_metadata` for encryption and formats

§8.3:

> To obtain the Verifier's public key to which to encrypt the Authorization Response, the Wallet uses JWKs from client
> metadata (such as the jwks member within the client_metadata request parameter or other mechanisms as allowed by the
> given Client Identifier Prefix). Using what it supports and its preferences, the Wallet selects the public key to
> encrypt the Authorization Response based on information about each key, such as the kty (Key Type), use (Public Key
> Use), alg (Algorithm), and other JWK parameters. The alg parameter MUST be present in the JWKs. The JWE alg
> algorithm used MUST be equal to the alg value of the chosen jwk. If the selected public key contains a kid
> parameter, the JWE MUST include the same value in the kid JWE Header Parameter (as defined in Section 4.1.6) of the
> encrypted response. This enables the Verifier to easily identify the specific public key that was used to encrypt
> the response. The JWE enc content encryption algorithm used is obtained from the encrypted_response_enc_values_supported
> parameter of client metadata, such as the client_metadata request parameter, allowing for the default value of
> A128GCM when not explicitly set.

> The payload of the encrypted JWT response MUST include the contents of the response as defined in Section 8.1 as
> top-level JSON members.

§11.1 (Verifier metadata):

> vp_formats_supported: REQUIRED. An object containing a list of name/value pairs, where the name is a Credential
> Format Identifier and the value defines format-specific parameters that a Verifier supports. For specific values
> that can be used, see Appendix B.

Appendix B.3.4 (`dc+sd-jwt` metadata):

> - sd-jwt_alg_values: OPTIONAL. A non-empty array containing fully-specified identifiers of cryptographic algorithms
>   (as defined in [I-D.ietf-jose-fully-specified-algorithms]) supported for an Issuer-signed JWT of an SD-JWT.
> - kb-jwt_alg_values: OPTIONAL. A non-empty array containing fully-specified identifiers of cryptographic algorithms
>   (as defined in [I-D.ietf-jose-fully-specified-algorithms]) supported for a Key Binding JWT (KB-JWT).

Appendix B.2.2 (`mso_mdoc` metadata):

> - issuerauth_alg_values: OPTIONAL. A non-empty array containing cryptographic algorithm identifiers. [...]
> - deviceauth_alg_values: OPTIONAL. A non-empty array containing cryptographic algorithm identifiers. The Credential
>   MUST be considered to fulfill the requirement(s) expressed in this parameter if one of the following is true: 1)
>   The value in the array matches the 'alg' value in the DeviceSignature or DeviceMac COSE header. [...] 3) The alg of
>   the DeviceMac COSE header is HMAC 256/256 [...] and the curve of the device key [...] matches a value in the array
>   using the identifiers defined in the following table: [-65537 P-256 ... -65545 brainpoolP512r1]

**Algorithm identifiers (IANA registries, fetched 2026-10-11):**

- JOSE: `ES256` (Recommended+), `ES384`, `ES512`, `PS256` are fully specified JOSE identifiers; `EdDSA` is
  Deprecated (use `Ed25519`).
- COSE: `ES256 = -7`, `ES384 = -35`, `ES512 = -36` (all marked "Deprecated" by RFC 9864 in favour of the fully
  specified) `ESP256 = -9`, `ESP384 = -51`, `ESP512 = -52`; `Ed25519 = -19`; `Ed448 = -53`; `ESB256 = -265`.
- **Do not copy the B.2.2 example `[-9, -50]`**: in today's IANA COSE registry `-50` is `ML-DSA-87`, not an ECDSA
  algorithm.
- COSE header labels: `alg = 1`, `kid = 4`, `x5chain = 33`, `x5t = 34`.

**Helix `client_metadata` (derived; field names verified above):**

```json
{
  "jwks": { "keys": [ { "kty": "EC", "crv": "P-256", "x": "...", "y": "...",
                        "use": "enc", "alg": "ECDH-ES", "kid": "<per-transaction kid>" } ] },
  "encrypted_response_enc_values_supported": ["A128GCM", "A256GCM"],
  "vp_formats_supported": {
    "dc+sd-jwt": { "sd-jwt_alg_values": ["ES256", "ES384", "ES512"],
                   "kb-jwt_alg_values": ["ES256", "ES384", "ES512"] },
    "mso_mdoc":  { "issuerauth_alg_values": [-7, -9, -35, -51, -36, -52],
                   "deviceauth_alg_values": [-7, -9, -35, -51, -36, -52] }
  }
}
```

There is **no** `authorization_encrypted_response_alg` / `authorization_encrypted_response_enc` in OpenID4VP 1.0.
The JWE `alg` comes from the JWK's `alg`; the `enc` set comes from `encrypted_response_enc_values_supported`.
Do not list the HMAC identifiers (`-65537`…) in `deviceauth_alg_values` (see §6.4 on `deviceMac`).

### 1.4 DCQL

§6 top level:

> credentials: REQUIRED. A non-empty array of Credential Queries as defined in Section 6.1 that specify the requested
> Credentials.
> credential_sets: OPTIONAL. A non-empty array of Credential Set Queries as defined in Section 6.2 that specifies
> additional constraints on which of the requested Credentials to return.

§6.1 Credential Query:

> id: REQUIRED. A string identifying the Credential in the response and, if provided, the constraints in
> credential_sets. The value MUST be a non-empty string consisting of alphanumeric, underscore (_), or hyphen (-)
> characters. Within the Authorization Request, the same id MUST NOT be present more than once.
> format: REQUIRED. A string that specifies the format of the requested Credential. [...]
> multiple: OPTIONAL. A boolean which indicates whether multiple Credentials can be returned for this Credential
> Query. If omitted, the default value is false.
> meta: REQUIRED. An object defining additional properties requested by the Verifier that apply to the metadata and
> validity data of the Credential. [...]
> trusted_authorities: OPTIONAL. A non-empty array of objects as defined in Section 6.1.1 [...]
> require_cryptographic_holder_binding: OPTIONAL. A boolean which indicates whether the Verifier requires a
> Cryptographic Holder Binding proof. The default value is true [...]
> claims: OPTIONAL. A non-empty array of objects as defined in Section 6.3 that specifies claims in the requested
> Credential. [...]
> claim_sets: OPTIONAL. A non-empty array containing arrays of identifiers for elements in claims [...]

§6.1.1.1 (`trusted_authorities` type `aki`, required by HAIP):

> Contains the KeyIdentifier of the AuthorityKeyIdentifier as defined in Section 4.2.1.1 of [RFC5280], encoded as
> base64url. The raw byte representation of this element MUST match with the AuthorityKeyIdentifier element of an
> X.509 certificate in the certificate chain present in the Credential (e.g., in the header of an mdoc or SD-JWT).

Example: `{ "type": "aki", "values": ["s9tIpPmhxdiuNkHMEWNpYim8S8Y"] }`.

§6.2 Credential Set Query:

> options: REQUIRED A non-empty array, where each value in the array is a list of Credential Query identifiers
> representing one set of Credentials that satisfies the use case. [...]
> required: OPTIONAL A boolean which indicates whether this set of Credentials is required to satisfy the particular
> use case at the Verifier. If omitted, the default value is true.

§6.3 Claims Query:

> id: REQUIRED if claim_sets is present in the Credential Query; OPTIONAL otherwise. [...]
> path: REQUIRED The value MUST be a non-empty array representing a claims path pointer that specifies the path to a
> claim within the Credential, as defined in Section 7.
> values: OPTIONAL A non-empty array of strings, integers or boolean values that specifies the expected values of the
> claim. [...]

§6.4:

> Wallets MUST NOT send selectively disclosable claims that have not been selected according to the rules below. A
> single Presentation of a Credential MAY contain more than the claims selected in the particular DCQL Credential
> Query if the same Credential is selected with the additional claims in a separate Credential Query in the same
> request, or the additional claims are not selectively disclosable.

§6.4.2:

> If the Wallet cannot deliver all non-optional Credentials requested by the Verifier according to these rules, it
> MUST NOT return any Credential(s).

§7.2 (claims path pointer for mdoc):

> A claims path pointer into an mdoc contains two elements of type string. The first element refers to a namespace and
> the second element refers to a data element identifier.

Format-specific `meta`:

- B.3.5 (`dc+sd-jwt`): "vct_values: REQUIRED. A non-empty array of strings that specifies allowed values for the type
  of the requested Verifiable Credential. [...] The Wallet MAY return Credentials that inherit from any of the
  specified types, following the inheritance logic defined in [I-D.ietf-oauth-sd-jwt-vc]."
- B.2.3 (`mso_mdoc`): "doctype_value: REQUIRED. String that specifies an allowed value for the doctype of the
  requested Verifiable Credential."
- B.2.4 (`mso_mdoc` claims query): "intent_to_retain OPTIONAL. A boolean that is equivalent to IntentToRetain variable
  defined in Section 8.3.2.1.2.1 of [ISO.18013-5]."

§14.9:

> While the Verifier can specify various constraints both on the claims level and the Credential level as shown in
> Section 6.4, it MUST NOT rely on the Wallet to enforce these constraints. The Wallet is not controlled by the
> Verifier and the Verifier MUST perform its own security checks on the returned Credentials and Presentations.

**Helix PID preset (derived from §7 above and the PID Rulebook in §7 of these notes):**

```json
{
  "credentials": [
    { "id": "pid_sd_jwt", "format": "dc+sd-jwt",
      "meta": { "vct_values": ["urn:eudi:pid:1"] },
      "claims": [ {"path": ["given_name"]}, {"path": ["family_name"]}, {"path": ["birthdate"]} ] },
    { "id": "pid_mdoc", "format": "mso_mdoc",
      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
      "claims": [ {"path": ["eu.europa.ec.eudi.pid.1", "given_name"]},
                  {"path": ["eu.europa.ec.eudi.pid.1", "family_name"]},
                  {"path": ["eu.europa.ec.eudi.pid.1", "birth_date"]} ] }
  ],
  "credential_sets": [ { "options": [ ["pid_sd_jwt"], ["pid_mdoc"] ] } ]
}
```

(The ids are our choice; only the field names and identifier values are normative.)

### 1.5 Response modes, `direct_post`, `direct_post.jwt`, `redirect_uri`

§8.2:

> direct_post: In this mode, the Authorization Response is sent to the Verifier using an HTTP POST request to an
> endpoint controlled by the Verifier. The Authorization Response MUST be encoded in the request body using the format
> defined by the application/x-www-form-urlencoded HTTP content type. The parameters in the request body MUST all be
> encoded using UTF-8. The Verifier can request that the Wallet redirects the End-User to the Verifier using the
> response as defined below.

> response_uri: REQUIRED when the Response Mode direct_post is used. The URL to which the Wallet MUST send the
> Authorization Response using an HTTP POST request as defined by the Response Mode direct_post. The Response URI
> receives all Authorization Response parameters as defined by the respective Response Type. When the response_uri
> parameter is present, the redirect_uri Authorization Request parameter MUST NOT be present. [...]

> If the Response URI has successfully processed the Authorization Response or Authorization Error Response, it MUST
> respond with an HTTP status code of 200 with Content-Type of application/json and a JSON object in the response
> body.

> redirect_uri: OPTIONAL. String containing a URI. When this parameter is present the Wallet MUST redirect the user
> agent to this URI. [...] The Response URI MAY return the redirect_uri parameter in response to successful
> Authorization Responses or for Error Responses.

> The value of the redirect URI is an absolute URI as defined by [RFC3986] Section 4.3 and is chosen by the Verifier.
> The Verifier MUST include a fresh, cryptographically random value in the URL. This value is used to ensure only the
> receiver of the redirect can fetch and process the Authorization Response. The value can be added as a path
> component, as a fragment or as a parameter to the URL. It is RECOMMENDED to use a cryptographic random value of 128
> bits or more.

Spec example response from the Response URI (§8.2):

```
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "redirect_uri": "https://client.example.org/cb#response_code=091535f699ea575c7937fa5f0f454aee"
}
```

> If the response does not contain the redirect_uri parameter, the Wallet is not required to perform any further
> steps.

§8.3.1:

> The Response Mode direct_post.jwt causes the Wallet to send the Authorization Response using an HTTP POST request
> instead of redirecting back to the Verifier as defined in Section 8.2. The Wallet adds the response parameter
> containing the JWT as defined in Section 8.3 in the body of an HTTP POST request using the
> application/x-www-form-urlencoded content type. The names and values in the body MUST be encoded using UTF-8.

> If a Wallet is unable to generate an encrypted response, it MAY send an error response without encryption as per
> Section 8.2.

§8.3:

> To encrypt the Authorization Response, implementations MUST use an unsigned, encrypted JWT as described in
> [RFC7519].

**`response_mode` values relevant to Helix:** `direct_post`, `direct_post.jwt` (redirect flows); `dc_api`,
`dc_api.jwt` (Appendix A, Phase 4). The default for `vp_token` is `fragment` (§5.6), which we never use.

**Consequences:** in `direct_post.jwt` mode the response endpoint must still accept an **unencrypted** `error` (+
`state`) form post. OpenID4VP does not specify the HTTP status or body the Response URI returns when it **rejects** a
response. **UNVERIFIED / unspecified:** we choose HTTP 400 with `{"error": "invalid_request"}` and no detail.

### 1.6 `vp_token` shape

§8.1:

> vp_token: REQUIRED. This is a JSON-encoded object containing entries where the key is the id value used for a
> Credential Query in the DCQL query and the value is an array of one or more Presentations that match the respective
> Credential Query. When multiple is omitted, or set to false, the array MUST contain only one Presentation. There
> MUST NOT be any entry in the JSON-encoded object for optional Credential Queries when there are no matching
> Credentials for the respective Credential Query. Each Presentation is represented as a string or object, depending
> on the format as defined in Appendix B.

Example (§8.1.1): `{ "my_credential": ["eyJhbGci...QMA"] }`.

- `dc+sd-jwt`: each presentation is the compact SD-JWT+KB string (B.3).
- `mso_mdoc` (B.2.5): "The VP Token contains the base64url-encoded DeviceResponse CBOR structure as defined in ISO/IEC
  18013-5 [ISO.18013-5] or ISO/IEC 23220-4 [ISO.23220-4]."

### 1.7 Error codes (§8.5)

Wallet → Verifier error codes (posted as `error`, optional `error_description`, `state`):

- `invalid_scope`, `invalid_request`, `invalid_client`, `access_denied` (RFC 6749 codes, with OpenID4VP clarifications)
- `vp_formats_not_supported`: "The Wallet does not support any of the formats requested by the Verifier [...]"
- `invalid_request_uri_method`: "The value of the request_uri_method request parameter is neither get nor post
  (case-sensitive)."
- `invalid_transaction_data`
- `wallet_unavailable`: "The Wallet appears to be unavailable and therefore unable to respond to the request. [...]"

`access_denied` is defined as:

> - The Wallet did not have the requested Credentials to satisfy the Authorization Request.
> - The End-User did not give consent to share the requested Credentials with the Verifier.
> - The Wallet failed to authenticate the End-User.

### 1.8 VP Token validation and replay (§8.6, §14.1.2)

§8.6:

> 1. Validate the format of the VP Token as defined in Section 8.1.
> 2. Check the individual Presentations according to the specific Credential Format requested: 1. Validate the
>    integrity and authenticity of the Presentation and Credential. 2. Validate that the returned Credential(s) meet
>    all criteria defined in the query in the Authorization Request (e.g., Claims included in the presentation). 3.
>    Validate that all Presentations contain a cryptographic proof of Holder Binding (i.e., that they are Verifiable
>    Presentations), unless specifically requested otherwise. 4. For Verifiable Presentations, validate the Holder
>    Binding, including the checks required to prevent replay described in Section 14.1. 5. Perform the checks
>    required by the Verifier's policy based on the set of trust requirements such as trust frameworks it belongs to
>    (e.g., revocation checks), if applicable.
> 3. Check that the set of Presentations returned satisfies all requirements defined in the Verifier's request as
>    described in Section 6.4.
>
> If any of the checks related to an individual Presentation fail, the effected Presentation MUST be discarded. If
> any of the checks pertaining to the VP Token or the overall response fails, the VP Token MUST be rejected.

§14.1.2:

> The Verifier MUST validate every individual Verifiable Presentation in an Authorization Response and ensure that it
> is linked to the values of the client_id and the nonce parameter it had used for the respective Authorization
> Request. If any Verifiable Presentation in the response does not contain the correct nonce value, the response MUST
> be rejected.

B.3.6 (KB-JWT for SD-JWT VC):

> - the nonce claim MUST be the value of nonce from the Authorization Request;
> - the aud claim MUST be the value of the Client Identifier, except for requests over the DC API where it MUST be the
>   Origin prefixed with origin:, as described in Appendix A.4.

### 1.9 mdoc SessionTranscript / OpenID4VPHandover (redirect and `direct_post` flows)

Appendix B.2.6.1 "Invocation via Redirects":

> If the presentation request is invoked using redirects, the SessionTranscript CBOR structure as defined in Section
> 9.1.5.1 in [ISO.18013-5] MUST be used with the following changes:
> - DeviceEngagementBytes MUST be null.
> - EReaderKeyBytes MUST be null.
> - Handover MUST be the OpenID4VPHandover CBOR structure as defined below.

```cddl
OpenID4VPHandover = [
  "OpenID4VPHandover", ; A fixed identifier for this handover type
  OpenID4VPHandoverInfoHash ; A cryptographic hash of OpenID4VPHandoverInfo
]

; Contains the sha-256 hash of OpenID4VPHandoverInfoBytes
OpenID4VPHandoverInfoHash = bstr

; Contains the bytes of OpenID4VPHandoverInfo encoded as CBOR
OpenID4VPHandoverInfoBytes = bstr .cbor OpenID4VPHandoverInfo

OpenID4VPHandoverInfo = [
  clientId,
  nonce,
  jwkThumbprint,
  responseUri
] ; Array containing handover parameters

clientId = tstr
nonce = tstr
jwkThumbprint = bstr
responseUri = tstr
```

> - The first element MUST be the string OpenID4VPHandover. [...]
> - The second element MUST be a Byte String which contains the sha-256 hash of the bytes of OpenID4VPHandoverInfo
>   when encoded as CBOR.
> - The OpenID4VPHandoverInfo has the following elements:
>   - The first element MUST be the client_id request parameter. If applicable, this includes the Client Identifier
>     Prefix.
>   - The second element MUST be the value of the nonce request parameter.
>   - If the response is encrypted, e.g., using direct_post.jwt, the third element MUST be the JWK SHA-256 Thumbprint
>     as defined in [RFC7638], encoded as a Byte String, of the Verifier's public key used to encrypt the response.
>     Otherwise, the third element MUST be null. See Appendix B.2.6.2 for an explanation of why this is important.
>   - The fourth element MUST be either the redirect_uri or response_uri request parameter, depending on which is
>     present, as determined by the Response Mode.
>
> Unless otherwise stated, the values of client_id, nonce, redirect_uri, and response_uri request parameters
> referenced above MUST be obtained from the Authorization Request query parameters if the request is unsigned, or
> from the signed Request Object if the request is signed.

So, precisely:

```
info        = CBOR([client_id, nonce, sha256(RFC7638-canonical-JWK) as bstr | null, response_uri])
handover    = ["OpenID4VPHandover", bstr(SHA-256(info))]
transcript  = CBOR([null, null, handover])
```

Notes for the implementation:

- The JWK thumbprint is the **raw 32 bytes** (CBOR byte string), not base64url text.
- RFC 7638 for EC keys hashes the UTF-8 JSON of exactly `{"crv":..,"kty":..,"x":..,"y":..}` (members in that
  lexicographic order, no whitespace). `use`, `alg` and `kid` are excluded. Verified against the spec vector.
- `direct_post` (unencrypted, dev only) → third element `null` (CBOR `f6`).
- **Official vector:** `vectors/openid4vp/openid4vp-1.0-B.2.6.1-handover.json` (inputs `x509_san_dns:example.com`,
  nonce, `https://example.com/response`, JWK; expected thumbprint, info, handover and SessionTranscript hex). We
  re-derived all four values from the inputs; they match byte for byte.

The SessionTranscript is then used inside ISO's `DeviceAuthentication` (see §6.3 of these notes).

### 1.10 Wallet invocation (§9, §13.1.2, Appendix E.8)

§9:

> The Verifier can use one of the following mechanisms to invoke a Wallet:
> - Custom URL scheme as an authorization_endpoint (for example, openid4vp:// as defined in Section 13.1.2)
> - URL (including Domain-bound Universal Links/App link) as an authorization_endpoint
>
> For a cross device flow, either of the above options MAY be presented as a QR code for the End-User to scan using a
> Wallet or an arbitrary camera application on a user-device.

§13.1.2 static configuration example uses `"authorization_endpoint": "openid4vp:"`. Appendix E.8 registers the URI
scheme `openid4vp` with **Status: Provisional**.

§5.4 example of an invocation by reference (verbatim, line breaks as in the spec):

```
GET /authorize?
  client_id=x509_san_dns%3Aclient.example.org
  &request_uri=https%3A%2F%2Fclient.example.org%2Frequest%2Fvapof4ql2i7m41m68uep
  &request_uri_method=post HTTP/1.1
```

### 1.11 Response code, session fixation, response endpoint protection (§13.3, §14.2, §14.3)

§14.2:

> The Verifier's Response URI MUST include a fresh secret (Response Code) into the redirect URI returned to the Wallet
> and the Verifier's Response URI MUST require the frontend to pass the respective Response Code when fetching the
> Authorization Response. That stops session fixation attacks as long as the attacker is unable to get access to the
> Response Code.

> Note that this protection technique is not applicable to cross-device scenarios because the browser used by the
> Wallet will not have the original session.

§14.3.2:

> The Verifier SHOULD protect its Response URI from inadvertent requests by checking that the value of the received
> state parameter corresponds to a recent Authorization Request.

§13.3 (non-normative design), step (1):

> The Verifier produces a nonce value by generating at least 16 fresh, cryptographically random bytes with sufficient
> entropy, associates it with the session and base64url encodes it.

---

## 2. OpenID4VC High Assurance Interoperability Profile (HAIP) 1.0 (Final)

### 2.1 Requirements on every OpenID4VP flow (§5)

> - The Response type MUST be vp_token.
> - For signed requests, the Verifier MUST use, and the Wallet MUST accept the Client Identifier Prefix x509_hash as
>   defined in Section 5.9.3 of [OIDF.OID4VP]. The X.509 certificate of the trust anchor MUST NOT be included in the
>   x5c JOSE header of the signed request. The X.509 certificate signing the request MUST NOT be self-signed. X.509
>   certificate profiles to be used with x509_hash are out of scope of this specification.
> - The DCQL query and response MUST be used as defined in Section 6 of [OIDF.OID4VP].
> - Response encryption MUST be performed as specified in Section 8.3 of [OIDF.OID4VP]. The JWE alg (algorithm)
>   header parameter (see Section 4.1.1 of [RFC7516]) value ECDH-ES (as defined in Section 4.6 of [RFC7518]), with key
>   agreement utilizing keys on the P-256 curve (see Section 6.2.1.1 of [RFC7518]) MUST be supported. The JWE enc
>   (encryption algorithm) header parameter (see Section 4.1.2 of [RFC7516]) values A128GCM and A256GCM (as defined in
>   Section 5.3 of [RFC7518]) MUST be supported by Verifiers. Wallets MUST support A128GCM or A256GCM, or both. If both
>   are supported, the Wallet SHOULD use A256GCM for the JWE enc. Verifiers MUST list both A128GCM and A256GCM in
>   encrypted_response_enc_values_supported in their client metadata.
> - Verifiers MUST supply ephemeral encryption public keys specific to each Authorization Request passed via client
>   metadata as specified in Section 8.3 of [OIDF.OID4VP].
> - The Authority Key Identifier (aki)-based Trusted Authority Query (trusted_authorities) for DCQL, as defined in
>   section 6.1.1.1 of [OIDF.OID4VP], MUST be supported. [...]

### 2.2 Redirect flows (§5.1)

> - As a way to invoke the Wallet, the custom URL scheme haip-vp:// MAY be supported by the Wallet and the Verifier.
>   Implementations MAY support other ways to invoke the Wallets as agreed upon by trust frameworks/Ecosystems/
>   jurisdictions, including but not limited to using other custom URL schemes or claimed "https" scheme URIs.
> - Signed Authorization Requests MUST be used by utilizing JWT-Secured Authorization Request (JAR) [RFC9101] with the
>   request_uri parameter.
> - Response encryption MUST be used by utilizing response mode direct_post.jwt, as defined in Section 8.3 of
>   [OIDF.OID4VP]. Security considerations in Section 14.3 of [OIDF.OID4VP] MUST be applied.
> - Verifiers and Wallets MUST support the "same-device" flow. Verifiers are RECOMMENDED to use only the "same-device"
>   flow unless the Verifier does not rely on session binding for phishing resistance, e.g. in a proximity scenario.
>   If "same-device" flow is used, then:
>   - Verifiers MUST include redirect_uri in the HTTP response to the Wallet's HTTP POST to the response_uri, as
>     defined in Section 8.2 of [OIDF.OID4VP].
>   - Wallets MUST follow the redirect to redirect_uri.
>   - Verifiers MUST reject presentations if Wallets do not follow the redirect back or the redirect back arrives in a
>     different user session to the one the request was initiated in.

Appendix A.1.2 registers `haip-vp` with **Status: Permanent**.

### 2.3 Format requirements (§5.3, §6.1, §7, §8)

§5.3.1 (mdoc):

> - The Credential Format identifier MUST be mso_mdoc.
> - When multiple ISO mdocs are being returned, each ISO mdoc MUST be returned in a separate DeviceResponse (as
>   defined in 8.3.2.1.2.2 of [ISO.18013-5]), each matching to a respective DCQL query. Therefore, the resulting
>   vp_token contains multiple DeviceResponse instances.
> - The Credential Issuer MAY include the MSO revocation mechanism in the issued mdoc. When doing so, it MUST use one
>   of the mechanisms defined in ISO/IEC 18013-5 ([ISO.18013-5.second.edition]).

§5.3.2: "The Credential Format identifier MUST be dc+sd-jwt."

§6.1 (SD-JWT VC profile):

> - Compact serialization MUST be supported as defined in [RFC9901]. JSON serialization MAY be supported.
> - It is RECOMMENDED that Issuers limit the validity period when issuing SD-JWT VC. When doing so, the Issuer MUST
>   use an exp claim, a status claim, or both.
> - The cnf claim [RFC7800] MUST conform to the definition given in [I-D.ietf-oauth-sd-jwt-vc]. Implementations
>   conforming to this specification MUST include the JSON Web Key [RFC7517] in the jwk member if the corresponding
>   Credential Configuration requires cryptographic holder binding.
> - The status claim, if present, MUST contain status_list as defined in [I-D.ietf-oauth-status-list]
> - The public key used to validate the signature on the Status List Token defined in [I-D.ietf-oauth-status-list]
>   MUST be included in the x5c JOSE header of the Token. The X.509 certificate of the trust anchor MUST NOT be
>   included in the x5c JOSE header of the Status List Token. The X.509 certificate signing the request MUST NOT be
>   self-signed.

§6.1.1:

> This specification mandates the support for X.509 certificate-based key resolution to validate the issuer signature
> of an SD-JWT VC. This MUST be supported by all entities (Issuer, Wallet, Verifier). The SD-JWT VC MUST contain the
> credential issuer's signing certificate along with a trust chain in the x5c JOSE header parameter as described in
> section 3.5 of [I-D.ietf-oauth-sd-jwt-vc]. The X.509 certificate of the trust anchor MUST NOT be included in the x5c
> JOSE header of the SD-JWT VC. The X.509 certificate signing the request MUST NOT be self-signed.

§6.1.1.1:

> If the credential has cryptographic holder binding, a KB-JWT, as defined in [I-D.ietf-oauth-sd-jwt-vc], MUST always
> be present when presenting an SD-JWT VC.

§7:

> Issuers, Verifiers, and Wallets MUST, at a minimum, support ECDSA with P-256 and SHA-256 (JOSE algorithm identifier
> ES256; COSE algorithm identifier -7 or -9, as applicable) for the purpose of validating the following: [...]
> Verifiers: the signature of the Verifiable Presentation, e.g., KB-JWT of an SD-JWT VC, or deviceSignature CBOR
> structure in case of ISO mdocs. [...] the status information of the Verifiable Credential or Wallet Attestation.

§8: "The hash algorithm SHA-256 MUST be supported by all the entities to generate and validate the digests in the IETF
SD-JWT VC and ISO mdoc."

### 2.4 HAIP answers to the questions the plan asked

| Question | Answer from HAIP 1.0 final |
|---|---|
| Required client-id prefix | **`x509_hash`** (MUST for signed requests). `x509_san_dns` is not mentioned by HAIP at all. |
| Required `alg` / `enc` | JWE `alg=ECDH-ES` with P-256 keys; Verifiers MUST support **and list** `enc` `A128GCM` **and** `A256GCM`. Signatures: at minimum ES256 / COSE -7 or -9. |
| `request_uri_method` | **Not addressed.** HAIP only requires JAR "with the request_uri parameter". So `request_uri_method` stays OPTIONAL per OpenID4VP; GET is the default. |
| `deviceMac` allowed? | **Not addressed.** §7 only lists `deviceSignature` for Verifiers. See §6.4 below for why `deviceMac` cannot work in the redirect flow anyway. |
| Recommended invocation scheme | `haip-vp://` ("MAY be supported", IANA status Permanent). The §9.3.1 examples have wallets "register for the haip-vp:// custom scheme". |
| Response mode | `direct_post.jwt` (MUST) for redirect flows; `dc_api.jwt` for DC API. |
| Same vs cross device | Same-device MUST be supported; Verifiers are RECOMMENDED to use only same-device unless they do not rely on session binding. |

---

## 3. RFC 9901: Selective Disclosure for JWTs (SD-JWT)

### 3.1 Serialisation (§4)

> <Issuer-signed JWT>~<D.1>~<D.2>~...~<D.N>~

> In the case that there is no Key Binding JWT, the last element MUST be an empty string and the last separating tilde
> character MUST NOT be omitted.

> <Issuer-signed JWT>~<D.1>~<D.2>~...~<D.N>~<KB-JWT>

> A Verifier that expects an SD-JWT MUST verify that the final tilde-separated component is empty. A Verifier that
> expects an SD-JWT+KB MUST verify that its final tilde-separated component is a valid KB-JWT.

> A Holder MUST NOT send a Disclosure that was not included in the issued SD-JWT or send a Disclosure more than once.

### 3.2 Issuer-signed JWT (§4.1, §4.1.1)

> An SD-JWT has a JWT component that MUST be signed using the Issuer's private key. It MUST NOT use the none
> algorithm.

> 7. The payload MUST NOT contain the claims _sd or ... except for the purpose of conveying digests as described in
> Sections 4.2.4.1 and 4.2.4.2, respectively.
> The same digest value MUST NOT appear more than once in the SD-JWT.

> The claim _sd_alg indicates the hash algorithm used by the Issuer to generate the digests as described in Section
> 4.2. When used, this claim MUST appear at the top level of the SD-JWT payload. It MUST NOT be used in any object
> nested within the payload. If the _sd_alg claim is not present at the top level, a default value of sha-256 MUST be
> used.

> This claim value is a case-sensitive string with the hash algorithm identifier. The hash algorithm identifier MUST
> be a hash algorithm value from the "Hash Name String" column in the "Named Information Hash Algorithm Registry"
> [Hash.Algs] [...]. To promote interoperability, implementations MUST support the sha-256 hash algorithm.

`_sd_alg` values are lower-case IANA names: `sha-256`, `sha-384`, `sha-512`. (mdoc uses upper-case `SHA-256`; see
§6.2.)

### 3.3 Disclosures (§4.2.1, §4.2.2, §4.2.3)

Object property:

> Create a JSON array of three elements in the following order: 1. A salt value. MUST be a string. [...] 2. The claim
> name, or key, as it would be used in a regular JWT payload. It MUST be a string and MUST NOT be _sd, ..., or a claim
> name existing in the object as a permanently disclosed claim. 3. The claim value [...]
> base64url-encode the UTF-8 byte sequence of the JSON array. This string is the Disclosure.

Array element:

> The array MUST contain two elements in this order: 1. The salt value as described in Section 4.2.1. 2. The array
> element that is to be hidden.

Hashing:

> The digest MUST be computed over the US-ASCII bytes of the base64url-encoded value that is the Disclosure. [...] The
> bytes of the digest MUST then be base64url encoded.

Example: the digest of
`WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0` is
`X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0` (§4.2.3).

### 3.4 `_sd` and `...` (§4.2.4.1, §4.2.4.2)

> Digests of Disclosures for object properties are added to an array under the new key _sd in the object. The _sd key
> MUST refer to an array of strings, each string being a digest of a Disclosure or a decoy digest [...]. An _sd key can
> be present at any level of the JSON object hierarchy [...].

> Digests of Disclosures for array elements are added to the array in the same position as the original claim value
> in the array. For each digest, an object of the form {"...": "<digest>"} is added to the array. The key MUST always
> be the string ... (three dots). [...] There MUST NOT be any other keys in the object.

### 3.5 Key Binding JWT (§4.3, §4.3.1)

> in the JOSE header, typ: REQUIRED. MUST be kb+jwt [...]. alg: REQUIRED. [...] It MUST NOT be "none".
> in the JWT payload, iat: REQUIRED. [...] aud: REQUIRED. The value MUST be a single string that identifies the
> intended receiver of the Key Binding JWT. [...] "nonce": REQUIRED. [...] The value type of this claim MUST be a
> string. [...] sd_hash: REQUIRED. The base64url-encoded hash value over the Issuer-signed JWT and the selected
> Disclosures as defined below.

**Exact `sd_hash` input (§4.3.1):**

> The sd_hash value MUST be computed over the US-ASCII bytes of the encoded SD-JWT, i.e., the Issuer-signed JWT, a
> tilde character, and zero or more Disclosures selected for presentation to the Verifier, each followed by a tilde
> character:
> `<Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure N>~`
> The bytes of the digest MUST then be base64url encoded.
> The same hash algorithm as for the Disclosures MUST be used (defined by the _sd_alg element in the Issuer-signed JWT
> or the default value, as defined in Section 4.1.1).

So `sd_hash = base64url(H(ASCII(everything up to and including the last "~" before the KB-JWT)))` with
`H = _sd_alg` (not always SHA-256). Vectors: `rfc9901-5.2-sd-jwt-kb.txt` (`sd_hash`
`0_Af-2B-EhLWX5ydh_w2xzwmO6iM66B_2QCEanI4fUY`), `rfc9901-A.3-sd-jwt-vc-kb.txt` (`sd_hash`
`PjMYfM07VbJdMxLIluvRNb88JFljSX4n-G43Uc_BSRM`).

### 3.6 Verification (§7.1, §7.3)

§7.1 (verbatim, abridged to the numbered checks):

> 2. Validate the Issuer-signed JWT: a. Ensure that the used signing algorithm was deemed secure for the application.
> [...] The "none" algorithm MUST NOT be accepted. b. Validate the signature over the Issuer-signed JWT per Section 5.2
> of [RFC7515]. c. Validate the Issuer and that the signing key belongs to this Issuer. d. Check that the _sd_alg
> claim value is understood and the hash algorithm is deemed secure according to the Holder or Verifier's policy.
>
> 3. [...] c. (**) For each embedded digest found in the previous step: i. Compare the value with the digests
> calculated previously and find the matching Disclosure. If no such Disclosure can be found, the digest MUST be
> ignored. ii. If the digest was found in an object's _sd key: 1. If the contents of the respective Disclosure is not
> a JSON array of three elements (salt, claim name, claim value), the SD-JWT MUST be rejected. 2. If the claim name is
> _sd or ..., the SD-JWT MUST be rejected. 3. If the claim name already exists at the level of the _sd key, the SD-JWT
> MUST be rejected. 4. Insert, at the level of the _sd key, a new claim using the claim name and claim value from the
> Disclosure. 5. Recursively process the value using the steps described in (*) and (**). iii. If the digest was found
> in an array element: 1. If the contents of the respective Disclosure is not a JSON array of two elements (salt,
> value), the SD-JWT MUST be rejected. 2. Replace the array element with the value from the Disclosure. 3. Recursively
> process the value using the steps described in (*) and (**). d. Remove all array elements for which the digest was
> not found in the previous step. e. Remove all _sd keys and their contents from the Issuer-signed JWT payload. [...]
> f. Remove the claim _sd_alg from the SD-JWT payload.
>
> 4. If any digest value is encountered more than once in the Issuer-signed JWT payload (directly or recursively via
> other Disclosures), the SD-JWT MUST be rejected.
> 5. If any Disclosure was not referenced by digest value in the Issuer-signed JWT (directly or recursively via other
> Disclosures), the SD-JWT MUST be rejected.
> 6. Check that the SD-JWT is valid using claims such as nbf, exp, and aud in the processed payload, if present. [...]

§7.3 step 5 (KB-JWT):

> a. Determine the public key for the Holder from the SD-JWT (see Section 4.1.2). b. Ensure that a signing algorithm
> was used that was deemed secure for the application. [...] c. Validate the signature over the Key Binding JWT per
> Section 5.2 of [RFC7515]. d. Check that the typ of the Key Binding JWT is kb+jwt (see Section 4.3). e. Check that the
> creation time of the Key Binding JWT, as determined by the iat claim, is within an acceptable window. f. Determine
> that the Key Binding JWT is bound to the current transaction and was created for this Verifier (replay detection)
> by validating nonce and aud claims. g. Calculate the digest over the Issuer-signed JWT and Disclosures as defined in
> Section 4.3.1 and verify that it matches the value of the sd_hash claim in the Key Binding JWT. h. Check that the Key
> Binding JWT is a valid JWT in all other respects, per [RFC7519] and [RFC8725].

§7.3 step 1: "This decision MUST NOT be based on whether or not a Key Binding JWT is provided by the Holder."

### 3.7 `typ` values

- RFC 9901 itself only RECOMMENDS explicit typing (§9.11, `application/example+sd-jwt` → `typ` `example+sd-jwt`). Its
  §5 example uses `typ` `example+sd-jwt`, which a `dc+sd-jwt` verifier must **reject**.
- KB-JWT: `kb+jwt`.
- SD-JWT VC: `dc+sd-jwt` (see §4).

---

## 4. SD-JWT VC (`draft-ietf-oauth-sd-jwt-vc-19`)

§2.1: "SD-JWT VCs compliant with this specification MUST use the media type application/dc+sd-jwt [...]".

§2.2.1:

> The Issuer MUST include the typ header parameter in the SD-JWT. The typ value MUST use dc+sd-jwt.

**`vc+sd-jwt`:** the transition note allowing `vc+sd-jwt` was **removed** in draft-19 (change log, AD review: "Remove:
'Note that this draft used vc+sd-jwt as the value of the typ header from its inception in July 2023 until November
2024 [...] both vc+sd-jwt and dc+sd-jwt should be accepted [...] for a reasonable transitional period.'"). Keep
`allowLegacyVcSdJwtTyp` default **off**.

§2.2.2.1:

> This specification defines the new JWT claim vct (for verifiable credential type). Its value MUST be a
> case-sensitive string serving as an identifier for the type of the SD-JWT VC.

§2.2.2.2 (**draft-19 only**, not in the -13 that HAIP pins): `aka_vcts`:

> Its value MUST be a non-empty array of case-sensitive strings, each identifying an additional type of the SD-JWT VC.
> [...] An SD-JWT VC containing the aka_vcts claim is a Verifiable Digital Credential of the type identified by the vct
> claim and, additionally, of each of the types identified by the values in the aka_vcts claim.

§2.2.2.3 (claims that MUST NOT be selectively disclosed):

> - iss: OPTIONAL. As defined in Section 4.1.1 of [RFC7519] this claim explicitly indicates the Issuer of the
>   Verifiable Digital Credential when it is not conveyed by other means (e.g., the subject of the end-entity
>   certificate of an x5c header).
> - nbf: OPTIONAL. [...]
> - exp: OPTIONAL. [...]
> - cnf: OPTIONAL unless cryptographic Key Binding is to be supported, in which case it is REQUIRED. [...] For proof of
>   cryptographic Key Binding, the KB-JWT in the presentation of the SD-JWT MUST be secured by the key identified in
>   this claim.
> - vct: REQUIRED. [...]
> - vct#integrity: OPTIONAL. [...]
> - aka_vcts: OPTIONAL. [...]
> - status: OPTIONAL. The information on how to read the status of the Verifiable Credential. See
>   [I-D.ietf-oauth-status-list] for more information. When the status claim is present and using the status_list
>   mechanism, the associated Status List Token MUST be in JWT format.

Claims that MAY be selectively disclosed: `sub`, **`iat`**.

§2.4:

> If status is present in the verified payload of the SD-JWT, the status SHOULD be checked. Verifier policy decides
> whether to reject or accept a presentation of a SD-JWT VC based on the status of the Verifiable Digital Credential.

§2.5 (Inline X.509):

> When the protected header of the Issuer-signed JWT contains the x5c parameter, the recipient uses the public key
> from the end-entity certificate of the certificates from that x5c parameter and validates the X.509 certificate
> chain accordingly. In this case, the Issuer of the Verifiable Digital Credential is the subject of the end-entity
> certificate.

> If a recipient cannot validate that the public verification key corresponds to the Issuer of the Issuer-signed JWT
> using a permitted key discovery and validation mechanism, the SD-JWT VC MUST be rejected.

(HAIP §6.1.1 references "section 3.5 of [I-D.ietf-oauth-sd-jwt-vc]" for x5c; in draft-19 this is §2.5. The section was
renumbered between drafts.)

Vectors: `sd-jwt-vc-19-2.3.2-presentation-kb.txt` (typ `dc+sd-jwt`, KB `aud` `https://example.com/verifier`) and
`sd-jwt-vc-19-2.3.2-presentation-no-kb.txt` (same credential, no KB-JWT: use as the "missing holder binding"
negative). Issuer key: same as RFC 9901 A.5 (`rfc9901-A.5-issuer-public-key.jwk.json`; draft-19 Figure 14 uses the
same `x`). **No official vector carries an `x5c` header**; trust-chain tests must use TestWallet-generated credentials.

---

## 5. Token Status List (`draft-ietf-oauth-status-list-21`)

### 5.1 Referenced token claim (§6.2, §6.3)

JOSE:

> status: REQUIRED. The status (status) claim MUST specify a JSON Object that contains at least one reference to a
> status mechanism.
> - status_list: REQUIRED when the status mechanism defined in this specification is used. It MUST specify a JSON
>   Object that contains a reference to a Status List Token. It MUST at least contain the following claims:
>   - idx: REQUIRED. The idx (index) claim MUST specify a non-negative Integer that represents the index to check for
>     status information in the Status List for the current Referenced Token.
>   - uri: REQUIRED. The uri (URI) claim MUST specify a String value that identifies the Status List Token containing
>     the status information for the Referenced Token. The value of uri MUST be a URI conforming to [RFC3986].

```json
{ "status": { "status_list": { "idx": 0, "uri": "https://example.com/statuslists/1" } } }
```

COSE (incl. ISO mdoc): the same `status_list` with `idx` (uint) and `uri` (tstr), as a CBOR map keyed by text
strings.

### 5.2 Status List Token in JWT format (§5.1)

> typ: REQUIRED. The JWT type MUST be statuslist+jwt.
> sub: REQUIRED. [...] The sub (subject) claim MUST specify the URI of the Status List Token. The value MUST be equal
> to that of the uri claim contained in the status_list claim of the Referenced Token.
> iat: REQUIRED. [...]
> exp: RECOMMENDED. [...]
> ttl: RECOMMENDED. As generally defined in [RFC7519]. The ttl (time to live) claim, if present, MUST specify the
> maximum amount of time, in seconds, that the Status List Token can be cached by a consumer before a fresh copy SHOULD
> be retrieved. The value of the claim MUST be a positive number encoded in JSON as a number.
> status_list: REQUIRED. The status_list (status list) claim MUST specify the Status List conforming to the structure
> defined in Section 4.2.

> The JWT MUST be secured using a cryptographic signature or MAC algorithm. Relying Parties MUST reject JWTs with an
> invalid signature.

### 5.3 Status List Token in CWT format (§5.2) — used by mdoc

> The Status List Token MUST NOT be tagged with the CWT tag defined in Section 6 of [RFC8392]. The COSE message MUST
> either be the tagged COSE_Sign1_Tagged (18) or COSE_Mac0_Tagged (17) as defined in Section 2 of [RFC9052].
> 16 (type): REQUIRED. The type of the CWT MUST be application/statuslist+cwt or the registered CoAP Content-Format ID
> [...]
> 2 (subject): REQUIRED. [...] 6 (issued at): REQUIRED. [...] 4 (expiration time): RECOMMENDED. [...] 65534 (time to
> live): RECOMMENDED. [...] 65533 (status list): REQUIRED.

### 5.4 Status List structure, `bits`, compression (§4.1, §4.2, §4.3)

> 1. The Status Issuer MUST define a number of bits (bits) of either 1,2,4 or 8 [...]
> 3. [...] Each index identifies a contiguous block of bits in the byte array, with the blocks being packed into bytes
> from the least significant bit ("0") to the most significant bit ("7"). [...]
> 4. The Status Issuer compresses the byte array using DEFLATE [RFC1951] with the ZLIB [RFC1950] data format.

JSON:

> bits: REQUIRED. JSON Integer specifying the number of bits per Referenced Token in the compressed byte array (lst).
> The allowed values for bits are 1, 2, 4, and 8.
> lst: REQUIRED. JSON String that contains the status values for all the Referenced Tokens it conveys statuses for. The
> value MUST be the base64url-encoded compressed byte array as specified in Section 4.1.
> aggregation_uri: OPTIONAL. [...]

CBOR: `StatusList = { bits: 1 / 2 / 4 / 8, lst: bstr, ? aggregation_uri: tstr }`.

Bit extraction (our reading of §4.1, verified against all Appendix C vectors):
`status(i) = (byte[i * bits / 8] >> ((i % (8 / bits)) * bits)) & ((1 << bits) - 1)`.

### 5.5 Status types (§7.1)

> 0x00 - "VALID" [...] 0x01 - "INVALID" - The status of the Referenced Token is revoked, annulled, taken back,
> recalled or cancelled. 0x02 - "SUSPENDED" [...] The Status Type value 0x03 and Status Type values in the range 0x0C
> until 0x0F are permanently reserved as application specific. [...] All other Status Type values are reserved for
> future registration.

### 5.6 Fetching and validation (§8.1–§8.3)

Media types: `application/statuslist+jwt`, `application/statuslist+cwt` (request `Accept` and response
`Content-Type`).

> A response MAY also choose to redirect the client to another URI using an HTTP status code in the 3xx range, which
> clients SHOULD follow.

> If caching-related HTTP headers are present in the HTTP response, Relying Parties MUST prioritize the exp and ttl
> claims within the Status List Token over the HTTP headers for determining caching behavior.

§8.3:

> 4. All existing claims in the Status List Token MUST be checked according to the rules in Section 5.1 and Section
> 5.2 a. The subject claim (sub or 2) of the Status List Token MUST be equal to the uri claim in the status_list object
> of the Referenced Token b. [...] it SHOULD check the issued at claim (iat or 6) c. If the expiration time is defined
> (exp or 4), it MUST be checked if the Status List Token is expired d. If the Relying Party is using a system for
> caching the Status List Token, it SHOULD check the ttl claim of the Status List Token and retrieve a fresh copy if
> (time status was resolved + ttl < current time)
> 5. Decompress the Status List with a decompressor that is compatible with DEFLATE [RFC1951] and ZLIB [RFC1950]
> 6. Retrieve the status value of the index specified in the Referenced Token as described in Section 4. If the
> provided index is out of bounds of the Status List, no statement about the status of the Referenced Token can be
> made and the Referenced Token MUST be rejected.

Also: "The processing rules for Referenced Tokens (such as JWT or CWT) MUST precede any evaluation of a Referenced
Token's status. [...] If the validation procedures for the Referenced Token determine it is invalid, further
procedures regarding Status List MUST NOT be performed, e.g. fetching a Status List Token".

Vectors: `vectors/status-list/` (Appendix C 1/2/4/8-bit lists of 2^20 entries with every non-zero index, JSON `lst`
and CBOR hex; §4.1 small examples; §8.2 example token). **The §8.2 example token's signing key is not published in the
draft, so its signature cannot be verified**; use it for parsing only.

---

## 6. ISO/IEC 18013-5 structures used by OpenID4VP

**Source and licence.** The final ISO/IEC 18013-5:2021 text is paywalled and was **not read**. The facts below were
taken from the public 2nd-edition working draft ("Working Draft ISO_IEC_18013-5_second-edition_CD_ballot_resolution_v4",
dated 2025-09-14, https://github.com/ISOWG10/ISO-18013/tree/main/Working%20Documents). That repository has no
licence, so this section **does not reproduce its text**. It records only the structure facts later tasks need
(names, types, keys, tags, algorithm identifiers), with the draft's clause numbers. Read the draft itself for the full
definitions. **UNVERIFIED (all of §6):** that the 2021 final text is identical. The status/revocation part exists
**only** in the 2nd edition, whose mechanisms HAIP §5.3.1 requires.

Notation: "map" means a CBOR map with **text-string keys** exactly as written (case-sensitive). Every map in these
structures also allows further text-string keys reserved for future use: ignore unknown keys and do not reject them.
CBOR maps are unordered. The key order given is the draft's presentation order; nothing depends on it except
deterministic encoding when *we* produce structures (TestWallet).

### 6.1 DeviceResponse, Document, IssuerSigned (draft §10.3)

- **DeviceResponse** (map):
  - `"version"` tstr, value `"1.0"`
  - optional `"documents"`: array of Document
  - optional `"zkDocuments"`, `"encryptedDocuments"`: new in the 2nd edition; Helix does not support them and must
    reject them
  - optional `"documentErrors"`
  - `"status"`: uint, on the DeviceResponse itself, **not** on Document. `0` is OK.
- **Document** (map):
  - `"docType"` tstr
  - `"issuerSigned"` IssuerSigned
  - `"deviceSigned"` DeviceSigned
  - optional `"errors"`
- **IssuerSigned** (map):
  - `"issuerAuth"`: COSE_Sign1
  - optional `"nameSpaces"`: map NameSpace (tstr) → non-empty array of IssuerSignedItemBytes
- **IssuerSignedItemBytes** = CBOR tag **24** wrapping a bstr that contains the CBOR encoding of IssuerSignedItem.
- **IssuerSignedItem** (map):
  - `"digestID"` uint (< 2^31)
  - `"random"` bstr (≥ 16 bytes)
  - `"elementIdentifier"` tstr
  - `"elementValue"` any
- **DeviceSigned** (map):
  - `"nameSpaces"`: DeviceNameSpacesBytes, a tag-24 bstr of a map NameSpace → map(elementIdentifier → value); may be
    an empty map
  - `"deviceAuth"`: DeviceAuth
- **DeviceAuth** (map): exactly one of `"deviceSignature"` (COSE_Sign1) or `"deviceMac"` (COSE_Mac0).

### 6.2 IssuerAuth and the MSO (draft §12.3.4, §12.3.5)

- **IssuerAuth** = COSE_Sign1 whose payload is MobileSecurityObjectBytes: tag **24** wrapping a bstr of the CBOR
  MobileSecurityObject. When decoding the payload, expect the tag-24 wrapper.
- **MobileSecurityObject** (map):
  - `"version"` tstr (`"1.0"`)
  - `"digestAlgorithm"` tstr
  - `"valueDigests"`: map NameSpace → map(DigestID uint → Digest bstr)
  - `"deviceKeyInfo"` DeviceKeyInfo
  - `"docType"` tstr
  - `"validityInfo"` ValidityInfo
  - optional `"status"` Status (2nd edition)
- **DeviceKeyInfo** (map):
  - `"deviceKey"`: COSE_Key
  - optional `"keyAuthorizations"`: map with optional `"nameSpaces"` (array of tstr) and `"dataElements"` (map
    NameSpace → array of elementIdentifier)
  - optional `"keyInfo"`
- **ValidityInfo** (map): `"signed"`, `"validFrom"`, `"validUntil"`, optional `"expectedUpdate"`. All are `tdate`
  (CBOR tag 0 date-time string). Draft constraints:
  - validFrom ≥ signed
  - validUntil > validFrom
  - validUntil ≤ the leaf certificate's notAfter
- **digestAlgorithm** identifiers (draft Table 16): `"SHA-256"`, `"SHA-384"`, `"SHA-512"`. These are upper-case,
  unlike SD-JWT's `sha-256`.
- **Digest input:** the complete IssuerSignedItemBytes, including the tag-24 wrapper, exactly as received. Do not
  re-encode. One digest algorithm per MSO.
- **x5chain:** COSE header label **33** (RFC 9360). The draft requires it in the **unprotected** header. A reader
  should also accept it in the protected header (2nd-edition recommendation). `x5t` (label 34) may be present in the
  protected header.
- **IssuerAuth signature algorithms:** the draft lists ES256 / ES384 / ES512 / EdDSA, including brainpool curves.
  It says readers shall support all of them. The Helix constraints allow ES256/384/512 only; this is a recorded
  deviation.

### 6.3 DeviceAuthentication and the transcript (draft §12.4.4, §12.7.1)

- **DeviceAuthentication** = array of 4, in this order:
  1. tstr `"DeviceAuthentication"`
  2. SessionTranscript
  3. DocType (tstr, same as the Document)
  4. DeviceNameSpacesBytes (the tag-24 bstr, same as in the Document)
- **DeviceAuthenticationBytes** = tag **24** wrapping a bstr of the CBOR DeviceAuthentication.
- **DeviceSignature** = COSE_Sign1 with a **null payload** (detached). The detached content is
  DeviceAuthenticationBytes. Sig_structure per RFC 9052 §4.4: `["Signature1", protected, h'', DeviceAuthenticationBytes]`.
  Verify with MSO `deviceKeyInfo.deviceKey`.
- **SessionTranscript** (ISO generic form) = array of 3: [DeviceEngagementBytes or null, reader-key bytes or null,
  Handover]. For OpenID4VP redirects it is `[null, null, OpenID4VPHandover]` (§1.9, normative per OpenID4VP Annex
  B.2.6.1).
- Draft §12.4.4: device-signed data elements in DeviceNameSpaces are only valid if authorised by `keyAuthorizations`
  in the MSO. The reader must check this. Helix: reject non-empty DeviceNameSpaces (simplest compliant choice).

### 6.4 `deviceMac` (draft §12.4.5)

Per draft §12.4.5, the MAC key (EMacKey) is derived by ECDH between the mdoc device key and the **mdoc reader's
ephemeral public key**, then HKDF-SHA-256 with salt = SHA-256(SessionTranscriptBytes) and info `"EMacKey"`.

**Conclusion (our reading):** OpenID4VP redirect flows set the reader-key element of SessionTranscript to `null`, and
OpenID4VP 1.0 defines no reader ephemeral key for MAC derivation in that flow. HAIP §7 lists only `deviceSignature`
for Verifiers. So **reject `deviceMac`** (`HOLDER_BINDING_INVALID`) and do not advertise HMAC identifiers in
`deviceauth_alg_values`. **UNVERIFIED:** whether any wallet derives `EMacKey` from the response-encryption key in
redirect flows. Nothing in the texts read says so.

### 6.5 MSO status (draft §12.3.6) — differs from SD-JWT

- **MSO `"status"`** (map) has an optional `"identifier_list"` (IdentifierListInfo) and/or an optional
  `"status_list"` (StatusListInfo).
- **StatusListInfo** = the Token Status List `status_list` structure:
  - `"idx"` uint
  - `"uri"` tstr
  - optional `"certificate"` bstr: a trust point for the list's signer (draft §12.3.6.2)
- **IdentifierListInfo** (map):
  - `"id"` bstr (unique per MSO)
  - `"uri"` tstr
  - optional `"certificate"` bstr
- **MSO revocation list token** (both mechanisms):
  - a Token Status List **CWT** (COSE_Sign1)
  - `exp` required, `ttl` optional
  - **x5chain in the protected header**
  - signature algorithms as for IssuerAuth
- **Status list mechanism:**
  - content type `application/statuslist+cwt`
  - `bits` **= 1**
- **Identifier list mechanism:**
  - type `application/identifierlist+cwt`
  - no StatusList claim
  - claim key **65530** holds IdentifierList: a map with `"identifiers"` (map: bstr Identifier → map) and an optional
    `"aggregation_uri"` (tstr)
  - an MSO is revoked iff its `id` is present in `"identifiers"`
- **Certificate trust:** if `"certificate"` is absent, the list's x5chain top certificate must be signed by the
  certificate that signed the MSO x5chain (the IACA, for mDL).
- **Helix implementation (controller ruling, Task 19 fix round 1):** stricter than "same root". Both chains are the
  PKIX-validated paths and anchors, never the presented x5chain (which can be padded with another issuer's anchor).
  Without `"certificate"` the list is accepted only when signed by the MSO signer itself or chained to the MSO signer's
  own issuing CA; a sibling issuing CA under the same root is refused. With `"certificate"` the list must chain to it
  and still to the provider's trust anchors (`MdocStatusListSigner`).

ARF Annex 2 (v3.0.0), VCR_12:

> If a Relying Party decides it needs to be able to verify the revocation status of PIDs or attestations, it SHALL
> support both the Attestation Status List mechanism and the Attestation Revocation List mechanism specified per
> VCR_11.
>
> *Note: Per VCR_13, it is recommended but not mandatory for a Relying Party to verify whether a PID or attestation is
> revoked.*

ARF Annex 2 (v3.0.0), VCR_01 (ISO/IEC 18013-5 PIDs; VCR_01b is the SD-JWT VC equivalent) allows a PID Provider to:

> Only issue short-lived attestations having a validity period of 24 hours or less, such that revocation will never be
> necessary

Such PIDs carry **no** status at all.

### 6.6 ISO test vectors

ISO/IEC 18013-5 Annex D test vectors are ISO copyright and are **not** copied. None — generated by TestWallet.

---

## 7. ARF PID Rulebook (Annex 3.01, v1.7, 17 July 2026)

Licence note: the ARF repository is CC BY 4.0, but the rulebooks catalog repository that now holds the PID Rulebook
has **no licence file**. We therefore record identifiers (facts) only and copy no example from it.

### 7.1 Type identifiers

ARF Annex 2 (v3.0.0), PID_04 / PID_05 / PID_14:

> PID Providers SHALL use "eu.europa.ec.eudi.pid.1" as the attestation type for ISO/IEC 18013-5-compliant PIDs.

> When issuing a PID compliant with [ISO/IEC 18013-5], a PID Provider SHALL use the value "eu.europa.ec.eudi.pid.1" for
> the identifier of the namespace for the PID attributes [...]

> A PID Provider issuing [SD-JWT VC]-compliant PIDs SHALL include the vct claim in their PIDs, where the vct claim
> SHALL be a URN within the `urn:eudi:pid:` namespace. The type indicated by the vct claim SHALL be `urn:eudi:pid:1`
> for the type defined in this document or a domestic type that extends it.

PID_06: domestic mdoc namespaces append the country code, e.g. "eu.europa.ec.eudi.pid.de.1". Rulebook §4.2: "As a
convention, all PIDs must use types in the namespace "urn:eudi:pid:"." RFC 9901 A.3 uses `urn:eudi:pid:de:1` as a
domestic example.

| | Value |
|---|---|
| mdoc doctype | `eu.europa.ec.eudi.pid.1` |
| mdoc namespace | `eu.europa.ec.eudi.pid.1` (domestic extras: `eu.europa.ec.eudi.pid.<cc>[.<n>]`) |
| SD-JWT VC `vct` | `urn:eudi:pid:1` (base); domestic types `urn:eudi:pid:<...>` that extend it |

**Consequence:** a German PID may carry `vct = urn:eudi:pid:de:1`. Matching only `urn:eudi:pid:1` would reject it
unless the wallet also sends `aka_vcts` (draft-19 only) or the admin lists the domestic vct. Keep `pid.sdJwtVcts` a
list and accept a credential when `vct` **or** an `aka_vcts` entry is in that list.

### 7.2 Claim identifiers (mandatory and optional), both encodings

| Data identifier (CIR 2024/2977) | mdoc element identifier (ns `eu.europa.ec.eudi.pid.1`) | mdoc encoding | SD-JWT VC claim | SD-JWT VC encoding |
|---|---|---|---|---|
| family_name (M) | `family_name` | tstr | `family_name` | string |
| given_name (M) | `given_name` | tstr | `given_name` | string |
| birth_date (M) | `birth_date` | full-date = #6.1004(tstr) | `birthdate` | string YYYY-MM-DD |
| birth_place (M) | `place_of_birth` | map `{? "country", ? "region", ? "locality"}` (≥1) | `place_of_birth` | object (country/region/locality, ≥1) |
| nationality (M) | `nationality` | array of alpha-2 tstr | `nationalities` | array of strings |
| portrait (M, from +24 months) | `portrait` | bstr | `picture` | data URL (JPEG) |
| resident_address | `resident_address` | tstr | `address.formatted` | string |
| resident_country | `resident_country` | tstr | `address.country` | string |
| resident_state | `resident_state` | tstr | `address.region` | string |
| resident_city | `resident_city` | tstr | `address.locality` | string |
| resident_postal_code | `resident_postal_code` | tstr | `address.postal_code` | string |
| resident_street | `resident_street` | tstr | `address.street_address` | string |
| resident_house_number | (not listed for mdoc) | | `address.house_number` | string |
| personal_administrative_number | `personal_administrative_number` | tstr | `personal_administrative_number` | string |
| family_name_birth | `family_name_birth` | tstr | `birth_family_name` | string |
| given_name_birth | `given_name_birth` | tstr | `birth_given_name` | string |
| sex | `sex` | uint (0,1,2,3,4,5,6,9) | `sex` | number |
| email_address | `email_address` | tstr | `email` | string |
| mobile_phone_number | `mobile_phone_number` | tstr | `phone_number` | string |
| expiry_date | `expiry_date` | tdate or full-date | `date_of_expiry` | string YYYY-MM-DD |
| issuing_authority (M metadata) | `issuing_authority` | tstr | `issuing_authority` | string |
| issuing_country (M metadata) | `issuing_country` | tstr | `issuing_country` | string |
| document_number | `document_number` | tstr | `document_number` | string |
| issuing_jurisdiction | `issuing_jurisdiction` | tstr | `issuing_jurisdiction` | string |
| issuance_date | `issuance_date` | tdate or full-date | `date_of_issuance` | string YYYY-MM-DD |
| trust_anchor | `trust_anchor` | tstr | `trust_anchor` | string |
| attestation_legal_category | `attestation_legal_category` | tstr | `attestation_legal_category` | string |

(M) = mandatory per CIR 2024/2977. Note from the Rulebook §2.1: "a Relying Party is not required to request all
mandatory attributes. Also, a User is allowed to refuse to present a mandatory attribute".

**Age attributes:** Rulebook v1.1 change log: "Age verification attributes removed, following CIR 2024/2977." There
is **no** `age_over_18` in the PID any more.

SD-JWT DCQL paths for nested claims: `["address", "street_address"]`, `["place_of_birth", "locality"]`,
`["nationalities"]` (whole array) or `["nationalities", null]`.

### 7.3 Dates

Rulebook §3.1.2: `full-date = #6.1004(tstr)` (RFC 8943); `tdate` is RFC 3339 date-time with "Z", no fractions.
SD-JWT uses plain `YYYY-MM-DD` strings. Normalise both to ISO-8601 `YYYY-MM-DD`.

---

## 8. Quick reference for later tasks

| Item | Value | Source |
|---|---|---|
| Request object `typ` | `oauth-authz-req+jwt` | OpenID4VP §5 |
| Request URI response content type | `application/oauth-authz-req+jwt` | §5.10.1 |
| Request object `aud` | `https://self-issued.me/v2` (static discovery) | §5.8 |
| `client_id` (HAIP) | `x509_hash:` + base64url(SHA-256(DER leaf)) | HAIP §5, OpenID4VP §5.9.3 |
| `client_id` (optional) | `x509_san_dns:` + dNSName SAN of leaf; `response_uri` FQDN must equal it | §5.9.3, §8.2 |
| `x5c` in request object | leaf first; MUST NOT contain the trust anchor; leaf MUST NOT be self-signed | HAIP §5 |
| `response_type` | `vp_token` | HAIP §5 |
| `response_mode` | `direct_post.jwt` (HAIP); `direct_post` dev only | HAIP §5.1 |
| `request_uri_method` | optional `get` / `post`; HAIP silent; omit (GET) by default | §5.1 |
| `client_metadata` fields | `jwks` (each key with `kid`, `alg`), `encrypted_response_enc_values_supported`, `vp_formats_supported` | §5.1, §8.3, §11.1 |
| JWE | `alg=ECDH-ES` (P-256), `enc ∈ {A128GCM, A256GCM}`, header `kid` = JWK `kid`; unsigned encrypted JWT; payload has `vp_token` (+ `state`) top level | HAIP §5, OpenID4VP §8.3 |
| `vp_formats_supported` keys | `dc+sd-jwt`: `sd-jwt_alg_values`, `kb-jwt_alg_values`; `mso_mdoc`: `issuerauth_alg_values`, `deviceauth_alg_values` | B.3.4, B.2.2 |
| DCQL `meta` | `vct_values` (array) / `doctype_value` (string) | B.3.5, B.2.3 |
| mdoc claim path | `[namespace, elementIdentifier]` | §7.2 |
| `vp_token` | JSON object: DCQL id → array of presentations | §8.1 |
| mdoc presentation | base64url(DeviceResponse CBOR); one DeviceResponse per mdoc | B.2.5, HAIP §5.3.1 |
| Response endpoint success | HTTP 200, `application/json`, JSON object; `{"redirect_uri": ...}` for same-device | §8.2, HAIP §5.1 |
| SessionTranscript | `[null, null, ["OpenID4VPHandover", sha256(CBOR([client_id, nonce, jwk_thumbprint_bstr / null, response_uri]))]]` | B.2.6.1 |
| DeviceAuthentication | `["DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes]`, signed detached as `#6.24(bstr .cbor ...)` | ISO draft §12.4 |
| `deviceMac` | reject | §6.4 of these notes |
| SD-JWT VC `typ` | `dc+sd-jwt` (`vc+sd-jwt` removed in draft-19) | SD-JWT VC §2.2.1 |
| KB-JWT `typ` / claims | `kb+jwt`; `iat`, `aud` (= full client_id), `nonce`, `sd_hash` | RFC 9901 §4.3, OpenID4VP B.3.6 |
| `sd_hash` | base64url(H(ASCII(`<iss-jwt>~<d1>~...~<dN>~`))), H = `_sd_alg` | RFC 9901 §4.3.1 |
| `_sd_alg` | default `sha-256`; lower-case IANA names | RFC 9901 §4.1.1 |
| mdoc `digestAlgorithm` | `SHA-256` / `SHA-384` / `SHA-512` (upper-case) | ISO draft Table 16 |
| Status list (SD-JWT) | JWT, `typ=statuslist+jwt`, `application/statuslist+jwt`, `sub == uri`, `bits ∈ {1,2,4,8}`, zlib, `ttl` seconds | TSL §5.1, §4 |
| Status list (mdoc) | CWT (COSE_Sign1_Tagged 18), `application/statuslist+cwt`, `bits = 1`, x5chain in **protected** header; or identifier list `application/identifierlist+cwt` | ISO draft §12.3.6 |
| PID doctype / namespace | `eu.europa.ec.eudi.pid.1` / `eu.europa.ec.eudi.pid.1` | ARF PID_04, PID_05 |
| PID vct | `urn:eudi:pid:1` + domestic `urn:eudi:pid:*` extending it | ARF PID_14 |
| Invocation scheme | default `haip-vp://` (HAIP, IANA Permanent; EU reference verifier default); also `openid4vp://` (IANA Provisional), `eudi-openid4vp://`, `mdoc-openid4vp://` (EU reference Android wallet registers all four) | HAIP §5.1, A.1.2; OpenID4VP E.8 |
| Wallet error codes | `invalid_request`, `invalid_client`, `access_denied`, `vp_formats_not_supported`, `invalid_request_uri_method`, `invalid_transaction_data`, `wallet_unavailable`, `invalid_scope` | §8.5 |

Invocation evidence (not normative): the EU reference verifier
`eu-digital-identity-wallet/eudi-srv-verifier-endpoint` (Apache-2.0, commit `df07af2f1f`, 2026-10-08) sets
`verifier.authorizationRequestUri=haip-vp://` and `verifier.defaultHttpResponseMode=DirectPostJwt`. The reference
Android wallet `eudi-app-android-wallet-ui` (EUPL-1.2) registers `eudi-openid4vp`, `mdoc-openid4vp`, `openid4vp` and
`haip-vp` in `build-logic/convention/src/main/kotlin/AndroidLibraryConventionPlugin.kt`.

---

## 9. Open points and UNVERIFIED items

1. **UNVERIFIED:** ISO/IEC 18013-5:2021 final text (paywalled). mdoc structure facts come from the public 2nd-edition
   working draft (summarised, not quoted; see §6) and from OpenID4VP Annex B (quoted).
2. **UNVERIFIED:** whether HAIP's pinned SD-JWT VC -13 / TSL -14 differ from -19 / -21 in any verifier-relevant way
   beyond the items flagged (`aka_vcts`, removal of the `vc+sd-jwt` note, section renumbering).
3. **Unspecified by OpenID4VP:** the HTTP status/body of a **rejected** POST to the Response URI.
4. **Unspecified:** an X.509 certificate profile for the access certificate (HAIP: "out of scope"; ARF RPA_02 points
   to ETSI TS 119 475 and ETSI TS 119 411-8, **not read**). Key-usage/EKU checks for the access certificate and for
   PID-provider certificates are therefore **UNVERIFIED**. The TSL draft §10 defines an EKU OID for status-list
   signing certificates (not extracted here).
5. **Not read:** ETSI TS 119 475 (registration certificate / `verifier_info` format). `verifier_info` stays
   config-gated and off.
6. **UNVERIFIED:** whether national wallets accept `x509_san_dns` at all. HAIP only guarantees `x509_hash`.
7. **Not checked in detail:** OpenID4VP Appendix A (DC API, `origin:` audience, B.2.6.2 DC API handover). That is
   Phase 4.
