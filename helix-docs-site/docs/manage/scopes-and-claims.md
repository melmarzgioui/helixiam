# Scopes & claims

A client scope bundles a set of claims — user attributes mapped onto token fields — that a client may request and receive.

## What it is

**Claims** map user attributes (and other data) to fields in issued tokens (ID token, access token, userinfo). A **client scope** groups related claims under a scope name so they can be requested with the OAuth2 `scope` parameter and attached to clients as a unit.

Helix IAM seeds the **WSO2 base OIDC scopes** (such as `openid`, `profile`, `email`, `address`, `phone`) with their standard claims, so common OIDC requests work out of the box.

### Subject claim

The token subject (`sub`) is resolved with a fallback chain:

```
client subject-claim  ?? realm subject-claim  ?? sub
```

A per-client subject-claim override lets one application key users by, say, email or an external ID while others use the default subject. The realm-level setting applies when a client does not override it.

!!! note
    Changing the subject claim changes how downstream applications identify users. Coordinate the change with the relying party — existing user records keyed on the old subject will no longer match.

### Self-registration fields

When [self-registration](../operations/realm-settings.md#registration) is enabled for a realm, the `/register` sign-up form is built from the same realm claim catalogue described above: every claim becomes a form field, and a claim's `mandatory` flag decides whether that field is required to complete sign-up. Add or remove a claim here and the form changes with it — there is no separate registration-form editor.

Subject and verified claims (`sub`, `email`, `email_verified`, `phone_number_verified`, `updated_at`) are handled by the registration flow itself and are never rendered as form inputs. Whatever the user enters for the remaining claims is stored as [user profile attributes](users.md).

Every new realm is seeded with a standard claim set — the global default — in which `given_name` and `family_name` are marked mandatory. Loosen or tighten that default per realm by editing claims on this screen: mark a claim mandatory to require it at sign-up, or add a custom claim to collect an extra field.

## In the console

Client scopes and the realm claim catalogue are managed under **Manage → Applications & clients → Client scopes & claims**. Subject-claim settings appear at both the realm level (here) and on the individual [OIDC client](oidc-clients.md) / [application](applications.md).

1. Open **Manage → Applications & clients → Client scopes & claims**, click **Create**, and name the scope.
2. **Add claims to a scope** — attach claims from the realm catalogue that map user attributes to token fields.
3. **Attach a scope to a client** — assign the scope to an [OIDC client](oidc-clients.md) as default or optional.
4. **Override the subject claim for a client** — set the client's subject-claim to a specific attribute instead of the realm default.
5. **Set the realm subject claim** — define the fallback used when a client has no override.
6. **Shape the self-registration form** — mark a claim mandatory to require it at sign-up, or add a custom claim to collect an extra field; see [Self-registration fields](#self-registration-fields).

!!! tip
    Keep custom claims in their own scope rather than overloading `profile`. Clients then request exactly what they need, and tokens stay small.

## Over the API

Client scopes live under `/admin/realms/{realm}/client-scopes` and the realm claim catalogue under `/admin/realms/{realm}/claims`. The examples below assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

### List client scopes

Each scope reports how many claims it carries (`claimCount`) plus a short `claimPreview`. The WSO2 base OIDC scopes ship seeded.

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/client-scopes"
```
```json
[
  { "realmId": "acme", "scopeId": "66bf581b-022d-4f09-8250-d29847cc1963", "name": "OpenID",  "description": "OpenID claims",  "claimCount": 1,  "claimPreview": ["Subject identifier"] },
  { "realmId": "acme", "scopeId": "2dfa6fe0-1765-4cfe-9f99-55ae5c476476", "name": "Profile", "description": "Profile claims", "claimCount": 14, "claimPreview": ["Middle name","Picture URL","Locale"] },
  { "realmId": "acme", "scopeId": "f3319b39-2d3f-4fb2-a3fa-07dace3ea98f", "name": "Email",   "description": "Email claims",   "claimCount": 2,  "claimPreview": ["Email verified","Email"] }
]
```

### Create a client scope

Only `name` is required. The response returns the new `scopeId`, which addresses the scope in later calls.

```bash
# Refresh CSRF after any GET, then POST (see the auth guide for the helper)
curl -s -b cookies.txt -c cookies.txt "$HELIX_URL/admin/realms/$REALM/client-scopes" >/dev/null
CSRF=$(awk '$6=="XSRF-TOKEN"{t=$7} END{print t}' cookies.txt)

curl -s -b cookies.txt \
  -H "Content-Type: application/json" \
  -H "X-XSRF-TOKEN: $CSRF" \
  -d '{"name":"billing:read","description":"Read billing data"}' \
  "$HELIX_URL/admin/realms/$REALM/client-scopes"
```
```json
{
  "realmId": "acme",
  "scopeId": "d741792a-fa7c-4069-b76b-80c7c1a6577b",
  "name": "billing:read",
  "description": "Read billing data",
  "claimCount": 0,
  "claimPreview": []
}
```

### The realm claim catalogue

Claims are defined once at the realm level, then attached to scopes. List the catalogue, create a claim (`key` and `label` required), then attach it to a scope by `scopeId` + `claimId`:

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/claims"
```
```json
[
  { "realmId": "acme", "claimId": "eb5717c6-c654-4257-af9b-91ff646080cd", "key": "sub",   "label": "Subject identifier", "placeholder": null,               "mandatory": true },
  { "realmId": "acme", "claimId": "b18f7b07-5514-4c60-ba08-4fffba23ac7e", "key": "email", "label": "Email",              "placeholder": "alice@organisation.nl","mandatory": true }
]
```

```bash
# Create a custom claim in the realm catalogue
curl -s -b cookies.txt -H "Content-Type: application/json" -H "X-XSRF-TOKEN: $CSRF" \
  -d '{"key":"department","label":"Department"}' \
  "$HELIX_URL/admin/realms/$REALM/claims"
```
```json
{
  "realmId": "acme",
  "claimId": "56303db1-bd74-40ea-832b-bb05031607c7",
  "key": "department",
  "label": "Department",
  "placeholder": null,
  "mandatory": false
}
```

```bash
# Attach the claim to a scope (no body; 200 OK on success) — detach with DELETE
curl -s -b cookies.txt -X PUT -H "X-XSRF-TOKEN: $CSRF" \
  "$HELIX_URL/admin/realms/$REALM/client-scopes/d741792a-fa7c-4069-b76b-80c7c1a6577b/claims/56303db1-bd74-40ea-832b-bb05031607c7"
```

### The realm subject claim

The realm-level subject claim is the fallback `sub` source when a client sets no override:

```bash
curl -s -b cookies.txt "$HELIX_URL/admin/realms/$REALM/subject-claim"
```
```json
{ "realmId": "acme", "claimKey": "sub" }
```

```bash
# Change the realm default subject claim
curl -s -b cookies.txt -X PUT -H "Content-Type: application/json" -H "X-XSRF-TOKEN: $CSRF" \
  -d '{"claimKey":"email"}' \
  "$HELIX_URL/admin/realms/$REALM/subject-claim"
```

### Full endpoint set

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /client-scopes` · `POST /client-scopes` | List / create client scopes |
| `GET` · `DELETE /client-scopes/{scopeId}` | Read / delete a scope |
| `PUT` · `DELETE /client-scopes/{scopeId}/claims/{claimId}` | Attach / detach a claim to a scope |
| `GET /claims` · `POST /claims` | List / create realm claims |
| `PUT` · `DELETE /claims/{claimId}` | Update / delete a realm claim |
| `GET` · `PUT /subject-claim` | Read / set the realm subject-claim |

See the [API reference](../integration/api-reference.md).

## See also

- [OIDC clients](oidc-clients.md)
- [Applications](applications.md)
- [Users](users.md)
- [Roles](roles.md)
- [Realm settings — Registration](../operations/realm-settings.md#registration)
- [Login theming](../operations/theming.md)
