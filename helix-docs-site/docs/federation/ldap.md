# LDAP / Active Directory

Federate users from your LDAP or Active Directory directory — they authenticate against the directory and appear as managed Helix IAM users.

## What it is

Helix IAM federates users against an **LDAP or Active Directory** directory. Users authenticate with their directory credentials and are federated into the realm, so your existing directory remains the source of truth while Helix provides modern SSO, MFA, and federation on top.

- **Directory-backed authentication** — credentials are validated against the directory at sign-in (direct bind; no redirect).
- **Attribute mapping** — map directory attributes onto Helix user attributes.
- **On-demand sync** — bring directory users into the realm and refresh them when you choose.

An LDAP directory is an [identity provider](identity-providers.md) with `protocol: "ldap"` (or `"ad"`). Its `config` holds the directory URL, the service (bind) account Helix uses to search, and the search base, filter, and attribute names that turn directory entries into Helix users.

## In the console

1. Open **Federation & eIDs → Identity providers** and click **Add identity provider**.
2. Choose the **LDAP / Active Directory** directory type.
3. Provide the directory **connection** URL and the **bind account** Helix uses to read it.
4. Set the **search base**, **user search filter**, and **attribute mapping** that define which directory entries become Helix users and how their fields map.
5. Save, then **Sync users** on demand to populate or refresh the realm from the directory. The federation provider is loaded at runtime and authenticates matching users against the directory.

!!! tip
    LDAP and AD share the same wizard — the difference is only in the default attribute names (`sAMAccountName`/`objectGUID` for AD versus `uid` for OpenLDAP), which you set as part of the attribute mapping.

## Over the API

An LDAP directory is created like any [identity provider](identity-providers.md), with `protocol: "ldap"`. The examples below assume you have set `$HELIX_URL` / `$REALM` and logged in — see [Authenticating to the API](../getting-started/api-authentication.md).

### Create an LDAP provider

```bash
# Refresh CSRF after any GET, then POST (see the auth guide for the helper)
curl -s -b cookies.txt -c cookies.txt "$HELIX_URL/admin/realms/$REALM/identity-providers" >/dev/null
CSRF=$(awk '$6=="XSRF-TOKEN"{t=$7} END{print t}' cookies.txt)

curl -s -b cookies.txt \
  -H "Content-Type: application/json" \
  -H "X-XSRF-TOKEN: $CSRF" \
  -d '{
        "alias": "corp-ldap",
        "protocol": "ldap",
        "displayName": "Corporate Directory",
        "enabled": true,
        "config": {
          "url": "ldaps://ad.corp.example:636",
          "bindDn": "cn=helix,ou=service,dc=corp,dc=example",
          "bindPassword": "…",
          "userSearchBase": "ou=people,dc=corp,dc=example",
          "userSearchFilter": "(uid={0})",
          "uidAttribute": "uid",
          "emailAttribute": "mail",
          "firstNameAttribute": "givenName",
          "lastNameAttribute": "sn"
        }
      }' \
  "$HELIX_URL/admin/realms/$REALM/identity-providers"
```
```json
{
  "realmId": "acme",
  "alias": "corp-ldap",
  "protocol": "ldap",
  "displayName": "Corporate Directory",
  "enabled": true,
  "config": {
    "url": "ldaps://ad.corp.example:636",
    "bindDn": "cn=helix,ou=service,dc=corp,dc=example",
    "bindPassword": "…",
    "userSearchBase": "ou=people,dc=corp,dc=example",
    "userSearchFilter": "(uid={0})",
    "uidAttribute": "uid",
    "emailAttribute": "mail",
    "firstNameAttribute": "givenName",
    "lastNameAttribute": "sn"
  }
}
```

!!! note "Config keys"
    `url`, `bindDn`, `bindPassword`, `userSearchBase`, `userSearchFilter` (defaults to `(uid={0})`; `{0}` is the username), `uidAttribute` (default `uid`), `emailAttribute` (default `mail`), `firstNameAttribute` (default `givenName`), `lastNameAttribute` (default `sn`).

### Sync directory users

Run an on-demand synchronisation to import or refresh users — useful from a scheduled job or after a bulk change in the directory. The response reports how many entries synced and failed.

```bash
curl -s -b cookies.txt -X POST -H "X-XSRF-TOKEN: $CSRF" \
  "$HELIX_URL/admin/realms/$REALM/user-federation/corp-ldap/sync"
```
```json
{ "synced": 128, "failed": 0, "errors": [] }
```

### Full endpoint set

| Method & path (under `/admin/realms/{realm}`) | Purpose |
| --- | --- |
| `GET /identity-providers` · `POST /identity-providers` | List / create providers |
| `GET` · `PUT` · `DELETE /identity-providers/{alias}` | Read / update / delete a provider |
| `POST /user-federation/{alias}/sync` | Import / refresh directory users |

See [Identity providers](identity-providers.md) for the shared flow, and the [API reference](../integration/api-reference.md) for every field.

## See also

- [Identity providers](identity-providers.md) — broker model and mappers
- [OIDC & social brokers](oidc-social.md) · [SAML broker](saml.md)
- [Users & credentials](../manage/users.md) — how federated users are managed
- [Authentication flows](../authentication/flows.md)
