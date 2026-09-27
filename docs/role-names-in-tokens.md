# Role names in tokens

This page says exactly which role strings HelixIAM puts in access and ID tokens, so a relying party (RP) can
check roles without guessing. `RealmRoleNamesInTokensE2eTest` pins this behaviour.

## Summary

| Who the token is for | Claim | Role string | Example (role `accountant`, realm `monthfold`) |
|---|---|---|---|
| A user (authorization code and its refresh tokens) | `realm_access.roles` | `<role>_<realm>` | `accountant_monthfold` |
| A service account (`client_credentials`), realm role | `realm_access.roles` | `<role>` | `accountant` |
| A service account, client role of client `ledger` | `resource_access.ledger.roles` | `<role>` | `reader` |
| An agent (`client_credentials` of a registered agent), its own roles | `realm_access.roles` / `resource_access` | as configured on the agent | `read` |
| A user's organization membership | `organizations[].roles` | the membership role | `owner` |

So a user's realm role **carries the realm as a suffix**: the default role `user` of realm `monthfold` is
`user_monthfold` in the token, and the realm's `admin` role is `admin_monthfold`. The role's name in the admin API
and the console is still the plain name (`user`); only the token carries the qualified form.

The `USER_ROLE` protocol mapper emits the same strings (the qualified form for users).

## Why the suffix exists

- **One host, many realms.** Every realm of a HelixIAM installation issues tokens from the same host
  (`https://id.example/realms/{realm}`). A qualified role name cannot be mistaken for the same-named role of
  another realm, even by an RP that forgets to pin the issuer. RPs must still validate `iss`; the suffix is a second
  line of defence, not a replacement.
- **It is the authority string HelixIAM itself uses.** A signed-in user's Spring authorities are
  `<role>_<realm>`, and realm-admin rights are the authority `admin_<realm>` (see the security advisory in
  `CHANGES-1.0.md`: role names starting with `admin_` are refused because they could forge that string).

## What an RP should do

- Pin the issuer (`iss` = `https://<host>/realms/<realm>`) and the audience, as for any OIDC token.
- For users, check `realm_access.roles` for `<role>_<realm>`, for example `user_monthfold`. If your code wants the
  plain name, strip the suffix `"_" + realm` where `realm` is the last path segment of the pinned issuer. Do not strip
  "everything after the last underscore": realm ids and role names may themselves contain `_`.
- For service accounts, check the plain name.

## Why it is not configurable per realm (yet)

Open issue E8 asked to document the suffix or make it configurable per realm. It is documented only, for now:

1. **Consumers inside HelixIAM depend on today's strings.** The RFC 8693 delegation exchange intersects the
   user token's `realm_access.roles` (qualified) with the agent's roles (plain as configured), and the `USER_ROLE`
   mapper, organization claims and agent roles each have their own form. A per-realm switch has to define what each
   of these does in both modes; flipping only the user roles would silently change who may do what through
   delegation.
2. **The setting belongs in realm settings**, whose DTO is a positional record used at about 17 call sites
   (admin API, import/export, the settings resolver). Adding a field there is a cross-cutting change that should
   ship with its console control, import/export and migration in one piece, not as a side effect of this issue.
3. **Changing an existing realm's token contents breaks its RPs**, so the option needs a migration story
   (announce, dual-emit for a period, or new realms only).

Recommended follow-up: a realm setting `tokenRoleNames: qualified | plain` (default `qualified`), where `plain` emits
`<role>` for users too, together with a decision on the delegation intersection (compare plain names in both modes)
and a console switch with a clear warning that RPs of the realm must be updated.
