# OIDC sessions and logout: what a relying party gets and must check

This page is for teams building a relying party (RP) on HelixIAM. It covers the session claims in ID tokens
and how to handle OpenID Connect Back-Channel Logout safely.

## Session claims in ID tokens

Every ID token from the authorization-code flow, and every ID token issued on refresh, carries:

| Claim | Meaning |
|---|---|
| `sid` | The SSO session: one sign-in in one browser. Every client the user reaches through that sign-in gets the same `sid`. It stays the same on refresh and after a re-authentication in the same browser (`prompt=login`, `max_age`). A new sign-in after logout, or in another browser, gets a new `sid`. |
| `auth_time` | When the user last signed in interactively, in epoch seconds. Refreshing tokens or silent SSO doesn't change it. A `prompt=login` or an exceeded `max_age` sign-in moves it forward. |

Use `auth_time` to require a recent sign-in before sensitive actions: send `max_age=<seconds>` (or
`prompt=login`) and check `auth_time` in the returned ID token. Store `sid` with your local session, so you
can find that session when a logout token arrives.

## RP-initiated logout

Send the user to `{issuer}/connect/logout` with `id_token_hint` (any ID token of the session),
`post_logout_redirect_uri` (registered on the client) and optionally `state`. HelixIAM ends the SSO session
named by the token's `sid`. That means every client authorization in it, including refresh tokens. Then it
sends a back-channel logout to every client in that session that registered a `backchannel_logout_uri`.
The user's other browser sessions are not affected.

An administrator revoking the session (console or `DELETE /admin/realms/{realm}/sessions/{sid}`) and a user
ending it from the account page cause the same back-channel logout.

### Revoking every session of a user

`DELETE /admin/realms/{realm}/users/{userId}/sessions` (`manage-users`) signs a user out everywhere in the realm in
one call, for example after a suspected account compromise:

1. the user's browser sessions are deleted;
2. every SSO session of the user is ended as above: all its authorizations and refresh tokens are removed, and each
   of its clients with a `backchannel_logout_uri` gets a logout token with that session's `sid`;
3. every remaining authorization of the user at a client of the realm (one that was not part of an SSO session) is
   removed too, and each such client gets one logout token with `sub` and no `sid`, which means "every session of
   this user at your application".

The answer is `200 {"ssoSessions": n, "authorizations": n, "browserSessions": n}`; an unknown user, or a user of
another realm, is a 404. The call is audited as `USER_SESSIONS_REVOKE`. An RP must therefore also accept a logout token
without `sid` (OIDC Back-Channel Logout 1.0 §2.4 allows either claim) and then end all of that user's sessions.

## Back-channel logout: validating the `logout_token`

HelixIAM POSTs `logout_token=<JWT>` (form-encoded) to your `backchannel_logout_uri`. Validate it as
[OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html) §2.6
requires. Reject the token, and answer `400`, unless all of these hold:

1. The signature verifies against the **realm's** JWKS (`{issuer}/oauth2/jwks`), the same keys you use for
   ID tokens. The token is signed with the key of the realm the session belongs to, even when a master-realm
   administrator revoked the session.
2. `iss` equals the realm issuer, `{base}/realms/{realm}`.
3. `aud` contains your `client_id`.
4. `iat` is present and `exp` has not passed. Logout tokens are short-lived: 120 seconds by default
   (`HELIX_LOGOUT_TOKEN_TTL_SECONDS`, capped at 600). Allow only a small clock skew.
5. `events` contains the member `http://schemas.openid.net/event/backchannel-logout` with an empty object.
6. There is **no** `nonce` claim.
7. `sid` and/or `sub` is present. HelixIAM always sends both.
8. **Replay protection:** `jti` is unique for every logout token HelixIAM issues. Remember each `jti` you
   accept until that token's `exp`, and reject a token whose `jti` you have already seen. Because `exp` is
   short, this cache stays small.

Then end your local sessions that match `sid` (or, for `sub`, all of that user's sessions) and answer
`200`. Don't redirect or require cookies: the call comes from the server, not the browser.
