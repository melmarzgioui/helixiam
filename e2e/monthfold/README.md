# Monthfold release-gate check

The end-to-end check run before tagging a HelixIAM release. It boots the Helm chart's **default**
configuration on a fresh k3d cluster with an empty PostgreSQL, waits for readiness, then drives the public
HTTP APIs the way a first real deployment would (the "Monthfold" setup) and validates every issued token
from Go with `github.com/lestrrat-go/jwx/v3` (JWKS signature + exact issuer).

```bash
# from the repository root; needs docker, k3d, kubectl, helm, python3, go
e2e/monthfold/k3d-helm.sh              # KEEP=1 to leave the cluster running
```

What `run.py` does (Python 3 standard library only; point it at any running server with `--base`):

- master admin signs in (password + TOTP — `mfa.enabled` is on by default) and creates the service account
  `monthfold-provisioner` with the master realm role `admin`
- the provisioner, with its **bearer token**, creates realm `monthfold` (`requireMfa=true`), clients `web`,
  `portal`, `ledger`, ledger's token-exchange policy (only `web`), organization `harbor-pine`, users `joe`
  (owner) and `maya` (client)
- `joe`: authorization code + PKCE with **enforced TOTP** (enrolment on the first sign-in, a code on the next,
  a replayed code refused)
- token exchange `web` → `audience=ledger` (`aud=[ledger]`, `act.sub=web`, organizations kept; unknown
  audience → `invalid_target`); `ledger` client credentials
- `maya`: the claim-injection reproduction — `PUT /realms/monthfold/account/profile` with
  `{"attributes":{"sub":"<joe>"}}` is refused, and maya's tokens keep her own `sub`

`jwxcheck/` then validates the six tokens written to `out/tokens.json`.
