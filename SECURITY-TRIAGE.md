# Security scan triage

Scanner alerts (GitHub code scanning: Trivy, CodeQL) that are **not fixed in code** because they are
false positives, not applicable, or cannot be satisfied without replacing a component, with the reason.
Every other alert from the same scan was fixed on `fix/scan-deps-config`.

| Alert | Tool / rule | Path | Status | Reason |
|---|---|---|---|---|
| #59, #60 | Trivy KSV-0020 (`runAsUser` > 10000) | `e2e/monthfold/k8s-postgres-redis.yaml` | Not applicable | The pods run non-root as the users baked into the stock images: `postgres:16-alpine` (uid 70) and `redis:7-alpine` (uid 999). Those are the uids that own the images' own files and that `/etc/passwd` knows, so they are the ones the entrypoints are written for. A uid above 10000 would need a custom image (or nss_wrapper tricks) for a throw-away database that exists only for the length of `e2e/monthfold/k3d-helm.sh`. Every other hardening check passes (non-root, no privilege escalation, all capabilities dropped, RuntimeDefault seccomp, read-only root filesystem, resource limits, non-default namespace). |
| #61, #62 | Trivy KSV-0021 (`runAsGroup` > 10000) | `e2e/monthfold/k8s-postgres-redis.yaml` | Not applicable | Same as above: the image groups are gid 70 (postgres) and gid 1000 (redis). |
| #81 | CodeQL `js/clear-text-cookie` | `helix-sandbox-rp/server.js` | Fixed, may still be reported | The session cookie is `HttpOnly`, `SameSite=Lax` and `Secure` by default in production (`NODE_ENV=production`) or with `COOKIE_SECURE=true`. It stays configurable because the sandbox RP is a local test harness served over plain `http://localhost`, where a `Secure` cookie is never set and login would break (`docker-compose.yml` sets `COOKIE_SECURE=false` for that reason). CodeQL cannot prove a non-literal flag is always `true`, so it may keep reporting this. |
| #80 | CodeQL `js/missing-token-validation` | `helix-sandbox-rp/server.js` | Fixed, with a by-design exemption | A synchronizer-token CSRF middleware now guards every state-changing request. `/saml/acs` and `/saml/slo` are exempt because they are SAML HTTP-POST binding endpoints: the IdP posts to them cross-site from its own origin and cannot carry the RP's token. The ACS only accepts a SAMLResponse whose signature validates against the IdP metadata. |
