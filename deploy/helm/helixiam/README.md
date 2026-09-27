# helixiam Helm chart

Deploys **helix-iam-server** (the HelixIAM identity server). PostgreSQL and Redis are **not**
bundled — point the chart at your own managed instances.

## Security posture
- Non-root (uid 10001), `readOnlyRootFilesystem: true` (writes only an `emptyDir` `/tmp`),
  `allowPrivilegeEscalation: false`, all capabilities dropped, `seccompProfile: RuntimeDefault`.
- Service-account token not mounted (the server never calls the Kubernetes API).
- Secure config defaults: self-registration off, Prometheus scrape non-anonymous, secure cookies,
  Flyway-managed schema.
- **Secrets are referenced, never inlined** — you supply an existing `Secret`.
- A `NetworkPolicy` restricts ingress to the HTTP port and egress to DNS + database + Redis + TLS.
- Startup / liveness / readiness probes hit the actuator health groups.

## Required values
`config.idpBaseUrl`, `config.spBaseUrl`, `database.host`, `redis.host`, `secrets.existingSecret`
(render fails fast if any is missing).

## Install
```bash
# 1. Create the referenced Secret (out-of-band; keys are configurable in values.yaml).
kubectl create secret generic helixiam-secrets \
  --from-literal=db-username=helix \
  --from-literal=db-password='<db password>' \
  --from-literal=db-encryption='<16-byte hex, keep stable>' \
  --from-literal=admin-password='<bootstrap admin password>'

# 2. Install.
helm install helixiam deploy/helm/helixiam \
  --set config.idpBaseUrl=https://idp.example.com \
  --set config.spBaseUrl=https://console.example.com \
  --set database.host=postgres.db.svc \
  --set redis.host=redis.redis.svc \
  --set secrets.existingSecret=helixiam-secrets
```

## File themes
Set `themes.enabled=true` and point `themes.configMap.name` (with `items` mapping keys to
`{theme}/theme.json`, `{theme}/fonts.json` and `{theme}/assets/<file>`) or `themes.existingVolume` at your theme
files. They are mounted read-only at `themes.mountPath` (`HELIX_THEME_DIRECTORY`), validated at startup and
whenever they change, and a realm uses one after `PUT /admin/realms/{realm}/theme/base {"themeName": "<theme>"}`.
An invalid theme is refused (see the server log and `GET /admin/realms/{realm}/theme/base`) and realms fall back to
their database theme or the default.

```bash
kubectl create configmap helixiam-themes \
  --from-file=monthfold.theme.json=themes/monthfold/theme.json \
  --from-file=monthfold.logo.svg=themes/monthfold/assets/logo.svg
helm upgrade helixiam deploy/helm/helixiam --reuse-values \
  --set themes.enabled=true --set themes.configMap.name=helixiam-themes \
  --set 'themes.configMap.items[0].key=monthfold.theme.json' \
  --set 'themes.configMap.items[0].path=monthfold/theme.json' \
  --set 'themes.configMap.items[1].key=monthfold.logo.svg' \
  --set 'themes.configMap.items[1].path=monthfold/assets/logo.svg'
```

See [`values.yaml`](values.yaml) for the full set of options (ingress, resources, probes,
NetworkPolicy selectors, extra env).
