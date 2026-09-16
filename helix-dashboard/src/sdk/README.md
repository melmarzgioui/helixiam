# Helix IAM Admin SDK (TypeScript)

A small, typed wrapper over the Helix IAM **Admin API** (`/admin/realms/{realmId}/**`,
OpenAPI group `admin`). This is a demonstration stub — it covers **Users, Roles and
Organizations**, not the full surface — and shows the intended SDK story.

## Usage

```ts
import { createHelixAdminClient } from "./sdk";

const helix = createHelixAdminClient({
  baseUrl: "https://iam.example.com", // omit for same-origin
  token: "<admin bearer token>",       // optional; sent as Authorization: Bearer ...
});

const users = await helix.users.list("master");
const acme = await helix.organizations.create("master", { name: "Acme" });
await helix.roles.assign("master", users[0].userId, "role-id");
```

Errors surface as `HelixApiError` (carries `.status`, `.statusText`, and the parsed JSON
`.body` — e.g. the `{ message, fieldErrors }` shape returned by the backend validation advice).

## Files

- `types.ts` — hand-written types mirroring the OpenAPI schemas (`UserAdminDto`, `RoleDto`, `OrgDto`, ...).
- `index.ts` — `createHelixAdminClient(...)`: framework-free (`fetch`-based) client.
- `index.test.ts` — vitest coverage (path building, bearer header, JSON body, 204, error mapping).

## Regenerating from the live spec (recommended for full coverage)

The publisher serves the spec for this group at **`/v3/api-docs/admin`** and Swagger UI at
**`/swagger-ui.html`**. Rather than hand-maintaining the wrapper, generate the client from the
spec. Two common options:

### Option A — `openapi-typescript` (types only, lightweight)

```bash
npx openapi-typescript http://localhost:8080/v3/api-docs/admin \
  -o src/sdk/generated.d.ts
```

Produces a `paths` / `components` type tree. Pair it with a typed fetch helper such as
`openapi-fetch` to get an end-to-end-typed client while keeping the runtime tiny.

### Option B — `@openapitools/openapi-generator-cli` (full client)

```bash
npx @openapitools/openapi-generator-cli generate \
  -i http://localhost:8080/v3/api-docs/admin \
  -g typescript-fetch \
  -o src/sdk/generated
```

Generates model classes + per-tag API classes (`UsersApi`, `RolesApi`, `OrganizationsApi`, ...)
matching the `@Tag` names on the controllers.

> Note: the spec is intentionally scoped to `/admin/**` via the `GroupedOpenApi` bean, so the
> SAS OAuth2/OIDC and SAML protocol endpoints are **not** generated. Use the realm's OIDC
> discovery document / SAML metadata for those.

Neither generator is wired into the build; run it on demand against a running server (or a
saved `api-docs/admin.json`).
