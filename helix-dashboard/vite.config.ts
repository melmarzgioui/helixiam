import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "path";

// The console calls the admin API on its own origin (createHttpClient("")). In dev, Vite proxies
// /admin to the auth server so the browser stays same-origin (no CORS, no cookie juggling). Point
// HELIX_API_TARGET at the running auth server (default the e2e publisher on :8083).
const apiTarget = process.env.HELIX_API_TARGET ?? "http://localhost:8083";

export default defineConfig({
  plugins: [react()],
  // Two entry points: the admin console (index.html) and the end-user self-service Account
  // console (account.html, IAM gap feature 6). They share the component library + build.
  build: {
    rollupOptions: {
      input: {
        main: resolve(__dirname, "index.html"),
        account: resolve(__dirname, "account.html"),
      },
    },
  },
  server: {
    proxy: {
      // /admin → admin API. For the self-service Account console we proxy ONLY the account API
      // (/realms/{realm}/account/**) — a regex, NOT a bare "/realms" prefix, because the admin SPA
      // uses /realms/{realm}/{section} as its OWN client-side routes; proxying all of /realms would
      // 302 those deep-links to the backend login instead of serving index.html.
      "/admin": { target: apiTarget, changeOrigin: true },
      "^/realms/[^/]+/account": { target: apiTarget, changeOrigin: true },
      // Session login/logout so the admin can authenticate against the auth server through THIS origin
      // (so the SESSION + XSRF-TOKEN cookies land on the dev-server origin and ride the /admin proxy).
      // Specific auth sub-paths only — never the bare /realms/{realm}/{section} SPA routes.
      "^/realms/[^/]+/(login|logout|css|img|js)": { target: apiTarget, changeOrigin: true },
      // OIDC login for the console: realm-prefixed authorize/token, discovery, and RP-logout.
      "^/realms/[^/]+/(oauth2|connect|.well-known)/": { target: apiTarget, changeOrigin: true },
      "^/(login|logout|register|reset|flow|mfa|error)(/|$)": { target: apiTarget, changeOrigin: true },
      "/js": { target: apiTarget, changeOrigin: true },
      "/oauth2": { target: apiTarget, changeOrigin: true },
      "/.well-known": { target: apiTarget, changeOrigin: true },
    },
  },
});
