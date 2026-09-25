# syntax=docker/dockerfile:1
# helix-sandbox-rp: an OIDC/SAML relying-party test harness (Express, ESM).
FROM node:25-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

FROM node:25-alpine AS runtime
ENV NODE_ENV=production PORT=9090
# Run as the image's built-in non-root 'node' user.
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY --chown=node:node . .
USER node
EXPOSE 9090
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=5 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||9090)+'/').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "server.js"]
