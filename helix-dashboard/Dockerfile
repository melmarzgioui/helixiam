# Helix IAM admin console — production image (PROD-2). Multi-stage: build the Vite SPA, serve the
# static bundle with nginx, and reverse-proxy the admin + account APIs to the publisher so the
# browser stays same-origin (no CORS, no cookie juggling) exactly as the dev Vite proxy does.
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
# The HelixIAM server (admin API) base URL the console proxies to; overridable at deploy time.
ENV HELIX_API_TARGET=http://helix-iam-server:8080
COPY deploy/console/nginx.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
# nginx:alpine's entrypoint envsubst-expands /etc/nginx/templates/*.template into /etc/nginx/conf.d.
