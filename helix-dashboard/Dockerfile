# Helix IAM admin console — production image (PROD-2). Multi-stage: build the Vite SPA, serve the
# static bundle with nginx, and reverse-proxy the admin + account APIs to the publisher so the
# browser stays same-origin (no CORS, no cookie juggling) exactly as the dev Vite proxy does.
FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.29-alpine
# The HelixIAM server (admin API) base URL the console proxies to; overridable at deploy time.
ENV HELIX_API_TARGET=http://helix-iam-server:8080
COPY deploy/console/nginx.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build /app/dist /usr/share/nginx/html
# Run as the image's unprivileged nginx user (uid 101) instead of root: the server already listens on
# 8080 (no privileged port), so only the paths nginx and its entrypoint write to need to be owned by it
# (the envsubst output in conf.d, the proxy/temp cache) and the pid file moves to /tmp. The `user`
# directive only applies to a root master, so drop it.
RUN chown -R nginx:nginx /etc/nginx/conf.d /var/cache/nginx \
 && sed -i -e '/^user /d' -e 's,^pid .*,pid /tmp/nginx.pid;,' /etc/nginx/nginx.conf
USER nginx
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1
# nginx:alpine's entrypoint envsubst-expands /etc/nginx/templates/*.template into /etc/nginx/conf.d.
