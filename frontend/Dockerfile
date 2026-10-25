# Build static dashboard assets, then serve with nginx.
FROM node:20-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.27-alpine AS runtime
RUN adduser -D -u 10001 appuser
COPY --from=build /app/dist /usr/share/nginx/html
COPY deploy/nginx.conf.example /etc/nginx/conf.d/default.conf
# Prefer the example; operators should replace with a TLS-terminated config.
USER root
EXPOSE 80
HEALTHCHECK CMD wget -q -O /dev/null http://127.0.0.1/ || exit 1
CMD ["nginx", "-g", "daemon off;"]
