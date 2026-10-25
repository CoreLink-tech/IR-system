# Multi-stage production image for the Security API.
# Build: docker build -t security-api ./backend
# Run with env file; never bake secrets into the image.

FROM node:20-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY . .
RUN npx prisma generate && npm run build && npm prune --omit=dev

FROM node:20-bookworm-slim AS runtime
RUN useradd --system --uid 10001 --home /app appuser
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build --chown=appuser:appuser /app/dist ./dist
COPY --from=build --chown=appuser:appuser /app/node_modules ./node_modules
COPY --from=build --chown=appuser:appuser /app/package.json ./
COPY --from=build --chown=appuser:appuser /app/prisma ./prisma
USER appuser
EXPOSE 4000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:4000/api/v1/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "dist/main.js"]
