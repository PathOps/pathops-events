# syntax=docker/dockerfile:1
# The pathops-events image; context = repository root. The build stage
# installs the locked dependencies, runs every check (typecheck, lint, tests)
# and compiles TypeScript; the runtime is distroless Node.js (no shell, no
# npm), non-root, with the production dependencies only. The release adds
# org.opencontainers.image.revision and .version as build arguments and is
# consumed by digest.

FROM docker.io/library/node:24.22.3-alpine@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5 AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY tsconfig.json tsconfig.build.json eslint.config.js vitest.config.ts ./
COPY src ./src
COPY tests ./tests
RUN npm run check && npm run build && npm prune --omit=dev --ignore-scripts

FROM gcr.io/distroless/nodejs24-debian12:nonroot@sha256:14d42e2511532589a7c7e01a753667a74fcc96266e137e8125006b87b0c32d0a
ARG REVISION=unknown
ARG VERSION=unknown
LABEL org.opencontainers.image.source="https://github.com/PathOps/pathops-events" \
      org.opencontainers.image.title="pathops-events" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.version="${VERSION}"
WORKDIR /app
COPY --from=build /src/package.json ./
COPY --from=build /src/node_modules ./node_modules
COPY --from=build /src/dist ./dist
ENV NODE_ENV=production
USER 65532:65532
EXPOSE 8443 9443
CMD ["dist/index.js"]
