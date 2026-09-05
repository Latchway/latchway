# syntax=docker/dockerfile:1.9@sha256:fe40cf4e92cd0c467be2cfc30657a680ae2398318afd50b0c80585784c604f28

FROM --platform=$BUILDPLATFORM node:26.8.1-alpine3.24@sha256:2d984a15c9b54fd0aeb608b8e0d0d83529eb34d2966db27a1fb4f1edc3d298a3 AS console-build
RUN corepack enable && corepack prepare pnpm@10.15.0 --activate
WORKDIR /src/web/console
COPY web/console/package.json web/console/pnpm-lock.yaml web/console/.npmrc ./
RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile
COPY api/admin.openapi.yaml api/client.openapi.yaml api/config.schema.json /src/api/
COPY web/console/ ./
RUN pnpm exec vite build

FROM --platform=$BUILDPLATFORM golang:1.27.0-alpine3.24@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS go-build
RUN apk add --no-cache ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
COPY --from=console-build /src/web/console/dist ./web/console/dist
ARG VERSION=1.0.1
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath \
      -ldflags "-s -w -X github.com/latchway/latchway/internal/buildinfo.Version=${VERSION} -X github.com/latchway/latchway/internal/buildinfo.Commit=${COMMIT} -X github.com/latchway/latchway/internal/buildinfo.Date=${BUILD_DATE}" \
      -o /out/latchway ./cmd/latchway

FROM scratch
ARG VERSION=1.0.1
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
ARG SOURCE=https://github.com/Latchway/latchway
LABEL org.opencontainers.image.title="Latchway" \
      org.opencontainers.image.description="Self-hosted AI gateway for untrusted applications" \
      org.opencontainers.image.source=${SOURCE} \
      org.opencontainers.image.version=${VERSION} \
      org.opencontainers.image.revision=${COMMIT} \
      org.opencontainers.image.created=${BUILD_DATE} \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=go-build --chmod=0555 /out/latchway /latchway
COPY --from=go-build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY LICENSE NOTICE /licenses/latchway/
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/latchway"]
CMD ["serve", "--role", "all"]
