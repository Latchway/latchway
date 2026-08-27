# syntax=docker/dockerfile:1.9

FROM node:24.19.0-alpine3.24 AS console-build
RUN corepack enable && corepack prepare pnpm@10.15.0 --activate
WORKDIR /src/web/console
COPY web/console/package.json web/console/pnpm-lock.yaml web/console/.npmrc ./
RUN --mount=type=cache,target=/root/.local/share/pnpm/store \
    pnpm install --frozen-lockfile
COPY web/console/ ./
RUN pnpm check

FROM golang:1.27.0-alpine3.24 AS go-build
RUN apk add --no-cache ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
COPY --from=console-build /src/web/console/dist ./web/console/dist
ARG VERSION=0.1.0-dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go test ./...
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath \
      -ldflags "-s -w -X github.com/latchway/latchway/internal/buildinfo.Version=${VERSION} -X github.com/latchway/latchway/internal/buildinfo.Commit=${COMMIT} -X github.com/latchway/latchway/internal/buildinfo.Date=${BUILD_DATE}" \
      -o /out/latchway ./cmd/latchway

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=go-build /out/latchway /latchway
COPY LICENSE NOTICE /licenses/latchway/
EXPOSE 8080
ENTRYPOINT ["/latchway"]
CMD ["serve", "--role", "all"]
