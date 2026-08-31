# syntax=docker/dockerfile:1.9@sha256:fe40cf4e92cd0c467be2cfc30657a680ae2398318afd50b0c80585784c604f28

ARG COMMIT

FROM golang:1.27.0-alpine3.24@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -o /out/latchway-load ./tests/load/cmd/latchway-load && \
    CGO_ENABLED=0 go build -trimpath -o /out/latchway-load-fixture ./tests/load/cmd/latchway-load-fixture && \
    CGO_ENABLED=0 go build -trimpath -o /out/latchway-load-provision ./tests/load/cmd/latchway-load-provision && \
    CGO_ENABLED=0 go build -trimpath -o /out/latchway-failure-driver ./tests/failure/cmd/latchway-failure-driver && \
    CGO_ENABLED=0 go build -trimpath -o /out/latchway-failure-balancer ./tests/failure/cmd/latchway-failure-balancer

# The runner deliberately retains Git: complete evidence independently checks
# the exact mounted clean source commit instead of trusting a caller-supplied
# label. This image is test tooling and is never published as Latchway runtime.
FROM golang:1.27.0-alpine3.24@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc
ARG COMMIT
LABEL org.opencontainers.image.revision=$COMMIT
RUN apk add --no-cache git
COPY --from=build --chmod=0555 /out/latchway-load /tools/latchway-load
COPY --from=build --chmod=0555 /out/latchway-load-fixture /tools/latchway-load-fixture
COPY --from=build --chmod=0555 /out/latchway-load-provision /tools/latchway-load-provision
COPY --from=build --chmod=0555 /out/latchway-failure-driver /tools/latchway-failure-driver
COPY --from=build --chmod=0555 /out/latchway-failure-balancer /tools/latchway-failure-balancer
WORKDIR /src
USER 65532:65532
