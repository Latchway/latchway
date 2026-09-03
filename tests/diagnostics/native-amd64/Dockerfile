# syntax=docker/dockerfile:1.9@sha256:fe40cf4e92cd0c467be2cfc30657a680ae2398318afd50b0c80585784c604f28
FROM golang:1.27.0-alpine3.24@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go test ./internal/quota -run '^TestAdvisory(ProfilerRedaction|DatabaseOfflineValidation)$' -count=1
RUN CGO_ENABLED=0 go test -c -trimpath -o /out/quota-profile.test ./internal/quota

FROM scratch
ARG DIAGNOSTIC_OWNER
ARG TOOLING_COMMIT
LABEL dev.latchway.native-amd64-diagnostic=$DIAGNOSTIC_OWNER
LABEL dev.latchway.native-amd64-tooling=$TOOLING_COMMIT
COPY --from=build /out/quota-profile.test /quota-profile.test
USER 65532:65532
ENTRYPOINT ["/quota-profile.test"]
