# espdns-controller: one static binary in a distroless image, running as a non-root user.
# Base images pinned by digest (the tag says which; README.md, Pinned versions): the Go
# version is controller/go.mod's, as in CI (controller/pins_test.go checks both).
FROM golang:1.26.7-alpine@sha256:28d89ee9cc0ff9fec75c82ca201e6bf7fdf9a679d4b7b24dfa04f2bb766bb468 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# The version: the repository's VERSION (docker build --build-context version=..; its
# .dockerignore lets in nothing else), linked in (internal/version), as controller/Makefile does
COPY --from=version VERSION /VERSION
RUN v=$(cat /VERSION) && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/skitzo2000/espdns/controller/internal/version.Version=$v" -o /espdns-controller ./cmd/espdns-controller && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/skitzo2000/espdns/controller/internal/version.Version=$v" -o /espdns ./cmd/espdns

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /espdns-controller /espdns-controller
COPY --from=build /espdns /espdns
# The shipped board catalog (docker build --build-context boards=../boards); yours go in /data/boards
COPY --from=boards *.json /catalog/
# The public keys the firmware is built with (docker build --build-context keys=../firmware/keys):
# espdns release verify and import check a release's signature with /keys/release.pub
COPY --from=keys release.pub recovery.pub /keys/
# All state, shared with the CLI's fleet targets: settings.json, fleet.lock, log/ (the action log,
# job records), firmware/images/ and firmware/builds/, lists/, zones/, boards/, configs/ (the node configs), keys/release.pem,
# auth.json: every directory 0700 and every file 0600, the controller's user's only.
VOLUME /data
ENTRYPOINT ["/espdns-controller", "-data", "/data", "-catalog", "/catalog"]
CMD ["-listen", "127.0.0.1:8480"]
