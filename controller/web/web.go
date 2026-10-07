// Package web holds the dashboard's pages, built into the binary, and the third-party code
// they load: vendor/esp-web-tools/ (the builder's flasher, a pinned copy served from here,
// updated with `make vendor-ewt`; its THIRD_PARTY.md).
package web

import "embed"

//go:embed *.html *.css *.js vendor/esp-web-tools/*
var Files embed.FS
