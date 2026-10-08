#!/bin/sh
# Prints a release's notes: the version's CHANGELOG.md section, then where to read how to
# check the files. The draft release's text, on any forge (docs/releasing.md):
#
#   notes.sh 0.0.2
#
# ESPDNS_ROOT: the repository whose CHANGELOG.md is read (default: this script's).
set -eu
[ $# -eq 1 ] || { echo "usage: $0 MAJOR.MINOR.PATCH" >&2; exit 2; }
section=$(sh "$(dirname "$0")/changelog.sh" "$1")
printf '%s\n\n---\n\n%s\n%s\n' "$section" \
	"Every file is listed in SHA256SUMS, signed with the espDNS release key in SHA256SUMS.sig:" \
	"check them before use as docs/releasing.md, Checking a release, says."
