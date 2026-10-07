#!/bin/sh
# Checks a release tag against the repository (docs/releasing.md), and prints the version:
#
#   check-version.sh v0.0.2
#
# The tag must be "v" and the repository's VERSION, and CHANGELOG.md must have that
# version's section ("## [0.0.2] - YYYY-MM-DD", as scripts/bump-version.sh makes it) with
# something in it. The release workflow runs it first and stops on any mismatch, so a tag
# pushed by mistake (another version, a version without its changelog) releases nothing.
#
# ESPDNS_ROOT: the repository to check (default: this script's); the tests use another.
set -eu
root=${ESPDNS_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}
[ $# -eq 1 ] || { echo "usage: $0 vMAJOR.MINOR.PATCH" >&2; exit 2; }
tag=$1
v=$(cat "$root/VERSION")
printf '%s\n' "$v" | grep -Eq '^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$' ||
	{ echo "VERSION: '$v' is not MAJOR.MINOR.PATCH" >&2; exit 1; }
[ "$tag" = "v$v" ] || { echo "tag $tag is not the repository's version: VERSION says $v (tag v$v)" >&2; exit 1; }
sh "$(dirname "$0")/changelog.sh" "$v" >/dev/null
echo "$v"
