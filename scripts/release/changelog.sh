#!/bin/sh
# Prints one version's section of CHANGELOG.md, its heading left out: the release's notes.
#
#   changelog.sh 0.0.2
#
# The section is from "## [0.0.2] - YYYY-MM-DD" to the next "## " heading. No such section,
# or one with nothing in it, is an error: every version has its changelog.
#
# ESPDNS_ROOT: the repository to read (default: this script's); the tests use another.
set -eu
root=${ESPDNS_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}
[ $# -eq 1 ] || { echo "usage: $0 MAJOR.MINOR.PATCH" >&2; exit 2; }
log=$root/CHANGELOG.md
[ -f "$log" ] || { echo "no $log" >&2; exit 1; }
awk -v v="$1" '
	BEGIN { head = "## [" v "] - " }
	index($0, head) == 1 && substr($0, length(head) + 1) ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/ { found = 1; in_s = 1; next }
	in_s && /^## / { in_s = 0 }
	in_s { lines[++n] = $0; if ($0 ~ /[^[:space:]]/) { if (!first) first = n; last = n } }
	END {
		if (!found) exit 3
		if (!last) exit 4
		for (i = first; i <= last; i++) print lines[i]
	}
' "$log" || case $? in
3) echo "CHANGELOG.md: no \"## [$1] - YYYY-MM-DD\" section (scripts/bump-version.sh makes it)" >&2; exit 1 ;;
4) echo "CHANGELOG.md: the section for $1 is empty" >&2; exit 1 ;;
*) exit 1 ;;
esac
