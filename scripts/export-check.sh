#!/usr/bin/env bash
# export-check.sh: check the public export of this repository for site values before it
# is published. It exports a commit with `git archive` (which leaves out the files marked
# export-ignore in .gitattributes) and fails on:
#
#   - a private or shared address (RFC 1918 10/8, 172.16/12, 192.168/16; 100.64/10 shared
#     address space; 172.64/13), or its reverse zone, anywhere in the exported files. The documentation ranges
#     (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) are what examples use;
#   - any site name given to it: words that must never appear in the public tree, e.g. the
#     real zone names and people's names of a deployment. They are passed in, never written
#     into the repository: as SITE_NAMES (space-separated), as a file of names (one per line,
#     # comments allowed) in SITE_NAMES_FILE or with -n FILE. A name matches as a whole
#     word, ignoring case: "example" matches git.example.net and example-labs, not examples.
#
# Usage:
#   scripts/export-check.sh [-n names-file] [commit]      (commit: HEAD by default)
#   scripts/export-check.sh -w [-n names-file]            (the working tree as it would be
#       committed: tracked and new files that .gitignore does not ignore, uncommitted
#       changes and .gitattributes included)
#   SITE_NAMES="example corp" scripts/export-check.sh
#
# Prints every offending line as path:line: text, and exits 1 if there are any, 0 if none,
# 2 on a usage error. Needs git, tar and grep (GNU or BSD with -E).
set -euo pipefail

names_file="${SITE_NAMES_FILE:-}"
worktree=0
while getopts "n:wh" opt; do
	case "$opt" in
	n) names_file="$OPTARG" ;;
	w) worktree=1 ;;
	h) sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) exit 2 ;;
	esac
done
shift $((OPTIND - 1))
rev="${1:-HEAD}"

repo="$(git rev-parse --show-toplevel)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

if [ "$worktree" -eq 1 ]; then
	# A tree of the working tree, built in a throwaway index so the real one is untouched.
	idx="$(mktemp)"
	rm -f "$idx"
	tree="$(cd "$repo" && GIT_INDEX_FILE="$idx" git add -A . && GIT_INDEX_FILE="$idx" git write-tree)"
	rm -f "$idx"
	rev="working tree"
	git -C "$repo" archive --format=tar --worktree-attributes "$tree" | tar -x -C "$tmp"
else
	git -C "$repo" archive --format=tar "$rev" | tar -x -C "$tmp"
fi

# The names to refuse, from the environment and the file, one per line, lower case.
names="$tmp.names"
trap 'rm -rf "$tmp" "$names"' EXIT
{
	for n in ${SITE_NAMES:-}; do printf '%s\n' "$n"; done
	if [ -n "$names_file" ]; then
		if [ ! -r "$names_file" ]; then
			echo "export-check: cannot read names file $names_file" >&2
			exit 2
		fi
		sed -e 's/#.*//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$names_file"
	fi
} | grep -v '^$' | tr '[:upper:]' '[:lower:]' | sort -u >"$names" || true

fail=0
cd "$tmp"

# Addresses: an IPv4 address in a private or shared range, not part of a longer number.
oct='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
addr="(^|[^0-9.])(10\\.$oct\\.$oct\\.$oct|172\\.(1[6-9]|2[0-9]|3[01])\\.$oct\\.$oct|192\\.168\\.$oct\\.$oct|100\\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\.$oct\\.$oct|172\\.(6[4-9]|7[01])\\.$oct\\.$oct)([^0-9]|$)"
# Their reverse zones too (the in-addr.arpa zones of those ranges, and below).
rev_zone='(^|[^0-9])(10|(1[6-9]|2[0-9]|3[01])\.172|168\.192|(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.100|(6[4-9]|7[01])\.172)\.in-addr\.arpa'
if out="$(grep -rInE "$addr|$rev_zone" . | sed 's#^\./##')"; then
	echo "== private, shared or 172.64/13 addresses (use 192.0.2.0/24, 198.51.100.0/24, 2001:db8::/32):"
	printf '%s\n' "$out"
	fail=1
fi

# Site names, anywhere in a word, ignoring case. File names count too.
if [ -s "$names" ]; then
	if out="$(grep -rIniwF -f "$names" . | sed 's#^\./##')"; then
		echo "== site names in file contents:"
		printf '%s\n' "$out"
		fail=1
	fi
	if out="$(find . -path ./.git -prune -o -print | sed 's#^\./##' | grep -iwF -f "$names")"; then
		echo "== site names in file paths:"
		printf '%s\n' "$out"
		fail=1
	fi
fi

if [ "$fail" -eq 0 ]; then
	echo "export-check: $rev is clean ($(wc -l <"$names" | tr -d ' ') names checked)"
fi
exit "$fail"
