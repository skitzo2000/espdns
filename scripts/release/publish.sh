#!/bin/sh
# Puts a release's files on the forge as a draft release (docs/releasing.md):
#
#   publish.sh TAG DIST
#
# Makes a draft release for TAG, titled "espDNS <version>", its notes the version's
# CHANGELOG.md section, and uploads every file in DIST to it: the release workflow's last
# step. A draft is seen only by the repository's writers; a person signs its SHA256SUMS,
# adds SHA256SUMS.sig and publishes it. Nothing here has, or asks for, the signing key.
#
# From the environment: FORGE_API (the forge's API, https://<host>/api/v1), REPO
# (<owner>/<name>) and RELEASE_TOKEN (an access token that can write the repository's
# releases), read from the environment so it is never an argument a process list shows.
# A release already there for the tag is refused, not changed: delete it first.
#
# ESPDNS_ROOT: the repository whose CHANGELOG.md is read (default: this script's).
set -eu
[ $# -eq 2 ] || { echo "usage: $0 TAG DIST" >&2; exit 2; }
tag=$1
dist=$2
: "${FORGE_API:?FORGE_API: the forge API, https://<host>/api/v1}" "${REPO:?REPO: <owner>/<name>}"
: "${RELEASE_TOKEN:?RELEASE_TOKEN: a token that can write the repository releases}"
here=$(dirname "$0")
v=$(sh "$here/check-version.sh" "$tag")
[ -f "$dist/SHA256SUMS" ] || { echo "$dist: no SHA256SUMS: not a release's files (espdns release build)" >&2; exit 1; }

# The notes: the changelog's section, then where to read how to check the files
notes=$(sh "$here/changelog.sh" "$v")
notes="$notes

---

Every file is listed in SHA256SUMS, signed with the espDNS release key in SHA256SUMS.sig:
check them before use as docs/releasing.md, Checking a release, says."

# JSON string: backslashes, quotes, tabs and carriage returns escaped, lines joined with \n
# (sed and awk's printf "%s" only, the same in every awk)
tab=$(printf '\t')
cr=$(printf '\r')
json_str() {
	printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e "s/$tab/\\\\t/g" -e "s/$cr/\\\\r/g" |
		awk 'NR > 1 { printf "%s", "\\n" } { printf "%s", $0 }'
}

# curl reads the token from a header file on standard input, never an argument
auth() { printf 'Authorization: token %s\n' "$RELEASE_TOKEN"; }
api() { auth | curl -sS --fail-with-body -H @- "$@"; }

if auth | curl -sS -o /dev/null -w '%{http_code}' -H @- "$FORGE_API/repos/$REPO/releases/tags/$tag" | grep -q '^200$'; then
	echo "$REPO already has a release for $tag: delete it first (a release is never changed in place)" >&2
	exit 1
fi

body=$(printf '{"tag_name":"%s","name":"espDNS %s","body":"%s","draft":true,"prerelease":%s}' \
	"$(json_str "$tag")" "$(json_str "$v")" "$(json_str "$notes")" \
	"$(case $v in 0.*) echo true ;; *) echo false ;; esac)")
created=$(api -H 'Content-Type: application/json' -X POST --data-binary "$body" "$FORGE_API/repos/$REPO/releases")
id=$(printf '%s' "$created" | sed -n 's/^{"id":\([0-9][0-9]*\)[,}].*/\1/p')
[ -n "$id" ] || { echo "the forge's answer has no release id: $created" >&2; exit 1; }

n=0
for f in "$dist"/*; do
	[ -f "$f" ] || continue
	name=$(basename "$f")
	api -o /dev/null -F "attachment=@$f" "$FORGE_API/repos/$REPO/releases/$id/assets?name=$name"
	echo "uploaded $name"
	n=$((n + 1))
done
echo "draft release $id for $tag with $n files: sign its SHA256SUMS, add SHA256SUMS.sig, publish it (docs/releasing.md)"
