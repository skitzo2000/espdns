#!/bin/sh
# Vendors esp-web-tools' browser bundle into web/vendor/esp-web-tools/ (served by the
# controller, embedded in the binary): `make vendor-ewt V=<version> SHA512=<integrity>`.
#
#   V       the npm version, e.g. 10.4.0
#   SHA512  the registry's integrity for that version, sha512-<base64>, as
#           https://registry.npmjs.org/esp-web-tools/<version> gives it (dist.integrity)
#
# Downloads the package's tarball from the npm registry, refuses it unless its sha512 is
# the one given, then replaces the directory's .js files with the tarball's dist/web/ and
# its LICENSE, writes VERSION (the version and the integrity) and regenerates SHA256SUMS
# (which the controller's tests check against the embedded bytes). THIRD_PARTY.md is kept:
# check the new version's bundled dependencies against it.
set -eu

die() { echo "vendor-esp-web-tools: $*" >&2; exit 1; }

[ $# -eq 2 ] || die "usage: $0 <version> sha512-<base64>"
version=$1
want=$2
case $version in
'' | *[!0-9A-Za-z.+-]*) die "version '$version': digits, letters, '.', '+' and '-' only" ;;
esac
case $want in
sha512-?*) ;;
*) die "SHA512 must be the registry's integrity, sha512-<base64> (dist.integrity)" ;;
esac

# sha512 of a file as an SRI (sha512-<base64>)
sri() {
	if command -v openssl >/dev/null 2>&1; then
		printf 'sha512-%s' "$(openssl dgst -sha512 -binary "$1" | base64 | tr -d '\n')"
	elif command -v sha512sum >/dev/null 2>&1 && command -v xxd >/dev/null 2>&1; then
		printf 'sha512-%s' "$(sha512sum "$1" | cut -d' ' -f1 | xxd -r -p | base64 | tr -d '\n')"
	elif command -v python3 >/dev/null 2>&1; then
		python3 -c 'import base64,hashlib,sys; print("sha512-" + base64.b64encode(hashlib.sha512(open(sys.argv[1], "rb").read()).digest()).decode(), end="")' "$1"
	else
		die "need openssl, sha512sum and xxd, or python3 to check the download"
	fi
}

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

here=$(cd "$(dirname "$0")/.." && pwd)
dest=$here/web/vendor/esp-web-tools
[ -f "$dest/THIRD_PARTY.md" ] || die "$dest/THIRD_PARTY.md is missing"

# Next to the directory, so the swap at the end is a rename on one filesystem
tmp=$(mktemp -d "$here/web/vendor/.update.XXXXXX")
# Interrupted: exit (running the EXIT trap), not carry on after the interrupted command
trap 'rm -rf "$tmp"' EXIT
trap 'exit 1' HUP INT TERM

url=https://registry.npmjs.org/esp-web-tools/-/esp-web-tools-$version.tgz
curl -fsSL --proto '=https' -o "$tmp/package.tgz" "$url" || die "download failed: $url"
got=$(sri "$tmp/package.tgz")
[ "$got" = "$want" ] || die "refusing $url: its sha512 is $got, not $want"

tar -xzf "$tmp/package.tgz" -C "$tmp" package/dist/web package/LICENSE ||
	die "the tarball has no package/dist/web or package/LICENSE"
# Plain files only: cp follows a symlink, which would copy a file of this machine's instead
[ -f "$tmp"/package/LICENSE ] && [ ! -L "$tmp"/package/LICENSE ] || die "not a plain file: LICENSE"
for f in "$tmp"/package/dist/web/* "$tmp"/package/dist/web/.[!.]*; do
	[ -e "$f" ] || continue
	case $f in
	*.js) [ -f "$f" ] && [ ! -L "$f" ] || die "not a plain file: ${f#"$tmp"/package/}" ;;
	*) die "dist/web holds more than .js files: ${f#"$tmp"/package/}" ;;
	esac
done

new=$tmp/new
mkdir "$new"
cp "$tmp"/package/dist/web/*.js "$new"/
cp "$tmp"/package/LICENSE "$dest"/THIRD_PARTY.md "$new"/
printf 'esp-web-tools %s\n%s\n' "$version" "$want" >"$new"/VERSION
(cd "$new" && LC_ALL=C ls | while read -r f; do sha256 "$f"; done) >"$tmp"/SHA256SUMS
mv "$tmp"/SHA256SUMS "$new"/SHA256SUMS

# The old directory is kept until the new one is in place (then removed with $tmp)
mv "$dest" "$tmp"/old
mv "$new" "$dest" || { mv "$tmp"/old "$dest"; die "could not move the new files into $dest"; }
echo "esp-web-tools $version vendored in $dest ($(ls "$dest" | grep -c '\.js$') scripts)."
echo "Check THIRD_PARTY.md against its dependencies, then make test and flash a board from the builder."
