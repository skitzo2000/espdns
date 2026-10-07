#!/bin/sh
# Builds a release's chip images (docs/releasing.md), generic, and exports each for the
# controller's builder:
#
#   build-firmware.sh OUT [IMAGE ...]     every firmware/images/* without IMAGEs
#
# Runs in the pinned ESP-IDF image (firmware/Makefile IDF_IMAGE), as the release workflow
# and docs/releasing.md run it, from the top of a clean checkout (none of your keys, data
# or site files in it: the container mounts all of it, with network):
#
#   docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD:/src" -w /src \
#     espressif/idf:v5.5.5@sha256:... sh scripts/release/build-firmware.sh build/release/images
#
# Each image is built afresh in firmware/build/release/<image> (never a build made with a
# deployment's settings), with no board, no address and no site defaults built in: what
# makes a node is its board partition and the config adoption gives it. It fails on a
# compiler warning, on a build that changed a component lock, or on an image with a
# deployment's address or defaults compiled in. OUT/<image>/ is then
# firmware/tools/export_image.py's export: what `espdns release build` packs.
set -eu
[ $# -ge 1 ] || { echo "usage: $0 OUT [IMAGE ...]" >&2; exit 2; }
root=$(cd "$(dirname "$0")/../.." && pwd)
fw=$root/firmware
mkdir -p "$1"
out=$(cd "$1" && pwd)
shift
[ $# -gt 0 ] || set -- $(ls "$fw/images")
# In the ESP-IDF image the entrypoint has exported its environment; a CI job's step has not
command -v idf.py >/dev/null 2>&1 || . "$IDF_PATH/export.sh" >/dev/null
cd "$fw"
for img in "$@"; do
	defaults=images/$img/sdkconfig.defaults
	[ -f "$defaults" ] || { echo "no chip image $img (firmware/images/$img)" >&2; exit 1; }
	target=$(sed -n 's/^CONFIG_IDF_TARGET="\(.*\)"/\1/p' "$defaults")
	b=build/release/$img
	rm -rf "$b" "$b.log"
	mkdir -p build/release
	echo "== $img ($target)"
	if ! idf.py -B "$b" -DIMAGE="$img" -DBOARD= -DBOARDS_DIR="$root/boards" -DIDF_TARGET="$target" \
		-DSTATIC_IP= -DSTATIC_NETMASK= -DSTATIC_GATEWAY= -DSITE_DEFAULTS= -DSDKCONFIG="$b/sdkconfig" \
		build >"$b.log" 2>&1; then
		tail -n 60 "$b.log" >&2
		echo "$img: the build failed (firmware/$b.log)" >&2
		exit 1
	fi
	if grep -E '(: warning:|^warning:)' "$b.log" >&2; then
		echo "$img: compiler warnings (firmware/$b.log)" >&2
		exit 1
	fi
	# Generic: nothing of a deployment's compiled in (firmware/main/CMakeLists.txt)
	if grep -E 'DNS2_(STATIC_IP|SITE_DEFAULTS)=' "$b/compile_commands.json" >/dev/null; then
		echo "$img: built with an address or site defaults: a release's images carry none" >&2
		exit 1
	fi
	python tools/export_image.py "$img" --build "$b" --out "$out/$img"
done
# The committed component locks, used as they are: a build that solved again would have
# rewritten one, and built other components than the release says
if command -v git >/dev/null 2>&1 && git -C "$root" rev-parse >/dev/null 2>&1; then
	changed=$(git -C "$root" status --porcelain -- 'firmware/dependencies.lock.*')
	if [ -n "$changed" ]; then
		echo "$changed" >&2
		echo "the build changed a component lock (firmware/dependencies.lock.*)" >&2
		exit 1
	fi
fi
