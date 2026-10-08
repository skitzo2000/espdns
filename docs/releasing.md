# Releasing espDNS

A release is one version of the firmware and the controller together (they share the
repository's [`VERSION`](../VERSION); README.md, Versions). Every step here is a docker
command or git. Nothing needs installing but Docker and git.

## What a release holds

CI builds a release's files when a version tag is pushed
([`.github/workflows/release.yml`](../.github/workflows/release.yml)) and puts them on
GitHub as a **draft** release, which only the repository's writers see:

| File | What it is |
| --- | --- |
| `espdns-<version>-image-<image>.tar.gz` | Each chip image (`firmware/images/*`), exported as the controller's builder imports it: `<image>/` with the bootloader, both partition tables, the OTA data, the app and `image.json` |
| `espdns-<version>-factory-<board>.bin` | Each catalog board's factory image (`boards/*.json`): one file, written at offset 0 of a new node's flash |
| `espdns-<version>-factory-<board>.manifest.json` | Its [ESP Web Tools](https://esphome.github.io/esp-web-tools/) manifest, as the builder's: erase, then install that file at offset 0 |
| `espdns-<version>-controller-image.txt` | The controller's image, pushed to the GitHub container registry: `ghcr.io/<owner>/espdns-controller:<version>@sha256:<digest>` |
| `SHA256SUMS` | The SHA-256 of every file above, as `sha256sum` writes it |
| `SHA256SUMS.sig` | The release key's signature over `SHA256SUMS`, added by a person (below) |

The images are **generic**: built with no board, no address and no site defaults, so they are the same for everyone. A chip image becomes a
node with a board partition, written by the controller's builder with the node's address.
A factory image carries its catalog board's definition and the address `dhcp`: a release
can't know a node's address, so a node flashed with one asks the network's DHCP server for
its first address, and adoption then gives it its own. On a network without a DHCP server,
flash new nodes from the controller's builder instead (it writes a static address), with
the release's chip images imported (Using a release, below).

The signature is the one the nodes check on every release they take: ECDSA P-256 over the
SHA-256 of `SHA256SUMS`, 64 bytes (`r || s`), made with the release key, checked with the
public key the firmware is built with, [`firmware/keys/release.pub`](../firmware/keys/release.pub),
fingerprint `ceccd5865252c2df` (the first 8 bytes of its SHA-256, as a node's `/status`
`keys` lists it). The key never goes to CI: CI only builds and lists the files; a person
signs, with the key on standard input.

## Once: the repository's settings

There is no secret to set. The workflows use the token GitHub gives each run, and each job
asks only for what it writes: the release job writes the draft release, the image job writes
the package. The repository needs only:

- Actions enabled (Settings, Actions, General). The default workflow permissions, read
  only, are fine: the workflows ask for more themselves.
- The package public, after the first release. The first release creates the package
  `espdns-controller` under the repository's owner, and GitHub makes a new package
  private. On the package's page, Package settings, change its visibility to public, once.
  Its label links it to the repository.

## Making a release

1. **The version.** From the repository's top, on a branch from `main`, with the changes
   written under `## [Unreleased]` in [`CHANGELOG.md`](../CHANGELOG.md):

   ```sh
   docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp --network none -v "$PWD:/src" -w /src \
     espressif/idf:v5.5.5@sha256:a9231d0697ab8f7517cc072e93b7c83e04907bfbfba80b6440d7dbbf90665cf2 \
     sh scripts/bump-version.sh patch      # or minor, major, or the version itself: 0.0.4
   ```

   It writes `VERSION` and makes the Unreleased section the new version's, dated today.
   Review the diff, commit it and merge it to `main` as any change.

2. **The tag.** On `main`, at that merge:

   ```sh
   git tag -a v0.0.2 -m "espDNS 0.0.2" && git push origin v0.0.2
   ```

   The release workflow runs on the tag (only on a `v*` tag, never on a branch). It stops
   before building anything if the tag is not `v` and `VERSION`, or if `CHANGELOG.md` has no
   section for that version. Then it builds the chip images (one job each); once they have
   all built, the controller's image (pushed to the registry, so a release whose firmware
   fails pushes nothing); then the factory images and `SHA256SUMS`, and makes the draft
   release, its notes the version's changelog. To run it again for the same tag, delete
   the draft first: a release already there is never changed.

3. **The controller's image to sign with,** built from the tag you checked out, so the
   public key it checks with comes from your copy of the source:

   ```sh
   git checkout v0.0.2
   docker build -t espdns-controller:v0.0.2 \
     --build-context boards=boards --build-context version=. --build-context keys=firmware/keys controller
   ```

4. **Sign.** Download the draft's `SHA256SUMS` into an empty directory, `sign/`, and sign it
   with the release key, which comes on standard input: from its file, or piped from your
   password manager. It is never an argument or an environment variable, and never written
   anywhere.

   ```sh
   docker run --rm -i -u "$(id -u):$(id -g)" -v "$PWD/sign:/release" --network none \
     --entrypoint /espdns espdns-controller:v0.0.2 \
     release sign -dir /release -pub /keys/release.pub < release.pem
   ```

   It writes `sign/SHA256SUMS.sig`. A key that is not the firmware's release key
   (`-pub`) is refused: nobody could check its signature.

5. **Publish.** Add `SHA256SUMS.sig` to the draft, and publish it.

6. **Check it** as anyone will (Checking a release, below), from the published release.

## Checking a release

Download all of a release's files into one directory, e.g. `espdns-0.0.2/`, and:

```sh
docker run --rm -v "$PWD/espdns-0.0.2:/release:ro" --network none \
  --entrypoint /espdns espdns-controller:v0.0.2 release verify -dir /release -pub /keys/release.pub
```

(`espdns-controller:v0.0.2`: the image built from the source at the tag, Making a release,
step 3.) It checks `SHA256SUMS.sig` with the release key, then every file against `SHA256SUMS`, and
says each one is OK; any file missing or changed, or a signature that isn't the key's, is an
error. It prints the key's fingerprint: `ceccd5865252c2df` is espDNS's release key. Use a
controller image built from the source (step 3 above), or the one you already run, rather
than the image of the release being checked: the check is only as good as the key it uses.

## Using a release

A published release is signed with the project's release key, and its images carry the
project's public keys. Use one only for nodes that run the project's firmware. If you made
your own keys, as [Getting started](getting-started.md#3-make-your-keys) does, your nodes
refuse the project's releases: build and sign your own as that guide shows.

- **The controller.** Its image is in `espdns-<version>-controller-image.txt`, by digest.
  In `controller/`, put it in `.env` as `ESPDNS_IMAGE=<that line>` and start it without
  building:

  ```sh
  docker pull "$(cat ../espdns-0.0.2/espdns-0.0.2-controller-image.txt)"
  docker compose up -d --no-build
  ```

  (or build it from the source, `docker compose up -d --build`, as
  [Getting started](getting-started.md#5-start-the-controller) does).

- **The chip images,** for the builder and for firmware updates on the Nodes page: import
  them into the controller's data directory. The import checks the release first, as
  `release verify` does, and imports nothing if it doesn't check. It takes the fleet lock:
  while a rollout or a job runs it is refused; run it again after. From `controller/`:

  ```sh
  docker compose run --rm -T -v "$PWD/../espdns-0.0.2:/release:ro" --entrypoint /espdns \
    espdns-controller release import -dir /release -pub /keys/release.pub -data /data
  ```

- **A new node,** from a factory image: in the controller's builder (a static address), or
  with the release's file and esptool, which erases the flash first, the board on USB:

  ```sh
  docker run --rm --device /dev/ttyACM0 -v "$PWD/espdns-0.0.2:/release:ro" \
    espressif/idf:v5.5.5@sha256:a9231d0697ab8f7517cc072e93b7c83e04907bfbfba80b6440d7dbbf90665cf2 \
    esptool.py -p /dev/ttyACM0 write_flash --erase-all 0 /release/espdns-0.0.2-factory-xiao-s3-sense.bin
  ```

  The node then starts on DHCP (What a release holds, above) and waits to be adopted.

## Building a release by hand

The release workflow's steps, as docker commands, for trying a change to them or building
a release without CI. Build in a clean checkout of the commit, never in the one your keys
(`firmware/secrets/`), data directory or site files are in: the firmware build's container
mounts the whole checkout, with the network the component registry needs. A new
worktree of the tag, or of your branch with the change committed:

```sh
git worktree add ../espdns-release v0.0.2
```

Then, from its top (`../espdns-release`), into `build/release/` (not in git):

```sh
IDF=espressif/idf:v5.5.5@sha256:a9231d0697ab8f7517cc072e93b7c83e04907bfbfba80b6440d7dbbf90665cf2

# Every chip image, generic, exported (build/release/images/<image>/); a compiler warning,
# a changed component lock, or an address or site defaults built in fails it
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD:/src" -w /src "$IDF" \
  sh scripts/release/build-firmware.sh build/release/images

# The controller's image (as in step 3 above), then the release's files and SHA256SUMS
docker build -t espdns-controller:build \
  --build-context boards=boards --build-context version=. --build-context keys=firmware/keys controller
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD/build/release:/release" --network none \
  --entrypoint /espdns espdns-controller:build release build -version "$(cat VERSION)" \
  -images /release/images -catalog /catalog -out /release/dist
```

`release build` refuses a chip image of another version or with an address built in, a
catalog board whose chip image is missing, and an output directory with anything in it.
CI adds `-include` with the controller image's reference after pushing it.

To try signing and checking without the release key, with a throwaway key made for the
purpose (the firmware's own tool; never a real key, and never one the nodes trust):

```sh
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD/build/release:/out" -v "$PWD/firmware/tools:/tools:ro" \
  --network none "$IDF" python /tools/keygen.py /out/throwaway.pem /out/throwaway.pub
docker run --rm -i -u "$(id -u):$(id -g)" -v "$PWD/build/release:/release" --network none \
  --entrypoint /espdns espdns-controller:build \
  release sign -dir /release/dist -pub /release/throwaway.pub < build/release/throwaway.pem
docker run --rm -v "$PWD/build/release:/release:ro" --network none \
  --entrypoint /espdns espdns-controller:build release verify -dir /release/dist -pub /release/throwaway.pub
```

The scripts the workflow runs are in [`scripts/release/`](../scripts/release/):
`check-version.sh` (the tag against `VERSION` and `CHANGELOG.md`), `changelog.sh` (a
version's changelog), `notes.sh` (the draft's notes: the changelog and how to check the
files) and `build-firmware.sh` (above). The workflow makes the draft with GitHub's `gh`.
`publish.sh` makes the same draft on a Gitea or Forgejo forge, for a copy of the
repository kept there. The
release's files are `controller/internal/dist`; its tests and the scripts' run with the
controller's (`controller/releasescripts_test.go`).
