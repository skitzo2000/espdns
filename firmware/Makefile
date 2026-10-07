# Everything runs in the pinned ESP-IDF container — nothing is installed on the host.
# The main checkout (this one, or the one a git worktree belongs to)
FLEET_MAIN := $(patsubst %/.git,%,$(filter %/.git,$(shell git -C '$(CURDIR)' rev-parse --path-format=absolute --git-common-dir 2>/dev/null)))
# This deployment's own make settings, not in git (.gitignore): the values a site sets for
# itself, as `make VAR=...` would (the node ota pushes to, the addresses its transitional
# images carry, its firmware defaults), kept in the main checkout's firmware/local.mk so
# every worktree shares them, as controller/local.mk is for the controller. None: the
# project's defaults, which name no node and no address. Set them with ?= so the command
# line and the environment still win. local.mk.example shows each; docs/rollout.md, This site.
FW_LOCAL_MK ?= $(or $(FLEET_MAIN),$(abspath $(CURDIR)/..))/firmware/local.mk
-include $(FW_LOCAL_MK)
# The ESP-IDF image, pinned by digest (the tag says which release it is): every checkout
# builds with the same toolchain. CI runs in the same one (README.md, Pinned versions).
IDF_IMAGE ?= espressif/idf:v5.5.5@sha256:a9231d0697ab8f7517cc072e93b7c83e04907bfbfba80b6440d7dbbf90665cf2
PORT      ?= /dev/ttyACM0
# The node ota, status, boottime and bench-ota reach: no default (HOST ?= in local.mk)
HOST      ?=
NEW_HOST  ?=
SECS      ?= 30
# What to build (docs/design.md, Boards and images):
#   make build IMAGE=esp32s3-octal   a chip image, as the builder flashes with a board partition
#   make build BOARD=xiao-s3-sense   a transitional image: the board's chip image with that catalog
#                                    board built in, for a node without a board partition yet
# With neither, DEFAULT_BOARD (local.mk: a deployment's usual board); none, set one of them.
IMAGE     ?=
ifeq ($(IMAGE),)
BOARD     ?= $(DEFAULT_BOARD)
endif
ifneq ($(BOARD),)
IMAGE     := $(shell python3 -c "import json; print(json.load(open('../boards/$(BOARD).json'))['image'])")
BUILD     := build/$(BOARD)
else
BUILD     := build/$(IMAGE)
endif
# Addresses. A node never asks DHCP for one on its own (a network may have no DHCP server):
# it starts on the address in its node config, else in its board definition, else the one
# its image was built with, else it has none. The project names no address anywhere.
#   ADDRESS, GATEWAY  what `make factory` writes into the board partition, as the builder does
#                     ("dhcp" only for a network with a DHCP server). Required for a factory
#                     image, and always given: there is no default address, so a new node never
#                     gets another node's address by accident. GATEWAY defaults to
#                     STATIC_GATEWAY for a static ADDRESS. `make boards` takes one address per
#                     board, ADDRESS_<board>=a.b.c.d/nn.
#   STATIC_IP         built into a transitional image (BOARD=, no board partition): the nodes
#                     in service keep the address their earlier firmware was built with, so a
#                     deployment with such nodes names each one's in local.mk,
#                     STATIC_IP_<board> ?= a.b.c.d (rollouts depend on it), with the
#                     STATIC_NETMASK and STATIC_GATEWAY that go with them (required with a
#                     STATIC_IP). Without one, a transitional image carries no address. With a
#                     static ADDRESS, `make build` builds in that address instead: its netmask
#                     from the prefix length, and GATEWAY. Chip images (IMAGE=) carry none.
#   SITE_DEFAULTS     a header of the deployment's own firmware defaults (zone primary, zones,
#                     forwarders; main/config.h, site-defaults.h.example), built into every
#                     image made here; none, the project's (no primary, no zones).
STATIC_NETMASK ?=
STATIC_GATEWAY ?=
SITE_DEFAULTS  ?=
ADDRESS   ?= $(ADDRESS_$(BOARD))
GATEWAY   ?= $(if $(filter dhcp,$(ADDRESS)),,$(STATIC_GATEWAY))
ifneq ($(filter-out dhcp,$(ADDRESS)),)
STATIC_IP     ?= $(firstword $(subst /, ,$(ADDRESS)))
BUILT_NETMASK  = $(shell python3 -c 'import ipaddress,sys; print(ipaddress.ip_network(sys.argv[1], strict=False).netmask)' '$(ADDRESS)' 2>/dev/null)
BUILT_GATEWAY  = $(GATEWAY)
else
STATIC_IP     ?= $(if $(ADDRESS),,$(STATIC_IP_$(BOARD)))
BUILT_NETMASK  = $(STATIC_NETMASK)
BUILT_GATEWAY  = $(STATIC_GATEWAY)
endif
# What a target needs, else a make error naming the variable to set
need_image = $(if $(IMAGE),,$(error set BOARD=<catalog board> or IMAGE=<chip image> (or DEFAULT_BOARD ?= in local.mk)))
need_host  = $(if $(HOST),,$(error HOST= the node's address (or HOST ?= in local.mk): there is no default node))
# $(call need_static): a transitional image's address is whole, else a make error naming
# what is missing. REQUIRE_STATIC_IP=1 (controller/'s make fleet-firmware: the images of
# nodes in service, which keep the address they were built with): one is required, so a
# missing local.mk never builds a node's image without its address.
need_static = $(if $(REQUIRE_STATIC_IP),$(if $(STATIC_IP),,$(error BOARD=$(BOARD): no address to build in for a node \
	in service: set STATIC_IP_$(BOARD) ?= a.b.c.d in firmware/local.mk ($(FW_LOCAL_MK)))))$(if \
	$(STATIC_IP),$(if $(BUILT_NETMASK),,$(error STATIC_IP=$(STATIC_IP): set STATIC_NETMASK= (local.mk), or give ADDRESS=a.b.c.d/nn))$(if \
	$(BUILT_GATEWAY),,$(error STATIC_IP=$(STATIC_IP): set STATIC_GATEWAY= (local.mk), or GATEWAY= with ADDRESS)))
ifneq ($(SITE_DEFAULTS),)
ifeq ($(wildcard $(SITE_DEFAULTS)),)
$(error SITE_DEFAULTS: no such file: $(SITE_DEFAULTS))
endif
endif
IMAGES    := $(notdir $(wildcard images/*))
CATALOG   := $(basename $(notdir $(wildcard ../boards/*.json)))

# The containers (README.md, Builds and the release key). Each runs as you, with no network
# unless it talks to something, the source (this directory) read-only and only what it writes
# mounted writable over it, the board catalog (boards/ at the top of the repo) read-only at
# /boards, the repository's VERSION read-only at /VERSION (the source's parent, where
# CMakeLists.txt reads it) and the site defaults (if any) at /site/defaults.h. secrets/, the private keys, is
# covered by an empty read-only tmpfs in every container but the signing step's (SIGN): a
# build, a test, the component fetch or a push never sees a key. The directories mounted are
# made first, as you (docker would make a missing one as root, and can't make a mount point
# in the read-only source).
#   DOCKER      builds, tests, images, flashing: offline, writes build/ and dist/ only, reads
#               the components the committed lock names (managed_components/, read-only)
#   FETCH       the component fetch: the network, writes managed_components/ only
#   COMPONENTS_UPDATE  make components: the network, writes the locks (the source) too
#   NET         a push's talking to the node (make ota, bench-ota): host network, writes only
#               the release directory ($(OTA_DIR))
#   SIGN        the signing step: no network, secrets/ read-only (in the read-only source),
#               writes only the release directory; the one container that sees a key
#   KEYGEN      make keys: no network, writes keys/ and secrets/
MOUNT_DIRS = build dist managed_components secrets
CONTAINER = mkdir -p $(MOUNT_DIRS) && chmod 700 secrets && docker run --rm -u $(shell id -u):$(shell id -g) \
         -e HOME=/tmp -e PYTHONDONTWRITEBYTECODE=1 -v $(CURDIR)/../boards:/boards:ro -v $(CURDIR)/../VERSION:/VERSION:ro \
         $(if $(SITE_DEFAULTS),-v $(abspath $(SITE_DEFAULTS)):/site/defaults.h:ro )-w /project
SRC       = -v $(CURDIR):/project:ro
NO_KEYS   = --mount type=tmpfs,destination=/project/secrets,readonly
RW        = $(foreach d,$(1),-v $(CURDIR)/$(d):/project/$(d))
DOCKER    = $(CONTAINER) $(SRC) $(NO_KEYS) --network none $(call RW,build dist) \
            -v $(CURDIR)/managed_components:/project/managed_components:ro
FETCH     = $(CONTAINER) $(SRC) $(NO_KEYS) $(call RW,managed_components)
COMPONENTS_UPDATE = $(CONTAINER) -v $(CURDIR):/project $(NO_KEYS)
OTA_DIR   = $(BUILD)/release
NET       = mkdir -p $(OTA_DIR) && $(CONTAINER) $(SRC) $(NO_KEYS) --network host $(call RW,$(OTA_DIR))
SIGN      = mkdir -p $(OTA_DIR) && $(CONTAINER) $(SRC) --network none $(call RW,$(OTA_DIR))
KEYGEN    = $(CONTAINER) $(SRC) --network none $(call RW,keys secrets)
BOARDS_DIR = /boards
SITE_DEFAULTS_IN = $(if $(SITE_DEFAULTS),/site/defaults.h)
# NATIVE=1: already inside the ESP-IDF container (CI, ../.gitea/workflows/ci.yml). The same
# commands run without docker, with the catalog read from ../boards.
ifeq ($(NATIVE),1)
DOCKER     =
FETCH      =
COMPONENTS_UPDATE =
NET        =
SIGN       =
KEYGEN     =
IDF_IMAGE  =
BOARDS_DIR = $(abspath $(CURDIR)/../boards)
SITE_DEFAULTS_IN = $(if $(SITE_DEFAULTS),$(abspath $(SITE_DEFAULTS)))
endif
TARGET = $(shell sed -n 's/^CONFIG_IDF_TARGET="\(.*\)"/\1/p' images/$(IMAGE)/sdkconfig.defaults)
IDF    = idf.py -B $(BUILD) -DIMAGE=$(IMAGE) -DBOARD=$(BOARD) -DBOARDS_DIR=$(BOARDS_DIR) -DIDF_TARGET=$(TARGET) \
         -DSTATIC_IP=$(STATIC_IP) -DSTATIC_NETMASK=$(if $(STATIC_IP),$(BUILT_NETMASK)) \
         -DSTATIC_GATEWAY=$(if $(STATIC_IP),$(BUILT_GATEWAY)) -DSITE_DEFAULTS=$(SITE_DEFAULTS_IN) \
         -DSDKCONFIG=$(BUILD)/sdkconfig $(IDF_EXTRA)
FETCHED = build/.components-$(TARGET)
DEVICE = --device $(PORT) --group-add $(shell stat -c %g $(PORT) 2>/dev/null || echo 0)

.PHONY: need-host build components FORCE images export-images boards print-address print-idf-image factory flash ota status boottime keys key-restore release-key-restore enclosure monitor log menuconfig clean test bench-board bench-board-run bench-ota

need-host:
	$(need_host)

# A build's sdkconfig is made from the defaults once; start it over when they change. The
# components it uses are fetched first (FETCHED, below), so the build itself runs offline.
build: keys/release.pub keys/recovery.pub $(if $(DOCKER),$(if $(IMAGE),$(FETCHED)))
	@$(need_image)$(call need_static)for f in sdkconfig.defaults images/$(IMAGE)/sdkconfig.defaults; do \
	  if [ -f $(BUILD)/sdkconfig ] && [ $$f -nt $(BUILD)/sdkconfig ]; then echo "$$f changed: new sdkconfig"; rm -f $(BUILD)/sdkconfig; fi; done
	$(DOCKER) $(IDF_IMAGE) $(IDF) build

# The components from the ESP component registry (main/idf_component.yml), as the committed
# lock for the image's chip target, dependencies.lock.<target>, names them (CMakeLists.txt):
# fetched into managed_components/ once, with the network and nothing else writable, before
# the offline builds, and again when the manifest or the lock changes (or managed_components/
# is gone). The fetch never changes a lock: one that no longer matches the manifest is
# refused, and `make components` solves again.
build/.components-%: main/idf_component.yml dependencies.lock.% $(if $(wildcard managed_components/*/),,FORCE)
	@echo "fetching the components for $* (dependencies.lock.$*)"
	$(FETCH) $(IDF_IMAGE) idf.py -B /tmp/components -DIMAGE=$(IMAGE) -DBOARDS_DIR=$(BOARDS_DIR) \
	  -DIDF_TARGET=$* -DSDKCONFIG=/tmp/components/sdkconfig reconfigure >/dev/null
	@touch $@
dependencies.lock.%:
	@echo "no dependencies.lock.$* (the component lock for chip target $*): make components writes it"; exit 1
FORCE:

# The component locks, solved again from main/idf_component.yml: the newest versions it
# allows, for every chip target of images/*, written to dependencies.lock.<target> (and
# fetched). The one step that changes them, with the network: review the diff and commit it
# (README.md, Pinned versions).
components:
	rm -f dependencies.lock.* build/.components-*
	@for i in $(IMAGES); do t=$$(sed -n 's/^CONFIG_IDF_TARGET="\(.*\)"/\1/p' images/$$i/sdkconfig.defaults); \
	  case " $$done " in *" $$t "*) continue;; esac; done="$$done $$t"; echo "== $$t ($$i)"; \
	  $(COMPONENTS_UPDATE) $(IDF_IMAGE) idf.py -B /tmp/components -DIMAGE=$$i -DBOARDS_DIR=$(BOARDS_DIR) \
	    -DIDF_TARGET=$$t -DSDKCONFIG=/tmp/components/sdkconfig reconfigure >/dev/null || exit 1; \
	  touch build/.components-$$t; done

# Every chip image (images/*), as CI builds them (no address built in)
images: keys/release.pub keys/recovery.pub
	@for i in $(IMAGES); do echo "== $$i"; $(MAKE) -s build IMAGE=$$i BOARD= ADDRESS= STATIC_IP= || exit 1; done

# Every chip image, exported for the controller's builder into dist/images/<image>/
# (chip images carry no address: the builder writes the node's address into its board partition;
# SITE_DEFAULTS, if set, are built in as into every image made here)
# (built first, then exported: no docker run on a line with $(MAKE), which make -n would run)
export-images: images
	@for i in $(IMAGES); do echo "== $$i"; $(DOCKER) $(IDF_IMAGE) python tools/export_image.py $$i | tail -1; done

# A factory image for every catalog board given an address on the command line
# (ADDRESS_<board>=a.b.c.d/nn, e.g. ADDRESS_ws-s3-eth=...), in dist/<board>/. One ADDRESS
# for every board is refused: no two nodes may share an address.
boards: keys/release.pub keys/recovery.pub
	@test -z "$(filter command line environment,$(origin ADDRESS))" || \
	  { echo "make boards takes ADDRESS_<board>=a.b.c.d/nn per board, not one ADDRESS for all"; exit 1; }
	@for b in $(CATALOG); do echo "== $$b"; \
	  if [ -z "$$($(MAKE) -s --no-print-directory print-address BOARD=$$b)" ]; then \
	    echo "skipped: no address (ADDRESS_$$b=a.b.c.d/nn, or make factory BOARD=$$b ADDRESS=a.b.c.d/nn GATEWAY=...)"; continue; fi; \
	  $(MAKE) -s factory BOARD=$$b || exit 1; done

print-address:
	@echo $(ADDRESS)

# The pinned ESP-IDF image (CI's containers are the same one; controller/pins_test.go checks)
print-idf-image:
	@echo $(IDF_IMAGE)

# dist/<board>/: the board's chip image (built without a fallback or an address) with its board
# partition, which carries the node's address, as one whole-flash image for a new node, plus an
# ESP Web Tools manifest.json
factory: keys/release.pub keys/recovery.pub
	@test -n "$(ADDRESS)" || { echo "set ADDRESS=a.b.c.d/nn (and GATEWAY=), or ADDRESS=dhcp on a network with a DHCP server"; exit 1; }
	$(MAKE) -s build IMAGE=$(IMAGE) BOARD= ADDRESS= STATIC_IP=
	$(DOCKER) $(IDF_IMAGE) python tools/factory.py --board $(BOARDS_DIR)/$(BOARD).json --build build/$(IMAGE) \
	  --address $(ADDRESS) $(if $(GATEWAY),--gateway $(GATEWAY))

# Release signing keys (ECDSA P-256). The public halves in keys/ are built into the
# firmware and committed; the private halves in secrets/ are not. Created once: an
# existing file is never overwritten. Move secrets/recovery.pem offline after backing it up.
keys: keys/release.pub keys/recovery.pub
keys/%.pub:
	mkdir -p keys secrets && chmod 700 secrets
	$(KEYGEN) $(IDF_IMAGE) python tools/keygen.py secrets/$*.pem $@

# SECRET_RUN as controller/Makefile has it (empty by default): $(call SECRET_RUN,NAME ...)
# runs the command after it with each named environment variable set to its secret, from a
# password manager (local.mk). Empty: the variable must already be in make's environment.
SECRET_RUN ?=

# Recover the release signing key from $ESPDNS_RELEASE_KEY (the PEM file base64-encoded).
# Refuses to overwrite an existing key.
release-key-restore:
	@test ! -e secrets/release.pem || { echo "secrets/release.pem already exists"; exit 1; }
	mkdir -p secrets && chmod 700 secrets
	$(call SECRET_RUN,ESPDNS_RELEASE_KEY) sh -c 'umask 077; printf %s "$$ESPDNS_RELEASE_KEY" | base64 -d > secrets/release.pem'
	@head -1 secrets/release.pem | grep -q "BEGIN PRIVATE KEY" && echo "restored secrets/release.pem"

# Legacy HMAC key, needed only to push the first signed-release build to a node still
# running pre-manifest firmware (ota_push.py detects this). Recovered from $DNS2_OTA_KEY
# (base64 of the key).
key-restore:
	@test ! -e secrets/ota.key || { echo "secrets/ota.key already exists"; exit 1; }
	mkdir -p secrets && chmod 700 secrets
	$(call SECRET_RUN,DNS2_OTA_KEY) sh -c 'umask 077; printf %s "$$DNS2_OTA_KEY" | base64 -d > secrets/ota.key'
	@test "$$(stat -c %s secrets/ota.key)" = 32 && echo "restored secrets/ota.key"

# The fleet lock (controller/internal/fleetlock): ota and bench-ota push to a node, so they
# hold it as the controller's fleet-* targets and jobs do, and refuse to run while one of
# those changes the fleet (nor can one start during them). flock(1) takes the same flock(2)
# on the main checkout's controller/data/fleet.lock (shared by every git worktree); no data
# directory there, no lock (nothing else can be changing the fleet).
FLEET_DATA ?= $(or $(FLEET_MAIN),$(abspath $(CURDIR)/..))/controller/data
FLEET_LOCKED = $(if $(wildcard $(FLEET_DATA)/.),flock -n -E 75 '$(FLEET_DATA)/fleet.lock')
# $(call fleet_locked,command): the command under the fleet lock, or a refusal if it is held
fleet_locked = $(FLEET_LOCKED) $(1); s=$$?; test $$s != 75 || \
	echo "the fleet is locked ($(FLEET_DATA)/fleet.lock): a fleet change is running; try again when it is done"; exit $$s

# A push in three steps, three containers (tools/ota_push.py): prepare reads the node's
# /status and checks the image against it (the network, no key); sign writes the signed
# release into $(OTA_DIR) (no network, the key read-only: the only step that sees it); push
# uploads it and waits (the network, no key). What sign signs (the image, its name) is given
# to it here, never taken from prepare's plan. $(call ota_steps,<image file>,<prepare's flags>)
ota_steps = $(NET) $(IDF_IMAGE) python tools/ota_push.py prepare --dir $(OTA_DIR) --host $(HOST) $(if $(BOARD),--board $(BOARD)) \
	  --image $(1) --image-name $(IMAGE) $(2) && \
	$(SIGN) $(IDF_IMAGE) python tools/ota_push.py sign --dir $(OTA_DIR) --image $(1) --image-name $(IMAGE) \
	  $(if $(BOARD),--board $(BOARD)) && \
	$(NET) $(IDF_IMAGE) python tools/ota_push.py push --dir $(OTA_DIR)

# Network update: sign a release for this node, upload, wait for the new build to confirm itself
ota: need-host build
	$(call fleet_locked,sh -c '$(call ota_steps,$(BUILD)/dns2.bin,$(if $(NEW_HOST),--new-host $(NEW_HOST)) $(if $(FORCE),--force))')

status:
	@$(need_host)curl -s http://$(HOST)/status | python3 -m json.tool

# Probe DNS every 100 ms and report how long the node is silent across a reboot or power
# cycle (ROM and bootloader included). Start it, then power-cycle or `make ota` the node.
boottime:
	$(need_host)python3 tools/boottime.py --host $(HOST)

flash: build
	$(DOCKER) $(DEVICE) $(IDF_IMAGE) $(IDF) -p $(PORT) flash

# Interactive monitor (Ctrl+] to quit)
monitor:
	$(DOCKER) -it $(DEVICE) $(IDF_IMAGE) $(IDF) -p $(PORT) monitor

# Non-interactive: reset the board and capture $(SECS) seconds of log
log:
	$(DOCKER) $(DEVICE) $(IDF_IMAGE) python /project/tools/serial_log.py $(PORT) $(SECS)

menuconfig:
	$(DOCKER) -it $(IDF_IMAGE) $(IDF) menuconfig

clean:
	$(DOCKER) $(IDF_IMAGE) $(IDF) fullclean

# On-board blocklist benchmark (bench/blocklist, tests/bench_blocklist.c). FILE and QUERIES
# come from `blockbench -write` in controller/; the first 20000 queries are used.
#   make bench-board BOARD=xiao-s3-sense FILE=list.bin QUERIES=q.txt          build only
#   make bench-board-run BOARD=xiao-s3-sense FILE=... QUERIES=... SECS=60     flash, print results
# This replaces the board's firmware: reflash the node image afterwards.
BENCH     = bench/blocklist
BENCH_IDF = idf.py -C /project/$(BENCH) -B /project/$(BENCH)/build-$(IMAGE) -DIDF_TARGET=$(TARGET) \
            -DSDKCONFIG=/project/$(BENCH)/build-$(IMAGE)/sdkconfig \
            "-DSDKCONFIG_DEFAULTS=sdkconfig.defaults;/project/images/$(IMAGE)/sdkconfig.defaults"

bench-board:
	@test -n "$(FILE)" -a -n "$(QUERIES)" || { echo "set FILE= and QUERIES="; exit 1; }
	mkdir -p $(BENCH)/data && cp $(FILE) $(BENCH)/data/list.bin && head -n 20000 $(QUERIES) > $(BENCH)/data/q.txt
	$(DOCKER) $(call RW,$(BENCH)) $(IDF_IMAGE) $(BENCH_IDF) build

bench-board-run: bench-board
	$(DOCKER) $(call RW,$(BENCH)) $(DEVICE) $(IDF_IMAGE) $(BENCH_IDF) -p $(PORT) flash
	$(DOCKER) $(DEVICE) $(IDF_IMAGE) python /project/tools/serial_log.py $(PORT) $(SECS)

# The same benchmark on a node over the network, next to live DNS: push a bench build of
# the node firmware (POST /bench added; it never confirms itself and rolls back to the
# previous firmware on its own within 10 minutes), then post the list and queries to it.
# The push and the benchmark hold the fleet lock; the rollback, minutes later, is the
# node's own.
#   make bench-ota FILE=list.bin QUERIES=q.txt          (HOST and BOARD as for `make ota`)
BENCH_BUILD = build/bench-$(or $(BOARD),$(IMAGE))
bench-ota: OTA_DIR = $(BENCH_BUILD)/release
bench-ota: need-host keys/release.pub keys/recovery.pub
	@test -n "$(FILE)" -a -n "$(QUERIES)" || { echo "set FILE= and QUERIES="; exit 1; }
	$(MAKE) -s build BUILD=$(BENCH_BUILD) IDF_EXTRA=-DDNS2_BENCH_BLOCKLIST=1
	$(call fleet_locked,sh -c '$(call ota_steps,$(BENCH_BUILD)/dns2.bin,--force --trial) && \
	  python3 tools/bench_post.py $(HOST) $(FILE) $(QUERIES)')

# Host unit tests for the portable DNS core (ASan + UBSan)
test:
ifeq ($(NATIVE),1)
	$(MAKE) -s -B -C tests test
else
	$(DOCKER) $(call RW,tests) -w /project/tests $(IDF_IMAGE) make -s -B test
endif

# 3D-printable case: rebuild STL/STEP/FCStd in enclosure/out and run the fit checks;
# CASE_LABEL= the text on the lid (default espDNS; local.mk: the node's name and address)
enclosure:
	DNS2_CASE_OUT=$(CURDIR)/enclosure/out $(if $(CASE_LABEL),DNS2_CASE_LABEL='$(CASE_LABEL)') freecadcmd -c "exec(open('enclosure/dns2_case.py').read())" 2>&1 | \
	  grep -E "^(fit check|pin check|snap check|outside|hardware|RESULT|label)"
