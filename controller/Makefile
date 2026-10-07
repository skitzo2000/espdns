# espDNS controller. Running it: Docker Compose (compose.yaml; controller/README.md):
# docker compose up -d --build, not make. `make run`: the native binary, for development only.
# Static builds (CGO_ENABLED=0): no C compiler needed, on the host (Nix has none) or in Docker.
# The CLI: `make build`, then ./espdns blocklist|push|pause (or, in the image,
# `docker compose run --rm -T --entrypoint /espdns espdns-controller ...`).
# Operating the fleet (rollouts, adoption): the fleet-* targets below, docs/rollout.md.
# The data directory: controller/data of the main checkout, also from a git worktree (as
# .claude/worktrees/...), so every checkout shares one fleet lock, one settings file and one
# action log: a fleet-* target run from a worktree can't race one run from the main checkout.
MAIN_CHECKOUT := $(patsubst %/.git,%,$(filter %/.git,$(shell git -C '$(CURDIR)' rev-parse --path-format=absolute --git-common-dir 2>/dev/null)))
DATA   ?= $(if $(MAIN_CHECKOUT),$(MAIN_CHECKOUT)/controller/data,$(CURDIR)/data)
# This deployment's own make settings, not in git (.gitignore): the values a site sets for
# itself, as `make VAR=...` would, kept in the main checkout's controller/local.mk so every
# worktree shares them, as it shares the data directory; none, the project's defaults, which
# name no node, board or address. Set them with ?= so the command line and the environment
# still win: the fleet (NODES, CANARY, FLEET_BOARDS, CONFIGS, below), where the secrets come
# from (SECRET_RUN, PRIMARY_TOKEN_ENV, RELEASE_KEY_FILE, below). local.mk.example shows each;
# docs/rollout.md, This site. The firmware's own are in firmware/local.mk (fleet-firmware builds with them).
LOCAL_MK ?= $(if $(MAIN_CHECKOUT),$(MAIN_CHECKOUT)/controller/local.mk,$(CURDIR)/local.mk)
-include $(LOCAL_MK)
LISTEN ?= 127.0.0.1:8480
IMAGE  ?= espdns-controller

.PHONY: build run firmware test image data

# The version (internal/version): the repository's VERSION, linked in as the Dockerfile does.
# A build without it (go run, go test, the browser tests) says "dev".
VERSION_LDFLAGS = -X github.com/skitzo2000/espdns/controller/internal/version.Version=$(shell cat $(CURDIR)/../VERSION)

build:
	CGO_ENABLED=0 go build -trimpath -ldflags='$(VERSION_LDFLAGS)' -o espdns-controller ./cmd/espdns-controller
	CGO_ENABLED=0 go build -trimpath -ldflags='$(VERSION_LDFLAGS)' -o espdns ./cmd/espdns

# The browser tests (e2e/, controller/README.md): Chromium against a controller built from
# this checkout on 127.0.0.1:$(E2E_PORT), a throwaway data directory; no nodes. On the host,
# outside go test and Docker: Node.js, Playwright as e2e/package-lock.json pins it, and its
# Chromium (downloaded to ~/.cache/ms-playwright on the first run, no root).
E2E_PORT ?= 18480
.PHONY: e2e
e2e:
	cd e2e && npm ci --no-audit --no-fund && npx playwright install --only-shell chromium && E2E_PORT=$(E2E_PORT) npx playwright test

# Development only: the native binary in the foreground (the service: docker compose up -d)
run: build data
	./espdns-controller -data $(DATA) -listen $(LISTEN)

# Import the chip images exported by `make export-images` in firmware/
firmware:
	umask 077 && mkdir -p $(DATA)/firmware/images && cp -r ../firmware/dist/images/. $(DATA)/firmware/images/

test:
	CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...

# Updates the vendored esp-web-tools (web/vendor/esp-web-tools/, the builder's flasher):
# V=<version> SHA512=<the registry's dist.integrity for it, sha512-...>. Refuses a tarball
# whose sha512 differs. Then make test, make e2e, and flash a board from the builder.
.PHONY: vendor-ewt
vendor-ewt:
	@$(if $(and $(V),$(SHA512)),,echo "usage: make vendor-ewt V=<version> SHA512=sha512-<base64> (https://registry.npmjs.org/esp-web-tools/<version>, dist.integrity)"; exit 1)
	scripts/vendor-esp-web-tools.sh '$(V)' '$(SHA512)'

# The image the CLI targets below run, built as compose.yaml builds it (one definition: its
# build:, with the board catalog ../boards as its own context, at /catalog), named $(IMAGE).
# Compose reads all of compose.yaml for a build too, so the uid and gid it requires are given
# here (a build doesn't use them): no .env needed for the make targets. Docker Compose 2.17+.
image:
	ESPDNS_IMAGE='$(IMAGE)' ESPDNS_UID=$(shell id -u) ESPDNS_GID=$(shell id -g) docker compose build

# The data directory: the controller and the CLI (fleet-* below) share it, for settings.json,
# the fleet lock and the action log. Made here, so it is owned by the user running them (not
# by root, as docker would make it), and under umask 077, as everything make puts there: the
# user's only (directories 0700, files 0600 or 0700), as the controller makes what it
# writes, and makes what it finds open to group or others at start. A new one is empty: no settings.json (none is no nodes,
# no DNS peers, a manual zone primary) and no node configs. The repo has no deployment's
# settings or configs to put there, only examples (../configs/example-*.json, docs/rollout.md,
# This site), which make data never copies: write settings.json there, or start from the
# example, and make the configs in the controller's editor (or by hand in $(DATA)/configs).
#
# A deployment can seed a new data directory from its own files, kept outside the repo:
# SETTINGS_SEED=<its settings.json> and CONFIG_SEEDS=<a directory of node configs> (e.g. in
# local.mk). The settings are copied only if $(DATA)/settings.json isn't there; each
# <name>.json config (but settings.json, fleet.json, example-*.json, and a name the editor
# can't take: lowercase letters, digits, '.', '_' and '-' only, said) to
# $(DATA)/configs/<name>.json (mode 0600: a config can hold a Wi-Fi password) only if there is
# no file of that name there yet, so a file edited there (by hand or in the controller's
# editor) is never overwritten; a seed that differs from the file in use is noted. Either
# way $(DATA) holds the files in use: the controller edits and pushes the configs there, and
# KIND=config, fleet-config-check and fleet-adopt read them there.
#
# The hosted zones are $(DATA)/zones/<zone>.zone, made here empty: the repo has no zone files
# to seed it with. The controller's Zones page creates and edits them there (or put a master
# file there by hand); KIND=zones and the Push page push them from there. The compiled lists
# are $(DATA)/lists/<name>.bin, made here empty too: make blocklist writes them there.
SETTINGS_SEED ?=
CONFIG_SEEDS  ?=
data:
	@umask 077 && mkdir -p '$(DATA)' '$(DATA)/configs' '$(DATA)/zones' '$(DATA)/lists'
	@test -z '$(SETTINGS_SEED)' -o -f '$(SETTINGS_SEED)' || echo "settings: note: SETTINGS_SEED=$(SETTINGS_SEED): no such file"
	@test -z '$(CONFIG_SEEDS)' -o -d '$(CONFIG_SEEDS)' || echo "configs: note: CONFIG_SEEDS=$(CONFIG_SEEDS): no such directory"
	@test -z '$(SETTINGS_SEED)' -o -f '$(DATA)/settings.json' -o ! -f '$(SETTINGS_SEED)' || { (umask 077 && cp '$(SETTINGS_SEED)' '$(DATA)/settings.json') && \
	  echo "settings: copied $(SETTINGS_SEED) to $(DATA)/settings.json: edit that one from now on"; }
	@test -z '$(SETTINGS_SEED)' -o ! -f '$(SETTINGS_SEED)' || cmp -s '$(SETTINGS_SEED)' '$(DATA)/settings.json' || \
	  echo "settings: note: $(SETTINGS_SEED) differs from $(DATA)/settings.json, which is the one used"
	@test -z '$(CONFIG_SEEDS)' || for f in '$(CONFIG_SEEDS)'/*.json; do n=$${f##*/}; \
	  case "$$n" in fleet.json|settings.json|example-*|'*.json') continue;; \
	    *[!a-z0-9._-]*|[._-]*|*..*) echo "configs: note: $$f not copied: a config is <name>.json, with lowercase letters, digits, '.', '_' and '-' only"; continue;; esac; \
	  d='$(DATA)/configs/'"$$n"; \
	  if [ ! -e "$$d" ] && [ ! -L "$$d" ]; then \
	    (umask 077 && cp "$$f" "$$d") && \
	    echo "configs: copied $$f to $$d: edit that one from now on"; \
	  elif ! cmp -s "$$f" "$$d"; then echo "configs: note: $$f differs from $$d, which is the one used"; fi; done

# ---- Fleet operations (docs/rollout.md) -------------------------------------------------
# The espdns CLI from the image above, one `docker run` per target, host networking so it
# reaches the nodes on their LAN. Mounted: the data directory at /data, shared with the
# controller (settings.json, the fleet's settings; the fleet lock, so a CLI change and a
# controller job never run at once; the action log; the node configs, configs/ in it), and,
# read-only, what a rollout pushes (the firmware builds at /fleet/build, a blocklist
# file, zone files). Secrets come from the environment at run time (exported, or put there
# by SECRET_RUN, below), or a file, and go only to the targets that need them: the release key on the container's standard
# input (-key -), never in its environment; the zone primary's token by `docker run -e NAME`.
# No secret is written to disk or built into the image. Rollouts are always coordinated:
# canary first, one node at a time, a DNS peer or another node answering, stop on the
# first failure, and only the nodes in settings.json count (-mdns 0). There is no knob here
# for -force, -allow-single, -no-dns-checks, -reinstall, -soak or -recovery.
# SECRET_RUN: the hook to a password manager, empty by default. A make function: $(call
# SECRET_RUN,NAME ...) is a command prefix that runs the command after it with each named
# environment variable set to its secret (ESPDNS_RELEASE_KEY, the PRIMARY_TOKEN_ENV below,
# PASSWD_ENV, ESPDNS_BACKUP_PASSPHRASE), e.g. in local.mk
#   SECRET_RUN = my-secrets-tool exec $(1) --
# Empty: the command runs as it is, and each variable must already be in make's environment
# (exported), or the target takes the secret from a file instead (RELEASE_KEY_FILE,
# PRIMARY_TOKEN_FILE) or from standard input (passwd, backup, restore).
SECRET_RUN ?=
# The zone primary's API token, for a kind driven over an API (internal/primary:
# technitium): the environment variable that holds it (exported, or set by SECRET_RUN).
# Empty (the default): none is taken, and adoption uses the token make primary-import put in
# the data directory, if any (a primary of the manual kind needs none). A deployment that
# gives the token this way names the variable in local.mk (above).
PRIMARY_TOKEN_ENV    ?=
# The zone primary for adoption: settings.json's "primary", as the controller uses it
# ({"kind": "manual"} for any primary, changed by hand; {"kind": "technitium", "url": ...}).
# PRIMARY_KIND= (manual or technitium) and PRIMARY_URL= override it. A settings.json that
# names none is manual: the project's default; no other address is ever assumed.
# PRIMARY_DONE=1: the changes adoption names were made on the primary by hand.
PRIMARY_KIND ?=
PRIMARY_URL  ?=
PRIMARY_DONE ?=
# The release signing key (ECDSA P-256 PEM). Empty: from $ESPDNS_RELEASE_KEY (the PEM, or base64
# of it; exported, or set by SECRET_RUN), piped to the CLI's standard input. A path: that file, mounted
# read-only (../firmware/secrets/release.pem).
RELEASE_KEY_FILE   ?=
# The deployment's own fleet: none here (a site sets them in local.mk, docs/rollout.md, This
# site; local.mk.example). The nodes a rollout changes, in rollout order after the canary
# (required for KIND=firmware, blocklist, overrides and zones); the boards whose transitional
# firmware they run (make fleet-firmware, KIND=firmware; no two of them may share a chip
# image: the CLI picks a node's firmware by it).
NODES              ?=
# Changed first, if it is one of the nodes changed (else settings.json's "canary" if it is one
# of them, else the first of them goes first)
CANARY             ?=
FLEET_BOARDS       ?=
# firmware, config, blocklist, overrides or zones
KIND               ?= firmware
# KIND=config: host=file (in $(DATA)/configs) per node; only those nodes are changed (required)
CONFIGS            ?=
# KIND=blocklist or overrides: the file from `espdns blocklist` (a path)
FILE               ?=
# KIND=zones: the hosted zones' master files, each <zone>.zone or origin=path (paths)
ZONES              ?=
# Extra checks after each node, any KIND (they only add checks): names the blocklist must
# block (space-separated); a file of names that must resolve, one per line.
CHECK_BLOCKED      ?=
MUST_RESOLVE       ?=

# The checkout the paths resolve from: this Makefile's parent
REPO     ?= $(abspath $(CURDIR)/..)
FLEET    := -data /data
# SECRET_RUN gets every secret a command needs at once: one password manager call
TOKEN_ENV  = $(if $(PRIMARY_TOKEN_ENV),-e $(PRIMARY_TOKEN_ENV))
ifeq ($(RELEASE_KEY_FILE),)
# The key from the environment goes to the container on standard input: printenv writes it
# into the pipe, and docker (with the command after it) runs without it in its environment.
# The docker command is passed as sh's arguments ("$$@"), so it is not quoted again.
KEY_PIPE   = sh -c 'printenv ESPDNS_RELEASE_KEY | env -u ESPDNS_RELEASE_KEY "$$@"' fleet-key
WITH_KEY   = $(call SECRET_RUN,ESPDNS_RELEASE_KEY) $(KEY_PIPE)
WITH_TOKEN_KEY = $(call SECRET_RUN,$(PRIMARY_TOKEN_ENV) ESPDNS_RELEASE_KEY) $(KEY_PIPE)
KEY_STDIN  = -i
KEY_MOUNT  =
KEY_ARGS   = -key -
else
WITH_KEY   =
WITH_TOKEN_KEY = $(if $(PRIMARY_TOKEN_ENV),$(call SECRET_RUN,$(PRIMARY_TOKEN_ENV)))
KEY_STDIN  =
KEY_MOUNT  = -v $(abspath $(RELEASE_KEY_FILE)):/run/secrets/release.pem:ro
KEY_ARGS   = -key /run/secrets/release.pem
endif
# Set per target below: how it gets its secrets, what it has mounted besides the data directory
SECRET_ENV   =
EXTRA_MOUNTS =
FLEET_RUN = docker run --rm --network host --user $(shell id -u):$(shell id -g) \
	  $(SECRET_ENV) $(KEY_MOUNT) $(EXTRA_MOUNTS) \
	  -v '$(abspath $(DATA))':/data -w /fleet --entrypoint /espdns $(IMAGE)

comma  := ,
empty  :=
space  := $(empty) $(empty)
csv     = $(subst $(space),$(comma),$(strip $(1)))
board_image = $(shell sed -n 's/^ *"image": *"\([^"]*\)".*/\1/p' $(REPO)/boards/$(1).json 2>/dev/null)
CONFIG_HOSTS = $(foreach c,$(CONFIGS),$(firstword $(subst =, ,$(c))))
zone_path = $(lastword $(subst =, ,$(1)))
zone_orig = $(if $(findstring =,$(1)),$(firstword $(subst =, ,$(1)))=)
# Files on the host a rollout reads: each must exist (docker would make a directory there)
check_files = for f in $(1); do test -f "$$f" || { echo "no such file: $$f $(2)"; exit 1; }; done

# Per KIND: the nodes changed, what is mounted, the CLI's arguments, what is checked first
# The deployment's nodes and boards, which have no default (local.mk)
NEED_NODES  = $(if $(strip $(NODES)),,NODES= the nodes to change$(comma) in rollout order after the canary (local.mk: NODES ?= a.b.c.d ...))
NEED_BOARDS = $(if $(strip $(FLEET_BOARDS)),,FLEET_BOARDS= the boards whose firmware the nodes run (local.mk: FLEET_BOARDS ?= <board> ...))
ifeq ($(KIND),firmware)
ROLLOUT_HOSTS  = $(NODES)
FW_IMAGES      = $(foreach b,$(FLEET_BOARDS),$(call board_image,$(b)))
# The builds in the data directory (make fleet-firmware puts them there), as the
# controller's Push page pushes them: both routes push the same bytes.
ROLLOUT_KIND_ARGS = $(foreach b,$(FLEET_BOARDS),-image $(call board_image,$(b))=/data/firmware/builds/$(b)/dns2.bin)
ROLLOUT_ERR    = $(or $(NEED_NODES),$(NEED_BOARDS),$(if $(filter-out $(words $(FLEET_BOARDS)),$(words $(FW_IMAGES))),FLEET_BOARDS: a board with no boards/<board>.json image,$(if \
	$(filter-out $(words $(FW_IMAGES)),$(words $(sort $(FW_IMAGES)))),FLEET_BOARDS: two boards share a chip image ($(FW_IMAGES)))))
ROLLOUT_FILES  = $(foreach b,$(FLEET_BOARDS),$(DATA)/firmware/builds/$(b)/dns2.bin)
ROLLOUT_HINT   = (make fleet-firmware builds it there; make fleet-firmware-data copies a build already made)
# A build in firmware/build newer than its copy and different (made by hand with make -C
# firmware build BOARD=..., not copied since) refuses the rollout: it would push the old
# copy while you mean the new build.
ROLLOUT_STALE  = for b in $(FLEET_BOARDS); do f='$(REPO)/firmware/build/'"$$b"/dns2.bin; d='$(DATA)/firmware/builds/'"$$b"/dns2.bin; \
	if [ -f "$$f" ] && [ "$$f" -nt "$$d" ] && ! cmp -s "$$f" "$$d"; then echo "firmware: $$f is newer than $$d, the copy a rollout pushes, and differs:"; \
	echo "  make fleet-firmware-data copies it (make fleet-firmware builds and copies every board)"; exit 1; fi; done
else ifeq ($(KIND),config)
ROLLOUT_HOSTS  = $(CONFIG_HOSTS)
ROLLOUT_KIND_ARGS = $(foreach c,$(CONFIGS),-config $(firstword $(subst =, ,$(c)))=/data/configs/$(lastword $(subst =, ,$(c))))
ROLLOUT_FILES  = $(foreach c,$(CONFIGS),$(DATA)/configs/$(lastword $(subst =, ,$(c))))
ROLLOUT_ERR    = $(if $(strip $(CONFIGS)),,CONFIGS= host=file per node$(comma) the file in $(DATA)/configs (CONFIGS=a.b.c.d=name.json))
else ifneq ($(filter blocklist overrides,$(KIND)),)
ROLLOUT_HOSTS  = $(NODES)
ROLLOUT_MOUNT  = -v $(abspath $(FILE)):/fleet/payload/$(notdir $(FILE)):ro
ROLLOUT_KIND_ARGS = -file /fleet/payload/$(notdir $(FILE))
ROLLOUT_ERR    = $(or $(NEED_NODES),$(if $(FILE),$(if $(word 2,$(FILE)),FILE= one file),FILE= the $(KIND) file from espdns blocklist))
ROLLOUT_FILES  = $(abspath $(FILE))
else ifeq ($(KIND),zones)
ROLLOUT_HOSTS  = $(NODES)
ROLLOUT_MOUNT  = $(foreach z,$(ZONES),-v $(abspath $(call zone_path,$(z))):/fleet/zones/$(notdir $(call zone_path,$(z))):ro)
ROLLOUT_KIND_ARGS = $(foreach z,$(ZONES),-zone $(call zone_orig,$(z))/fleet/zones/$(notdir $(call zone_path,$(z))))
ROLLOUT_ERR    = $(or $(NEED_NODES),$(if $(ZONES),,ZONES= the hosted zones' files))
ROLLOUT_FILES  = $(foreach z,$(ZONES),$(abspath $(call zone_path,$(z))))
else
ROLLOUT_ERR    = KIND=firmware$(comma) config$(comma) blocklist$(comma) overrides or zones
endif
ifneq ($(MUST_RESOLVE),)
ROLLOUT_MOUNT += -v $(abspath $(MUST_RESOLVE)):/fleet/must-resolve.txt:ro
ROLLOUT_FILES += $(abspath $(MUST_RESOLVE))
endif
ROLLOUT_ARGS = -kind $(KIND) $(KEY_ARGS) $(FLEET) -mdns 0 -host $(call csv,$(ROLLOUT_HOSTS)) \
	$(if $(filter $(CANARY),$(ROLLOUT_HOSTS)),-canary $(CANARY)) $(ROLLOUT_KIND_ARGS) \
	$(foreach n,$(CHECK_BLOCKED),-check-blocked $(n)) $(if $(MUST_RESOLVE),-must-resolve /fleet/must-resolve.txt)
ROLLOUT_CHECK = $(if $(ROLLOUT_ERR),echo "$(ROLLOUT_ERR)"; exit 1,$(call check_files,$(ROLLOUT_FILES),$(ROLLOUT_HINT))$(if \
	$(ROLLOUT_STALE),; $(ROLLOUT_STALE)))

.PHONY: fleet-image fleet-firmware fleet-firmware-data fleet-status fleet-discover fleet-config-check fleet-rollout-dry \
	fleet-rollout fleet-reboot-pending fleet-revert fleet-adopt-dry fleet-adopt fleet-secret-check fleet-key-check

fleet-image: image data

# Each target gets only the secrets it uses; only a rollout sees what it pushes
fleet-rollout-dry fleet-rollout: EXTRA_MOUNTS = $(ROLLOUT_MOUNT)
fleet-rollout-dry fleet-rollout fleet-reboot-pending fleet-revert: SECRET_ENV = $(KEY_STDIN)
fleet-adopt-dry fleet-adopt: SECRET_ENV = $(KEY_STDIN) $(TOKEN_ENV)

# The transitional per-board images the nodes run (firmware/build/<board>/dns2.bin), built
# and copied into the data directory (fleet-firmware-data), where a rollout, from here or
# the controller's Push page, pushes them from.
fleet-firmware:
	$(if $(NEED_BOARDS),$(error $(NEED_BOARDS)))for b in $(FLEET_BOARDS); do $(MAKE) -C $(REPO)/firmware build BOARD=$$b REQUIRE_STATIC_IP=1 || exit 1; done
	@$(MAKE) --no-print-directory fleet-firmware-data

# Copies each board's build (firmware/build/<board>/dns2.bin) to
# $(DATA)/firmware/builds/<board>/dns2.bin, whole (a new file renamed over the old), so a
# rollout never reads half of one. The controller compiles nothing: what it pushes is there.
fleet-firmware-data: data
	@$(if $(NEED_BOARDS),$(error $(NEED_BOARDS)))for b in $(FLEET_BOARDS); do f='$(REPO)/firmware/build/'"$$b"/dns2.bin; d='$(DATA)/firmware/builds/'"$$b"; \
	  test -f "$$f" || { echo "no such file: $$f (make fleet-firmware builds it)"; exit 1; }; \
	  (umask 077 && mkdir -p "$$d" && cp "$$f" "$$d/.dns2.bin.tmp") && mv "$$d/.dns2.bin.tmp" "$$d/dns2.bin" && \
	  echo "firmware: copied $$f to $$d/dns2.bin"; done

# The secrets $(1) (environment variables) can be had: with SECRET_RUN, its command is there
# (a locked password manager is its own error); without, each is in the environment (never
# printed). $(2): what else would do instead, if anything.
secret_cmd   = $(firstword $(call SECRET_RUN,$(1)))
secret_check = $(if $(secret_cmd),command -v '$(secret_cmd)' >/dev/null || \
	{ echo "no $(secret_cmd)$(comma) SECRET_RUN's command$(if $(2), ($(2)))"; exit 1; },for v in $(1); do \
	[ -n "$$(printenv "$$v")" ] || { echo "$$v: not in the environment (export it, or set SECRET_RUN$(if $(2),$(comma) or $(2)))"; exit 1; }; done)
# The target that needs secrets sets SECRET_NAMES, the variables, and SECRET_ALT, the way to
# do without them
SECRET_NAMES =
SECRET_ALT   =
fleet-secret-check:
	@$(call secret_check,$(SECRET_NAMES),$(SECRET_ALT))

# The release key's source is there: $ESPDNS_RELEASE_KEY (SECRET_RUN), or RELEASE_KEY_FILE
fleet-key-check:
ifeq ($(RELEASE_KEY_FILE),)
	@$(call secret_check,ESPDNS_RELEASE_KEY,RELEASE_KEY_FILE= to sign with the key file)
else
	@test -f '$(abspath $(RELEASE_KEY_FILE))' || { echo "RELEASE_KEY_FILE: no such file: $(abspath $(RELEASE_KEY_FILE))"; exit 1; }
endif

# Every node found over mDNS or listed in $(DATA)/settings.json: health, firmware, seqs, reboot pending
fleet-status: fleet-image
	$(FLEET_RUN) status -all $(FLEET)

fleet-discover: fleet-image
	$(FLEET_RUN) discover $(FLEET)

# Checks a node config in $(DATA)/configs and prints its payload: CONFIG=<file>; with BOARD=<catalog
# board>, its memory plan on that board too
fleet-config-check: fleet-image
	@test -n "$(CONFIG)" || { echo "CONFIG= a file in $(DATA)/configs"; exit 1; }
	@$(call check_files,$(DATA)/configs/$(CONFIG))
	$(FLEET_RUN) config -check -file /data/configs/$(CONFIG) $(if $(BOARD),-board $(BOARD))

# Compiles a blocklist or overrides file into $(DATA)/lists/$(LIST), where KIND=blocklist
# FILE=... and the Push page take it from: espdns blocklist in the image, the same code the
# controller compiles with; no secret, no node touched. SOURCES= the lists to block and
# ALLOW_SOURCES= the lists to allow, each kind:path or kind:URL (kind hosts, domains,
# wildcard, adblock or rpz, a Response Policy Zone; a path on the host, mounted read-only;
# a URL fetched in the container); LIST= the file's name there (list.bin, overrides.bin).
# POPULAR= popular names never blocked by accident (a Tranco CSV); MUST_RESOLVE= names the
# list must not block (as for a rollout); XOR=0 for an overrides file (else 10). The
# size-change check: a build whose blocked or allowed entries change by more than
# MAX_CHANGE percent (default 20) and MIN_CHANGE entries (default 100) from the file it
# replaces is refused, naming both sizes, and nothing is written; ACCEPT_CHANGE=1 takes it
# once. MAX_CHANGE=0 refuses any change in size (whatever MIN_CHANGE); MIN_CHANGE=0 is no
# floor; unset is the default. No file there yet: any size.
SOURCES       ?=
ALLOW_SOURCES ?=
LIST          ?=
POPULAR       ?=
XOR           ?=
MAX_CHANGE    ?=
MIN_CHANGE    ?=
ACCEPT_CHANGE ?=
src_kind  = $(firstword $(subst :, ,$(1)))
src_path  = $(patsubst $(call src_kind,$(1)):%,%,$(1))
src_url   = $(filter http://% https://%,$(call src_path,$(1)))
# A source as the container sees it: a URL as given, a file at /fleet/src/<its name>
src_arg   = $(call src_kind,$(1)):$(if $(call src_url,$(1)),$(call src_path,$(1)),/fleet/src/$(notdir $(call src_path,$(1))))
SRC_FILES = $(foreach s,$(SOURCES) $(ALLOW_SOURCES),$(if $(call src_url,$(s)),,$(abspath $(call src_path,$(s)))))
BLOCKLIST_FILES = $(SRC_FILES) $(if $(POPULAR),$(abspath $(POPULAR))) $(if $(MUST_RESOLVE),$(abspath $(MUST_RESOLVE)))
# Each path and source single-quoted for the shell (a URL's ? and & are not the shell's);
# one with a ' in it is refused (BLOCKLIST_ERR)
BLOCKLIST_MOUNT = $(foreach f,$(SRC_FILES),-v '$(f):/fleet/src/$(notdir $(f)):ro') \
	$(if $(POPULAR),-v '$(abspath $(POPULAR)):/fleet/popular.txt:ro') \
	$(if $(MUST_RESOLVE),-v '$(abspath $(MUST_RESOLVE)):/fleet/must-resolve.txt:ro')
BLOCKLIST_ARGS = $(foreach s,$(SOURCES),-list '$(call src_arg,$(s))') $(foreach s,$(ALLOW_SOURCES),-allow '$(call src_arg,$(s))') \
	-out /data/lists/$(LIST) $(if $(POPULAR),-popular /fleet/popular.txt) $(if $(MUST_RESOLVE),-must-resolve /fleet/must-resolve.txt) \
	$(if $(XOR),-xor $(XOR)) $(if $(MAX_CHANGE),-max-change $(MAX_CHANGE)) $(if $(MIN_CHANGE),-min-change $(MIN_CHANGE)) \
	$(if $(filter 1,$(ACCEPT_CHANGE)),-accept-change)
BLOCKLIST_ERR = $(or $(if $(strip $(SOURCES) $(ALLOW_SOURCES)),,SOURCES= the lists to block$(comma) each kind:path or kind:URL), \
	$(if $(filter-out $(words $(LIST)),1)$(findstring /,$(LIST))$(filter-out %.bin,$(LIST)),LIST= the file to write in $(DATA)/lists$(comma) a name ending .bin (list.bin)), \
	$(if $(filter-out $(words $(SRC_FILES)),$(words $(sort $(notdir $(SRC_FILES))))),SOURCES: two files of the same name (each is mounted by its name)), \
	$(if $(findstring ',$(SOURCES) $(ALLOW_SOURCES) $(POPULAR) $(MUST_RESOLVE)),SOURCES$(comma) ALLOW_SOURCES$(comma) POPULAR and MUST_RESOLVE: no ' in a path or URL))

.PHONY: blocklist
blocklist: EXTRA_MOUNTS = $(BLOCKLIST_MOUNT)
blocklist: fleet-image
	@$(if $(strip $(BLOCKLIST_ERR)),echo "$(strip $(BLOCKLIST_ERR))"; exit 1,$(call check_files,$(foreach f,$(BLOCKLIST_FILES),'$(f)')))
	$(FLEET_RUN) blocklist $(BLOCKLIST_ARGS)

# Checks every node and the safety rule for each step; pushes nothing
fleet-rollout-dry: fleet-image fleet-key-check
	@$(ROLLOUT_CHECK)
	$(WITH_KEY) $(FLEET_RUN) rollout $(ROLLOUT_ARGS) -dry-run

fleet-rollout: fleet-image fleet-key-check
	@$(ROLLOUT_CHECK)
	$(WITH_KEY) $(FLEET_RUN) rollout $(ROLLOUT_ARGS)

# Recovery: reboot a node a release left waiting for one, coordinated (another node or the
# DNS peer must answer), then wait for it to come back in service. HOST= the node.
fleet-reboot-pending: fleet-image fleet-key-check
	@test -n "$(HOST)" || { echo "HOST= the node to reboot"; exit 1; }
	$(WITH_KEY) $(FLEET_RUN) reboot -host $(HOST) -if-pending $(KEY_ARGS) $(FLEET) -mdns 0

# Recovery: send a node's blocklist back to the older copy it keeps (LIST=overrides: its
# overrides; LIST=zones: its hosted zones), live; refused by the node when it keeps none
# older. HOST= the node. A list whose two copies don't fit goes back at the next reboot:
# then fleet-reboot-pending.
# LIST empty is the blocklist: make blocklist's LIST ?= (above) already set it, empty, so a
# LIST ?= blocklist here never took and fleet-revert without LIST= was refused.
REVERT_LIST = $(or $(LIST),blocklist)
fleet-revert: fleet-image fleet-key-check
	@test -n "$(HOST)" || { echo "HOST= the node whose $(REVERT_LIST) goes back"; exit 1; }
	@case '$(REVERT_LIST)' in blocklist|overrides|zones) ;; *) echo "LIST=blocklist, overrides or zones, not $(REVERT_LIST)"; exit 1;; esac
	$(WITH_KEY) $(FLEET_RUN) revert -host $(HOST) -kind $(REVERT_LIST) $(KEY_ARGS) $(FLEET)

# Adoption: HOST=<its address now> (or NODE=<its ID>) CONFIG=<file in $(DATA)/configs>, and
# optionally ADDRESS=a.b.c.d/nn [GATEWAY=...]. Without ADDRESS the address is the
# config's network, else the one the node runs on now (its /status). RESERVED=1 only with
# ADDRESS=dhcp, on a network with a DHCP server (never one in settings.json's no_dhcp). The zone primary
# is settings.json's "primary" (above: PRIMARY_KIND, PRIMARY_URL): over its API
# (technitium) with the token from PRIMARY_TOKEN_ENV, its allow lists are changed; by hand (manual, or no
# token) adopt names the changes to make on it and stops, and PRIMARY_DONE=1 goes on once
# they are made. ADD_TO_SETTINGS=1: once adopted, its address goes into settings.json. The
# controller's Adopt page builds the same adoption from the same request (internal/adoption).
ADOPT_PRIMARY = $(if $(PRIMARY_KIND),-primary-kind $(PRIMARY_KIND)) $(if $(PRIMARY_URL),-primary-url $(PRIMARY_URL)) \
	$(if $(PRIMARY_TOKEN_ENV),-primary-token-env $(PRIMARY_TOKEN_ENV)) $(if $(PRIMARY_DONE),-primary-done)
ADOPT_ARGS = $(KEY_ARGS) $(FLEET) -mdns 0 $(if $(HOST),-host $(HOST)) $(if $(NODE),-node $(NODE)) \
	$(if $(ADDRESS),-address $(ADDRESS)) $(if $(GATEWAY),-gateway $(GATEWAY)) \
	-config /data/configs/$(CONFIG) $(if $(RESERVED),-reserved) $(ADOPT_PRIMARY) $(if $(ADD_TO_SETTINGS),-add-to-settings)
ADOPT_CHECK = test -n "$(HOST)$(NODE)" -a -n "$(CONFIG)" || { echo "HOST= or NODE=, and CONFIG="; exit 1; }; \
	$(if $(RESERVED),$(if $(filter dhcp,$(ADDRESS)),,echo "RESERVED=1 is only for ADDRESS=dhcp (a static address needs no reservation)"; exit 1;)) \
	$(call check_files,$(DATA)/configs/$(CONFIG))

fleet-adopt-dry fleet-adopt: SECRET_NAMES = $(PRIMARY_TOKEN_ENV)
fleet-adopt-dry fleet-adopt: SECRET_ALT = leave PRIMARY_TOKEN_ENV empty to use the token make primary-import imported
fleet-adopt-dry: fleet-image $(if $(PRIMARY_TOKEN_ENV),fleet-secret-check) fleet-key-check
	@$(ADOPT_CHECK)
	$(WITH_TOKEN_KEY) $(FLEET_RUN) adopt $(ADOPT_ARGS) -dry-run

fleet-adopt: fleet-image $(if $(PRIMARY_TOKEN_ENV),fleet-secret-check) fleet-key-check
	@$(ADOPT_CHECK)
	$(WITH_TOKEN_KEY) $(FLEET_RUN) adopt $(ADOPT_ARGS)

# ---- The controller's login, release key and zone primary token (controller/README.md) --
# Set the one login: its user name (your choice) and password, kept as an argon2id hash in
# $(DATA)/auth.json (mode 0600), the password never an argument or in the container's
# environment. Every session before ends. The user name: PASSWD_USER=<name> (printable, no
# spaces, quotes or backslashes, at most 64 bytes); without it, asked first on a terminal
# (Enter keeps the one shown: the one set before, else admin), and with no terminal the one
# set before, else admin (a name an older passwd set that it no longer takes: asked for a
# new one, or PASSWD_USER). The password, from a terminal: asked twice, without echo. Without
# one (a script, CI): the first line piped in,
#   printf '%s\n' "$PW" | make passwd PASSWD_USER=admin
# or PASSWD_FROM_ENV=1: from the environment variable $(PASSWD_ENV) (exported, or set by
# SECRET_RUN) on the container's standard input, as key-import gets the release key. Nothing piped and no terminal: it fails at once
# (/dev/null, a closed or empty input), or once an open, silent standard input has given
# nothing for PASSWD_WAIT (empty: espdns passwd's -wait, 4m, which outlasts a password
# manager in the pipe waiting for an MFA approval), never hangs.
PASSWD_FROM_ENV   ?=
PASSWD_ENV        ?= ESPDNS_ADMIN_PASSWORD
PASSWD_WAIT       ?=
PASSWD_USER       ?=
# -user <name> when PASSWD_USER is given, exactly as typed: never expanded by make ($(value):
# a $ stays a $, $(...) is not run) and never parsed by the shell (it reaches docker run as
# one argument from the recipe's environment, "$$ESPDNS_PASSWD_USER"); espdns passwd alone
# decides whether it takes the name.
PASSWD_USER_ARG = $(if $(value PASSWD_USER),-user "$$ESPDNS_PASSWD_USER")
passwd: export ESPDNS_PASSWD_USER = $(value PASSWD_USER)
# docker run's -t only when standard input is a terminal, decided by the recipe's shell as it
# runs (make gives its recipes its own standard input; under -j a recipe run alongside
# another may get an empty one instead, and fails at once): docker refuses -t on a pipe, and
# without -t a terminal's password would be echoed. Always with -i, so a pipe reaches it.
DOCKER_TTY = $$( [ -t 0 ] && echo -t )
PASSWD_RUN = docker run --rm -i $(1) --user $(shell id -u):$(shell id -g) -v '$(abspath $(DATA))':/data \
	  --entrypoint /espdns $(IMAGE) passwd -data /data $(PASSWD_USER_ARG) $(if $(PASSWD_WAIT),-wait $(PASSWD_WAIT))
.PHONY: passwd key-import key-status primary-import primary-status
ifeq ($(filter-out 0,$(PASSWD_FROM_ENV)),)
passwd: fleet-image
	$(call PASSWD_RUN,$(DOCKER_TTY))
else
# Standard input is the environment's pipe here, never a terminal: no -t. SECRET_RUN has
# the password before it starts the pipe; a variable it doesn't set (another name than
# PASSWD_ENV) is said so (never the value), not taken for an empty input.
passwd: SECRET_NAMES = $(PASSWD_ENV)
passwd: SECRET_ALT = leave PASSWD_FROM_ENV empty and pipe the password in
passwd: fleet-image fleet-secret-check
	$(call SECRET_RUN,$(PASSWD_ENV)) sh -c '[ -n "$$$(PASSWD_ENV)" ] || { echo "no $(PASSWD_ENV) in the environment (PASSWD_ENV=: the variable that holds it)" >&2; exit 1; }; \
	  printenv $(PASSWD_ENV) | env -u $(PASSWD_ENV) "$$@"' passwd-env $(call PASSWD_RUN)
endif

# Import the release key into $(DATA)/keys/release.pem (mode 0600), where the controller
# signs its actions with it: from $ESPDNS_RELEASE_KEY on the container's standard input as
# the fleet targets get it, or RELEASE_KEY_FILE. Refused unless the firmware is
# built with it (../firmware/keys/release.pub) or a node in settings.json trusts it, and
# refused if it is the recovery key. It only reads the nodes' /status.
KEY_TRUST_ARGS = $(FLEET) -mdns 0 -pub /fleet/keys/release.pub -recovery-pub /fleet/keys/recovery.pub
key-import key-status: EXTRA_MOUNTS = -v $(REPO)/firmware/keys:/fleet/keys:ro
key-import: SECRET_ENV = $(KEY_STDIN)
key-import: fleet-image fleet-key-check
	$(WITH_KEY) $(FLEET_RUN) key import $(KEY_ARGS) $(KEY_TRUST_ARGS)

# Is the imported key there, usable (mode 0600, this user's), and trusted? Prints its fingerprint.
key-status: fleet-image
	$(FLEET_RUN) key status $(KEY_TRUST_ARGS)


# Import the zone primary's API token (the technitium kind's) into $(DATA)/keys/primary.token
# (mode 0600), where the controller's adoption and its Zone primary view use it: from the
# environment variable PRIMARY_TOKEN_ENV names on the container's standard input,
# as the release key goes to key-import (never its environment, an argument or a file but
# that one), or PRIMARY_TOKEN_FILE. It doesn't call the primary.
PRIMARY_TOKEN_FILE ?=
primary-import: SECRET_ENV = -i
ifeq ($(PRIMARY_TOKEN_FILE),)
primary-import: SECRET_NAMES = $(PRIMARY_TOKEN_ENV)
primary-import: SECRET_ALT = PRIMARY_TOKEN_FILE= to import it from a file
primary-import: fleet-image $(if $(PRIMARY_TOKEN_ENV),fleet-secret-check)
	@test -n '$(PRIMARY_TOKEN_ENV)' || { echo "PRIMARY_TOKEN_ENV= the environment variable that holds the token, or PRIMARY_TOKEN_FILE="; exit 1; }
	$(call SECRET_RUN,$(PRIMARY_TOKEN_ENV)) sh -c 'printenv $(PRIMARY_TOKEN_ENV) | env -u $(PRIMARY_TOKEN_ENV) "$$@"' primary-token \
	  $(FLEET_RUN) primary import $(FLEET)
else
primary-import: fleet-image
	@test -f '$(abspath $(PRIMARY_TOKEN_FILE))' || { echo "PRIMARY_TOKEN_FILE: no such file: $(abspath $(PRIMARY_TOKEN_FILE))"; exit 1; }
	$(FLEET_RUN) primary import $(FLEET) < '$(abspath $(PRIMARY_TOKEN_FILE))'
endif

# Which zone primary settings.json names, and is the imported token there and usable (mode
# 0600, this user's)? Never prints it.
primary-status: fleet-image
	$(FLEET_RUN) primary status $(FLEET)

# ---- Backup, restore, recovery (controller/README.md, Backup and recovery) ----------------
# make backup OUT=<file>: the data directory in one encrypted file (age, to a passphrase),
# written next to OUT and renamed into place; never over a file. The passphrase is asked on
# the terminal (twice, not echoed), else read from standard input: piped in (no terminal:
# docker run -i, -t only on a terminal, as make passwd), or with BACKUP_FROM_ENV=1 piped
# from $ESPDNS_BACKUP_PASSPHRASE (exported, or set by SECRET_RUN) on the container's standard
# input as the release key goes to key-import: never an argument, the environment of the
# CLI, or a file.
# FIRMWARE=1 includes firmware/ (the builds and chip images, made again by make).
#
# make restore IN=<file> DATA=<a new or empty data directory> [DRY=1] [FORCE=1]: into a
# stopped controller's data directory only (DATA must be given, and isn't the one a running
# container (the controller, a CLI run) has mounted; FORCE=1: what is there is moved into
# .before-restore-<time>/ first). It doesn't make data (no seeds copied: they would make the
# directory not empty). DRY=1 lists and checks the backup, writing nothing.
#
# make recover [HOSTS="a b"] [RECOVER_ARGS=-dry-run|-add-to-settings]: no backup; the release
# key imported first (key-import). Only reads the nodes; writes settings.json if there is none
# (make data makes none) and recovered/<time>/.
BACKUP_FROM_ENV   ?=
OUT               ?=
IN                ?=
HOSTS             ?=
RECOVER_ARGS      ?=
BACKUP_RUN = docker run --rm --user $(shell id -u):$(shell id -g) -v '$(abspath $(DATA))':/data --entrypoint /espdns
# BACKUP_FROM_ENV=1 on; empty or 0 off (as PASSWD_FROM_ENV)
BACKUP_ENV = $(filter-out 0,$(strip $(BACKUP_FROM_ENV)))
ifeq ($(BACKUP_ENV),)
WITH_PASSPHRASE =
PASS_STDIN      = -i $(DOCKER_TTY)
else
WITH_PASSPHRASE = $(call SECRET_RUN,ESPDNS_BACKUP_PASSPHRASE) sh -c 'printenv ESPDNS_BACKUP_PASSPHRASE | env -u ESPDNS_BACKUP_PASSPHRASE "$$@"' backup-passphrase
PASS_STDIN      = -i
backup restore: SECRET_NAMES = ESPDNS_BACKUP_PASSPHRASE
backup restore: SECRET_ALT = leave BACKUP_FROM_ENV empty and pipe the passphrase in
endif
.PHONY: backup restore recover

backup: fleet-image $(if $(BACKUP_ENV),fleet-secret-check)
	@test -n "$(OUT)" || { echo "OUT= the backup file to write (make backup OUT=../espdns-backup.age)"; exit 1; }
	@test ! -e '$(abspath $(OUT))' || { echo "OUT: $(abspath $(OUT)) already exists: a backup never replaces a file"; exit 1; }
	@mkdir -p '$(dir $(abspath $(OUT)))'
	$(WITH_PASSPHRASE) $(BACKUP_RUN) $(PASS_STDIN) -v '$(dir $(abspath $(OUT)))':/backup $(IMAGE) \
	  backup -data /data -out '/backup/$(notdir $(OUT))' $(if $(FIRMWARE),-firmware)

restore: image $(if $(BACKUP_ENV),fleet-secret-check)
	@test -n "$(IN)" -a -f '$(abspath $(IN))' || { echo "IN= the backup file (and DATA= the new data directory)"; exit 1; }
	@case "$(origin DATA)" in command*|environment*) ;; *) echo "DATA= the data directory to restore into, given: a new or empty one (not the default, $(DATA))"; exit 1;; esac
	@for c in $$(docker ps -q); do docker inspect -f '{{.Name}} {{range .Mounts}}{{if eq .Destination "/data"}}{{.Source}}{{end}}{{end}}' $$c; done 2>/dev/null | \
	  while read -r name src; do if [ -n "$$src" ] && [ "$$(readlink -f "$$src")" = "$$(readlink -f '$(DATA)')" ]; then \
	  echo "container $${name#/} is running on $(DATA): stop it first (docker compose down, or docker stop $${name#/})"; exit 1; fi; done
	@umask 077 && mkdir -p '$(DATA)'
	$(WITH_PASSPHRASE) $(BACKUP_RUN) $(PASS_STDIN) -v '$(abspath $(IN))':/backup/in.age:ro $(IMAGE) \
	  restore -data /data -in /backup/in.age $(if $(DRY),-dry-run) $(if $(FORCE),-force)

recover: fleet-image
	$(FLEET_RUN) recover $(FLEET) $(if $(HOSTS),-host $(call csv,$(HOSTS))) $(RECOVER_ARGS)
