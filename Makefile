MATRIX_OS ?= darwin linux windows
MATRIX_ARCH ?= amd64

GIT_HASH ?= $(shell git show -s --format=%h)
GIT_TAG ?= $(shell git tag -l --merged $(GIT_HASH))
APP_VERSION ?= $(if $(TRAVIS_TAG),$(TRAVIS_TAG),$(if $(GIT_TAG),$(GIT_TAG),$(GIT_HASH)))
APP_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

DEBUG_ARGS = --ldflags "-X main.version=$(APP_VERSION)-debug -X main.gitHash=$(GIT_HASH) -X main.buildDate=$(APP_DATE)"
RELEASE_ARGS = -v -ldflags "-X main.version=$(APP_VERSION) -X main.gitHash=$(GIT_HASH) -X main.buildDate=$(APP_DATE) -s -w" -tags release

-include artifacts/make/go/Makefile

artifacts/make/%/Makefile:
	curl -sf https://jmalloc.github.io/makefiles/fetch | bash /dev/stdin $*

.PHONY: install
install: vendor $(REQ) $(_SRC) | $(USE)
	$(eval PARTS := $(subst /, ,$*))
	$(eval BUILD := $(word 1,$(PARTS)))
	$(eval OS    := $(word 2,$(PARTS)))
	$(eval ARCH  := $(word 3,$(PARTS)))
	$(eval BIN   := $(word 4,$(PARTS)))
	@# $(eval PKG   := $(basename $(BIN)))
	$(eval ARGS  := $(if $(findstring debug,$(BUILD)),$(DEBUG_ARGS),$(RELEASE_ARGS)))

	@# CGO_ENABLED=$(CGO_ENABLED) GOOS="$(OS)" GOARCH="$(ARCH)" go install $(ARGS) "./src/cmd/$(PKG)"
	CGO_ENABLED=$(CGO_ENABLED) GOOS="$(OS)" GOARCH="$(ARCH)" go install $(ARGS) "./src/cmd/..."

.PHONY: run
run: artifacts/build/debug/$(GOOS)/$(GOARCH)/proxyclient
	$< $(RUN_ARGS)