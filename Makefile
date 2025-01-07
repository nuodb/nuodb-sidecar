PROJECT_DIR := $(shell pwd)
BIN_DIR ?= $(PROJECT_DIR)/bin
export TEST_RESULTS ?= $(PROJECT_DIR)/test-results
export TMP_DIR ?= $(PROJECT_DIR)/tmp
export PATH := $(BIN_DIR):$(PATH)
export OUTPUT_DIR ?= $(TMP_DIR)/test-artifacts

OS := $(shell go env GOOS)
ARCH := $(shell go env GOARCH)

KUBECTL_VERSION ?= 1.31.1
KWOKCTL_VERSION ?= 0.6.0

KUBECTL := bin/kubectl
KWOKCTL := bin/kwokctl

IGNORE_NOT_FOUND ?= true

# Image to use all building/pushing image targets
IMG_REPO ?= nuodb/nuodb-sidecar
IMG_TAG ?= latest

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Dependencies

$(KUBECTL):
	mkdir -p bin
	curl -L -s https://dl.k8s.io/release/v$(KUBECTL_VERSION)/bin/$(OS)/$(ARCH)/kubectl -o $(KUBECTL)
	chmod +x $(KUBECTL)

$(KWOKCTL):
	mkdir -p bin
	curl -L -s https://github.com/kubernetes-sigs/kwok/releases/download/v$(KWOKCTL_VERSION)/kwokctl-$(OS)-$(ARCH) -o $(KWOKCTL)
	chmod +x $(KWOKCTL)

bin/%:
	$(MAKE) install-tools


##@ Development



##@ Testing

.PHONY: test
test: test-config-watcher

.PHONY: test-config-watcher
test-config-watcher: test-setup


test-setup: $(KWOKCTL) $(KUBECTL)
	mkdir -p $(OUTPUT_DIR) $(TMP_DIR)
	@[ ! -x "./k8s-config-watcher/test/setup.sh" ] || ./k8s-config-watcher/test/setup.sh

test-tierdown:
	[ ! -x "./k8s-config-watcher/test/tierdown.sh" ] || ./k8s-config-watcher/test/tierdown.sh

##@ Build

.PHONY: docker-build
docker-build: ## Build docker image with NuoDB Control Plane.
	IMG_REPO="$(IMG_REPO)" IMG_TAG="$(IMG_TAG)" ./docker/build.sh
