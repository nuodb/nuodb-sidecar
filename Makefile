PROJECT_DIR := $(shell pwd)
BIN_DIR ?= $(PROJECT_DIR)/bin
OUTPUT_DIR ?= $(PROJECT_DIR)/test-results
VENV_DIR ?= $(BIN_DIR)/venv
export TMP_DIR ?= $(OUTPUT_DIR)/tmp
export PATH := $(BIN_DIR):$(VENV_DIR)/bin:$(PATH)
export KUBECONFIG ?= $(TMP_DIR)/kubeconfig.yaml

VENV := $(VENV_DIR)/touchfile #file to mark that venv is set up

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

# Python linter
PYLINT = python3 -m pylint
PYLINTFLAGS = -rn
PYTHONFILES := $(shell find $(PROJECT_DIR) -type f -name "*.py" -not -path "$(PROJECT_DIR)/.*/*" -not -path "*/test_*.py" -not -path "$(BIN_DIR)/*")
PYTHONTESTFILES := $(shell find $(PROJECT_DIR) -type f -name "test_*.py" -not -path "$(PROJECT_DIR)/.*/*" -not -path "$(BIN_DIR)/*")

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

##@ Development

.PHONY: lint
lint: $(VENV) $(patsubst %.py,%.pylint,$(PYTHONFILES)) ## Lint Python files

.PHONY: fmt ## Format Python files
fmt: $(VENV)
	python3 -m black --quiet $(PYTHONFILES) $(PYTHONTESTFILES)

##@ Testing

.PHONY: test
test: test-nuodb-operations test-config-watcher ## Run tests

test-config-watcher: test-setup $(VENV)
	cd config_watcher \
		&& python3 -m pytest \
			--junitxml $(OUTPUT_DIR)/reports/config_watcher.xml

test-nuodb-operations: $(VENV)
	cd nuodb-operations \
		&& python3 -m pytest \
			--junitxml $(OUTPUT_DIR)/reports/nuodb-operations.xml

test-setup: $(KWOKCTL) $(KUBECTL) ## Run tests setup
	mkdir -p $(TMP_DIR)
	@[ ! -x "./config_watcher/test_setup.sh" ] || ./config_watcher/test_setup.sh

test-teardown: $(KWOKCTL) ## Run tests teardown
	@[ ! -x "./config_watcher/test_teardown.sh" ] || ./config_watcher/test_teardown.sh

##@ Build

.PHONY: docker-build
docker-build: ## Build NuoDB sidecar docker image.
	IMG_REPO="$(IMG_REPO)" IMG_TAG="$(IMG_TAG)" ./docker/build.sh

$(VENV): nuodb-operations/test-requirements.txt config_watcher/test-requirements.txt config_watcher/requirements.txt
	python3 -m venv $(VENV_DIR)
	pip3 install -r nuodb-operations/test-requirements.txt -r config_watcher/test-requirements.txt -r config_watcher/requirements.txt --ignore-installed 
	touch $(VENV)

$(KUBECTL):
	mkdir -p bin
	curl -L -s https://dl.k8s.io/release/v$(KUBECTL_VERSION)/bin/$(OS)/$(ARCH)/kubectl -o $(KUBECTL)
	chmod +x $(KUBECTL)

$(KWOKCTL):
	mkdir -p bin
	curl -L -s https://github.com/kubernetes-sigs/kwok/releases/download/v$(KWOKCTL_VERSION)/kwokctl-$(OS)-$(ARCH) -o $(KWOKCTL)
	chmod +x $(KWOKCTL)

%.pylint:
	$(PYLINT) $(PYLINTFLAGS) $*.py