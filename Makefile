# SPDX-FileCopyrightText: (C) 2025 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

SUBPROJECTS := loca-metadata loca-onboarding loca-templates

.DEFAULT_GOAL := help
.PHONY: all build clean clean-all help lint test

SHELL	:= bash -eu -o pipefail

# Repo root directory, where base makefiles are located
REPO_ROOT := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

#### Python venv Target ####
VENV_DIR := venv_external

$(VENV_DIR): requirements.txt ## Create Python venv
	python3 -m venv $@ ;\
  set +u; . ./$@/bin/activate; set -u ;\
  python -m pip install --upgrade pip ;\
  python -m pip install -r requirements.txt

#### common targets ####
all: lint build test ## run lint, build, test for all subprojects

dependency-check: $(VENV_DIR)

lint: $(VENV_DIR) mdlint license ## lint common and all subprojects
	for dir in $(SUBPROJECTS); do $(MAKE) -C $$dir lint; done

MD_FILES := $(shell find . -type f \( -name '*.md' \) -print )
mdlint: ## lint all markdown README.md files
	markdownlint --version
	markdownlint *.md

license: $(VENV_DIR) ## Check licensing with the reuse tool
	set +u; . ./$</bin/activate; set -u ;\
  reuse --version ;\
  reuse --root . lint

build: ## build in all subprojects
	for dir in $(SUBPROJECTS); do $(MAKE) -C $$dir build; done

docker-build: ## build all docker containers
	for dir in $(SUBPROJECTS); do $(MAKE) -C $$dir $@; done

docker-push: ## push all docker containers
	for dir in $(SUBPROJECTS); do $(MAKE) -C $$dir $@; done

docker-list: ## list all docker containers
	@echo "images:"
	@for dir in $(SUBPROJECTS); do $(MAKE) -C $$dir $@; done

test: ## test in all subprojects
	for dir in $(SUBPROJECTS); do $(MAKE) -C $$dir test; done

clean: ## clean in all subprojects
	for dir in $(SUBPROJECTS); do $(MAKE) -C $$dir clean; done

clean-all: ## clean-all in all subprojects, and delete virtualenv
	for dir in $(SUBPROJECTS); do $(MAKE) -C $$dir clean-all; done
	rm -rf $(VENV_DIR)

lm-%: ## Runs loca-metadata subproject's tasks, e.g. lm-test
	$(MAKE) -C loca-metadata $*

lo-%: ## Runs loca-onboarding subproject's tasks, e.g. lo-test
	$(MAKE) -C loca-onboarding $*

lt-%: ## Runs loca-templates subproject's tasks, e.g. lt-test
	$(MAKE) -C loca-templates $*

#### Help Target ####
help: ## print help for each target
	@echo infra-external make targets
	@echo "Target               Makefile:Line    Description"
	@echo "-------------------- ---------------- -----------------------------------------"
	@grep -H -n '^[[:alnum:]%_-]*:.* ##' $(MAKEFILE_LIST) \
    | sort -t ":" -k 3 \
    | awk 'BEGIN  {FS=":"}; {sub(".* ## ", "", $$4)}; {printf "%-20s %-16s %s\n", $$3, $$1 ":" $$2, $$4};'
