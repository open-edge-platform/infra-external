# Makefile for LOCA Plugin

# SPDX-FileCopyrightText: (C) 2025 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_GOAL := help
.PHONY: help lint

# Project variables
PROJECT_NAME := locaplugin

#### Python venv Target ####

VENV_NAME := venv_$(PROJECT_NAME)

$(VENV_NAME): requirements.txt ## Create Python venv
	python3 -m venv $@ ;\
  set +u; . ./$@/bin/activate; set -u ;\
  python -m pip install --upgrade pip ;\
  python -m pip install -r requirements.txt

#### Test Targets ####

lint: yamllint ansiblelint shellcheck reuse mdlint

YAML_FILES := $(shell find -name "*.y*ml" -not -path "./venv_locaplugin/*" -print )

yamllint: $(VENV_NAME) ## lint yaml files with yamllint
	set +u; . ./$</bin/activate; set -u ;\
	yamllint --version ;\
	yamllint -s $(YAML_FILES)

ansiblelint: $(VENV_NAME) ## lint ansible modules with ansible-lint
	set +u; . ./$</bin/activate; set -u ;\
	ansible-lint --version ;\
	ansible-galaxy collection install community.general ;\
	ansible-lint edge-node/

SH_FILES := $(shell find -name "*.sh*" -not -path "./venv_locaplugin/*" -print )

shellcheck: ## lint shell scripts with shellcheck
	shellcheck --version
	shellcheck -a $(SH_FILES)

reuse: $(VENV_NAME) ## Check licensing with the reuse tool
	set +u; . ./$</bin/activate; set -u ;\
	reuse --version ;\
	reuse --root . lint

mdlint: ## Lint MD files
	markdownlint --version ;\
	markdownlint "**/*.md" -c ../.markdownlint.yml

#### Clean Target ###

clean: ## Delete Python venv
	rm -rf "$(VENV_NAME)"

#### Help Target ####

help: ## Print help for each target
	@echo $(PROJECT_NAME) make targets
	@echo "Target               Makefile:Line    Description"
	@echo "-------------------- ---------------- -----------------------------------------"
	@grep -H -n '^[[:alnum:]_-]*:.* ##' $(MAKEFILE_LIST) \
    | sort -t ":" -k 3 \
    | awk 'BEGIN  {FS=":"}; {sub(".* ## ", "", $$4)}; {printf "%-20s %-16s %s\n", $$3, $$1 ":" $$2, $$4};'
