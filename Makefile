# SPDX-FileCopyrightText: (C) 2025 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

SUBPROJECTS := loca-metadata loca-onboarding loca-templates amt-manager

.DEFAULT_GOAL := help
.PHONY: all build clean clean-all help lint test

all: build lint test
	@# Help: Runs build, lint, test stages for all subprojects
	
build:
	@# Help: Runs build stage in all subprojects
	@echo "---MAKEFILE BUILD---"
	for dir in $(SUBPROJECTS); do $(MAKE) -C $$dir build; done
	@echo "---END MAKEFILE Build---"

lint:
	@# Help: Runs lint stage in all subprojects
	@echo "---MAKEFILE LINT---"
	@for dir in $(SUBPROJECTS); do $(MAKE) -C $$dir lint; done
	@echo "---END MAKEFILE LINT---"

mdlint:
	@echo "---MAKEFILE LINT README---"
	@markdownlint --version
	@markdownlint "*.md"
	@echo "---END MAKEFILE LINT README---"

test:
	@# Help: Runs test stage in all subprojects
	@echo "---MAKEFILE TEST---"
	for dir in $(SUBPROJECTS); do $(MAKE) -C $$dir test; done
	@echo "---END MAKEFILE TEST---"
	
clean:
	@# Help: Runs clean stage in all subprojects
	@echo "---MAKEFILE CLEAN---"
	for dir in $(SUBPROJECTS); do $(MAKE) -C $$dir clean; done
	@echo "---END MAKEFILE CLEAN---"

clean-all:
	@# Help: Runs clean-all stage in all subprojects
	@echo "---MAKEFILE CLEAN-ALL---"
	for dir in $(SUBPROJECTS); do $(MAKE) -C $$dir clean-all; done
	@echo "---END MAKEFILE CLEAN-ALL---"

lm-%:
	@# Help: Runs loca-metadata subproject's tasks, e.g. lm-test
	$(MAKE) -C loca-metadata $*

lo-%:
	@# Help: Runs loca-onboarding subproject's tasks, e.g. lo-test
	$(MAKE) -C loca-onboarding $*

lt-%:
	@# Help: Runs loca-templates subproject's tasks, e.g. lt-test
	$(MAKE) -C loca-templates $*

# TODO: move to a common file shared with common.mk
venv_infra: requirements.txt ## Create Python venv
	python3 -m venv $@ ;\
  set +u; . ./$@/bin/activate; set -u ;\
  python -m pip install --upgrade pip ;\
  python -m pip install -r requirements.txt

license: venv_infra ## Check licensing with the reuse tool
	set +u; . ./$</bin/activate; set -u ;\
  reuse --version ;\
  reuse --root . lint

help:
	@printf "%-20s %s\n" "Target" "Description"
	@printf "%-20s %s\n" "------" "-----------"
	@grep -E '^[a-zA-Z0-9_%-]+:|^[[:space:]]+@# Help:' Makefile | \
	awk '\
		/^[a-zA-Z0-9_%-]+:/ { \
			target = $$1; \
			sub(":", "", target); \
		} \
		/^[[:space:]]+@# Help:/ { \
			if (target != "") { \
				help_line = $$0; \
				sub("^[[:space:]]+@# Help: ", "", help_line); \
				printf "%-20s %s\n", target, help_line; \
				target = ""; \
			} \
		}'
