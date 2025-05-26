# version.mk - check versions of tools for Infra External repository

# SPDX-FileCopyrightText: (C) 2025 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

GOLINTVERSION_HAVE             := $(shell golangci-lint version | sed 's/.*version //' | sed 's/ .*//')
GOLINTVERSION_REQ              := 1.64.5
GOJUNITREPORTVERSION_HAVE      := $(shell go-junit-report -version | sed s/.*" v"// | sed 's/ .*//')
GOJUNITREPORTVERSION_REQ       := 2.1.0
GOVERSION_REQ                  := 1.24.1
GOVERSION_HAVE                 := $(shell go version | sed 's/.*version go//' | sed 's/ .*//')
MOCKGENVERSION_HAVE            := $(shell mockgen -version | sed s/.*"v"// | sed 's/ .*//')
MOCKGENVERSION_REQ             := 1.6.0
SWAGGERVERSION_HAVE            := $(shell swagger version | sed 's/.*version: v//' | sed 's/ .*//'| sed 's/commit.*//')
SWAGGERVERSION_REQ             := 0.31.0
MOCKERYVERSION_HAVE            := $(shell mockery version)
MOCKERYVERSION_REQ             := v3.2.4
OAPI_CODEGEN_HAVE              := $(shell oapi-codegen -version |sed '1d')
OAPI_CODEGENVERSION_REQ        := v2.4.1
OASDIFF_HAVE                   := $(shell oasdiff --version | sed -n 's/^oasdiff version //p')
OASDIFF_REQ                    := 1.11.4
# No version reported
GOCOBERTURAVERSION_REQ         := 1.2.0
POSTGRES_VERSION               := 16.4

dependency-check: go-dependency-check

go-dependency-check:
	@(echo "$(GOVERSION_HAVE)" | grep "$(GOVERSION_REQ)" > /dev/null) || \
	(echo  "\e[1;31mWARNING: You are not using the recommended version of go\nRecommended: $(GOVERSION_REQ)\nYours: $(GOVERSION_HAVE)\e[1;m" && exit 1)
ifeq ($(GOLINT), true)
	@(echo "$(GOLINTVERSION_HAVE)" | grep "$(GOLINTVERSION_REQ)" > /dev/null) || \
	(echo  "\e[1;31mWARNING: You are not using the recommended version of go-lint\nRecommended: $(GOLINTVERSION_REQ)\nYours: $(GOLINTVERSION_HAVE)\e[1;m" && exit 1)
endif
ifeq ($(GOJUNITREPORT), true)
	@(echo "$(GOJUNITREPORTVERSION_HAVE)" | grep "$(GOJUNITREPORTVERSION_REQ)" > /dev/null) || \
	(echo  "\e[1;31mWARNING: You are not using the recommended version of go-junit-report\nRecommended: $(GOJUNITREPORTVERSION_REQ)\nYours: $(GOJUNITREPORTVERSION_HAVE)\e[1;m" && exit 1)
endif
ifeq ($(MOCKGENGEN), true)
	@(echo "$(MOCKGENVERSION_HAVE)" | grep "$(MOCKGENVERSION_REQ)" > /dev/null) || \
	(echo  "\e[1;31mWARNING: You are not using the recommended version of mockgen\nRecommended:: $(MOCKGENVERSION_REQ)"\nYours: $(MOCKGENVERSION_HAVE)\e[1;m" && exit 1)
endif
ifeq ($(SWAGGER), true)
	@(echo "$(SWAGGERVERSION_HAVE)" | grep "$(SWAGGERVERSION_REQ)" > /dev/null) || \
	(echo  "\e[1;31mWARNING: You are not using the recommended version of swagger\nRecommended: $(SWAGGERVERSION_REQ)\nYours: $(SWAGGERVERSION_HAVE)\e[1;m" && exit 1)
endif
ifeq ($(MOCKERY), true)
	@(echo "$(MOCKERY_HAVE)" | grep "$(MOCKERY_REQ)" > /dev/null) || \
	(echo  "\e[1;31mWARNING: You are not using the recommended version of mockery\nRecommended: $(MOCKERY_REQ)\nYours: $(MOCKERY_HAVE)\e[1;m" && exit 1)
endif
ifeq ($(OAPI_CODEGEN), true)
	@(echo "$(OAPI_CODEGEN_HAVE)" | grep "$(OAPI_CODEGEN_REQ)" > /dev/null) || \
	(echo  "\e[1;31mWARNING: You are not using the recommended version of oapi-codegen\nRecommended: $(OAPI_CODEGEN_REQ)\nYours: $(OAPI_CODEGEN_HAVE)\e[1;m" && exit 1)
endif
ifeq ($(OASDIFF), true)
	@(echo "$(OASDIFF_HAVE)" | grep "$(OASDIFF_REQ)" > /dev/null) || \
	(echo  "\e[1;31mWARNING: You are not using the recommended version of oasdiff\nRecommended: $(OASDIFF_REQ)\nYours: $(OASDIFF_HAVE)\e[1;m" && exit 1)
endif

go-dependency: ## install go dependency tooling
ifeq ($(GOJUNITREPORT), true)
	$(GOCMD) install github.com/jstemmer/go-junit-report/v2@v$(GOJUNITREPORTVERSION_REQ)
endif
ifeq ($(GOLINT), true)
	$(GOCMD) install github.com/golangci/golangci-lint/cmd/golangci-lint@v$(GOLINTVERSION_REQ)
endif
ifeq ($(MOCKGEN), true)
	$(GOCMD) install github.com/golang/mock/mockgen@v$(MOCKGENVERSION_REQ)
endif
ifeq ($(GOCOBERTURA), true)
	$(GOCMD) install github.com/boumenot/gocover-cobertura@v$(GOCOBERTURAVERSION_REQ)
endif
ifeq ($(SWAGGER), true)
	$(GOCMD) install github.com/go-swagger/go-swagger/cmd/swagger@v${SWAGGERVERSION_REQ}
endif
ifeq ($(MOCKERY), true)
	$(GOCMD) install github.com/vektra/mockery/v3@${MOCKERYVERSION_REQ}
endif
ifeq ($(OAPI_CODEGEN), true)
	$(GOCMD) install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@${OAPI_CODEGENVERSION_REQ}
endif
ifeq ($(OASDIFF), true)
	$(GOCMD) install github.com/oasdiff/oasdiff@v${OASDIFF_REQ}
endif
