// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"os"
	"time"

	"google.golang.org/grpc/codes"

	providerv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/provider/v1"
	inverror "github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/providerconfiguration"
)

type TemplatesManagerConfig struct {
	OsPassword       string   `json:"os_password"`
	SupportedServers []string `json:"supported_servers"`
	PostScript       string   `json:"post_script"`

	TemplateCreationTimeout time.Duration `json:"template_creation_timeout"`
	TemplateReconcilePeriod time.Duration `json:"template_reconcile_period"`
	TinkerbellURL           string        `json:"tinkerbell_url"`
}

const (
	defaultTemplateCreationTimeout = time.Hour
	defaultTemplateReconcilePeriod = time.Minute
	defaultTinkerbellURL           = "ingress-nginx-controller.orch-boots.svc:443"
	defaultPostScript              = "echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config && systemctl restart sshd"
)

var (
	Path          = "/etc/templates-manager/config"
	log           = logging.GetLogger("Config")
	managerConfig = &TemplatesManagerConfig{}
	initialized   = false
)

func readConfig(path string) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatal().Msgf("failed to read config file - %v", err)
	}

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&managerConfig)
	if err != nil {
		log.Fatal().Msgf("failed to unmarshal config file - %v", err)
	}

	setDefaultsIfNotSet()
}

func GetProviderConfig(provider *providerv1.ProviderResource) (*providerconfiguration.LOCAProviderConfig, error) {
	config := &providerconfiguration.LOCAProviderConfig{}
	if provider.GetConfig() == "" {
		return nil, inverror.Errorfc(codes.FailedPrecondition,
			"provider config for %v is empty, but it should contain DNS-related configuration - %+v", provider.GetName(), config)
	}

	err := json.Unmarshal([]byte(provider.GetConfig()), config)
	if err != nil {
		err = inverror.Errorfc(codes.InvalidArgument, "failed to unmarshall response into ProviderConfig config")
		log.Err(err).Msgf("")
		return nil, err
	}

	if config.DNSDomain == "" || config.InstanceTpl == "" {
		err = inverror.Errorfc(codes.InvalidArgument, "one of the required fields is empty - %+v", config)
		return nil, err
	}
	return config, nil
}

func setDefaultsIfNotSet() {
	var zeroValueDuration time.Duration
	if managerConfig.TemplateCreationTimeout == zeroValueDuration {
		log.Info().Msgf("TemplateCreationTimeout is not set - using default value of '%v' instead",
			defaultTemplateCreationTimeout)
		managerConfig.TemplateCreationTimeout = defaultTemplateCreationTimeout
	}
	if managerConfig.TemplateReconcilePeriod == zeroValueDuration {
		log.Info().Msgf("TemplateReconcilePeriod is not set - using default value of '%v' instead",
			defaultTemplateReconcilePeriod)
		managerConfig.TemplateReconcilePeriod = defaultTemplateReconcilePeriod
	}
	if managerConfig.TinkerbellURL == "" {
		log.Info().Msgf("TinkerbellURL is not set - using default value of '%v' instead", defaultTinkerbellURL)
		managerConfig.TinkerbellURL = defaultTinkerbellURL
	}
	if managerConfig.PostScript == "" {
		log.Info().Msgf("PostScript is not set - using default value of '%v' instead", defaultPostScript)
		managerConfig.PostScript = defaultPostScript
	}
}

func GetConfig() *TemplatesManagerConfig {
	if !initialized {
		readConfig(Path)
		initialized = true
	}
	return managerConfig
}
