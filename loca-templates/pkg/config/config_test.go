// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

//nolint:testpackage // tests private functions
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	providerv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/provider/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/providerconfiguration"
	inv_testing "github.com/open-edge-platform/infra-core/inventory/v2/pkg/testing"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/loca"
	_ "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/examples"
	loca_testing "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/testing"
)

const clientName = "TestTMInventoryClient"

func Test_setDefaultsIfNotSet_whenConfigIsEmptyShouldSetDefaultValues(t *testing.T) {
	assert.Empty(t, managerConfig.TemplateCreationTimeout)
	assert.Empty(t, managerConfig.TemplateReconcilePeriod)
	assert.Empty(t, managerConfig.TinkerbellURL)
	assert.Empty(t, managerConfig.PostScript)

	setDefaultsIfNotSet()

	assert.Equal(t, defaultTemplateCreationTimeout, managerConfig.TemplateCreationTimeout)
	assert.Equal(t, defaultTemplateReconcilePeriod, managerConfig.TemplateReconcilePeriod)
	assert.Equal(t, defaultTinkerbellURL, managerConfig.TinkerbellURL)
	assert.Equal(t, defaultPostScript, managerConfig.PostScript)
}

func Test_setDefaultsIfNotSet_whenValuesAreSetShouldNotOverwriteThem(t *testing.T) {
	stringValue := "test"
	durationValue := time.Millisecond
	managerConfig.TemplateCreationTimeout = durationValue
	managerConfig.TemplateReconcilePeriod = durationValue
	managerConfig.TinkerbellURL = stringValue
	managerConfig.PostScript = stringValue

	setDefaultsIfNotSet()

	assert.Equal(t, durationValue, managerConfig.TemplateCreationTimeout)
	assert.Equal(t, durationValue, managerConfig.TemplateReconcilePeriod)
	assert.Equal(t, stringValue, managerConfig.TinkerbellURL)
	assert.Equal(t, stringValue, managerConfig.PostScript)
}

func Test_readConfig(t *testing.T) {
	file, err := os.CreateTemp("/tmp", t.Name())
	assert.NoError(t, err)

	const tinkerBellURL = "test"
	const reconciliationPeriod = time.Millisecond
	mc := TemplatesManagerConfig{
		TinkerbellURL:           tinkerBellURL,
		TemplateReconcilePeriod: reconciliationPeriod,
	}
	bytes, err := json.Marshal(mc)
	assert.NoError(t, err)

	_, err = file.Write(bytes)
	assert.NoError(t, err)

	readConfig(file.Name())

	assert.Equal(t, tinkerBellURL, managerConfig.TinkerbellURL)
	assert.Equal(t, reconciliationPeriod, managerConfig.TemplateReconcilePeriod)

	assert.Equal(t, defaultTemplateCreationTimeout, managerConfig.TemplateCreationTimeout) // default value
}

func TestMain(t *testing.M) {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	projectRoot := filepath.Dir(filepath.Dir(wd))
	policyPath := projectRoot + "/out"
	migrationsDir := projectRoot + "/out"
	err = os.Setenv(loca.CaCertPath, projectRoot+"/secrets")
	if err != nil {
		panic(err)
	}
	loca_testing.StartTestingEnvironment(policyPath, migrationsDir, clientName)

	code := t.Run()

	inv_testing.StopTestingEnvironment()
	os.Exit(code)
}

func TestGetProviderConfig_whenProviderIsWithoutConfigThenShouldReturnError(t *testing.T) {
	provConfig, err := GetProviderConfig(&providerv1.ProviderResource{})

	assert.ErrorContains(t, err, "is empty")
	assert.Zero(t, provConfig)
}

func TestGetProviderConfig_whenProviderConfigIsInvalidJsonShouldReturnError(t *testing.T) {
	provConfig, err := GetProviderConfig(&providerv1.ProviderResource{Config: "notajson"})

	assert.ErrorContains(t, err, "failed to unmarshall response into ProviderConfig config")
	assert.Zero(t, provConfig)
}

func TestGetProviderConfig_whenProviderConfigIsValidJsonButDoesntHasRequiredFieldsShouldReturnError(t *testing.T) {
	provConfig, err := GetProviderConfig(&providerv1.ProviderResource{Config: "{}"})

	assert.ErrorContains(t, err, "one of the required fields is empty")
	assert.Zero(t, provConfig)
}

func TestGetProviderConfig_happyPath(t *testing.T) {
	mockedConfig := &providerconfiguration.LOCAProviderConfig{
		InstanceTpl: "instanceTpl",
		DNSDomain:   "dnsDomain",
	}
	configBytes, err := json.Marshal(mockedConfig)
	assert.NoError(t, err)

	provConfig, err := GetProviderConfig(&providerv1.ProviderResource{Config: string(configBytes)})

	assert.NoError(t, err)
	assert.Equal(t, mockedConfig.InstanceTpl, provConfig.InstanceTpl)
	assert.Equal(t, mockedConfig.DNSDomain, provConfig.DNSDomain)
}
