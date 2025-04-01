// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package loca

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	loca_testing "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/testing"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/util"
)

func TestMain(m *testing.M) {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	projectRoot := filepath.Dir(filepath.Dir(filepath.Dir(wd)))
	err = os.Setenv(CaCertPath, projectRoot+"/secrets")
	if err != nil {
		panic(err)
	}

	loca_testing.StartMockSecretService()
	run := m.Run() // run all tests

	os.Exit(run)
}

func Test_initialiseLOCAClient(t *testing.T) {
	// preparing input data
	url := "192.168.0.2"
	// should be encoded or contain a Vault token to retrieve credentials from Vault
	wrongCredentials := []string{"dummy:dummy", "username:value"}

	// no URL
	_, err := InitialiseLOCAClient("", []string{loca_testing.LocaSecret})
	require.Error(t, err)

	// no credentials
	_, err = InitialiseLOCAClient(url, nil)
	require.Error(t, err)

	// wrong, multiple credentials
	_, err = InitialiseLOCAClient(url, wrongCredentials)
	require.Error(t, err)

	// correct data on input
	lc, err := InitialiseLOCAClient(url, []string{loca_testing.LocaSecret})
	require.NoError(t, err)
	assert.Equal(t, lc.URL, url)
}

func TestInitialiseLOCAClient_whenEmptyUrlIsProvidedThenErrorShouldBeReturned(t *testing.T) {
	assertHook := util.NewTestAssertHook("Failed to create LOC-A client")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	defer func() {
		if r := recover(); r != nil {
			assertHook.Assert(t)
		}
	}()

	InitialiseTestLocaClient("", "abc")
}
