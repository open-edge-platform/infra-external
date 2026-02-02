// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package testing

import (
	"context"

	"github.com/stretchr/testify/mock"

	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/secretprovider"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/secrets"
)

const (
	base64Admin = "YWRtaW4=" // corresponds to 'admin'
	usernameKey = "username"
	passwordKey = "password"
	dataKey     = "data"
)

// SecretServiceMock is a LOC-A specific mock of a secret service.
var SecretServiceMock = &MockSecretsService{}

type MockSecretsService struct {
	mock.Mock
}

func (m *MockSecretsService) ReadSecret(_ context.Context, _ string) (map[string]interface{}, error) {
	creds := make(map[string]interface{}, 0)
	creds[usernameKey] = base64Admin
	creds[passwordKey] = base64Admin

	resp := make(map[string]interface{}, 0)
	resp[dataKey] = creds
	return resp, nil
}

func (m *MockSecretsService) WriteSecret(_ context.Context, _ string, _ map[string]interface{}) (map[string]interface{}, error) {
	// function is needed to be implemented, even if it does nothing,
	// in order to comply with the secretservice interface
	return map[string]interface{}{}, nil
}

func (m *MockSecretsService) Logout(_ context.Context) {
	// function is needed to be implemented, even if it does nothing,
	// in order to comply with the secretservice interface
}

func StartMockSecretService() {
	secrets.SecretServiceFactory = func(context.Context) (secrets.SecretsService, error) {
		return SecretServiceMock, nil
	}
	PopulateProviderCredentials()
}

func PopulateProviderCredentials() {
	if initErr := secretprovider.Init(context.Background(), []string{LocaSecret}); initErr != nil {
		zlog.InfraSec().Fatal().Err(initErr).Msgf("Unable to initialize required secrets")
	}
}
