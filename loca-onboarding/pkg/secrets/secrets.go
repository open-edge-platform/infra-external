// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"

	inv_errors "github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/flags"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/secretprovider"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/secrets"
)

var zlog = logging.GetLogger("secrets")

type SecretProvider interface {
	// Init initializes the SecretProvider.
	// It should always be invoked at the very beginning, before other methods are used.
	Init(ctx context.Context, secretName []string) error
	// GetSecret obtains a value of the `secretKey` from the secret identified by the `secretName`.
	GetSecret(secretName, secretKey string) string
}

type VaultSecretProvider struct{}

func Init(ctx context.Context, secretNames []string) error {
	if len(secretNames) == 0 {
		err := inv_errors.Errorfc(codes.Internal, "Init called with empty secrets")
		return err
	}

	vsp := &VaultSecretProvider{}
	return vsp.Init(ctx, secretNames)
}

func (vsp *VaultSecretProvider) GetSecret(secretName, secretKey string) string {
	if *flags.FlagDisableCredentialsManagement {
		zlog.Warn().Msgf("disableCredentialsManagement flag is set to true, " +
			"skip GetSecret")
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	zlog.Info().Msgf("getting %v-%v secret", secretName, secretKey)
	vaultS, err := secrets.SecretServiceFactory(ctx)
	if err != nil {
		return ""
	}
	defer vaultS.Logout(ctx)

	credentials, err := vaultS.ReadSecret(ctx, secretName)
	if err != nil {
		return ""
	}

	dataMap, ok := credentials["data"].(map[string]interface{})
	if !ok {
		err = inv_errors.Errorf("Cannot read credentials data from Vault secret")
		zlog.InfraSec().Err(err).Msg("")
		return ""
	}

	for key, secretValue := range dataMap {
		if key == secretKey {
			secret, ok := secretValue.(string)
			if !ok {
				err = inv_errors.Errorf("Wrong format of %v read from Vault, expected string, got %T", secretKey, secretValue)
				zlog.InfraSec().Err(err).Msg("")
				return ""
			}
			return secret
		}
	}
	return ""
}

func (vsp *VaultSecretProvider) Init(ctx context.Context, secretNames []string) error {
	if *flags.FlagDisableCredentialsManagement {
		zlog.Warn().Msgf("disableCredentialsManagement flag is set to true, " +
			"skip secrets initialization")
		return nil
	}

	if len(secretNames) == 0 {
		err := inv_errors.Errorfc(codes.Internal, "Init called with empty secrets")
		return err
	}

	// checking if we are able to connect to Vault
	vaultS, err := secrets.SecretServiceFactory(ctx)
	if err != nil {
		return err
	}
	defer vaultS.Logout(ctx)
	zlog.Info().Msgf("connected to Vault and got %v secrets", secretNames)

	return secretprovider.Init(ctx, secretNames)
}
