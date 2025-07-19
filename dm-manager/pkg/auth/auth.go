// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"os"

	"google.golang.org/grpc/metadata"

	vaultAuth "github.com/open-edge-platform/orch-library/go/pkg/auth"
)

func GetToken(ctx context.Context) (context.Context, error) {
	keycloakServer := os.Getenv("KEYCLOAK_SERVER")
	vaultServer := os.Getenv("VAULT_SERVER")
	serviceAcct := os.Getenv("SERVICE_ACCOUNT")
	vaultAuthClient, err := vaultAuth.NewVaultAuth(keycloakServer, vaultServer, serviceAcct)
	if err != nil {
		return ctx, err
	}

	tokenStr, err := vaultAuthClient.GetM2MToken(ctx)
	if err != nil {
		logoutErr := vaultAuthClient.Logout(ctx)
		if logoutErr != nil {
			return ctx, logoutErr
		}
		return ctx, err
	}
	if tokenStr == "" {
		return ctx, nil
	}

	updatedCtx := metadata.AppendToOutgoingContext(ctx, "Authorization", "Bearer "+tokenStr)
	err = vaultAuthClient.Logout(ctx)
	return updatedCtx, err
}
