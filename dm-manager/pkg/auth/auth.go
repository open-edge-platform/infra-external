// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"os"
	"strconv"

	vaultAuth "github.com/open-edge-platform/orch-library/go/pkg/auth"
)

type ContextValue string

func GetToken(ctx context.Context) (updatedCtx context.Context, err error) {
	requireTokenStr := os.Getenv("USE_M2M_TOKEN")
	requireToken, err := strconv.ParseBool(requireTokenStr)
	updatedCtx = ctx
	if err != nil || !requireToken {
		return //nolint: nakedret // no return values specified since variables specified in function definition
	}
	keycloakServer := os.Getenv("KEYCLOAK_SERVER")
	vaultServer := os.Getenv("VAULT_SERVER")
	serviceAcct := os.Getenv("SERVICE_ACCOUNT")
	vaultAuthClient, err := vaultAuth.NewVaultAuth(keycloakServer, vaultServer, serviceAcct)
	if err != nil {
		return //nolint: nakedret // no return values specified since variables specified in function definition
	}

	defer func() {
		logoutErr := vaultAuthClient.Logout(ctx)
		if logoutErr != nil {
			err = logoutErr
		}
	}()

	tokenStr, err := vaultAuthClient.GetM2MToken(ctx)
	if err != nil {
		return //nolint: nakedret // no return values specified since variables specified in function definition
	}
	if tokenStr == "" {
		return //nolint: nakedret // no return values specified since variables specified in function definition
	}

	updatedCtx = context.WithValue(ctx, ContextValue("Authorization"), "Bearer "+tokenStr)
	return //nolint: nakedret // no return values specified since variables specified in function definition
}
