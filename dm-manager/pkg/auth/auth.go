// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"fmt"
	"os"
	"strconv"

	vaultAuth "github.com/open-edge-platform/orch-library/go/pkg/auth"
)

type ContextValue string

func GetToken(ctx context.Context) (context.Context, error) {
	requireTokenStr := os.Getenv("USE_M2M_TOKEN")
	requireToken, err := strconv.ParseBool(requireTokenStr)
	if err != nil || !requireToken {
		fmt.Printf("USE_M2M_TOKEN not set")
		return ctx, fmt.Errorf("environment variable not set")
	}
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
		fmt.Printf("tokenStr empty")
		return ctx, fmt.Errorf("tokenStr empty")
	}

	updatedCtx := context.WithValue(ctx, ContextValue("Authorization"), "Bearer "+tokenStr)
	err = vaultAuthClient.Logout(ctx)
	return updatedCtx, err
}
