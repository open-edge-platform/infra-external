// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

// Package auth provides a Keycloak JWT token provider for SOL-manager.
// It uses the inventory auth package's AuthService + GetCredentialsByUUID
// to obtain edge-node Keycloak client credentials, then performs a
// client_credentials OAuth2 grant to obtain a short-lived JWT.
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	invAuth "github.com/open-edge-platform/infra-core/inventory/v2/pkg/auth"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
)

var log = logging.GetLogger("sol-auth")

// tokenResponse is the JSON body returned by the Keycloak token endpoint.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"` // seconds
	TokenType   string `json:"token_type"`
}

// TokenProvider obtains and caches a Keycloak JWT for MPS authentication.
// Flow:
//  1. Call AuthService.GetCredentialsByUUID to get edge-node clientID + clientSecret.
//  2. POST client_credentials grant to Keycloak to obtain a JWT.
//  3. Cache and auto-refresh the JWT (with a 30 s safety margin).
type TokenProvider struct {
	keycloakURL string // e.g. "http://platform-keycloak.orch-platform:8080"
	realm       string // e.g. "master"

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

// NewTokenProvider creates a new TokenProvider.
func NewTokenProvider(keycloakURL, realm string) *TokenProvider {
	return &TokenProvider{
		keycloakURL: strings.TrimRight(keycloakURL, "/"),
		realm:       realm,
	}
}

// GetTokenForHost obtains a Keycloak JWT by:
//  1. Creating an AuthService via the inventory auth package.
//  2. Calling GetCredentialsByUUID to retrieve the edge-node Keycloak clientID / clientSecret.
//  3. Performing a client_credentials grant to Keycloak with those credentials.
//
// The returned JWT is cached and reused until it nears expiration.
func (p *TokenProvider) GetTokenForHost(ctx context.Context, tenantID, hostUUID string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Return cached token if still valid (30 s safety margin).
	if p.token != "" && time.Now().Before(p.expiresAt.Add(-30*time.Second)) {
		return p.token, nil
	}

	// Step 1 -- Get edge-node Keycloak client credentials via auth service.
	authService, err := invAuth.AuthServiceFactory(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to create auth service: %w", err)
	}
	defer authService.Logout(ctx)

	clientID, clientSecret, err := authService.GetCredentialsByUUID(ctx, tenantID, hostUUID)
	if err != nil {
		return "", fmt.Errorf("GetCredentialsByUUID failed for host %s: %w", hostUUID, err)
	}

	// Step 2 -- Exchange credentials for a JWT via client_credentials grant.
	accessToken, expiresIn, err := fetchToken(p.keycloakURL, p.realm, clientID, clientSecret)
	if err != nil {
		return "", err
	}

	p.token = accessToken
	p.expiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
	log.Debug().Msgf("Keycloak JWT acquired for host %s (expires in %d s), token: %s", hostUUID, expiresIn, accessToken)
	return p.token, nil
}

// fetchToken performs a client_credentials POST to Keycloak's token endpoint.
func fetchToken(keycloakURL, realm, clientID, clientSecret string) (string, int, error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token",
		keycloakURL, realm)

	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}

	resp, err := http.Post(tokenURL, "application/x-www-form-urlencoded", //nolint:gosec,noctx // cluster-internal call
		strings.NewReader(data.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("keycloak token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("keycloak token endpoint returned HTTP %d", resp.StatusCode)
	}

	var tokenResp tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", 0, fmt.Errorf("failed to decode keycloak token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return "", 0, fmt.Errorf("keycloak returned empty access_token")
	}
	return tokenResp.AccessToken, tokenResp.ExpiresIn, nil
}
