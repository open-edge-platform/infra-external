// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package loca

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-openapi/runtime"
	runtimeClient "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"google.golang.org/grpc/codes"

	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/client"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/client/authentication_and_authorization"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/model"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/secrets"
	loca_testing "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/testing"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/util"
)

const (
	disableTLS            = "disableTLS"
	disableTLSDescription = "Disables secure communication with LOC-A over HTTP (using TLS)"
	CaCertPath            = "CA_CERT_PATH"
	usernameKey           = "username"
	passwordKey           = "password"
	// access token is valid for 15 minutes, setting it to lower value to avoid retries.
	tokenRefreshInterval = time.Minute * 14
)

var (
	zlog                        = logging.GetLogger("LOCAClient")
	clients                     sync.Map
	FlagDisableTLSCommunication = flag.Bool(disableTLS, false, disableTLSDescription)
)

type AuthWriter struct {
	secretName string

	token         string
	refreshToken  string
	updatedAt     time.Time
	locaAPIClient *client.LocaAPI

	mutex *sync.Mutex
}

func (aw *AuthWriter) AuthenticateRequest(request runtime.ClientRequest, _ strfmt.Registry) error {
	aw.mutex.Lock()
	defer aw.mutex.Unlock()

	if aw.shouldRefreshToken() {
		err := aw.refreshStoredToken()
		if err != nil {
			return err
		}
	}

	return request.SetHeaderParam("Authorization", "Bearer "+aw.token)
}

func (aw *AuthWriter) shouldRefreshToken() bool {
	return time.Now().After(aw.updatedAt.Add(tokenRefreshInterval)) || aw.token == ""
}

func (aw *AuthWriter) refreshStoredToken() error {
	log.Debug().Msgf("refreshing token")
	if aw.refreshToken != "" {
		return aw.refreshUsingRefreshToken()
	}
	return aw.refreshUsingCredentials()
}

func (aw *AuthWriter) refreshUsingCredentials() error {
	username, password, err := extractCredentials([]string{aw.secretName})
	if err != nil {
		return err
	}
	postLogin, err := aw.locaAPIClient.AuthenticationAndAuthorization.PostAPIV1AuthLogin(
		&authentication_and_authorization.PostAPIV1AuthLoginParams{Body: &model.DtoUserLoginRequest{
			Name:     &username,
			Password: &password,
		}})
	if err != nil {
		log.Err(err).Msgf("failed to refresh token using credentials")
		return errors.Errorfc(codes.Internal, "failed to refresh token using credentials")
	}
	aw.updatedAt = time.Now()
	aw.refreshToken = postLogin.Payload.Data.RefreshToken
	aw.token = postLogin.Payload.Data.Token
	log.Debug().Msgf("Token refreshed successfully using credentials")
	return nil
}

func (aw *AuthWriter) refreshUsingRefreshToken() error {
	postRefresh, err := aw.locaAPIClient.AuthenticationAndAuthorization.PostAPIV1AuthRefreshToken(
		&authentication_and_authorization.PostAPIV1AuthRefreshTokenParams{
			Body: aw.refreshToken,
		}, nil)
	if err != nil {
		log.Err(err).Msgf("failed to refresh token using refresh_token. Trying credentials instead.")
		return aw.refreshUsingCredentials()
	}
	aw.updatedAt = time.Now()
	aw.refreshToken = postRefresh.Payload.Data.RefreshToken
	aw.token = postRefresh.Payload.Data.AccessToken
	log.Debug().Msgf("Token refreshed successfully using refresh_token")
	return nil
}

//nolint:revive // Name is much clearer with Loca prefix.
type LocaCli struct {
	HTTPCli    *http.Client
	LocaAPI    *client.LocaAPI
	URL        string
	AuthWriter *AuthWriter
}

func InitialiseLOCAClient(url string, credentials []string) (*LocaCli, error) {
	if url == "" {
		err := errors.Errorfc(codes.InvalidArgument, "An empty Provider URL is passed")
		zlog.InfraErr(err).Msgf("Failed to create LOC-A client")
		return nil, err
	}

	if len(credentials) != 1 {
		err := errors.Errorfc(codes.InvalidArgument,
			"Expected to obtain one entry in Provider's credential field (secret name), got %d", len(credentials))
		zlog.InfraErr(err).Msgf("Failed to create LOC-A client")
		return nil, err
	}

	if locaClient, ok := clients.Load(url); ok {
		locaCli, ok := locaClient.(*LocaCli)
		if !ok {
			log.Warn().Msgf("couldn't load client for %v, will try to create new one", url)
		}
		return locaCli, nil
	}

	locaAPIClient, authWriter := InitialiseClient(url, credentials[0])
	locaClient := &LocaCli{LocaAPI: locaAPIClient, URL: url, AuthWriter: authWriter}
	clients.Store(url, locaClient)
	return locaClient, nil
}

func InitialiseTestLocaClient(url, secretName string) *LocaCli {
	if url == "" {
		err := errors.Errorfc(codes.InvalidArgument, "An empty Provider URL is passed")
		zlog.InfraErr(err).Msgf("Failed to create LOC-A client")
		panic(err)
	}

	if locaClient, ok := clients.Load(url); ok {
		locaCli, ok := locaClient.(*LocaCli)
		if !ok {
			log.Warn().Msgf("couldn't load client for %v, will try to create new one", url)
		}
		return locaCli
	}

	loca_testing.StartMockSecretService()
	locaAPIClient, authWriter := InitialiseClient(url, secretName)
	locaClient := &LocaCli{LocaAPI: locaAPIClient, URL: url, AuthWriter: authWriter}
	clients.Store(url, locaClient)
	return locaClient
}

func extractCredentials(providerSecret []string) (string, string, error) {
	zlog.Debug().Msgf("Extracting credentials for Provider")
	// assuming that each Provider contains only one item in the slice
	if len(providerSecret) != 1 {
		err := errors.Errorfc(codes.InvalidArgument,
			"Expected to obtain one entry in Provider's credential field (secret name), got %d", len(providerSecret))
		zlog.InfraSec().InfraErr(err).Msgf("Can't parse credentials")
		return "", "", err
	}
	secret := providerSecret[0]

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	vsp := secrets.VaultSecretProvider{}
	if initErr := vsp.Init(ctx, []string{secret}); initErr != nil {
		zlog.InfraSec().Fatal().Err(initErr).Msgf("Unable to initialize required secrets")
	}

	base64Username := vsp.GetSecret(secret, usernameKey)
	base64Password := vsp.GetSecret(secret, passwordKey)
	if base64Username == "" || base64Password == "" {
		err := errors.Errorfc(codes.InvalidArgument,
			"LOC-A Provider credentials are incomplete - missing username or password")
		zlog.InfraSec().InfraErr(err).Msgf("Failed to parse credentials")
		return "", "", err
	}

	// decoding credentials
	username, decoded1 := util.DecodeBase64(base64Username)
	password, decoded2 := util.DecodeBase64(base64Password)
	if !decoded1 || !decoded2 {
		err := errors.Errorfc(codes.InvalidArgument,
			"One (or both) of the LOC-A Provider credentials were not decoded successfully")
		zlog.InfraSec().InfraErr(err).Msgf("Failed to decode credentials")
		return "", "", err
	}

	return username, password, nil
}

func InitialiseClient(locaURL, secretName string) (*client.LocaAPI, *AuthWriter) {
	schema := "https"
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if *FlagDisableTLSCommunication || strings.HasPrefix(locaURL, "http://") {
		// disable TLS verification
		tr.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // No need to verify LOC-A cert
		}
		schema = "http"
		log.Info().Msgf("disabling HTTPS check and using HTTP instead")
	} else {
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		// embedding certificate into HTTP
		tr.TLSClientConfig = tlsConfig
	}
	httpClient := &http.Client{Transport: tr}
	locaURL = strings.TrimPrefix(strings.TrimPrefix(locaURL, "http://"), "https://")
	locaURL = strings.TrimSuffix(locaURL, "/api/v1")
	locaAPIClient := client.New(runtimeClient.NewWithClient(locaURL, "", []string{schema}, httpClient), nil)

	authWriter := &AuthWriter{locaAPIClient: locaAPIClient, mutex: &sync.Mutex{}, secretName: secretName}
	return locaAPIClient, authWriter
}

func (lc *LocaCli) GetURL() string {
	return lc.URL
}

func NameFilter(name string) *string {
	filter := fmt.Sprintf(`[{"attributes": "name", "values":"%v"}]`, name)
	return &filter
}
