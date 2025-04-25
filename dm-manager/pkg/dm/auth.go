// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package dm

import (
	"context"
	"net/http"
	"os"
	"time"

	"google.golang.org/grpc/codes"
	"gopkg.in/yaml.v3"

	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	"github.com/open-edge-platform/infra-external/dm-manager/pkg/api"
)

var tokenRefreshInterval = 23 * time.Hour // by-default token is valid for 24 hours

type MpsAuthHandler struct {
	APIClient api.ClientWithResponsesInterface
	token     string
	updatedAt time.Time
}

type credentials struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

func (mah *MpsAuthHandler) getToken(ctx context.Context) error {
	mpsCredentials := getCredentials()
	authResp, err := mah.APIClient.PostApiV1AuthorizeWithResponse(ctx, api.PostApiV1AuthorizeJSONRequestBody{
		Username: mpsCredentials.Username,
		Password: mpsCredentials.Password,
	})
	if err != nil {
		log.Err(err).Msgf("cannot auth to MPS")
		return errors.Errorfc(codes.Internal, "cannot auth to MPS- %v", err)
	}
	if authResp.JSON200 == nil {
		log.Err(err).Msgf("received empty token from MPS")
		return errors.Errorfc(codes.Internal, "received empty token from MPS - %v", err)
	}

	mah.token = *authResp.JSON200.Token
	mah.updatedAt = time.Now()

	log.Info().Msgf("MPS token is refreshed")

	return nil
}

// TODO: should read from Vault instead.
func getCredentials() credentials {
	file, err := os.Open("/etc/dm/credentials.yaml")
	if err != nil {
		log.Fatal().Err(err).Msgf("Error opening credentials file")
	}

	var mpsCredentials credentials
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&mpsCredentials); err != nil {
		file.Close()
		log.Fatal().Err(err).Msgf("Error parsing credentials file")
	}
	file.Close()

	if mpsCredentials.Username == "" || mpsCredentials.Password == "" {
		log.Fatal().Msgf("Username or Password is empty")
	}

	return mpsCredentials
}

func (mah *MpsAuthHandler) MpsAuth(ctx context.Context, req *http.Request) error {
	if time.Now().After(mah.updatedAt.Add(tokenRefreshInterval)) || mah.token == "" {
		err := mah.getToken(ctx)
		if err != nil {
			return err
		}
	}

	req.Header.Set("Authorization", "Bearer "+mah.token)
	return nil
}
