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
	"github.com/open-edge-platform/infra-external/dm-manager/pkg/api/mps"
)

var (
	tokenRefreshInterval = 23 * time.Hour             // by-default token is valid for 24 hours.
	credentialsFile      = "/etc/dm/credentials.yaml" //nolint:gosec // not a credential
)

type DmtAuthHandler struct {
	MpsClient mps.ClientWithResponsesInterface
	token     string
	updatedAt time.Time
}

type credentials struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

func (dah *DmtAuthHandler) getToken(ctx context.Context) error {
	dmtCredentials := getCredentials()
	authResp, err := dah.MpsClient.PostApiV1AuthorizeWithResponse(ctx, mps.PostApiV1AuthorizeJSONRequestBody{
		Username: dmtCredentials.Username,
		Password: dmtCredentials.Password,
	})
	if err != nil {
		log.Err(err).Msgf("cannot auth to MPS")
		return errors.Errorfc(codes.Internal, "cannot auth to MPS - %v", err)
	}
	if authResp.JSON200 == nil {
		log.Err(err).Msgf("received empty token from MPS")
		return errors.Errorfc(codes.Internal, "received empty token from MPS - %v", err)
	}

	dah.token = *authResp.JSON200.Token
	dah.updatedAt = time.Now()

	log.Info().Msgf("MPS token is refreshed")

	return nil
}

// TODO: should read from Vault instead.
func getCredentials() credentials {
	file, err := os.Open(credentialsFile)
	if err != nil {
		log.Fatal().Err(err).Msgf("Error opening credentials file")
	}

	var dmtCredentials credentials
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&dmtCredentials); err != nil {
		file.Close()
		log.Fatal().Err(err).Msgf("Error parsing credentials file")
	}
	file.Close()

	if dmtCredentials.Username == "" || dmtCredentials.Password == "" {
		log.Fatal().Msgf("Username or Password is empty")
	}

	return dmtCredentials
}

func (dah *DmtAuthHandler) DmtAuth(ctx context.Context, req *http.Request) error {
	if time.Now().After(dah.updatedAt.Add(tokenRefreshInterval)) || dah.token == "" {
		err := dah.getToken(ctx)
		if err != nil {
			return err
		}
	}

	req.Header.Set("Authorization", "Bearer "+dah.token)
	return nil
}
