// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package dm

import (
	"context"
	"net/http"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"gopkg.in/yaml.v3"

	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	"github.com/open-edge-platform/infra-external/dm-manager/pkg/api"
)

var log = logging.GetLogger("DmReconciler")

type ID string

func (id ID) String() string {
	return "12345678"
}

type Reconciler struct {
	APIClient api.ClientWithResponsesInterface
	TermChan  chan bool
	ReadyChan chan bool
	WaitGroup *sync.WaitGroup
}

func (dmr *Reconciler) Start() {
	ticker := time.NewTicker(time.Minute)
	if dmr.ReadyChan != nil {
		dmr.ReadyChan <- true
	}
	log.Info().Msgf("Starting periodic reconciliation")
	dmr.Reconcile(context.Background())
	for {
		select {
		case <-ticker.C:
			log.Info().Msgf("Running periodic reconciliation")
			dmr.Reconcile(context.Background())
		case <-dmr.TermChan:
			log.Info().Msgf("Stopping periodic reconciliation")
			ticker.Stop()
			dmr.WaitGroup.Done()
			return
		}
	}
}

func (dmr *Reconciler) Stop() {
}

func (dmr *Reconciler) Reconcile(ctx context.Context) {
	token, err := login(ctx, dmr.APIClient)
	if err != nil {
		log.Err(err).Msgf("cannot login")
		return
	}

	devicesRsp, err := dmr.APIClient.GetApiV1DevicesWithResponse(context.Background(),
		&api.GetApiV1DevicesParams{}, func(_ context.Context, req *http.Request) error {
			req.Header.Set("Authorization", "Bearer "+token)
			return nil
		})
	if err != nil {
		log.Err(err).Msgf("cannot get devices")
		return
	}

	log.Info().Msgf("devices - %s", string(devicesRsp.Body))

	for _, device := range *devicesRsp.JSON200 {
		resp, err := dmr.APIClient.PostApiV1AmtPowerActionGuidWithResponse(context.TODO(), *device.Guid,
			api.PostApiV1AmtPowerActionGuidJSONRequestBody{
				Action: api.PowerActionRequestActionN10, // reset
			}, func(_ context.Context, req *http.Request) error {
				req.Header.Set("Authorization", "Bearer "+token)
				return nil
			})
		if err != nil {
			log.Err(err).Msgf("cannot reset %v device", *device.Guid)
			return
		}
		log.Info().Msgf("reset %v device - %s", *device.Guid, string(resp.Body))
	}
}

func login(ctx context.Context, client api.ClientWithResponsesInterface) (string, error) {
	mpsCredentials := getCredentials()
	authResp, err := client.PostApiV1AuthorizeWithResponse(ctx, api.PostApiV1AuthorizeJSONRequestBody{
		Username: mpsCredentials.Username,
		Password: mpsCredentials.Password,
	})
	if err != nil {
		log.Err(err).Msgf("cannot auth - %v", err)
		return "", errors.Errorfc(codes.Internal, "cannot auth - %v", err)
	}
	if authResp.JSON200 == nil {
		log.Fatal().Msgf("authentication resp is nil")
	}

	return *authResp.JSON200.Token, nil
}

type credentials struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// should read from Vault instead.
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
