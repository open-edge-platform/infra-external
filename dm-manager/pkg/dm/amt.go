// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package dm

import (
	"context"
	"sync"
	"time"

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
	devicesRsp, err := dmr.APIClient.GetApiV1DevicesWithResponse(ctx,
		&api.GetApiV1DevicesParams{})
	if err != nil {
		log.Err(err).Msgf("cannot get devices")
		return
	}

	log.Info().Msgf("devices - %s", string(devicesRsp.Body))

	for _, device := range *devicesRsp.JSON200 {
		resp, err := dmr.APIClient.PostApiV1AmtPowerActionGuidWithResponse(ctx, *device.Guid,
			api.PostApiV1AmtPowerActionGuidJSONRequestBody{
				Action: api.PowerActionRequestActionN10, // reset
			})
		if err != nil {
			log.Err(err).Msgf("cannot reset %v device", *device.Guid)
			return
		}
		log.Info().Msgf("reset %v device - %s", *device.Guid, string(resp.Body))
	}
}
