/*
 * // SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * // SPDX-License-Identifier: Apache-2.0
 */

package devices

import (
	"context"
	"sync"

	"github.com/rs/zerolog/log"

	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	"github.com/open-edge-platform/infra-external/dm-manager/pkg/api/mps"
	"github.com/open-edge-platform/infra-external/dm-manager/pkg/api/rps"
	rec_v2 "github.com/open-edge-platform/orch-library/go/pkg/controller/v2"
)

type DeviceID string

func (id DeviceID) String() string {
	return string(id)
}

type DeviceController struct {
	MpsClient        mps.ClientWithResponsesInterface
	RpsClient        rps.ClientWithResponsesInterface
	InventoryClient  client.TenantAwareInventoryClient
	TermChan         chan bool
	ReadyChan        chan bool
	WaitGroup        *sync.WaitGroup
	DeviceController *rec_v2.Controller[DeviceID]
}

func (dc *DeviceController) Start() {
	//ticker := time.NewTicker(time.Minute)
	//dmm.ReadyChan <- true
	log.Info().Msgf("Starting periodic reconciliation for devices")
}

func (dc *DeviceController) Stop() {

}

func (dc *DeviceController) Reconcile(ctx context.Context, request rec_v2.Request[DeviceID]) rec_v2.Directive[DeviceID] {
	return request.Ack()
}
