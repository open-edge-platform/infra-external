/*
 * // SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * // SPDX-License-Identifier: Apache-2.0
 */

package devices

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	inventoryv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	"github.com/open-edge-platform/infra-external/dm-manager/pkg/api/mps"
	"github.com/open-edge-platform/infra-external/dm-manager/pkg/api/rps"
	rec_v2 "github.com/open-edge-platform/orch-library/go/pkg/controller/v2"
)

type HostID string

func (id HostID) GetTenantID() string {
	return strings.Split(string(id), "_")[0]
}

func (id HostID) GetHostID() string {
	return strings.Split(string(id), "_")[0]
}

func (id HostID) String() string {
	return fmt.Sprintf("[tenantID=%s, hostID=%s]", id.GetTenantID(), id.GetHostID())
}

func NewDeviceID(tenantID, hostID string) HostID {
	return HostID(tenantID + "_" + hostID)
}

type DeviceController struct {
	MpsClient        mps.ClientWithResponsesInterface
	RpsClient        rps.ClientWithResponsesInterface
	InventoryClient  client.TenantAwareInventoryClient
	TermChan         chan bool
	ReadyChan        chan bool
	EventsWatcher    chan *client.WatchEvents
	WaitGroup        *sync.WaitGroup
	DeviceController *rec_v2.Controller[HostID]

	ReconcilePeriod time.Duration
	RequestTimeout  time.Duration
}

func (dc *DeviceController) Start() {
	ticker := time.NewTicker(dc.ReconcilePeriod)
	dc.ReadyChan <- true
	log.Info().Msgf("Starting periodic reconciliation for devices")
	dc.ReconcileAll()
	for {
		select {
		case <-ticker.C:
			dc.ReconcileAll()
		case <-dc.TermChan:
			log.Info().Msgf("Stopping periodic reconciliation")
			ticker.Stop()
			dc.Stop()
			return
		case event, ok := <-dc.EventsWatcher:
			if !ok {
				ticker.Stop()
				dc.Stop()
				return
			}
			log.Info().Msgf("event received: %v", event)
		}
	}
}

func (dc *DeviceController) ReconcileAll() {
	ctx, cancel := context.WithTimeout(context.Background(), dc.RequestTimeout)
	defer cancel()
	hosts, err := dc.InventoryClient.ListAll(ctx, &inventoryv1.ResourceFilter{
		Resource: &inventoryv1.Resource{Resource: &inventoryv1.Resource_Host{}},
	})
	if err != nil {
		log.Error().Err(err).Msgf("Failed to list hosts")
		return
	}

	for _, host := range hosts {
		err := dc.DeviceController.Reconcile(NewDeviceID(host.GetHost().GetTenantId(), host.GetHost().GetResourceId()))
		if err != nil {
			log.Err(err).Msgf("failed to reconcile device")
		}
	}
	log.Debug().Msgf("reconcilation of devices is done")
}

func (dc *DeviceController) Stop() {

}

func (dc *DeviceController) Reconcile(ctx context.Context, request rec_v2.Request[HostID]) rec_v2.Directive[HostID] {

	return request.Ack()
}
