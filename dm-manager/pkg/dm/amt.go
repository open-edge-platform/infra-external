// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package dm

import (
	"context"
	"sync"
	"time"

	inventoryv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	tenantv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/tenant/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	"github.com/open-edge-platform/infra-external/dm-manager/pkg/api/mps"
	"github.com/open-edge-platform/infra-external/dm-manager/pkg/api/rps"
)

const (
	mpsPort          = 4433
	fqdnServerFormat = 201
	passwordAuth     = 2
)

var log = logging.GetLogger("DmReconciler")

type Reconciler struct {
	MpsClient       mps.ClientWithResponsesInterface
	RpsClient       rps.ClientWithResponsesInterface
	InventoryClient client.TenantAwareInventoryClient
	EventsWatcher   chan *client.WatchEvents
	TermChan        chan bool
	ReadyChan       chan bool
	WaitGroup       *sync.WaitGroup
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
		case event := <-dmr.EventsWatcher:
			if event.Event.GetEventKind() == inventoryv1.SubscribeEventsResponse_EVENT_KIND_CREATED {
				log.Info().Msgf("Received create event: %v", event.Event.GetResource().GetTenant().GetResourceId())
				dmr.handleTenantCreation(context.Background(), event.Event.GetResource().GetTenant())
			}

			if event.Event.GetEventKind() == inventoryv1.SubscribeEventsResponse_EVENT_KIND_DELETED {
				log.Info().Msgf("Received delete event: %v", event.Event.GetResource().GetTenant().GetResourceId())
				dmr.handleTenantCreation(context.Background(), event.Event.GetResource().GetTenant())
			}
		}
	}
}

func (dmr *Reconciler) handleTenantCreation(
	ctx context.Context,
	tenant *tenantv1.Tenant,
) {
	clusterDomain := "cluster.onprem"
	password := "password"

	log.Info().Msgf("Handling tenant creation: %v", tenant.GetResourceId())
	cert, err := dmr.MpsClient.GetApiV1CiracertWithResponse(ctx)
	if err != nil {
		log.Err(err).Msgf("cannot get CIRA cert")
		return
	}

	_, err = dmr.RpsClient.CreateCIRAConfigWithResponse(ctx, rps.CreateCIRAConfigJSONRequestBody{
		AuthMethod:          passwordAuth, // password auth
		ServerAddressFormat: fqdnServerFormat,
		CommonName:          "mps-node." + clusterDomain,
		MpsServerAddress:    "mps-node." + clusterDomain,
		MpsPort:             mpsPort,
		ConfigName:          tenant.GetTenantId(),
		MpsRootCertificate:  cert.Body,
		ProxyDetails:        "", // TODO: pass proxy from config
		Username:            "admin",
		Password:            &password,
	})
	if err != nil {
		log.Err(err).Msgf("cannot create CIRA config for %v tenant", tenant.GetTenantId())
		return
	}

	_, err = dmr.RpsClient.CreateProfileWithResponse(ctx, rps.CreateProfileJSONRequestBody{
		Activation:                 "ccmactivate",
		AmtPassword:                &password,
		CiraConfigName:             Ptr(tenant.GetTenantId()),
		DhcpEnabled:                true,
		GenerateRandomMEBxPassword: false,
		GenerateRandomPassword:     false,
		IpSyncEnabled:              Ptr(true),
		KvmEnabled:                 Ptr(true),
		MebxPassword:               Ptr(password),
		ProfileName:                tenant.GetTenantId(),
		SolEnabled:                 Ptr(true),
	})
	if err != nil {
		log.Err(err).Msgf("cannot create profile for %v tenant", tenant.GetTenantId())
		return
	}
}

func (dmr *Reconciler) Stop() {
}

func (dmr *Reconciler) Reconcile(ctx context.Context) {
	devicesRsp, err := dmr.MpsClient.GetApiV1DevicesWithResponse(ctx,
		&mps.GetApiV1DevicesParams{})
	if err != nil {
		log.Err(err).Msgf("cannot get devices")
		return
	}

	log.Info().Msgf("devices - %s", string(devicesRsp.Body))

	for _, device := range *devicesRsp.JSON200 {
		resp, err := dmr.MpsClient.PostApiV1AmtPowerActionGuidWithResponse(ctx, *device.Guid,
			mps.PostApiV1AmtPowerActionGuidJSONRequestBody{
				Action: mps.PowerActionRequestActionN10, // reset
			})
		if err != nil {
			log.Err(err).Msgf("cannot reset %v device", *device.Guid)
			return
		}
		log.Info().Msgf("reset %v device - %s", *device.Guid, string(resp.Body))
	}
}

func Ptr[T any](v T) *T {
	return &v
}
