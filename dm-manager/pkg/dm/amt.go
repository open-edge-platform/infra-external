// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package dm

import (
	"context"
	"fmt"
	"strings"
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

type ReconcilerConfig struct {
	ClusterDomain string
	AmtPassword   string

	RequestTimeout  time.Duration
	ReconcilePeriod time.Duration
}
type Reconciler struct {
	MpsClient       mps.ClientWithResponsesInterface
	RpsClient       rps.ClientWithResponsesInterface
	InventoryClient client.TenantAwareInventoryClient
	EventsWatcher   chan *client.WatchEvents
	TermChan        chan bool
	ReadyChan       chan bool
	WaitGroup       *sync.WaitGroup
	Config          *ReconcilerConfig
}

func (dmr *Reconciler) Start() {
	ticker := time.NewTicker(dmr.Config.ReconcilePeriod)
	if dmr.ReadyChan != nil {
		dmr.ReadyChan <- true
	}
	log.Info().Msgf("Starting periodic reconciliation")
	dmr.Reconcile()
	for {
		select {
		case <-ticker.C:
			log.Info().Msgf("Running periodic reconciliation")
			dmr.Reconcile()
		case <-dmr.TermChan:
			log.Info().Msgf("Stopping periodic reconciliation")
			ticker.Stop()
			dmr.WaitGroup.Done()
			return
		case event := <-dmr.EventsWatcher:
			if event.Event.GetEventKind() == inventoryv1.SubscribeEventsResponse_EVENT_KIND_CREATED {
				log.Info().Msgf("Received create event: %v", event.Event.GetResource().GetTenant().GetResourceId())
				dmr.handleTenantCreation(event.Event.GetResource().GetTenant())
			}

			if event.Event.GetEventKind() == inventoryv1.SubscribeEventsResponse_EVENT_KIND_DELETED {
				log.Info().Msgf("Received delete event: %v", event.Event.GetResource().GetTenant().GetResourceId())
				dmr.handleTenantRemoval(event.Event.GetResource().GetTenant())
			}
		}
	}
}

func convertCertToCertBlob(cert []byte) string {
	certString := string(cert)
	certString = strings.ReplaceAll(certString, "-----BEGIN CERTIFICATE-----", "")
	certString = strings.ReplaceAll(certString, "-----END CERTIFICATE-----", "")
	certString = strings.ReplaceAll(certString, "\r", "")
	certString = strings.ReplaceAll(certString, "\n", "")
	return certString
}

func (dmr *Reconciler) handleTenantRemoval(
	tenant *tenantv1.Tenant,
) {
	log.Info().Msgf("Handling tenant removal: %v", tenant.GetTenantId())
	ctx, cancel := context.WithTimeout(context.Background(), dmr.Config.RequestTimeout)
	defer cancel()

	profileResp, err := dmr.RpsClient.RemoveProfileWithResponse(ctx, tenant.GetTenantId())
	if err != nil {
		log.Err(err).Msgf("cannot remove profile for %v tenant", tenant.GetTenantId())
	}

	log.Info().Msgf("profile removal response: %v", string(profileResp.Body))

	ciraResp, err := dmr.RpsClient.RemoveCIRAConfigWithResponse(ctx, tenant.GetTenantId())
	if err != nil {
		log.Err(err).Msgf("cannot remove CIRA config for %v tenant", tenant.GetTenantId())
	}
	log.Info().Msgf("cira removal response: %v", string(ciraResp.Body))

	log.Info().Msgf("Finished tenant removal: %v", tenant.GetTenantId())
}

func (dmr *Reconciler) handleTenantCreation(
	tenant *tenantv1.Tenant,
) {
	log.Info().Msgf("Handling tenant creation: %v", tenant.GetTenantId())
	ctx, cancel := context.WithTimeout(context.Background(), dmr.Config.RequestTimeout)
	defer cancel()

	cert, err := dmr.MpsClient.GetApiV1CiracertWithResponse(ctx)
	if err != nil {
		log.Err(err).Msgf("cannot get CIRA cert")
		return
	}

	ciraConfig, err := dmr.RpsClient.GetCIRAConfigWithResponse(ctx, tenant.GetTenantId())
	if err != nil {
		log.Err(err).Msgf("cannot get CIRA config for %v tenant", tenant.GetTenantId())
		return
	}

	if ciraConfig.JSON404 != nil {
		log.Info().Msgf("CIRA config not found for %v tenant, creating it", tenant.GetTenantId())
		postCiraConfig, postErr := dmr.RpsClient.CreateCIRAConfigWithResponse(ctx, rps.CreateCIRAConfigJSONRequestBody{
			AuthMethod:          passwordAuth, // password auth
			ServerAddressFormat: fqdnServerFormat,
			CommonName:          "mps-node." + dmr.Config.ClusterDomain,
			MpsServerAddress:    "mps-node." + dmr.Config.ClusterDomain,
			MpsPort:             mpsPort,
			ConfigName:          tenant.GetTenantId(),
			MpsRootCertificate:  convertCertToCertBlob(cert.Body),
			ProxyDetails:        "", // TODO: pass proxy from config
			Username:            "admin",
			Password:            &dmr.Config.AmtPassword,
		})
		if postErr != nil {
			log.Err(err).Msgf("cannot create CIRA config for %v tenant", tenant.GetTenantId())
			return
		}

		if postCiraConfig.JSON201 != nil {
			log.Info().Msgf("created CIRA config for %v", tenant.GetTenantId())
		} else {
			log.Err(fmt.Errorf("%v", string(postCiraConfig.Body))).Msgf("cannot create CIRA config for %v", tenant.GetTenantId())
			return
		}
	}

	profile, err := dmr.RpsClient.GetProfileWithResponse(ctx, tenant.GetTenantId())
	if err != nil {
		log.Err(err).Msgf("cannot get profile for %v tenant", tenant.GetTenantId())
		return
	}
	if profile.JSON404 != nil {
		log.Info().Msgf("profile not found for %v tenant, creating it", tenant.GetTenantId())

		profilePostResponse, err := dmr.RpsClient.CreateProfileWithResponse(ctx, rps.CreateProfileJSONRequestBody{
			Activation:                 "ccmactivate",
			AmtPassword:                &dmr.Config.AmtPassword,
			CiraConfigName:             Ptr(tenant.GetTenantId()),
			DhcpEnabled:                true,
			GenerateRandomMEBxPassword: false,
			GenerateRandomPassword:     false,
			IpSyncEnabled:              Ptr(false),
			KvmEnabled:                 Ptr(true),
			MebxPassword:               Ptr(dmr.Config.AmtPassword),
			ProfileName:                tenant.GetTenantId(),
			SolEnabled:                 Ptr(true),
			TlsMode:                    nil,
			TlsSigningAuthority:        "SelfSigned",
		})
		if err != nil {
			log.Err(err).Msgf("cannot create profile for %v tenant", tenant.GetTenantId())
			return
		}
		if profilePostResponse.JSON201 != nil {
			log.Info().Msgf("created profile for %v", tenant.GetTenantId())
		} else {
			log.Err(fmt.Errorf("%v", string(profilePostResponse.Body))).Msgf("cannot create profile for %v", tenant.GetTenantId())
			return
		}
	}

	log.Info().Msgf("creation for %v tenant is done", tenant.GetTenantId())
}

func (dmr *Reconciler) Stop() {
}

func (dmr *Reconciler) Reconcile() {
	ctx, cancel := context.WithTimeout(context.Background(), dmr.Config.RequestTimeout)
	defer cancel()
	tenants, err := dmr.InventoryClient.ListAll(ctx, &inventoryv1.ResourceFilter{
		Resource: &inventoryv1.Resource{Resource: &inventoryv1.Resource_Tenant{}},
	})
	if err != nil {
		log.Err(err).Msgf("cannot list tenants")
		return
	}

	for _, tenant := range tenants {
		dmr.handleTenantCreation(tenant.GetTenant())
	}
}

func Ptr[T any](v T) *T {
	return &v
}
