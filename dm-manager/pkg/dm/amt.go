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
	dmr.ReconcileAdd()
	dmr.ReconcileRemove()
	for {
		select {
		case <-ticker.C:
			log.Info().Msgf("Running periodic reconciliation")
			dmr.ReconcileAdd()
			dmr.ReconcileRemove()
		case <-dmr.TermChan:
			log.Info().Msgf("Stopping periodic reconciliation")
			ticker.Stop()
			dmr.WaitGroup.Done()
			return
		case event := <-dmr.EventsWatcher:
			if event.Event.GetEventKind() == inventoryv1.SubscribeEventsResponse_EVENT_KIND_CREATED {
				log.Info().Msgf("Received create event: %v", event.Event.GetResource().GetTenant().GetResourceId())
				dmr.handleTenantCreation(event.Event.GetResource().GetTenant().GetTenantId())
			}

			if event.Event.GetEventKind() == inventoryv1.SubscribeEventsResponse_EVENT_KIND_DELETED {
				log.Info().Msgf("Received delete event: %v", event.Event.GetResource().GetTenant().GetResourceId())
				dmr.handleTenantRemoval(event.Event.GetResource().GetTenant().GetTenantId())
			}
		}
	}
}

func (dmr *Reconciler) handleTenantRemoval(
	tenantID string,
) {
	log.Info().Msgf("Handling tenant removal: %v", tenantID)
	ctx, cancel := context.WithTimeout(context.Background(), dmr.Config.RequestTimeout)
	defer cancel()

	profileResp, err := dmr.RpsClient.RemoveProfileWithResponse(ctx, tenantID)
	if err != nil {
		log.Err(err).Msgf("cannot remove profile for %v tenant", tenantID)
	}

	log.Debug().Msgf("profile removal response: %v", string(profileResp.Body))

	ciraResp, err := dmr.RpsClient.RemoveCIRAConfigWithResponse(ctx, tenantID)
	if err != nil {
		log.Err(err).Msgf("cannot remove CIRA config for %v tenant", tenantID)
	}
	log.Debug().Msgf("cira removal response: %v", string(ciraResp.Body))

	log.Info().Msgf("Finished tenant removal: %v", tenantID)
}

func (dmr *Reconciler) handleTenantCreation(
	tenantID string,
) {
	log.Info().Msgf("Handling tenant creation: %v", tenantID)
	ctx, cancel := context.WithTimeout(context.Background(), dmr.Config.RequestTimeout)
	defer cancel()

	cert, err := dmr.MpsClient.GetApiV1CiracertWithResponse(ctx)
	if err != nil {
		log.Err(err).Msgf("cannot get CIRA cert")
		return
	}

	ciraConfig, err := dmr.RpsClient.GetCIRAConfigWithResponse(ctx, tenantID)
	if err != nil {
		log.Err(err).Msgf("cannot get CIRA config for %v tenant", tenantID)
		return
	}

	if ciraConfig.JSON404 != nil {
		log.Info().Msgf("CIRA config not found for %v tenant, creating it", tenantID)
		postCiraConfig, postErr := dmr.RpsClient.CreateCIRAConfigWithResponse(ctx, rps.CreateCIRAConfigJSONRequestBody{
			AuthMethod:          passwordAuth, // password auth
			ServerAddressFormat: fqdnServerFormat,
			CommonName:          "mps-node." + dmr.Config.ClusterDomain,
			MpsServerAddress:    "mps-node." + dmr.Config.ClusterDomain,
			MpsPort:             mpsPort,
			ConfigName:          tenantID,
			MpsRootCertificate:  convertCertToCertBlob(cert.Body),
			ProxyDetails:        "", // TODO: pass proxy from config
			Username:            "admin",
			Password:            &dmr.Config.AmtPassword,
		})
		if postErr != nil {
			log.Err(err).Msgf("cannot create CIRA config for %v tenant", tenantID)
			return
		}

		if postCiraConfig.JSON201 != nil {
			log.Info().Msgf("created CIRA config for %v", tenantID)
		} else {
			log.Err(fmt.Errorf("%v", string(postCiraConfig.Body))).Msgf("cannot create CIRA config for %v", tenantID)
			return
		}
	}

	profile, err := dmr.RpsClient.GetProfileWithResponse(ctx, tenantID)
	if err != nil {
		log.Err(err).Msgf("cannot get profile for %v tenant", tenantID)
		return
	}
	if profile.JSON404 != nil {
		log.Info().Msgf("profile not found for %v tenant, creating it", tenantID)

		profilePostResponse, err := dmr.RpsClient.CreateProfileWithResponse(ctx, rps.CreateProfileJSONRequestBody{
			Activation:                 "acmactivate",
			AmtPassword:                &dmr.Config.AmtPassword,
			CiraConfigName:             Ptr(tenantID),
			DhcpEnabled:                true,
			GenerateRandomMEBxPassword: false,
			GenerateRandomPassword:     false,
			IpSyncEnabled:              Ptr(false),
			KvmEnabled:                 Ptr(true),
			MebxPassword:               Ptr(dmr.Config.AmtPassword),
			ProfileName:                tenantID,
			SolEnabled:                 Ptr(true),
			TlsMode:                    nil,
			TlsSigningAuthority:        "SelfSigned",
		})
		if err != nil {
			log.Err(err).Msgf("cannot create profile for %v tenant", tenantID)
			return
		}
		if profilePostResponse.JSON201 != nil {
			log.Info().Msgf("created profile for %v", tenantID)
		} else {
			log.Err(fmt.Errorf("%v", string(profilePostResponse.Body))).Msgf("cannot create profile for %v", tenantID)
			return
		}
	}

	log.Debug().Msgf("creation for %v tenant is done", tenantID)
}

func (dmr *Reconciler) Stop() {
}

func (dmr *Reconciler) ReconcileAdd() {
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
		dmr.handleTenantCreation(tenant.GetTenant().GetTenantId())
	}
}

func (dmr *Reconciler) ReconcileRemove() {
	ctx, cancel := context.WithTimeout(context.Background(), dmr.Config.RequestTimeout)
	defer cancel()

	tenantsList, err := dmr.InventoryClient.ListAll(ctx, &inventoryv1.ResourceFilter{
		Resource: &inventoryv1.Resource{Resource: &inventoryv1.Resource_Tenant{}},
	})
	if err != nil {
		log.Err(err).Msgf("cannot list tenants")
		return
	}

	tenants := []string{}
	for _, tenant := range tenantsList {
		tenants = append(tenants, tenant.GetTenant().GetTenantId())
	}

	dmr.removeProfiles(ctx, tenants)
	dmr.removeCIRAConfigs(ctx, tenants)
}

func (dmr *Reconciler) removeCIRAConfigs(ctx context.Context, tenants []string) {
	CIRAConfigsResp, err := dmr.RpsClient.GetAllCIRAConfigsWithResponse(ctx, &rps.GetAllCIRAConfigsParams{})
	if err != nil {
		log.Err(err).Msgf("cannot list CIRA configs,continuing")
		return
	}

	if CIRAConfigsResp.JSON200 != nil {
		presentCiraConfigs := []string{}
		for _, ciraConfig := range *CIRAConfigsResp.JSON200 {
			presentCiraConfigs = append(presentCiraConfigs, ciraConfig.ConfigName)
		}

		for _, ciraConfigName := range findExtraElements(presentCiraConfigs, tenants) {
			log.Info().Msgf("%v CIRA config doesn't has matching tenant - removing it", ciraConfigName)
			dmr.handleTenantRemoval(ciraConfigName)
		}
	}
}

func (dmr *Reconciler) removeProfiles(ctx context.Context, tenants []string) {
	profilesResp, err := dmr.RpsClient.GetAllProfilesWithResponse(ctx, &rps.GetAllProfilesParams{})
	if err != nil {
		log.Err(err).Msgf("cannot list profiles, continuing")
	}
	if profilesResp.JSON200 != nil {
		presentProfiles := []string{}
		for _, profile := range *profilesResp.JSON200 {
			presentProfiles = append(presentProfiles, profile.ProfileName)
		}
		for _, profileName := range findExtraElements(presentProfiles, tenants) {
			log.Info().Msgf("%v profile doesn't has matching tenant - removing it", profileName)
			dmr.handleTenantRemoval(profileName)
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

func findExtraElements(left, right []string) []string {
	diff := []string{}
	m := make(map[string]bool)

	// Add all elements of b to a map
	for _, item := range right {
		m[item] = true
	}

	// Check if elements of a are not in the map
	for _, item := range left {
		if !m[item] {
			diff = append(diff, item)
		}
	}

	return diff
}

func Ptr[T any](v T) *T {
	return &v
}
