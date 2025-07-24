// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package tenant

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	inventoryv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/secretprovider"
	"github.com/open-edge-platform/infra-external/dm-manager/pkg/api/mps"
	"github.com/open-edge-platform/infra-external/dm-manager/pkg/api/rps"
	rec_v2 "github.com/open-edge-platform/orch-library/go/pkg/controller/v2"
)

const (
	minDelay = 1 * time.Second
	maxDelay = 5 * time.Second
	// Use domain name (like mps-node.kind.internal) instead of IP address of service, which will not
	// go through traefik gateway due to SNI filtering.
	// AddressFormat valid values:
	// 3 = IPv4 address
	// 201 = FQDN.
	fqdnServerFormat = 201
	// Use password authentication instead of certificate authentication.
	passwordAuth = 2

	AmtPasswordSecretName = "amt-password"
	passwordKey           = "password"

	StaticPasswordPolicy  = "static"
	DynamicPasswordPolicy = "dynamic"
)

var log = logging.GetLogger("DmReconciler")

type contextValue string

type ReconcilerConfig struct {
	MpsAddress     string
	MpsPort        int32
	PasswordPolicy string

	RequestTimeout  time.Duration
	ReconcilePeriod time.Duration
}
type Controller struct {
	MpsClient        mps.ClientWithResponsesInterface
	RpsClient        rps.ClientWithResponsesInterface
	InventoryClient  client.TenantAwareInventoryClient
	EventsWatcher    chan *client.WatchEvents
	SecretProvider   secretprovider.SecretProvider
	TermChan         chan bool
	ReadyChan        chan bool
	WaitGroup        *sync.WaitGroup
	Config           *ReconcilerConfig
	TenantController *rec_v2.Controller[ReconcilerID]
}

func (tc *Controller) Start() {
	ticker := time.NewTicker(tc.Config.ReconcilePeriod)
	tc.ReadyChan <- true
	log.Info().Msgf("Starting periodic reconciliation for Device Management Toolkit")
	tc.ReconcileAll()
	for {
		select {
		case <-ticker.C:
			tc.ReconcileAll()
		case <-tc.TermChan:
			log.Info().Msgf("Stopping periodic reconciliation")
			ticker.Stop()
			tc.Stop()
			return
		case event, ok := <-tc.EventsWatcher:
			if !ok {
				ticker.Stop()
				tc.Stop()
				log.InfraSec().Fatal().Msg("gRPC stream with Inventory closed")
				return
			}
			if event.Event.GetEventKind() == inventoryv1.SubscribeEventsResponse_EVENT_KIND_CREATED {
				log.Info().Msgf("Received create event: %v", event.Event.GetResource().GetTenant().GetResourceId())
				err := tc.TenantController.Reconcile(NewReconcilerID(true, event.Event.GetResource().GetTenant().GetTenantId()))
				if err != nil {
					log.Err(err).
						Msgf("failed to create request for %v tenant", event.Event.GetResource().GetTenant().GetTenantId())
				}
			}

			if event.Event.GetEventKind() == inventoryv1.SubscribeEventsResponse_EVENT_KIND_DELETED {
				log.Info().Msgf("Received delete event: %v", event.Event.GetResource().GetTenant().GetResourceId())
				err := tc.TenantController.Reconcile(NewReconcilerID(false, event.Event.GetResource().GetTenant().GetTenantId()))
				if err != nil {
					log.Err(err).
						Msgf("failed to create request for %v tenant", event.Event.GetResource().GetTenant().GetTenantId())
				}
			}
		}
	}
}

func (tc *Controller) handleTenantRemoval(ctx context.Context,
	tenantID string,
) error {
	log.Info().Msgf("Handling tenant removal: %v", tenantID)

	updatedCtx := context.WithValue(ctx, contextValue("tenantId"), tenantID)
	callbackFunc := clientCallback()

	profileResp, err := tc.RpsClient.RemoveProfileWithResponse(updatedCtx, tenantID, callbackFunc)
	if err != nil {
		log.Err(err).Msgf("cannot remove profile for %v tenant", tenantID)
		return err
	}
	log.Debug().Msgf("profile removal response: %v", string(profileResp.Body))

	ciraResp, err := tc.RpsClient.RemoveCIRAConfigWithResponse(updatedCtx, tenantID, callbackFunc)
	if err != nil {
		log.Err(err).Msgf("cannot remove CIRA config for %v tenant", tenantID)
		return err
	}
	log.Debug().Msgf("cira removal response: %v", string(ciraResp.Body))

	log.Info().Msgf("Finished tenant removal: %v", tenantID)
	return nil
}

func (tc *Controller) handleTenantCreation(ctx context.Context,
	tenantID string,
) error {
	log.Info().Msgf("Handling tenant creation: %v", tenantID)

	updatedCtx := context.WithValue(ctx, contextValue("tenantId"), tenantID)
	callbackFunc := clientCallback()

	cert, err := tc.MpsClient.GetApiV1CiracertWithResponse(updatedCtx, callbackFunc)
	if err != nil {
		log.Err(err).Msgf("cannot get CIRA cert")
		return err
	}

	if err := tc.handleCiraConfig(updatedCtx, tenantID, cert.Body, callbackFunc); err != nil {
		return err
	}

	if err := tc.handleProfile(updatedCtx, tenantID, callbackFunc); err != nil {
		return err
	}

	log.Debug().Msgf("creation for %v tenant is done", tenantID)
	return nil
}

func (tc *Controller) handleProfile(ctx context.Context, tenantID string,
	callbackFunc func(ctx context.Context, req *http.Request) error,
) error {
	profile, err := tc.RpsClient.GetProfileWithResponse(ctx, tenantID, callbackFunc)
	if err != nil {
		log.Err(err).Msgf("cannot get profile for %v tenant", tenantID)
		return err
	}
	if profile.JSON404 != nil {
		log.Info().Msgf("profile not found for %v tenant, creating it", tenantID)

		postProfileBody := rps.CreateProfileJSONRequestBody{
			Activation:          "acmactivate",
			CiraConfigName:      Ptr(tenantID),
			DhcpEnabled:         true,
			IpSyncEnabled:       Ptr(false),
			KvmEnabled:          Ptr(true),
			ProfileName:         tenantID,
			SolEnabled:          Ptr(true),
			TlsMode:             nil,
			TlsSigningAuthority: "SelfSigned",
		}

		amtPassword := tc.SecretProvider.GetSecret(AmtPasswordSecretName, passwordKey)
		if amtPassword == "" {
			log.Error().Msgf("Couldn't get password from secret provider, see logs above for details")
			return err
		}

		if strings.EqualFold(tc.Config.PasswordPolicy, StaticPasswordPolicy) {
			postProfileBody.AmtPassword = &amtPassword
			postProfileBody.MebxPassword = &amtPassword
			postProfileBody.GenerateRandomPassword = false
			postProfileBody.GenerateRandomMEBxPassword = false
		} else {
			postProfileBody.AmtPassword = nil
			postProfileBody.MebxPassword = nil
			postProfileBody.GenerateRandomPassword = true
			postProfileBody.GenerateRandomMEBxPassword = true
		}

		profilePostResponse, err := tc.RpsClient.CreateProfileWithResponse(ctx, postProfileBody, callbackFunc)
		if err != nil {
			log.Err(err).Msgf("cannot create profile for %v tenant", tenantID)
			return err
		}
		if profilePostResponse.JSON201 != nil {
			log.Info().Msgf("created profile for %v", tenantID)
		} else {
			err = errors.Errorf("%v", string(profilePostResponse.Body))
			log.Err(err).Msgf("cannot create profile for %v", tenantID)
			return err
		}
	}
	return nil
}

func (tc *Controller) handleCiraConfig(ctx context.Context, tenantID string, cert []byte,
	callbackFunc func(ctx context.Context, req *http.Request) error,
) error {
	ciraConfig, err := tc.RpsClient.GetCIRAConfigWithResponse(ctx, tenantID, callbackFunc)
	if err != nil {
		log.Err(err).Msgf("cannot get CIRA config for %v tenant", tenantID)
		return err
	}

	if ciraConfig.JSON404 != nil {
		amtPassword := tc.SecretProvider.GetSecret(AmtPasswordSecretName, passwordKey)
		if amtPassword == "" {
			log.Error().Msgf("Couldn't get password from secret provider, see logs above for details")
			return err
		}

		log.Info().Msgf("CIRA config not found for %v tenant, creating it", tenantID)
		postCiraConfig, err := tc.RpsClient.CreateCIRAConfigWithResponse(ctx, rps.CreateCIRAConfigJSONRequestBody{
			AuthMethod:          passwordAuth, // password auth
			ServerAddressFormat: fqdnServerFormat,
			CommonName:          tc.Config.MpsAddress,
			MpsServerAddress:    tc.Config.MpsAddress,
			MpsPort:             tc.Config.MpsPort,
			ConfigName:          tenantID,
			MpsRootCertificate:  convertCertToCertBlob(cert),
			ProxyDetails:        "", // TODO: pass proxy from config
			Username:            "admin",
			Password:            &amtPassword,
		}, callbackFunc)
		if err != nil {
			log.Err(err).Msgf("cannot create CIRA config for %v tenant", tenantID)
			return err
		}

		if postCiraConfig.JSON201 != nil {
			log.Info().Msgf("created CIRA config for %v", tenantID)
		} else {
			log.Err(errors.Errorf("%v", string(postCiraConfig.Body))).Msgf("cannot create CIRA config for %v", tenantID)
			return err
		}
	}
	return nil
}

func (tc *Controller) Stop() {
	tc.WaitGroup.Done()
}

func (tc *Controller) ReconcileAll() {
	ctx, cancel := context.WithTimeout(context.Background(), tc.Config.RequestTimeout)
	defer cancel()
	tenantsResp, err := tc.InventoryClient.ListAll(ctx, &inventoryv1.ResourceFilter{
		Resource: &inventoryv1.Resource{Resource: &inventoryv1.Resource_Tenant{}},
	})
	if err != nil {
		log.Err(err).Msgf("cannot list tenants")
		return
	}

	tenants := []string{}
	for _, tenant := range tenantsResp {
		tenants = append(tenants, tenant.GetTenant().GetTenantId())
		err = tc.TenantController.Reconcile(NewReconcilerID(true, tenant.GetTenant().GetTenantId()))
		if err != nil {
			log.Err(err).Msgf("failed to create reconcile request for %v tenant", tenant.GetTenant().GetTenantId())
			continue
		}
	}

	tc.removeProfiles(ctx, tenants)
	tc.removeCIRAConfigs(ctx, tenants)
}

func (tc *Controller) Reconcile(ctx context.Context, request rec_v2.Request[ReconcilerID]) rec_v2.Directive[ReconcilerID] {
	if request.ID.isCreate() {
		if err := tc.handleTenantCreation(ctx, request.ID.GetTenantID()); err != nil {
			return request.Retry(err).With(rec_v2.ExponentialBackoff(minDelay, maxDelay))
		}
		return request.Ack()
	}
	if err := tc.handleTenantRemoval(ctx, request.ID.GetTenantID()); err != nil {
		return request.Retry(err).With(rec_v2.ExponentialBackoff(minDelay, maxDelay))
	}
	return request.Ack()
}

func (tc *Controller) removeCIRAConfigs(ctx context.Context, tenants []string) {
	CIRAConfigsResp, err := tc.RpsClient.GetAllCIRAConfigsWithResponse(ctx, &rps.GetAllCIRAConfigsParams{})
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
			log.Info().Msgf("%v CIRA config doesn't have matching tenant - removing it", ciraConfigName)
			if err = tc.TenantController.Reconcile(NewReconcilerID(false, ciraConfigName)); err != nil {
				log.Err(err).Msgf("failed to create reconcile request for %v tenant", ciraConfigName)
			}
		}
	}
}

func (tc *Controller) removeProfiles(ctx context.Context, tenants []string) {
	profilesResp, err := tc.RpsClient.GetAllProfilesWithResponse(ctx, &rps.GetAllProfilesParams{})
	if err != nil {
		log.Err(err).Msgf("cannot list profiles, continuing")
	}
	if profilesResp.JSON200 != nil {
		presentProfiles := []string{}
		for _, profile := range *profilesResp.JSON200 {
			presentProfiles = append(presentProfiles, profile.ProfileName)
		}
		for _, profileName := range findExtraElements(presentProfiles, tenants) {
			log.Info().Msgf("%v profile doesn't have matching tenant - removing it", profileName)
			if err = tc.TenantController.Reconcile(NewReconcilerID(false, profileName)); err != nil {
				log.Err(err).Msgf("failed to create reconcile request for %v tenant", profileName)
			}
		}
	}
}
