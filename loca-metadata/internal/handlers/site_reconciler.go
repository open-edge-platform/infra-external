// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"

	locationv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/location/v1"
	providerv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/provider/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/tracing"
	"github.com/open-edge-platform/infra-external/loca-metadata/pkg/util"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/client/inventory"
	site_inventory_calls "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/inventory"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/loca"
	loca_util "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/util"
	rec_v2 "github.com/open-edge-platform/orch-library/go/pkg/controller/v2"
)

const (
	loggerName = "SiteReconciler"
)

// Misc variables.
var (
	zlog = logging.GetLogger(loggerName)
)

// SiteReconciler handles reconciliation of site resources with LOC-A providers.
type SiteReconciler struct {
	TracingEnabled bool
	InvClient      client.TenantAwareInventoryClient
}

// NewSiteReconciler creates a new SiteReconciler with the specified tracing configuration and inventory client.
func NewSiteReconciler(tracingEnabled bool, invClient client.TenantAwareInventoryClient) *SiteReconciler {
	return &SiteReconciler{
		TracingEnabled: tracingEnabled,
		InvClient:      invClient,
	}
}

// Reconcile checks the type of event performed on site by inventory and performs reconciliation.
func (sr *SiteReconciler) Reconcile(ctx context.Context, request rec_v2.Request[ReconcilerID]) rec_v2.Directive[ReconcilerID] {
	if sr.TracingEnabled {
		ctx = tracing.StartTrace(ctx, "LOC-A MM", "SiteReconciler")
		defer tracing.StopTrace(ctx)
	}

	resourceID := request.ID.GetResourceID()
	tenantID := request.ID.GetTenantID()
	zlog.Info().Msgf("Reconciling Site: %s", request.ID)

	// check if site exists in inventory for specific tenant
	var deleteSiteFromLOCA bool
	site, err := site_inventory_calls.GetSiteResourceByResourceID(ctx, sr.InvClient, tenantID, resourceID)
	if errors.IsNotFound(err) {
		zlog.Info().Msgf("site %s is not found in inventory for tenant:%s", resourceID, tenantID)
		// site not present in inv
		deleteSiteFromLOCA = true
	} else if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("error %s, while fetching site %s from inventory for tenant: %s",
			err, resourceID, tenantID)
		return request.Retry(err).With(rec_v2.ExponentialBackoff(minDelay, maxDelay))
	}

	// fetching all LOC-A providers from inventory
	locaProviders, err := site_inventory_calls.ListLOCAProviderResources(ctx, sr.InvClient)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("err while getting list of provider resource: %s", err)
		return request.Retry(err).With(rec_v2.ExponentialBackoff(minDelay, maxDelay))
	}
	retry := false

	// adding site to all providers
	for _, locaProvider := range locaProviders {
		err = sr.ReconcileSite(ctx, deleteSiteFromLOCA, site, locaProvider, request.ID.GetName())
		if err != nil {
			zlog.InfraSec().InfraErr(err).Msgf("err %s while reconcileSite %v with provider %s",
				err, site.GetName(), locaProvider.GetName())
			retry = true
		}
		continue
	}
	if retry {
		return request.Retry(err).With(rec_v2.ExponentialBackoff(minDelay, maxDelay))
	}
	return request.Ack()
}

// ReconcileSite performs reconciliation of a site resource for a specific LOC-A provider.
//
//nolint:cyclop // main logic
func (sr *SiteReconciler) ReconcileSite(ctx context.Context, deleteSiteFromLOCA bool, reconcileSite *locationv1.SiteResource,
	provider *providerv1.ProviderResource, siteName string,
) (err error) {
	zlog.Debug().Msgf("Reconciling site %s in %s provider %v",
		site_inventory_calls.FormatTenantResourceID(reconcileSite.GetTenantId(), reconcileSite.GetResourceId()),
		provider.GetName(), provider.GetApiCredentials())

	locaClient, err := loca.InitialiseLOCAClient(
		provider.GetApiEndpoint(),
		provider.GetApiCredentials(),
	)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to initialize LOC-A client for endpoint: %s with error %s",
			provider.GetApiEndpoint(), err)
		return err
	}

	// get list of sites from LOCA
	locaSitesRsp, err := locaClient.LocaAPI.Inventory.GetAPIV1InventorySites(
		&inventory.GetAPIV1InventorySitesParams{Context: ctx}, locaClient.AuthWriter)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("received error while getting list of sites from LOCA: %s", err)
		return err
	}

	currentSite, found := loca_util.FindLOCASiteInLOCASiteListByName(siteName, locaSitesRsp.Payload.Data.Results)
	desiredSite, err := loca_util.ConvertSiteResourceToLOCASite(reconcileSite)

	// supporting update from UI by removing old site and creating new one
	// in the next reconciliation cycle
	if deleteSiteFromLOCA || found && err == nil && !util.SiteIsUpToDate(currentSite, desiredSite) {
		if !found {
			zlog.Warn().Msgf("wanted to delete %v, but it is already gone", siteName)
			return nil
		}

		zlog.Debug().Msgf("site %s[%v] deleted in inventory, deleting site from LOCA",
			siteName, currentSite.ID)
		err = util.DeleteSite(ctx, locaClient, currentSite.ID)
		if err != nil {
			zlog.InfraSec().InfraErr(err).Msgf("error while trying to delete site: %s from %s",
				siteName, provider.GetName())
			return err
		}
	} else {
		zlog.Debug().Msgf("site %s exists in inventory, creating %s site in LOCA if it doesn't exist",
			reconcileSite.GetName(), reconcileSite.GetName())
		err = util.AddSite(ctx, locaClient, util.FindOrCreateSiteCreationRequest(reconcileSite,
			locaSitesRsp.Payload.Data.Results))
		if err != nil {
			zlog.InfraSec().InfraErr(err).Msgf("error while trying to add site: %s from %s",
				reconcileSite.GetName(), provider.GetName())
			return err
		}

		err = util.UpdateSiteCloudServices(ctx, locaClient, reconcileSite.GetName())
		if err != nil {
			zlog.InfraSec().InfraErr(err).Msgf("error while trying to update site cloud services: %s from %s",
				reconcileSite.GetName(), provider.GetName())
			return err
		}
	}
	return nil
}
