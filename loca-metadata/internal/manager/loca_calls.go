// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"

	locationv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/location/v1"
	"github.com/open-edge-platform/infra-external/loca-metadata/pkg/util"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/client/inventory"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/model"
	inventory_client "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/inventory"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/loca"
	loca_util "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/util"
)

func (lmm *LOCAMM) updateMetadata(ctx context.Context, locaClient *loca.LocaCli, tenantID string) error {
	// retrieve list of sites from LOC-A
	locaSites, err := locaClient.LocaAPI.Inventory.GetAPIV1InventorySites(
		&inventory.GetAPIV1InventorySitesParams{Context: ctx}, locaClient.AuthWriter)
	if err != nil {
		return err
	}

	// retrieve list of Site Resources from Inventory
	invSites, err := inventory_client.ListAllSitesByTenantID(ctx, lmm.invClient, tenantID)
	if err != nil {
		return err
	}

	// retrieve list of Cloud Services from LOC-A
	csList, err := locaClient.LocaAPI.Inventory.GetAPIV1InventoryCloudServices(
		&inventory.GetAPIV1InventoryCloudServicesParams{Context: ctx}, locaClient.AuthWriter)
	if err != nil {
		return err
	}

	lmm.createSites(ctx, locaClient, invSites, locaSites.Payload)
	// no need in all newly created Cloud Services - CA is valid at the time of creation
	lmm.deleteSites(ctx, locaClient, invSites, locaSites.Payload, csList.Payload.Data.Results)
	return nil
}

// createSites pushes Site (or Cloud Service) to LOC-A if it doesn't exist in LOC-A.
// Within this loop we maintain a 1-to-1 relation between Cloud Service with TinkerBell CA
// and a Site.
func (lmm *LOCAMM) createSites(
	ctx context.Context,
	locaClient *loca.LocaCli,
	invSites []*locationv1.SiteResource,
	locaSites *model.DtoSitesQueryResponse,
) {
	for _, site := range invSites {
		siteCreateRequest := util.FindOrCreateSiteCreationRequest(site, locaSites.Data.Results)
		if siteCreateRequest != nil {
			err := util.AddSite(ctx, locaClient, siteCreateRequest)
			if err != nil {
				zlog.InfraSec().InfraErr(err).Msgf("Failed to add site: %v into LOCA with error: %s",
					siteCreateRequest, err)
			}
		}
		// site exists at this point so we can create the Cloud Service
		err := util.UpdateSiteCloudServices(ctx, locaClient, site.GetName())
		if err != nil {
			zlog.InfraSec().InfraErr(err).Msgf("Failed to add cloud service for %v site into LOCA",
				site.GetName())
		}
	}
}

// deleteSites removes Site (or Cloud Service) from LOC-A if it doesn't exist in LOC-A.
func (lmm *LOCAMM) deleteSites(
	ctx context.Context,
	locaClient *loca.LocaCli,
	invSites []*locationv1.SiteResource,
	locaSitesRsp *model.DtoSitesQueryResponse,
	csList []*model.DtoCloudServiceListElement,
) {
	locaSites := locaSitesRsp.Data.Results
	for _, locaSite := range locaSites {
		// check if LOC-A Site exists in Inventory
		inventorySite, siteIsFound := loca_util.FindInventorySiteInInventorySiteListByName(locaSite.Name, invSites)
		currentSite, foundInLoca := loca_util.FindLOCASiteInLOCASiteListByName(inventorySite.GetName(), locaSites)
		desiredSite, err := loca_util.ConvertSiteResourceToLOCASite(inventorySite)
		if !siteIsFound || (foundInLoca && err == nil && !util.SiteIsUpToDate(currentSite, desiredSite)) {
			err = util.DeleteSite(ctx, locaClient, locaSite.ID)
			if err != nil {
				zlog.InfraErr(err).Msgf("Failed to delete site: %v from LOC-A with error: %s", locaSite, err)
			}
			continue
		}
		// site exists at this point so we can check if Tinkerbell CA
		// is valid for current Cloud Service or not
		//nolint:errcheck // no need to check error, it is logged inside of the function
		_, _ = util.DeleteCloudServiceCAIfNeeded(ctx, locaClient, locaSite.Name, csList)
	}
}
