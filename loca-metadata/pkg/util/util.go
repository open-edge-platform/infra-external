// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

//nolint:revive // util is an acceptable package name for utility functions
package util

import (
	"context"
	"strings"

	locationv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/location/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/client/inventory"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/model"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/loca"
	loca_util "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/util"
)

var zlog = logging.GetLogger("util")

func FindOrCreateSiteCreationRequest(
	site *locationv1.SiteResource,
	locaSites []*model.DtoSites,
) *model.DtoSiteCreateRequest {
	zlog.Debug().Msgf("finding site %s in LOC-A site list", site.Name)
	_, found := loca_util.FindLOCASiteInLOCASiteListByName(site.GetName(), locaSites)
	desiredSite, err := loca_util.ConvertSiteResourceToLOCASite(site)
	if err != nil {
		return nil
	}
	if found {
		zlog.Debug().Msgf("%s site found in LOC-A", site.Name)
		return nil
	}
	siteCreateRequest := &model.DtoSiteCreateRequest{
		Address:        desiredSite.Address,
		City:           &desiredSite.City,
		CloudType:      &desiredSite.CloudType,
		Country:        &desiredSite.Country,
		Geo:            &desiredSite.Geo,
		GpsCoordinates: desiredSite.GpsCoordinates,
		Name:           &desiredSite.Name,
		PostCode:       desiredSite.PostCode,
		Province:       &desiredSite.Province,
		SiteCode:       &desiredSite.SiteCode,
	}
	// adding newly created Sites to LOC-A Site list and returning it
	return siteCreateRequest
}

// DeleteCloudServiceCAIfNeeded checks if Tinkerbell CA is up-to-date in the Cloud Service and performs its update if needed.
func DeleteCloudServiceCAIfNeeded(
	ctx context.Context,
	locaClient *loca.LocaCli,
	siteName string,
	csList []*model.DtoCloudServiceListElement,
) (bool, error) {
	// checking if corresponding Cloud Service exists
	cs, csFound := loca_util.FindWhichCloudServiceAttachedToSite(siteName, csList)
	if !csFound {
		// Cloud Service does not exist. Nothing to check
		return true, nil
	}
	// Cloud Service exists
	// Retrieve all Cloud Service information by its ID
	csFull, err := locaClient.LocaAPI.Inventory.GetAPIV1InventoryCloudServicesID(
		&inventory.GetAPIV1InventoryCloudServicesIDParams{
			ID:      cs.ID,
			Context: ctx,
		},
		locaClient.AuthWriter,
	)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("error while getting cloudService from LOC-A")
		return false, err
	}

	var obtainedTinkCA string
	// extracting Tinkerbell CA

	configs, _ := csFull.Payload.Data.ServiceSettings.(map[string]interface{}) //nolint:errcheck // Ignoring error check
	// because ServiceSettings is guaranteed to be of type map[string]interface{}

	// Check if the "TinkerbellCA" key exists
	if value, exists := configs[loca_util.TinkerbellCAKey]; exists {
		if valStr, ok := value.(string); ok {
			obtainedTinkCA = valStr
		} else {
			zlog.Debug().Msgf("error while extracting TinkerbellCA")
		}
	} else {
		zlog.Debug().Msgf("TinkerbellCA not set")
	}

	currentTinkCA, err := loca_util.ReadTinkerbellCA()
	if err != nil {
		return false, err
	}

	// as this whitespace and newlines are replaced for currentCA in ReadTinkerbellCA
	obtainedTinkCA = strings.ReplaceAll(strings.ReplaceAll(obtainedTinkCA, " ", ""), "\n", "")
	currentTinkCA = strings.ReplaceAll(strings.ReplaceAll(currentTinkCA, " ", ""), "\n", "")

	if obtainedTinkCA != currentTinkCA {
		// once task will finish, a new reconcile loop will detect that cloud service is missing
		// and will create a new instance - which will contain correct CA cert
		err := deleteCloudService(ctx, locaClient, cs)
		if err != nil {
			return false, err
		}
		return true, nil
	}
	zlog.Debug().Msgf("Tinkerbell CA for Cloud Service (%s) is up to date", cs.ID)
	// both certificates match, no need to update Cloud Service
	return false, nil
}

func deleteCloudService(ctx context.Context, locaClient *loca.LocaCli, cs *model.DtoCloudServiceListElement) error {
	zlog.Debug().Msgf("Deleting Cloud Service (%s)", cs.ID)

	removeTaskIsRunning, err := loca.DefaultTaskTracker.TaskIsRunningFor(locaClient, cs.ID)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("failed to check if a task is running for cloudService (%v)", cs.ID)
		return err
	}
	if removeTaskIsRunning {
		zlog.Debug().Msgf("task for removal of %v cloudService is already running", cs.ID)
		return nil
	}
	postResp, err := locaClient.LocaAPI.Inventory.PostAPIV1InventoryCloudServicesRemove(
		&inventory.PostAPIV1InventoryCloudServicesRemoveParams{
			Body: &model.DtoServiceRemoveRequest{
				Ids: []string{cs.ID},
			},
			Context: ctx,
		}, locaClient.AuthWriter)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("error while deleting cloud service: %s", err)
		return err
	}
	err = loca.DefaultTaskTracker.TrackTask(cs.ID, postResp.Payload.Data.TaskUUID)
	if err != nil {
		return err
	}
	return nil
}

func UpdateSiteCloudServices(ctx context.Context, locaClient *loca.LocaCli, siteName string) error {
	resp, err := locaClient.LocaAPI.Inventory.GetAPIV1InventoryCloudServices(
		&inventory.GetAPIV1InventoryCloudServicesParams{Context: ctx}, locaClient.AuthWriter)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("error occurred while getting cloud service: %v", err)
		return err
	}

	// Delete if needed and report back.
	deleted, err := DeleteCloudServiceCAIfNeeded(ctx, locaClient, siteName, resp.Payload.Data.Results)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("error occurred while updating the cloud service: %v", err)
		return err
	}
	// If the Cloud Service was deleted/did not exist, we need to re-create the updated one.
	if deleted {
		// creating Cloud Service structure to send to LOC-A
		cloudServiceCreateRequest, err := loca_util.CreateCloudServiceTemplate(siteName)
		if err != nil {
			zlog.InfraErr(err).Msg("Error creating cloud Service structure")
			return err
		}
		//nolint:errcheck // no need to check response
		_, err = locaClient.LocaAPI.Inventory.PostAPIV1InventoryCloudServices(
			&inventory.PostAPIV1InventoryCloudServicesParams{
				Body:    []*model.DtoCloudServiceCreateRequest{cloudServiceCreateRequest},
				Context: ctx,
			},
			locaClient.AuthWriter,
		)
		if err != nil {
			zlog.InfraSec().InfraErr(err).Msgf("Failed to add cloud service: %s into LOCA with error: %s",
				siteName, err)
			return err
		}
	}

	return nil
}

// comparing only using fields that are managed by MM.
func SiteIsUpToDate(left, right *model.DtoSites) bool {
	return left.Address == right.Address && left.GpsCoordinates == right.GpsCoordinates &&
		left.Name == right.Name
}

func DeleteSite(ctx context.Context, locaClient *loca.LocaCli, locaSiteID string,
) (err error) {
	removeTaskIsRunning, err := loca.DefaultTaskTracker.TaskIsRunningFor(locaClient, locaSiteID)
	if err != nil {
		zlog.Err(err).Msgf("failed to check if a task is running for site (%v)", locaSiteID)
		return err
	}
	if removeTaskIsRunning {
		zlog.Debug().Msgf("task for removal of %v site is already running", locaSiteID)
		return nil
	}
	postResp, err := locaClient.LocaAPI.Inventory.PostAPIV1InventorySitesRemove(
		&inventory.PostAPIV1InventorySitesRemoveParams{
			Body:    &model.DtoSitesRemoveRequest{Ids: []string{locaSiteID}},
			Context: ctx,
		}, locaClient.AuthWriter)
	if err != nil {
		if strings.Contains(err.Error(), "is not found") {
			zlog.Warn().Msgf("wanted to delete %v, but it is already gone", locaSiteID)
			return nil
		}
		zlog.InfraSec().InfraErr(err).Msgf("error while removing site %v from LOCA", locaSiteID)
		return errors.Wrap(err)
	}
	err = loca.DefaultTaskTracker.TrackTask(locaSiteID, postResp.Payload.Data.TaskUUID)
	if err != nil {
		return err
	}
	return nil
}

func AddSite(ctx context.Context, locaClient *loca.LocaCli,
	siteCreationRequest *model.DtoSiteCreateRequest,
) (err error) {
	if siteCreationRequest == nil {
		return nil
	}

	//nolint:errcheck // no need to check response
	_, err = locaClient.LocaAPI.Inventory.PostAPIV1InventorySites(
		&inventory.PostAPIV1InventorySitesParams{
			Body:    []*model.DtoSiteCreateRequest{siteCreationRequest},
			Context: ctx,
		}, locaClient.AuthWriter)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to add site: %s into LOCA with error: %s",
			*siteCreationRequest.Name, err)
		return err
	}
	return nil
}
