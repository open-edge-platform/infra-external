// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package testing

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	inv_v1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	inv_testing "github.com/open-edge-platform/infra-core/inventory/v2/pkg/testing"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/client/inventory"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/model"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/loca"
	loca_testing "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/testing"
	loca_util "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/util"
)

const (
	timeout            = 1 * time.Second
	ReconciliationWait = 120 * time.Millisecond
)

var (
	LocaRMClient       client.TenantAwareInventoryClient
	LocaRMEventsClient chan *client.WatchEvents
)

func InitializeInventoryClient(clientName string) {
	resourceKinds := []inv_v1.ResourceKind{
		inv_v1.ResourceKind_RESOURCE_KIND_SITE,
		inv_v1.ResourceKind_RESOURCE_KIND_REGION,
	}
	clType := inv_testing.ClientType(clientName)

	err := inv_testing.CreateClient(clType, inv_v1.ClientKind_CLIENT_KIND_RESOURCE_MANAGER, resourceKinds, "")
	if err != nil {
		panic(err)
	}

	// assigning created client to global variable
	LocaRMClient = inv_testing.TestClients[clType].GetTenantAwareInventoryClient()
	LocaRMEventsClient = inv_testing.TestClientsEvents[clType]
}

func CloseInventoryClientChannel(clientName string) {
	if err := LocaRMClient.Close(); err != nil {
		fmt.Printf("Error occurred while closing the Inventory channel: %v\n", err)
	}
	delete(inv_testing.TestClients, inv_testing.ClientType(clientName))
	delete(inv_testing.TestClientsEvents, inv_testing.ClientType(clientName))
}

func AssertNumberOfSitesInLOCA(t *testing.T, locaURL string, numSites int) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	locaClient := loca.InitialiseTestLocaClient(locaURL, loca_testing.LocaSecret)
	sites, err := locaClient.LocaAPI.Inventory.GetAPIV1InventorySites(
		&inventory.GetAPIV1InventorySitesParams{Context: ctx}, locaClient.AuthWriter)
	require.NoError(t, err)
	assert.Equal(t, numSites, len(sites.Payload.Data.Results))
}

func AssertNumberOfCSSInLOCA(t *testing.T, locaURL string, numCSS int) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	locaClient := loca.InitialiseTestLocaClient(locaURL, loca_testing.LocaSecret)
	css, err := locaClient.LocaAPI.Inventory.GetAPIV1InventoryCloudServices(
		&inventory.GetAPIV1InventoryCloudServicesParams{Context: ctx}, locaClient.AuthWriter)
	require.NoError(t, err)
	assert.Equal(t, numCSS, len(css.Payload.Data.Results))
}

func AssertLOCASite(t *testing.T, locaURL, name, address string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	locaClient := loca.InitialiseTestLocaClient(locaURL, loca_testing.LocaSecret)
	sites, err := locaClient.LocaAPI.Inventory.GetAPIV1InventorySites(
		&inventory.GetAPIV1InventorySitesParams{Context: ctx}, locaClient.AuthWriter)
	require.NoError(t, err)

	locaSite, found := loca_util.FindLOCASiteInLOCASiteListByName(name, sites.Payload.Data.Results)
	require.True(t, found)
	assert.Equal(t, locaSite.Name, name)
	assert.Equal(t, locaSite.Address, address)
}

func AssertLOCACS(t *testing.T, locaURL, name, fqdn, tinkCA, siteName string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	locaClient := loca.InitialiseTestLocaClient(locaURL, loca_testing.LocaSecret)

	css, err := locaClient.LocaAPI.Inventory.GetAPIV1InventoryCloudServices(
		&inventory.GetAPIV1InventoryCloudServicesParams{Context: ctx}, locaClient.AuthWriter)
	require.NoError(t, err)
	locaCS, found := loca_util.FindWhichCloudServiceAttachedToSite(siteName, css.Payload.Data.Results)

	csFull, err := locaClient.LocaAPI.Inventory.GetAPIV1InventoryCloudServicesID(
		&inventory.GetAPIV1InventoryCloudServicesIDParams{
			ID:      locaCS.ID,
			Context: ctx,
		},
		locaClient.AuthWriter,
	)
	require.NoError(t, err)

	cs := csFull.Payload.Data
	configs, ok := cs.ServiceSettings.(map[string]interface{})
	require.True(t, ok, "ServiceSettings is not a map")

	require.True(t, found)
	assert.Equal(t, cs.Name, name)
	assert.Equal(t, cs.ServiceAddress, fqdn)

	expectedTinkCA := strings.ReplaceAll(strings.ReplaceAll(tinkCA, " ", ""), "\n", "")
	tinkCAValue, ok := configs[loca_util.TinkerbellCAKey].(string)
	require.True(t, ok, "TinkerbellCAKey value is not a string")
	currentTinkCA := strings.ReplaceAll(strings.ReplaceAll(tinkCAValue, " ", ""), "\n", "")
	assert.Equal(t, expectedTinkCA, currentTinkCA)
}

// helper functions to mock LOC-A server.

func AddSitePostErr(res http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet {
		response := &model.DtoSitesQueryResponse{
			StatusCode: 0,
			Data: &model.DtoSiteListData{
				Results: []*model.DtoSites{},
			},
		}
		loca_testing.WriteStructToResponse(res, req, response, http.StatusOK)
	} else {
		response := &model.DtoErrResponse{
			//nolint:mnd // LOC-A status code
			StatusCode: 3004,
			Message:    "Bad request: site with name INTC-SC11 already exists, please check your request body",
		}
		loca_testing.WriteStructToResponse(res, req, response, http.StatusBadRequest)
	}
}

func DeleteSitePostErr(res http.ResponseWriter, req *http.Request) {
	response := &model.DtoResponseCUD{
		//nolint:mnd // LOC-A status code
		StatusCode: 3003,
		Message:    "id: 671fab7ad1d25ae77722a8e8 is not found",
	}
	loca_testing.WriteStructToResponse(res, req, response, http.StatusBadRequest)
}

func DeleteSitePostNoTask(res http.ResponseWriter, req *http.Request) {
	response := &model.DtoResponseCUD{
		StatusCode: 0,
		Data: &model.DtoTaskResponseData{
			TaskUUID: []string{},
		},
	}
	loca_testing.WriteStructToResponse(res, req, response, http.StatusCreated)
}

func GetCS(res http.ResponseWriter, req *http.Request) {
	response := &model.DtoCloudServiceListResponse{
		StatusCode: 0,
		Data: &model.DtoCloudServiceListData{
			Results: []*model.DtoCloudServiceListElement{
				{
					ID: "671fab7ad1d25ae77722a8e8",
					SiteAssociation: []string{
						loca_testing.LocaSiteName,
					},
					Name: loca_testing.LocaSiteName,
				},
			},
		},
	}
	loca_testing.WriteStructToResponse(res, req, response, http.StatusOK)
}

func GetCSByID(cs *model.DtoCloudServiceSingleElement) func(w http.ResponseWriter, r *http.Request) {
	return func(res http.ResponseWriter, req *http.Request) {
		response := &model.DtoCloudServiceResponse{
			StatusCode: 0,
			Message:    "",
			Data:       cs,
		}
		loca_testing.WriteStructToResponse(res, req, response, http.StatusOK)
	}
}

func GetCSByIDErr(res http.ResponseWriter, req *http.Request) {
	response := &model.DtoCloudServiceResponse{
		//nolint:mnd // LOC-A status code
		StatusCode: 3003,
		Message:    "id: 671fab7ad1d25ae77722a8e8 is not found",
	}
	loca_testing.WriteStructToResponse(res, req, response, http.StatusBadRequest)
}

func GetTaskByIDErr(res http.ResponseWriter, req *http.Request) {
	// task details
	resourceUUID := uuid.New().String()

	response := &model.DtoTask{Name: "dummy-task", UUID: resourceUUID}
	loca_testing.WriteStructToResponse(res, req, response, http.StatusBadRequest)
}

func DeleteCSPostNoTask(res http.ResponseWriter, req *http.Request) {
	response := &model.DtoResponseCUD{
		StatusCode: 0,
		Data: &model.DtoTaskResponseData{
			TaskUUID: []string{},
		},
	}
	loca_testing.WriteStructToResponse(res, req, response, http.StatusCreated)
}
