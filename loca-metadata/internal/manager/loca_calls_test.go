// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"os"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	location_v1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/location/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	inv_testing "github.com/open-edge-platform/infra-core/inventory/v2/pkg/testing"
	metadata_testing "github.com/open-edge-platform/infra-external/loca-metadata/pkg/testing"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/model"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/loca"
	_ "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/examples"
	loca_testing "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/testing"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/util"
)

// shared implementation with locamm_test.go

func TestLOCAMM_UpdateMetaData(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	siteToCreate := dao.CreateSite(t, loca_testing.Tenant1, inv_testing.SiteName("new-site"),
		inv_testing.SiteCoordinates(373541070, -1219552380))

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() { locaTS.StopDummyLOCAServer() })
	// assuming 1 site exists only in LOCA
	siteToRemove := &location_v1.SiteResource{
		ResourceId: "site-a6fca33c",
		Name:       "INTC-SC11",
		Address:    "Foobar Av. 123",
	}
	loca_testing.SitesCrudFuncs(locaTS, true, siteToRemove)
	// Check that LOC-A Mock contains only 1 Site (siteToRemove)
	metadata_testing.AssertNumberOfSitesInLOCA(t, locaTS.GetURL(), 1)
	// Checking that this is the exact same site
	metadata_testing.AssertLOCASite(t, locaTS.GetURL(), siteToRemove.GetName(), siteToRemove.GetAddress())

	assertHook := util.NewTestAssertHook("Failed to add cloud service")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	lmm := LOCAMM{
		invClient: dao.GetAPIClient(),
	}
	cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)

	err = lmm.updateMetadata(context.Background(), cli, loca_testing.Tenant1)
	assert.NoError(t, err)
	// Check that LOC-A Mock contains only 1 Site (siteToCreate)
	metadata_testing.AssertNumberOfSitesInLOCA(t, locaTS.GetURL(), 1)
	// Checking that this is the exact same site
	metadata_testing.AssertLOCASite(t, locaTS.GetURL(), siteToCreate.GetName(), siteToCreate.GetAddress())
}

// expected error while getting cs from LOC-A.
func TestLOCAMM_UpdateMetaData_ErrWhileGetCSFromLoca(t *testing.T) {
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() { locaTS.StopDummyLOCAServer() })
	loca_testing.SitesCrudFuncs(locaTS, false, nil)
	locaTS.Override(loca_testing.InventoryCloudServicesPath, loca_testing.ReturnServerUnavailable)

	lmm := LOCAMM{
		invClient: metadata_testing.LocaRMClient,
	}
	cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)

	err = lmm.updateMetadata(context.Background(), cli, loca_testing.Tenant1)
	assert.ErrorContains(t, err, "503")
}

// expected error while creating sites to LOC-A.
//
//nolint:dupl // similar to TestLOCAMM_CreateSites_ErrWhileUpdateSiteCS but with different path.
func TestLOCAMM_CreateSites_ErrWhileAddSite(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	site := dao.CreateSite(t, loca_testing.Tenant1, inv_testing.SiteName("new-site"),
		inv_testing.SiteCoordinates(373541070, -1219552380))
	invSiteList := []*location_v1.SiteResource{site}

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() { locaTS.StopDummyLOCAServer() })
	loca_testing.SitesCrudFuncs(locaTS, false, nil)
	// get error while tring to add site
	locaTS.Override(loca_testing.InventorySitesPath, loca_testing.ReturnServerUnavailable)

	locaSiteList := &model.DtoSitesQueryResponse{
		StatusCode: 0,
		Data: &model.DtoSiteListData{
			Results: []*model.DtoSites{},
		},
	}

	assertHook := util.NewTestAssertHook("Failed to add site:")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	lmm := LOCAMM{
		invClient: dao.GetAPIClient(),
	}
	cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)

	lmm.createSites(context.Background(), cli, invSiteList, locaSiteList)
	assertHook.Assert(t)
}

// expected error while updating CS to LOC-A.
//
//nolint:dupl // similar to TestLOCAMM_CreateSites_ErrWhileAddSite but with different path.
func TestLOCAMM_CreateSites_ErrWhileUpdateSiteCS(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	site := dao.CreateSite(t, loca_testing.Tenant1, inv_testing.SiteName("new-site"),
		inv_testing.SiteCoordinates(373541070, -1219552380))
	invSiteList := []*location_v1.SiteResource{site}

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() { locaTS.StopDummyLOCAServer() })
	loca_testing.SitesCrudFuncs(locaTS, false, nil)
	locaTS.Override(loca_testing.InventoryCloudServicesPath, loca_testing.ReturnServerUnavailable)

	locaSiteList := &model.DtoSitesQueryResponse{
		StatusCode: 0,
		Data: &model.DtoSiteListData{
			Results: []*model.DtoSites{},
		},
	}

	assertHook := util.NewTestAssertHook("Failed to add cloud service")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	lmm := LOCAMM{
		invClient: dao.GetAPIClient(),
	}
	cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)

	lmm.createSites(context.Background(), cli, invSiteList, locaSiteList)
	assertHook.Assert(t)
}

// expected an error when delete site.
func TestLOCAMM_DeleteSites_ErrWhileDeleteSite(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	invSiteList := []*location_v1.SiteResource{}

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() { locaTS.StopDummyLOCAServer() })
	loca_testing.SitesCrudFuncs(locaTS, false, nil)
	locaTS.Override(loca_testing.InventorySitesRemovePath, loca_testing.ReturnServerUnavailable)

	locaSiteList := &model.DtoSitesQueryResponse{
		StatusCode: 0,
		Data: &model.DtoSiteListData{
			Results: []*model.DtoSites{
				{
					Name:    "INTC-SC11",
					Address: "Foobar Av. 123",
				},
			},
		},
	}

	assertHook := util.NewTestAssertHook("Failed to delete site:")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	lmm := LOCAMM{
		invClient: dao.GetAPIClient(),
	}
	cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)

	lmm.deleteSites(context.Background(), cli, invSiteList, locaSiteList, []*model.DtoCloudServiceListElement{})
	assertHook.Assert(t)
}
