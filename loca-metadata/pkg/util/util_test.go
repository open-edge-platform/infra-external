// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	location_v1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/location/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	inv_testing "github.com/open-edge-platform/infra-core/inventory/v2/pkg/testing"
	test "github.com/open-edge-platform/infra-external/loca-metadata/pkg/testing"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/model"
	inventory_client "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/inventory"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/loca"
	loca_testing "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/testing"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/util"
)

var (
	caPath = ""
	fqdn   = "kind.internal"
)

const clientName = "TestLOCAMMInventoryClient"

func TestMain(m *testing.M) {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	projectRoot := filepath.Dir(filepath.Dir(wd))
	policyPath := projectRoot + "/out"
	migrationsDir := projectRoot + "/out"
	caPath = projectRoot + "/secrets"
	err = os.Setenv(loca.CaCertPath, projectRoot+"/secrets")
	if err != nil {
		panic(err)
	}

	inv_testing.StartTestingEnvironment(policyPath, "", migrationsDir)
	test.InitializeInventoryClient(clientName)
	loca_testing.StartMockSecretService()
	loca_testing.SetupTenantGetterTest()
	if err != nil {
		panic(err)
	}

	run := m.Run() // run all tests
	inventory_client.StopTenantGetter()
	test.CloseInventoryClientChannel(clientName)
	inv_testing.StopTestingEnvironment()

	os.Exit(run)
}

// search for preloaded site in LOC-A.
func Test_FindOrCreateSiteCreationRequest_ErrWhileConvertSite(t *testing.T) {
	site := &location_v1.SiteResource{
		ResourceId: "site-1234abc",
		Name:       "INTC-SC11",
		Address:    "2191,Laurelwood Road",
		SiteLat:    1373541070,
		SiteLng:    -1219552380,
	}
	locaSites := []*model.DtoSites{}

	rsp := FindOrCreateSiteCreationRequest(site, locaSites)
	// no new site to add, as site is found in LOC-A
	require.Nil(t, rsp)
}

// expect error as CA details are empty.
func Test_DeleteCloudServiceCAIfNeeded_ErrWhileGetCSByID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), loca_testing.TestTimeout2S)
	defer cancel()

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() { locaTS.StopDummyLOCAServer() })
	// mock server updated to throw error during cloud service deletion
	locaTS.Override(loca_testing.InventoryCloudServicesIDPath, test.GetCSByIDErr)

	cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)
	rsp, err := cli.GetTask(ctx, loca_testing.LocaTaskUUID)
	require.Nil(t, err)
	require.NotNil(t, rsp)
	csListElement := &model.DtoCloudServiceListElement{
		Name:            loca_testing.LocaSiteName,
		SiteAssociation: []string{loca_testing.LocaSiteName},
		ServiceAddress:  "",
	}

	assertHook := util.NewTestAssertHook("error while getting cloudService from LOC-A")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	deleted, err := DeleteCloudServiceCAIfNeeded(ctx, cli, loca_testing.LocaSiteName,
		[]*model.DtoCloudServiceListElement{csListElement})
	require.NotNil(t, err)
	require.False(t, deleted)
	assertHook.Assert(t)
}

// TinkerBellCA is updated, happy path.
func Test_DeleteCloudServiceCAIfNeeded_SameCA(t *testing.T) {
	t.Setenv(util.ClusterDomain, fqdn)

	wd, err := os.Getwd()
	require.NoError(t, err)
	projectRoot := filepath.Dir(filepath.Dir(wd))
	tinkCAPath := projectRoot + "/secrets"
	t.Setenv(util.TinkCAPath, tinkCAPath)

	data, err := os.ReadFile(tinkCAPath + "/ca-cert.crt")
	require.NoError(t, err)
	fileContent := string(data)
	cs := &model.DtoCloudServiceSingleElement{
		ID:              "abc",
		Name:            loca_testing.LocaSiteName,
		SiteAssociation: []string{loca_testing.LocaSiteName},
		ServiceSettings: map[string]string{
			"TinkerbellCA": fileContent,
		},
	}

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() { locaTS.StopDummyLOCAServer() })
	locaTS.Override(loca_testing.InventoryCloudServicesIDPath, test.GetCSByID(cs))

	ctx, cancel := context.WithTimeout(context.Background(), loca_testing.TestTimeout2S)
	defer cancel()
	// creating client
	cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)
	csListElement := &model.DtoCloudServiceListElement{
		Name:            cs.Name,
		SiteAssociation: cs.SiteAssociation,
		ID:              cs.ID,
	}

	deleted, err := DeleteCloudServiceCAIfNeeded(ctx, cli, loca_testing.LocaSiteName,
		[]*model.DtoCloudServiceListElement{csListElement})
	require.False(t, deleted)
	require.NoError(t, err)
}

// expect error while no CA is found.
func Test_DeleteCloudServiceCAIfNeeded_ErrWhileReadTinkerBellCA(t *testing.T) {
	wd, err := os.Getwd()
	require.NoError(t, err)
	projectRoot := filepath.Dir(filepath.Dir(wd))
	tinkCAPath := projectRoot + "/secrets"
	t.Setenv(util.TinkCAPath, tinkCAPath+"/foobar")

	data, err := os.ReadFile(tinkCAPath + "/ca-cert.crt")
	require.NoError(t, err)
	fileContent := string(data)
	cs := &model.DtoCloudServiceSingleElement{
		ID:              "abc",
		Name:            loca_testing.LocaSiteName,
		SiteAssociation: []string{loca_testing.LocaSiteName},
		ServiceSettings: map[string]string{
			"TinkerbellCA": fileContent,
		},
	}

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() { locaTS.StopDummyLOCAServer() })
	locaTS.Override(loca_testing.InventoryCloudServicesIDPath, test.GetCSByID(cs))

	ctx, cancel := context.WithTimeout(context.Background(), loca_testing.TestTimeout2S)
	defer cancel()
	// creating client
	cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)
	csListElement := &model.DtoCloudServiceListElement{
		Name:            cs.Name,
		SiteAssociation: cs.SiteAssociation,
		ID:              cs.ID,
	}

	deleted, err := DeleteCloudServiceCAIfNeeded(ctx, cli, loca_testing.LocaSiteName,
		[]*model.DtoCloudServiceListElement{csListElement})
	require.False(t, deleted)
	require.Error(t, err)
}

// expect error while deleting cs.
func Test_DeleteCloudServiceCAIfNeeded_ErrWhileDeleteCloudService(t *testing.T) {
	wd, err := os.Getwd()
	require.NoError(t, err)
	projectRoot := filepath.Dir(filepath.Dir(wd))
	tinkCAPath := projectRoot + "/secrets"
	t.Setenv(util.TinkCAPath, tinkCAPath+"/garbage")

	data, err := os.ReadFile(tinkCAPath + "/ca-cert.crt")
	require.NoError(t, err)
	fileContent := string(data)
	cs := &model.DtoCloudServiceSingleElement{
		ID:              "abc",
		Name:            loca_testing.LocaSiteName,
		SiteAssociation: []string{loca_testing.LocaSiteName},
		ServiceSettings: map[string]string{
			"TinkerbellCA": fileContent,
		},
	}

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() { locaTS.StopDummyLOCAServer() })
	locaTS.Override(loca_testing.InventoryCloudServicesIDPath, test.GetCSByID(cs))
	locaTS.Override(loca_testing.TaskManagementTasksIDPath, loca_testing.ReturnServerUnavailable)

	ctx, cancel := context.WithTimeout(context.Background(), loca_testing.TestTimeout2S)
	defer cancel()
	// creating client
	cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)
	csListElement := &model.DtoCloudServiceListElement{
		Name:            cs.Name,
		SiteAssociation: cs.SiteAssociation,
		ID:              cs.ID,
	}

	deleted, err := DeleteCloudServiceCAIfNeeded(ctx, cli, loca_testing.LocaSiteName,
		[]*model.DtoCloudServiceListElement{csListElement})
	require.False(t, deleted)
	require.Error(t, err)
}

// error while checking if delete cs task is running.
func Test_DeleteCloudService_ErrWhileTaskIsRunningFor(t *testing.T) {
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer locaTS.StopDummyLOCAServer()

	// error while checking if task is running
	locaTS.Override(loca_testing.TaskManagementTasksIDPath, test.GetTaskByIDErr)

	ctx, cancel := context.WithTimeout(context.Background(), loca_testing.TestTimeout2S)
	defer cancel()
	cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)
	cs1 := &model.DtoCloudServiceListElement{
		ID:              "cs-123",
		Name:            loca_testing.LocaSiteName,
		SiteAssociation: []string{loca_testing.LocaSiteName},
		ServiceAddress:  "",
	}

	assertHook := util.NewTestAssertHook("failed to check if")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	err = deleteCloudService(ctx, cli, cs1)
	require.NoError(t, err)
	err = deleteCloudService(ctx, cli, cs1)
	require.Error(t, err)
	assertHook.Assert(t)
}

// error while tracking task.
func Test_DeleteCloudService_ErrWhileTrackTask(t *testing.T) {
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer locaTS.StopDummyLOCAServer()

	// error while checking if task is running
	locaTS.Override(loca_testing.InventoryCloudServicesRemovePath, test.DeleteCSPostNoTask)

	ctx, cancel := context.WithTimeout(context.Background(), loca_testing.TestTimeout2S)
	defer cancel()
	cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)
	cs1 := &model.DtoCloudServiceListElement{
		ID:              "cs-3",
		Name:            loca_testing.LocaSiteName,
		SiteAssociation: []string{loca_testing.LocaSiteName},
		ServiceAddress:  "",
	}

	err = deleteCloudService(ctx, cli, cs1)
	require.Error(t, err)
}

func Test_UpdateSiteCloudServices_Update(t *testing.T) {
	t.Setenv(util.ClusterDomain, fqdn)

	wd, err := os.Getwd()
	require.NoError(t, err)
	projectRoot := filepath.Dir(filepath.Dir(wd))
	tinkCAPath := projectRoot + "/secrets"
	t.Setenv(util.TinkCAPath, tinkCAPath)

	data, err := os.ReadFile(tinkCAPath + "/ca-cert.crt")
	require.NoError(t, err)
	fileContent := string(data)

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() { locaTS.StopDummyLOCAServer() })
	loca_testing.CSCrudFuncs(locaTS, false, nil)

	test.AssertNumberOfCSSInLOCA(t, locaTS.GetURL(), 0)

	ctx, cancel := context.WithTimeout(context.Background(), loca_testing.TestTimeout2S)
	defer cancel()
	// creating client
	cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)

	err = UpdateSiteCloudServices(ctx, cli, "test-site")
	require.NoError(t, err)
	test.AssertNumberOfCSSInLOCA(t, locaTS.GetURL(), 1)
	test.AssertLOCACS(t, locaTS.GetURL(), "test-site", fqdn, fileContent, "test-site")

	tinkCAPath = projectRoot + "/secrets/new"
	t.Setenv(util.TinkCAPath, tinkCAPath)

	data, err = os.ReadFile(tinkCAPath + "/ca-cert.crt")
	require.NoError(t, err)
	fileContent = string(data)

	err = UpdateSiteCloudServices(ctx, cli, "test-site")
	require.NoError(t, err)
	test.AssertNumberOfCSSInLOCA(t, locaTS.GetURL(), 1)
	test.AssertLOCACS(t, locaTS.GetURL(), "test-site", fqdn, fileContent, "test-site")
}

// error while creating cs.
func Test_UpdateSiteCloudServices_ErrWhilePostCS(t *testing.T) {
	t.Setenv(util.ClusterDomain, fqdn)

	wd, err := os.Getwd()
	require.NoError(t, err)
	projectRoot := filepath.Dir(filepath.Dir(wd))
	tinkCAPath := projectRoot + "/secrets"
	t.Setenv(util.TinkCAPath, tinkCAPath)

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() { locaTS.StopDummyLOCAServer() })
	locaTS.Override(loca_testing.InventoryCloudServicesPath, test.GetCS)
	locaTS.Override(loca_testing.InventoryCloudServicesPost, loca_testing.ReturnServerUnavailable)

	ctx, cancel := context.WithTimeout(context.Background(), loca_testing.TestTimeout2S)
	defer cancel()
	// creating client
	cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)

	assertHook := util.NewTestAssertHook("Failed to add cloud service")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	err = UpdateSiteCloudServices(ctx, cli, "random")
	require.Error(t, err)
	assertHook.Assert(t)
}

func Test_UpdateSiteCloudServices_ErrWhileCreateCSTemplate(t *testing.T) {
	wd, err := os.Getwd()
	require.NoError(t, err)
	projectRoot := filepath.Dir(filepath.Dir(wd))
	tinkCAPath := projectRoot + "/secrets"
	t.Setenv(util.TinkCAPath, tinkCAPath)

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() { locaTS.StopDummyLOCAServer() })

	cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)

	assertHook := util.NewTestAssertHook("Error creating cloud Service structure")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	err = UpdateSiteCloudServices(context.Background(), cli, "test-site")
	require.Error(t, err)
	assertHook.Assert(t)
}

// operation is deferred because there is already a task.
func Test_DeleteSite_WhileTaskIsRunning(t *testing.T) {
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() { locaTS.StopDummyLOCAServer() })
	// assuming 1 site exists only in LOCA
	site := &location_v1.SiteResource{
		ResourceId: "site-9234abc",
		Name:       "INTC-SC11",
		Address:    "2191,Laurelwood Road",
		SiteLat:    373541070,
		SiteLng:    -1219552380,
	}
	loca_testing.SitesCrudFuncs(locaTS, true, site)
	test.AssertNumberOfSitesInLOCA(t, locaTS.GetURL(), 1)

	// configure provider in LOCA
	_ = loca_testing.PopulateInventoryWithLOCAProvider(t,
		loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL())

	cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)

	// Prepopulate use the resourceID as LOC-A id to simplify the tests
	err = DeleteSite(context.Background(), cli, site.GetResourceId())
	require.NoError(t, err, "Delete should not fail")
	err = DeleteSite(context.Background(), cli, site.GetResourceId())
	require.NoError(t, err, "Delete should not fail")
}

// error is expected while checking if task is running.
func Test_DeleteSite_ErrWhileTaskIsRunning(t *testing.T) {
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() { locaTS.StopDummyLOCAServer() })
	// assuming 1 site exists only in LOCA
	site := &location_v1.SiteResource{
		ResourceId: "site-9234abc",
		Name:       "INTC-SC11",
		Address:    "2191,Laurelwood Road",
		SiteLat:    373541070,
		SiteLng:    -1219552380,
	}
	loca_testing.SitesCrudFuncs(locaTS, true, site)
	test.AssertNumberOfSitesInLOCA(t, locaTS.GetURL(), 1)

	// configure provider in LOCA
	_ = loca_testing.PopulateInventoryWithLOCAProvider(t,
		loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL())

	// assuming 1 site exists only in LOCA
	assertHook := util.NewTestAssertHook("failed to check if a task is running for site")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)

	err = DeleteSite(context.Background(), cli, site.GetResourceId())
	require.NoError(t, err, "Delete should not fail")

	// mock server updated to throw error while checking the task status
	locaTS.Override(loca_testing.TaskManagementTasksIDPath, loca_testing.ReturnServerUnavailable)

	err = DeleteSite(context.Background(), cli, site.GetResourceId())
	require.Error(t, err, "Delete should fail")
	assertHook.Assert(t)
}

// not found is expected while checking if site exists.
func Test_DeleteSite_ErrWhileSiteNotFound(t *testing.T) {
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() { locaTS.StopDummyLOCAServer() })
	locaTS.Override(loca_testing.InventorySitesRemovePath, test.DeleteSitePostErr)
	siteID := "site-a6feea33c"

	// configure provider for LOC-A
	_ = loca_testing.PopulateInventoryWithLOCAProvider(t,
		loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL())

	cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)

	err = DeleteSite(context.Background(), cli, siteID)
	require.NoError(t, err, "Delete should not fail")
}

// error is expected while deleting a site.
func Test_DeleteSite_ErrWhilePostSitesRemove(t *testing.T) {
	// Starting Mock LOC-A server which does not report any Instances and sites and does not contain any metadata
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() { locaTS.StopDummyLOCAServer() })
	// assuming 1 site exists only in LOCA
	site := &location_v1.SiteResource{
		ResourceId: "site-3234abc",
		Name:       "INTC-SC11",
		Address:    "2191,Laurelwood Road",
		SiteLat:    373541070,
		SiteLng:    -1219552380,
	}
	locaTS.Override(loca_testing.InventorySitesRemovePath, loca_testing.ReturnServerUnavailable)

	// configure provider in LOCA
	_ = loca_testing.PopulateInventoryWithLOCAProvider(t,
		loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL())

	// assuming 1 site exists only in LOCA
	assertHook := util.NewTestAssertHook("error while removing site")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)

	err = DeleteSite(context.Background(), cli, site.GetResourceId())
	require.Error(t, err, "Site cannot be deleted")
	require.ErrorContains(t, err, "503")
	assertHook.Assert(t)
}

// error is expected while getting not task uuid.
func Test_DeleteSite_Err_WhileGettingNoTask(t *testing.T) {
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() { locaTS.StopDummyLOCAServer() })
	locaTS.Override(loca_testing.InventorySitesRemovePath, test.DeleteSitePostNoTask)

	// configure provider in LOCA
	_ = loca_testing.PopulateInventoryWithLOCAProvider(t,
		loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL())

	cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)

	err = DeleteSite(context.Background(), cli, "site-b6fca33c")
	require.Error(t, err, "Site cannot be deleted")
	require.ErrorContains(t, err, "Got empty list of taskUUIDs for resourceID")
}
