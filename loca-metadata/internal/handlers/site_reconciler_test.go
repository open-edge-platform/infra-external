// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	locationv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/location/v1"
	providerv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/provider/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	inv_testing "github.com/open-edge-platform/infra-core/inventory/v2/pkg/testing"
	test "github.com/open-edge-platform/infra-external/loca-metadata/pkg/testing"
	inventory_client "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/inventory"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/loca"
	loca_testing "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/testing"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/util"
	rec_v2 "github.com/open-edge-platform/orch-library/go/pkg/controller/v2"
)

const (
	clientName = "TestLOCAMMInventoryClient"
	fqdn       = "kind.internal"
	address    = "streetName"
)

var caPath = ""

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

// test SiteReconcilers initialization.
func TestNewSiteReconciler(t *testing.T) {
	reconciler := NewSiteReconciler(true, loca_testing.LocaRMClient)
	assert.Equal(t, true, reconciler.TracingEnabled)
	assert.Equal(t, loca_testing.LocaRMClient, reconciler.InvClient)
}

// site must be added into LOC-A without error.
func Test_Reconcile_AddSite(t *testing.T) {
	// setting LOC-A MM environment to contain the CA
	t.Setenv(util.ClusterDomain, fqdn)
	t.Setenv(util.TinkCAPath, caPath)

	// setup inventory
	dao := inv_testing.NewInvResourceDAOOrFail(t)

	// Starting Mock LOC-A server which does not report any sites and does not contain any metadata
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() { locaTS.StopDummyLOCAServer() })
	loca_testing.SitesCrudFuncs(locaTS, false, nil)

	// configure LOC-A provider in Inventory
	_ = loca_testing.PopulateInventoryWithLOCAProvider(t,
		loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL())

	// add new site into inventory
	site := dao.CreateSite(t, loca_testing.Tenant1, func(site *locationv1.SiteResource) {
		site.Name = loca_testing.LocaSiteName
		site.Address = address
		site.SiteLat = 373541070
		site.SiteLng = 121955238
	})
	// reconcile for site add event
	siteReconciler := NewSiteReconciler(
		true, inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient())
	require.NotNil(t, siteReconciler)
	locasiteReconciler := rec_v2.NewController[ReconcilerID](
		siteReconciler.Reconcile,
		rec_v2.WithParallelism(1),
	)

	err = locasiteReconciler.Reconcile(NewReconcilerID(loca_testing.Tenant1, site.GetResourceId(),
		site.GetName()))
	time.Sleep(test.ReconciliationWait)
	require.NoError(t, err, "Reconciliation should not fail")
	// site must be added to LOCA post reconcilaion
	test.AssertNumberOfSitesInLOCA(t, locaTS.GetURL(), 1)
	test.AssertLOCASite(t, locaTS.GetURL(), site.GetName(), site.GetAddress())
}

// site must be deleted from LOC-A without error.
func Test_Reconcile_DeleteSite(t *testing.T) {
	t.Setenv(util.ClusterDomain, fqdn)
	t.Setenv(util.TinkCAPath, caPath)

	// Starting Mock LOC-A server which does not report any Instances and sites and does not contain any metadata
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() { locaTS.StopDummyLOCAServer() })

	// configure provider in LOCA
	_ = loca_testing.PopulateInventoryWithLOCAProvider(t,
		loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL())

	// assuming 1 site exists only in LOCA
	site := &locationv1.SiteResource{
		ResourceId: "site-a6fca33c",
		Name:       "INTC-SC11",
	}
	loca_testing.SitesCrudFuncs(locaTS, true, site)
	test.AssertNumberOfSitesInLOCA(t, locaTS.GetURL(), 1)
	// reconcile for site delete
	siteReconciler := NewSiteReconciler(
		true, inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient())
	require.NotNil(t, siteReconciler)
	locasiteReconciler := rec_v2.NewController[ReconcilerID](
		siteReconciler.Reconcile,
		rec_v2.WithParallelism(1),
	)

	err = locasiteReconciler.Reconcile(NewReconcilerID(loca_testing.Tenant1, site.GetResourceId(),
		site.GetName()))
	time.Sleep(test.ReconciliationWait)
	require.NoError(t, err, "Reconciliation failed")
	// site should be deleted from LOCA post reconcile as it's not present in inventory
	test.AssertNumberOfSitesInLOCA(t, locaTS.GetURL(), 0)
}

// site must be updated in LOC-A without error.
func Test_UpdateSite(t *testing.T) {
	t.Setenv(util.ClusterDomain, fqdn)
	t.Setenv(util.TinkCAPath, caPath)

	// setup inventory
	dao := inv_testing.NewInvResourceDAOOrFail(t)

	newSite := dao.CreateSite(t, loca_testing.Tenant1, func(site *locationv1.SiteResource) {
		site.Name = loca_testing.LocaSiteName
		site.Address = address
		site.SiteLat = 373541070
		site.SiteLng = 121955238
	})

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() { locaTS.StopDummyLOCAServer() })

	// configure provider in LOCA
	_ = loca_testing.PopulateInventoryWithLOCAProvider(t,
		loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL())

	// assuming 1 site exists only in LOCA
	site := &locationv1.SiteResource{
		ResourceId: newSite.GetResourceId(),
		Name:       newSite.GetName(),
		SiteLat:    newSite.SiteLat,
		SiteLng:    newSite.SiteLng,
	}
	loca_testing.SitesCrudFuncs(locaTS, true, site)
	test.AssertNumberOfSitesInLOCA(t, locaTS.GetURL(), 1)
	test.AssertLOCASite(t, locaTS.GetURL(), site.GetName(), site.GetAddress())

	// reconcile for site delete
	siteReconciler := NewSiteReconciler(
		true, inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient())
	require.NotNil(t, siteReconciler)
	locasiteReconciler := rec_v2.NewController[ReconcilerID](
		siteReconciler.Reconcile,
		rec_v2.WithParallelism(1),
	)

	err = locasiteReconciler.Reconcile(NewReconcilerID(loca_testing.Tenant1, newSite.GetResourceId(),
		newSite.GetName()))
	time.Sleep(test.ReconciliationWait)
	require.NoError(t, err, "Reconciliation failed")
	// site should be deleted from LOCA post reconcile as it's different
	test.AssertNumberOfSitesInLOCA(t, locaTS.GetURL(), 0)

	err = locasiteReconciler.Reconcile(NewReconcilerID(loca_testing.Tenant1, newSite.GetResourceId(),
		newSite.GetName()))
	time.Sleep(test.ReconciliationWait)
	require.NoError(t, err, "Reconciliation failed")
	// newSite should be added to LOCA post reconcile
	test.AssertNumberOfSitesInLOCA(t, locaTS.GetURL(), 1)
	test.AssertLOCASite(t, locaTS.GetURL(), newSite.GetName(), newSite.GetAddress())
}

// no-op expected.
func Test_UpdateSite_NoOp(t *testing.T) {
	t.Setenv(util.ClusterDomain, fqdn)
	t.Setenv(util.TinkCAPath, caPath)

	// setup inventory
	dao := inv_testing.NewInvResourceDAOOrFail(t)

	newSite := dao.CreateSite(t, loca_testing.Tenant1, func(site *locationv1.SiteResource) {
		site.Name = loca_testing.LocaSiteName
		site.Address = address
		site.SiteLat = 373541070
		site.SiteLng = 121955238
	})

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() { locaTS.StopDummyLOCAServer() })

	// configure provider in LOCA
	_ = loca_testing.PopulateInventoryWithLOCAProvider(t,
		loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL())

	// assuming 1 site exists only in LOCA
	site := &locationv1.SiteResource{
		ResourceId: newSite.GetResourceId(),
		Name:       newSite.GetName(),
		SiteLat:    newSite.SiteLat,
		SiteLng:    newSite.SiteLng,
		Address:    newSite.Address,
	}
	loca_testing.SitesCrudFuncs(locaTS, true, site)
	test.AssertNumberOfSitesInLOCA(t, locaTS.GetURL(), 1)
	test.AssertLOCASite(t, locaTS.GetURL(), site.GetName(), site.GetAddress())

	// reconcile for site delete
	siteReconciler := NewSiteReconciler(
		true, inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient())
	require.NotNil(t, siteReconciler)
	locasiteReconciler := rec_v2.NewController[ReconcilerID](
		siteReconciler.Reconcile,
		rec_v2.WithParallelism(1),
	)

	err = locasiteReconciler.Reconcile(NewReconcilerID(loca_testing.Tenant1, newSite.GetResourceId(),
		newSite.GetName()))
	time.Sleep(test.ReconciliationWait)
	require.NoError(t, err, "Reconciliation failed")
	// newSite should be added to LOCA post reconcile
	test.AssertNumberOfSitesInLOCA(t, locaTS.GetURL(), 1)
	test.AssertLOCASite(t, locaTS.GetURL(), newSite.GetName(), newSite.GetAddress())
}

// error is expected while initializing LOCA client.
func Test_Reconcile_ErrWhileInitClient(t *testing.T) {
	t.Setenv(util.ClusterDomain, fqdn)
	t.Setenv(util.TinkCAPath, caPath)

	// Starting Mock LOC-A server which does not report any Instances and sites and does not contain any metadata
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() { locaTS.StopDummyLOCAServer() })

	// configure provider in LOCA
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	_ = dao.CreateProviderWithArgs(t,
		loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL(),
		[]string{},
		providerv1.ProviderVendor_PROVIDER_VENDOR_LENOVO_LOCA,
		inv_testing.ProviderKind(providerv1.ProviderKind_PROVIDER_KIND_BAREMETAL),
	)

	// assuming 1 site exists only in LOCA
	assertHook := util.NewTestAssertHook("Failed to initialize LOC-A client")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}
	// reconcile for site delete
	siteReconciler := NewSiteReconciler(
		true, inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient())
	require.NotNil(t, siteReconciler)
	locasiteReconciler := rec_v2.NewController[ReconcilerID](
		siteReconciler.Reconcile,
		rec_v2.WithParallelism(1),
	)

	err = locasiteReconciler.Reconcile(NewReconcilerID(loca_testing.Tenant1, "site-a6fca33c",
		"foobar"))
	time.Sleep(test.ReconciliationWait)
	require.NoError(t, err, "Reconciliation failed")
	assertHook.Assert(t)
}

// error is expected while getting sites from LOC-A.
func Test_ReconcileSite_ErrWhileGettingSites(t *testing.T) {
	// setting LOC-A MM environment to contain the CA
	t.Setenv(util.ClusterDomain, fqdn)
	t.Setenv(util.TinkCAPath, caPath)

	// setup inventory
	dao := inv_testing.NewInvResourceDAOOrFail(t)

	// Starting Mock LOC-A server which does not report any Instances and sites and does not contain any metadata
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() { locaTS.StopDummyLOCAServer() })
	// get site error 503
	locaTS.Override(loca_testing.InventorySitesPath, loca_testing.ReturnServerUnavailable)

	// configure provider in LOCA
	_ = loca_testing.PopulateInventoryWithLOCAProvider(t,
		loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL())

	assertHook := util.NewTestAssertHook("received error while getting list of sites from LOCA:")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}
	sr := SiteReconciler{
		InvClient:      dao.GetAPIClient(),
		TracingEnabled: true,
	}
	site := &locationv1.SiteResource{
		ResourceId: "site-1234abc",
		Name:       "INTC-SC11",
		Address:    "2191,Laurelwood Road",
		SiteLat:    373541070,
		SiteLng:    -1219552380,
	}

	err = sr.ReconcileSite(context.TODO(), false, site, &providerv1.ProviderResource{
		ApiEndpoint:    locaTS.GetURL(),
		ApiCredentials: []string{loca_testing.LocaSecret},
		Name:           "LOC-A",
	}, site.GetName())
	assert.ErrorContains(t, err, "503")
	assertHook.Assert(t)
}

// not found is expected while checking if site exists.
func Test_ReconcileSite_WhileSiteNotFound(t *testing.T) {
	t.Setenv(util.ClusterDomain, fqdn)
	t.Setenv(util.TinkCAPath, caPath)

	// setup inventory
	dao := inv_testing.NewInvResourceDAOOrFail(t)

	// Starting Mock LOC-A server which does not report any Instances and sites and does not contain any metadata
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() { locaTS.StopDummyLOCAServer() })
	loca_testing.SitesCrudFuncs(locaTS, false, nil)

	// configure provider in LOCA
	_ = loca_testing.PopulateInventoryWithLOCAProvider(t,
		loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL())

	assertHook := util.NewTestAssertHook("but it is already gone")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}
	sr := SiteReconciler{
		InvClient:      dao.GetAPIClient(),
		TracingEnabled: true,
	}

	err = sr.ReconcileSite(context.TODO(), true, nil, &providerv1.ProviderResource{
		ApiEndpoint:    locaTS.GetURL(),
		ApiCredentials: []string{loca_testing.LocaSecret},
		Name:           "LOC-A",
	}, "test-site")
	require.NoError(t, err, "ReconcileSite should not fail")
	assertHook.Assert(t)
}

// error is expected while deleting a site that does not exist.
func Test_ReconcileSite_ErrWhileDeleteSite(t *testing.T) {
	t.Setenv(util.ClusterDomain, fqdn)
	t.Setenv(util.TinkCAPath, caPath)

	// setup inventory
	dao := inv_testing.NewInvResourceDAOOrFail(t)

	// Starting Mock LOC-A server which does not report any Instances and sites and does not contain any metadata
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() { locaTS.StopDummyLOCAServer() })

	// configure provider in LOCA
	_ = loca_testing.PopulateInventoryWithLOCAProvider(t,
		loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL())

	// assuming 1 site exists only in LOCA
	site := &locationv1.SiteResource{
		ResourceId: "site-1234abc",
		Name:       "INTC-SC11",
		Address:    "2191,Laurelwood Road",
		SiteLat:    373541070,
		SiteLng:    -1219552380,
	}
	assertHook := util.NewTestAssertHook("error while trying to delete")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}
	loca_testing.SitesCrudFuncs(locaTS, true, site)
	locaTS.Override(loca_testing.InventorySitesRemovePath, loca_testing.ReturnServerUnavailable, http.MethodPost)
	sr := SiteReconciler{
		InvClient:      dao.GetAPIClient(),
		TracingEnabled: true,
	}

	err = sr.ReconcileSite(context.TODO(), true, nil, &providerv1.ProviderResource{
		ApiEndpoint:    locaTS.GetURL(),
		ApiCredentials: []string{loca_testing.LocaSecret},
		Name:           "LOC-A",
	}, site.GetName())
	require.Error(t, err, "Site cannot be deleted")
	assert.ErrorContains(t, err, "503")
	assertHook.Assert(t)
}

func Test_ReconcileSite_ErrWhileAddSite(t *testing.T) {
	t.Setenv(util.ClusterDomain, fqdn)
	t.Setenv(util.TinkCAPath, caPath)

	// setup inventory
	dao := inv_testing.NewInvResourceDAOOrFail(t)

	// Starting Mock LOC-A server which does not report any Instances and sites and does not contain any metadata
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() { locaTS.StopDummyLOCAServer() })

	// configure provider in LOCA
	_ = loca_testing.PopulateInventoryWithLOCAProvider(t,
		loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL())

	site := &locationv1.SiteResource{
		ResourceId: "site-1234abc",
		Name:       "INTC-SC11",
		Address:    "2191,Laurelwood Road",
		SiteLat:    373541070,
		SiteLng:    -1219552380,
	}
	assertHook := util.NewTestAssertHook("error while trying to add")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}
	loca_testing.SitesCrudFuncs(locaTS, false, nil)
	locaTS.Override(loca_testing.InventorySitesPath, test.AddSitePostErr, http.MethodPost, http.MethodGet)
	sr := SiteReconciler{
		InvClient:      dao.GetAPIClient(),
		TracingEnabled: true,
	}

	err = sr.ReconcileSite(context.TODO(), false, site, &providerv1.ProviderResource{
		ApiEndpoint:    locaTS.GetURL(),
		ApiCredentials: []string{loca_testing.LocaSecret},
		Name:           "LOC-A",
	}, site.GetName())
	require.Error(t, err, "Site cannot be added")
	assert.ErrorContains(t, err, "400")
	assertHook.Assert(t)
}

// error is expected while getting cloud services.
func Test_ReconcileSite_ErrWhileUpdateCS(t *testing.T) {
	t.Setenv(util.ClusterDomain, fqdn)
	t.Setenv(util.TinkCAPath, caPath)

	// setup inventory
	dao := inv_testing.NewInvResourceDAOOrFail(t)

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() { locaTS.StopDummyLOCAServer() })

	site := &locationv1.SiteResource{
		ResourceId: "site-1234abc",
		Name:       "INTC-SC11",
		Address:    "2191,Laurelwood Road",
		SiteLat:    373541070,
		SiteLng:    -1219552380,
	}
	loca_testing.SitesCrudFuncs(locaTS, false, nil)
	locaTS.Override(loca_testing.InventoryCloudServicesPath, loca_testing.ReturnServerUnavailable)
	assertHook := util.NewTestAssertHook("error while trying to update site cloud services")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}
	sr := SiteReconciler{
		InvClient:      dao.GetAPIClient(),
		TracingEnabled: true,
	}

	err = sr.ReconcileSite(context.TODO(), false, site, &providerv1.ProviderResource{
		ApiEndpoint:    locaTS.GetURL(),
		ApiCredentials: []string{loca_testing.LocaSecret},
		Name:           "LOC-A",
	}, site.GetName())
	require.Error(t, err, "CS cannot be updated")
	assert.ErrorContains(t, err, "503")
	assertHook.Assert(t)
}
