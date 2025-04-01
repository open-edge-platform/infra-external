// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	inv_v1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	provider_v1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/provider/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	inv_testing "github.com/open-edge-platform/infra-core/inventory/v2/pkg/testing"
	metadata_testing "github.com/open-edge-platform/infra-external/loca-metadata/pkg/testing"
	inventory_client "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/inventory"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/loca"
	_ "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/examples"
	loca_testing "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/testing"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/util"
)

const clientName = "TestLOCAMMInventoryClient"

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
	metadata_testing.InitializeInventoryClient(clientName)
	loca_testing.StartMockSecretService()
	loca_testing.SetupTenantGetterTest()

	run := m.Run() // run all tests
	inventory_client.StopTenantGetter()
	metadata_testing.CloseInventoryClientChannel(clientName)
	inv_testing.StopTestingEnvironment()

	os.Exit(run)
}

// This TC verifies main control loop functionality, i.e., its reaction on Site resources changes in Inventory.
func TestProvisioningCycle(t *testing.T) {
	// setting LOC-A MM environment to contain the CA
	fqdn := "kind.internal"
	t.Setenv(util.ClusterDomain, fqdn)
	t.Setenv(util.TinkCAPath, caPath)

	dao := inv_testing.NewInvResourceDAOOrFail(t)
	// Starting Mock LOC-A server which does not report any Instances and Hosts and does not contain any metadata
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() { locaTS.StopDummyLOCAServer() })
	loca_testing.SitesCrudFuncs(locaTS, false, nil)

	_ = loca_testing.PopulateInventoryWithLOCAProvider(t,
		loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL())

	// Starting LOC-A metadata manager
	lmm, err := NewLOCAMetadataManager(
		metadata_testing.LocaRMClient,
		metadata_testing.LocaRMEventsClient,
		loca_testing.TestReconciliationPeriod,
		&sync.WaitGroup{},
	)
	require.NoError(t, err)

	// Check that LOC-A Mock does not contain any Sites
	metadata_testing.AssertNumberOfSitesInLOCA(t, locaTS.GetURL(), 0)

	// Starting provisioning cycle
	readyChan := make(chan bool, 1)
	lmm.Start(readyChan)
	// Stopping provisioning cycle
	t.Cleanup(func() { lmm.Stop() })

	// Give enough room to perform 1 provisioning cycle (update) - no Sites should be registered
	time.Sleep(loca_testing.TestReconciliationPeriod)

	// Check that no new Sites was added to the LOC-A
	metadata_testing.AssertNumberOfSitesInLOCA(t, locaTS.GetURL(), 0)

	// Creating new Site
	siteRes := dao.CreateSiteNoCleanup(t, loca_testing.Tenant1, inv_testing.SiteName("new-site"),
		inv_testing.SiteCoordinates(373541070, -1219552380))

	// Give enough room to perform 1 provisioning cycle (update) - new Site should be onboarded in LOC-A
	time.Sleep(loca_testing.TestReconciliationPeriod)

	// Check that LOC-A Mock contains only 1 Site (pre-uploaded)
	metadata_testing.AssertNumberOfSitesInLOCA(t, locaTS.GetURL(), 1)
	// Checking that this is the exact same site
	metadata_testing.AssertLOCASite(t, locaTS.GetURL(), siteRes.GetName(), siteRes.GetAddress())

	// Adding one more Site
	siteRes2 := dao.CreateSite(t, loca_testing.Tenant1, inv_testing.SiteName("site2"),
		inv_testing.SiteCoordinates(37354107, -121955238))

	// Give enough room to perform 1 provisioning cycle (update) - another new Site should be onboarded in LOC-A
	time.Sleep(loca_testing.TestReconciliationPeriod)

	// Check that LOC-A Mock contains only 2 Sites (pre-uploaded)
	metadata_testing.AssertNumberOfSitesInLOCA(t, locaTS.GetURL(), 2)
	// Checking that the two exact sites are pushed to LOC-A
	metadata_testing.AssertLOCASite(t, locaTS.GetURL(), siteRes.GetName(), siteRes.GetAddress())
	metadata_testing.AssertLOCASite(t, locaTS.GetURL(), siteRes2.GetName(), siteRes2.GetAddress())

	// Deleting existing Site resource
	dao.DeleteResource(t, loca_testing.Tenant1, siteRes.GetResourceId())

	// Give enough room to perform 1 provisioning cycle (update)- existing Site should be removed from LOC-A,
	// another one should remain
	time.Sleep(loca_testing.TestReconciliationPeriod)

	// Check that the Site which was removed from Inventory is now gone from LOC-A
	loca_testing.RequireIsNotFound(t, loca_testing.Tenant1, siteRes.GetResourceId())
	// Check that LOC-A now contains only one Site
	metadata_testing.AssertNumberOfSitesInLOCA(t, locaTS.GetURL(), 1)
	// Check that this Site is exactly the other one, which was added later
	metadata_testing.AssertLOCASite(t, locaTS.GetURL(), siteRes2.GetName(), siteRes2.GetAddress())
}

// error is expected because there are no tenants.
func TestSyncErrWhileGettingTenant(t *testing.T) {
	assertHook := util.NewTestAssertHook("LOCA providers belongs to different tenants! Skip reconciliation!")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}
	// Starting LOC-A metadata manager
	lmm, err := NewLOCAMetadataManager(
		metadata_testing.LocaRMClient,
		metadata_testing.LocaRMEventsClient,
		loca_testing.TestReconciliationPeriod,
		&sync.WaitGroup{},
	)
	require.NoError(t, err)

	err = lmm.handleSynchronizationCycle()
	require.NoError(t, err, "handleSynchronizationCycle should not fail")
	assertHook.Assert(t)
}

// error is expected while initializing LOCA client.
func Test_SyncProviderErrWhileInitClient(t *testing.T) {
	// configure a broken provider
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	provider := dao.CreateProviderWithArgs(t,
		loca_testing.Tenant1, loca_testing.DefaultProviderName, "foobar",
		[]string{},
		provider_v1.ProviderVendor_PROVIDER_VENDOR_LENOVO_LOCA,
		inv_testing.ProviderKind(provider_v1.ProviderKind_PROVIDER_KIND_BAREMETAL),
	)

	// Starting LOC-A metadata manager
	lmm, err := NewLOCAMetadataManager(
		metadata_testing.LocaRMClient,
		metadata_testing.LocaRMEventsClient,
		loca_testing.TestReconciliationPeriod,
		&sync.WaitGroup{},
	)
	require.NoError(t, err)

	assertHook := util.NewTestAssertHook("Failed to initialize LOC-A client for endpoint")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	lmm.synchronizeProvider(context.Background(), loca_testing.Tenant1, provider)
	assertHook.Assert(t)
}

// error is expected while initializing LOCA client.
func Test_SyncProviderErrWhileUpdateMetadata(t *testing.T) {
	// Starting Mock LOC-A server which does not report any Instances and sites and does not contain any metadata
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() { locaTS.StopDummyLOCAServer() })
	// get site error 500
	locaTS.Override(loca_testing.InventorySitesPath, loca_testing.ReturnServerUnavailable)

	// configure provider in LOCA
	provider := loca_testing.PopulateInventoryWithLOCAProvider(t,
		loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL())

	assertHook := util.NewTestAssertHook("Failed to synchronize metadata")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	// Starting LOC-A metadata manager
	lmm, err := NewLOCAMetadataManager(
		metadata_testing.LocaRMClient,
		metadata_testing.LocaRMEventsClient,
		loca_testing.TestReconciliationPeriod,
		&sync.WaitGroup{},
	)
	require.NoError(t, err)

	lmm.synchronizeProvider(context.Background(), loca_testing.Tenant1, provider)
	assertHook.Assert(t)
}

// test different error cases.
func TestFilterEventErr(t *testing.T) {
	lmm := LOCAMM{}

	testcases := map[string]struct {
		event *inv_v1.SubscribeEventsResponse
		hook  string
		valid bool
	}{
		"EmptyEvent": {
			event: &inv_v1.SubscribeEventsResponse{},
			hook:  "Unknown resource kind",
			valid: false,
		},
		"InvalidEvent": {
			event: &inv_v1.SubscribeEventsResponse{
				ClientUuid: "foobar",
			},
			hook:  "Invalid event received",
			valid: false,
		},
		"UnexpectedEvent": {
			event: &inv_v1.SubscribeEventsResponse{
				ResourceId: "host-12345678",
			},
			valid: false,
		},
	}
	for tcname, tc := range testcases {
		t.Run(tcname, func(t *testing.T) {
			assertHook := util.NewTestAssertHook(tc.hook)
			zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}
			processed := lmm.filterEvent(tc.event)
			if tc.hook != "" {
				assertHook.Assert(t)
			}
			assert.Equal(t, tc.valid, processed)
		})
	}
}

func TestReconcileResourceErr(t *testing.T) {
	lmm, err := NewLOCAMetadataManager(
		metadata_testing.LocaRMClient,
		metadata_testing.LocaRMEventsClient,
		loca_testing.TestReconciliationPeriod,
		&sync.WaitGroup{},
	)
	require.NoError(t, err)

	testcases := map[string]struct {
		resourceID string
		hook       string
	}{
		"InvalidResource": {
			resourceID: "foobar",
			hook:       "Unknown resource kind",
		},
		"UnhandledResource": {
			resourceID: "host-12345678",
			hook:       "Unhandled resource",
		},
	}
	for tcname, tc := range testcases {
		t.Run(tcname, func(t *testing.T) {
			assertHook := util.NewTestAssertHook(tc.hook)
			zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}
			lmm.ReconcileResource(loca_testing.Tenant1, tc.resourceID, tc.resourceID)
			assertHook.Assert(t)
		})
	}
}
