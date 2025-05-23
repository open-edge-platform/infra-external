// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

//nolint:dogsled // declarations with blank identifiers are required to set the Host with its components
package manager

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	computev1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/compute/v1"
	inv_v1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	provider_v1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/provider/v1"
	statusv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/status/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/auth"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/flags"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	inv_status "github.com/open-edge-platform/infra-core/inventory/v2/pkg/status"
	inv_testing "github.com/open-edge-platform/infra-core/inventory/v2/pkg/testing"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/model"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/inventory"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/loca"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/secrets"
	loca_status "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/status"
	loca_testing "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/testing"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/util"
)

const clientName = "TestLOCARMInventoryClient"

var locaTS *loca_testing.MockServer

func TestMain(m *testing.M) {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	projectRoot := filepath.Dir(filepath.Dir(wd))
	policyPath := projectRoot + "/out"
	migrationsDir := projectRoot + "/out"
	err = os.Setenv(loca.CaCertPath, projectRoot+"/secrets")
	if err != nil {
		panic(err)
	}

	locaTS = loca_testing.StartTestingEnvironment(policyPath, migrationsDir, clientName)
	loca_testing.StartMockSecretService()
	loca_testing.SetupTenantGetterTest()
	err = secrets.Init(context.Background(), []string{"default-secret"})
	if err != nil {
		panic(err)
	}

	run := m.Run() // run all tests
	inventory.StopTenantGetter()
	loca_testing.StopTestingEnvironment(locaTS, clientName)

	os.Exit(run)
}

// This TC verifies the case, when Host is registered from the NB, but the Host discovery is disabled in LOC-A RM,
// The update part is also skipped due to the Host not present in LOC-A (different UUID and Serial Number
// than reported by LOC-A).
// This test covers the case when LOC-A is not yet brought up, but the Edge Infrastructure Manager is filled with the data
// that would be reported by LOC-A.
func Test_SkipHostRegistration(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	lc := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)
	// disabling Host discovery
	HostDiscovery = false

	lenovo := loca_testing.PopulateInventoryWithLOCAProvider(
		t, loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL())
	// creating Host from NB, but not the one, which is reported by LOC-A
	hostInv := dao.CreateHost(t, loca_testing.Tenant1, inv_testing.HostProvider(lenovo))

	// starting LOC-A manager
	lrm, err := NewLOCAManager(
		loca_testing.LocaRMClient,
		loca_testing.LocaRMEventsClient,
		loca_testing.TestReconciliationPeriod,
		&sync.WaitGroup{},
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), loca_testing.TestTimeout2S)
	defer cancel()

	// running Host-related part of main control loop - no Hosts should be registered
	err = lrm.UpdateHosts(ctx, lc, loca_testing.Tenant1, lenovo)
	require.NoError(t, err)

	// read Hosts from Inventory and make sure there are no new Hosts added
	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), hostInv.GetSerialNumber(), hostInv.GetUuid(),
		hostInv.GetDesiredState(), hostInv.GetCurrentState(),
		hostInv.GetOnboardingStatus(), hostInv.GetOnboardingStatusIndicator(),
		hostInv.GetHostStatus(), hostInv.GetHostStatusIndicator())
}

// This TC verifies the case, when the Host is registered from the NB, but the Host discovery is disabled in LOC-A RM,
// The update part is performed and updates Onboarding Status and Status Indicator of the Host.
func Test_NoHostDiscoveryUpdateHost(t *testing.T) {
	// adding data of the Host that is going to be added
	uuID := loca_testing.ParseUUID(t, loca_testing.LocaDeviceRawUUID)

	lc := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)
	// disabling Host discovery
	HostDiscovery = false

	// creating Site in Inventory
	site := loca_testing.PopulateInventoryWithSite(t, loca_testing.Tenant1, loca_testing.LocaSiteName)
	locaTS.SeedSiteResourceID(site.GetResourceId())

	lenovo := loca_testing.PopulateInventoryWithLOCAProvider(
		t, loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL())
	loca_testing.PopulateInventoryWithHostResources(t, loca_testing.Tenant1, lenovo, true)

	// starting LOC-A manager
	lrm, err := NewLOCAManager(
		loca_testing.LocaRMClient,
		loca_testing.LocaRMEventsClient,
		loca_testing.TestReconciliationPeriod,
		&sync.WaitGroup{},
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), loca_testing.TestTimeout2S)
	defer cancel()

	// running Host-related part of main control loop - no Hosts should be registered
	err = lrm.UpdateHosts(ctx, lc, loca_testing.Tenant1, lenovo)
	require.NoError(t, err)

	// read Hosts from Inventory and make sure that the Host corresponds
	// to the Host with status 'staged' in LOC-A
	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaDeviceSN, uuID,
		computev1.HostState_HOST_STATE_ONBOARDED, computev1.HostState_HOST_STATE_ONBOARDED,
		loca_status.DeviceStatusStaged.Status, loca_status.DeviceStatusStaged.StatusIndicator,
		// Host Status and Host Status Indicator remain unset
		inv_status.DefaultHostStatus, statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)
}

// Discover, register and update new Host. Host discovery is enabled.
func Test_RegisterNewHost(t *testing.T) {
	// getting credentials should succeed
	auth.AuthServiceFactory = auth.AuthServiceMockFactory(t, false, false, false)

	// adding data of the Host that is going to be added
	uuID := loca_testing.ParseUUID(t, loca_testing.LocaDeviceRawUUID)

	lc := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)
	// allowing Host discovery
	HostDiscovery = true

	// creating Lenovo provider
	lenovo := loca_testing.PopulateInventoryWithLOCAProvider(
		t, loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL())

	// creating Site in Inventory
	site := loca_testing.PopulateInventoryWithSite(t, loca_testing.Tenant1, loca_testing.LocaSiteName)
	locaTS.SeedSiteResourceID(site.GetResourceId())

	// read Hosts from Inventory and make sure there are no Hosts
	loca_testing.AssertNumberHostsForProvider(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), 0)

	// starting LOC-A manager
	lrm, err := NewLOCAManager(
		loca_testing.LocaRMClient,
		loca_testing.LocaRMEventsClient,
		loca_testing.TestReconciliationPeriod,
		&sync.WaitGroup{},
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), loca_testing.TestTimeout5S)
	defer cancel()
	// registering new Host and updating its Current State and Onboarding status - should return nil error
	err = lrm.UpdateHosts(ctx, lc, loca_testing.Tenant1, lenovo)
	require.NoError(t, err)
	// Cleaning up Host onboarded by LOC-A RM
	t.Cleanup(func() {
		loca_testing.HostCleanupByUUID(t, loca_testing.LocaRMClient, loca_testing.Tenant1, uuID)
	})

	// reading Hosts from Inventory back. There should be present one Host,
	// which corresponds to the 'staged' status in LOC-A
	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaDeviceSN, uuID,
		computev1.HostState_HOST_STATE_UNSPECIFIED, computev1.HostState_HOST_STATE_ONBOARDED,
		loca_status.DeviceStatusStaged.Status, loca_status.DeviceStatusStaged.StatusIndicator,
		// Host Status and Status Indicator are not set
		inv_status.DefaultHostStatus, statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)
}

// This TC verifies the case when Inventory contains Host with inconsistent UUID,
// i.e., a Host with reported by LOC-A SN already exists, but have different UUID, than the one reported by LOC-A.
func Test_InconsistencyInInventory(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	locaDeviceUUID := loca_testing.ParseUUID(t, loca_testing.LocaDeviceRawUUID)

	lc := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)
	// allowing Host discovery
	HostDiscovery = true

	// creating Lenovo provider
	lenovo := loca_testing.PopulateInventoryWithLOCAProvider(
		t, loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL())

	// creating Site in Inventory
	site := loca_testing.PopulateInventoryWithSite(t, loca_testing.Tenant1, loca_testing.LocaSiteName)
	locaTS.SeedSiteResourceID(site.GetResourceId())

	// creating a Host in Inventory
	hostInv := dao.CreateHost(t, loca_testing.Tenant1, inv_testing.HostProvider(lenovo), func(host *computev1.HostResource) {
		host.Site = site
	})
	oldSN := hostInv.GetSerialNumber()
	// faking its Serial Number with the Serial Number reported by LOC-A
	err := loca_testing.UpdateHostSerialNumber(t, loca_testing.Tenant1, hostInv.GetResourceId(), loca_testing.LocaDeviceSN)
	require.NoError(t, err)

	// read Hosts from Inventory and make sure there is exactly one Host
	loca_testing.AssertNumberHostsForProvider(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), 1)

	// starting LOC-A manager
	lrm, err := NewLOCAManager(
		loca_testing.LocaRMClient,
		loca_testing.LocaRMEventsClient,
		loca_testing.TestReconciliationPeriod,
		&sync.WaitGroup{},
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), loca_testing.TestTimeout5S)
	defer cancel()
	// running a provisioning cycle - it should not add any new hosts (i.e., inconsistent SN)
	err = lrm.UpdateHosts(ctx, lc, loca_testing.Tenant1, lenovo)
	require.NoError(t, err)

	// checking that the number of Hosts is still the same
	loca_testing.AssertNumberHostsForProvider(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), 1)

	// Returning the Host to the initial state, i.e., with
	// old SN and old UUID (assigned by default by the Inventory helper function).
	err = loca_testing.UpdateHostSerialNumber(t, loca_testing.Tenant1, hostInv.GetResourceId(), oldSN)
	require.NoError(t, err)

	// Running Host-related provisioning cycle again - new Host should be created
	err = lrm.UpdateHosts(ctx, lc, loca_testing.Tenant1, lenovo)
	require.NoError(t, err)
	// Cleaning up Host onboarded by LOC-A RM
	t.Cleanup(func() {
		loca_testing.HostCleanupByUUID(t, loca_testing.LocaRMClient, loca_testing.Tenant1, locaDeviceUUID)
	})

	// an additional Host should occur in Inventory - 2 in total
	loca_testing.AssertNumberHostsForProvider(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), 2)
}

// This TC verifies two cases:
// 1. LOC-A device reports a Site ID that does not exist in Inventory - Host site should not be updated
// 2. LOC-A device reports a Site ID that exists in Inventory - Host site should be updated.
func Test_AssociateHostWithSiteID(t *testing.T) {
	// adding data of the Host that is going to be added
	uuID := loca_testing.ParseUUID(t, loca_testing.LocaDeviceRawUUID)

	lc := loca.InitialiseTestLocaClient(
		locaTS.GetURL(),
		loca_testing.LocaSecret,
	)
	// disabling Host discovery
	HostDiscovery = false

	// creating Site in Inventory
	site := loca_testing.PopulateInventoryWithSite(t, loca_testing.Tenant1, loca_testing.LocaSiteName)
	locaTS.SeedSiteResourceID(site.GetResourceId())

	lenovo := loca_testing.PopulateInventoryWithLOCAProvider(
		t, loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL())
	loca_testing.PopulateInventoryWithHostResources(t, loca_testing.Tenant1, lenovo, true)

	// starting LOC-A manager
	lrm, err := NewLOCAManager(
		loca_testing.LocaRMClient,
		loca_testing.LocaRMEventsClient,
		loca_testing.TestReconciliationPeriod,
		&sync.WaitGroup{},
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), loca_testing.TestTimeout2S)
	defer cancel()

	// LOC-A device reports a Site ID that does not exist in Inventory
	nonExistingSiteID := "site-00000000"
	locaTS.SeedSiteResourceID(nonExistingSiteID)

	// running Host-related part of main control loop
	err = lrm.UpdateHosts(ctx, lc, loca_testing.Tenant1, lenovo)
	require.NoError(t, err)

	// Host site shouldn't be updated
	host, err := inventory.GetHostResourceByUUID(ctx, loca_testing.LocaRMClient, loca_testing.Tenant1, uuID)
	require.NoError(t, err)
	require.Nil(t, host.GetSite())

	// LOC-A device reports a Site ID that exists in Inventory
	locaTS.SeedSiteResourceID(site.GetResourceId())

	// running Host-related part of main control loop
	err = lrm.UpdateHosts(ctx, lc, loca_testing.Tenant1, lenovo)
	require.NoError(t, err)

	// Host site should be updated
	host, err = inventory.GetHostResourceByUUID(ctx, loca_testing.LocaRMClient, loca_testing.Tenant1, uuID)
	require.NoError(t, err)
	require.NotNil(t, host.GetSite())
	require.Equal(t, site.GetResourceId(), host.GetSite().GetResourceId())
}

// This TC verifies the case when LOC-A device reports a Site Name that does not exist in LOC-A.
// Host should not be associated with the Site due to obtaining a non-singular Site resource from LOC-A.
func Test_NonExistingSiteInLOCA(t *testing.T) {
	// adding data of the Host that is going to be added
	uuID := loca_testing.ParseUUID(t, loca_testing.LocaDeviceRawUUID)

	// starting LOC-A server without a predefined Site
	testLocaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() {
		// gracefully cleaning up Mock LOC-A Server state
		testLocaTS.StopDummyLOCAServer()
	})

	lc := loca.InitialiseTestLocaClient(
		testLocaTS.GetURL(),
		loca_testing.LocaSecret,
	)
	// disabling Host discovery
	HostDiscovery = false

	lenovo := loca_testing.PopulateInventoryWithLOCAProvider(
		t, loca_testing.Tenant1, loca_testing.DefaultProviderName, testLocaTS.GetURL())
	loca_testing.PopulateInventoryWithHostResources(t, loca_testing.Tenant1, lenovo, true)

	// starting LOC-A manager
	lrm, err := NewLOCAManager(
		loca_testing.LocaRMClient,
		loca_testing.LocaRMEventsClient,
		loca_testing.TestReconciliationPeriod,
		&sync.WaitGroup{},
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), loca_testing.TestTimeout2S)
	defer cancel()

	// running Host-related part of main control loop
	err = lrm.UpdateHosts(ctx, lc, loca_testing.Tenant1, lenovo)
	require.NoError(t, err)

	// Host site shouldn't be updated
	host, err := inventory.GetHostResourceByUUID(ctx, loca_testing.LocaRMClient, loca_testing.Tenant1, uuID)
	require.NoError(t, err)
	require.Nil(t, host.GetSite())
}

// This TC covers the Instance discovery (i.e., creating Instance Resource in Inventory) and
// Instance update (i.e., updating Instance's Current State and Status in Inventory) parts
// of the provisioning cycle.
func Test_DiscoverInstance(t *testing.T) {
	lc := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)

	// creating Lenovo provider
	lenovo := loca_testing.PopulateInventoryWithLOCAProvider(
		t, loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL())
	// creating Host and OS Resources from NB to get Inventory ready for Instance onboarding
	loca_testing.PopulateInventoryWithHostResources(t, loca_testing.Tenant1, lenovo, true)
	loca_testing.PopulateInventoryWithOSResource(t, []*loca_testing.MockServer{locaTS}, loca_testing.Tenant1)

	// starting LOC-A manager
	lrm, err := NewLOCAManager(
		loca_testing.LocaRMClient,
		loca_testing.LocaRMEventsClient,
		loca_testing.TestReconciliationPeriod,
		&sync.WaitGroup{},
	)
	require.NoError(t, err)

	// retrieve all Instances from Inventory attached to LOC-A provider => there should be no Instances present at that point
	loca_testing.AssertNumberInstancesForProvider(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), 0)

	ctx, cancel := context.WithTimeout(context.Background(), loca_testing.TestTimeout5S)
	defer cancel()
	// Run one provisioning cycle to discover and create an Instance
	err = lrm.UpdateInstances(ctx, lc, loca_testing.Tenant1, lenovo)
	require.NoError(t, err)
	t.Cleanup(func() {
		loca_testing.InstanceCleanupByName(t, loca_testing.LocaRMClient, loca_testing.Tenant1, loca_testing.LocaInstanceID)
	})

	// list all Instances from Inventory attached to LOC-A provider and
	// make sure there is a new Instances discovered and its Current State, Provisioning Status and Provisioning
	// Status Indicator are updated and correspond to the 'Failed' status at stage 'Instance postrconfigured'
	loca_testing.AssertNumberInstancesForProvider(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), 1)
	loca_testing.AssertInstance(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaInstanceID,
		computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED, computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED,
		loca_status.InstanceStatusInstancePostconfiguredFailed.Status,
		loca_status.InstanceStatusInstancePostconfiguredFailed.StatusIndicator,
		// Instance Status remains untouched
		inv_status.DefaultInstanceStatus, statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)
}

// This TC verifies that the Host is being invalidated during the main control loop tick phase (not in event).
func TestInvalidateHostInSynchronizationPhase(t *testing.T) {
	*flags.FlagDisableCredentialsManagement = false
	// revoking of credentials should succeed
	auth.AuthServiceFactory = auth.AuthServiceMockFactory(t, false, false, false)

	// adding data of the Host that is going to be added
	uuID := loca_testing.ParseUUID(t, loca_testing.LocaDeviceRawUUID)

	// allowing Host discovery
	HostDiscovery = true

	// creating Lenovo provider
	lenovo := loca_testing.PopulateInventoryWithLOCAProvider(
		t, loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL())
	// creating Host resource and its components
	host, _, _, _, _, _ := loca_testing.PopulateInventoryWithHostResources(t, loca_testing.Tenant1, lenovo, true)
	// creating OS Resource and Host component resources
	instance, _ := loca_testing.PopulateInventoryWithInstanceAndOSResource(t, []*loca_testing.MockServer{locaTS},
		loca_testing.Tenant1, host, true)
	// Bootstrapping production environment
	loca_testing.BootstrapProductionEnvironment(t, loca_testing.Tenant1, host.GetResourceId(), instance.GetResourceId())

	// read Hosts from Inventory and make sure there is exactly one Host.
	// Verify that Host's Current state is ONBOARDED, Desired State is ONBOARDED,
	// Onboarding Status and its Indicator correspond to Device status 'active' (set in the production environment).
	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaDeviceSN, uuID,
		computev1.HostState_HOST_STATE_ONBOARDED, computev1.HostState_HOST_STATE_ONBOARDED,
		loca_status.DeviceStatusActive.Status, loca_status.DeviceStatusActive.StatusIndicator,
		loca_testing.HostStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)

	// setting Desired state of the Host to be UNTRUSTED
	loca_testing.InvalidateHost(t, loca_testing.Tenant1, host.GetResourceId())

	// starting LOC-A manager
	lrm, err := NewLOCAManager(
		loca_testing.LocaRMClient,
		loca_testing.LocaRMEventsClient,
		loca_testing.TestReconciliationPeriod,
		&sync.WaitGroup{},
	)
	require.NoError(t, err)

	// starting provisioning cycle
	lrm.Start(nil)
	// stopping provisioning cycle
	t.Cleanup(func() { lrm.Stop() })

	// letting another synchronization and reconciliation cycles to pass.
	// Host is invalidated during synchronization phase
	time.Sleep(loca_testing.TestReconciliationPeriod)

	// read Hosts from Inventory and make sure there is exactly one Host
	// Verify that Host's Current state is UNTRUSTED, Desired State is UNTRUSTED,
	// Onboarding Status and its Indicator remain unchanged.
	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaDeviceSN, uuID,
		computev1.HostState_HOST_STATE_UNTRUSTED, computev1.HostState_HOST_STATE_UNTRUSTED,
		loca_status.DeviceStatusActive.Status, loca_status.DeviceStatusActive.StatusIndicator,
		loca_status.HostStatusInvalidated.Status, loca_status.HostStatusInvalidated.StatusIndicator)
}

// This TC verifies that the Host is being validated by event received from the NB, i.e., once synchronization
// and reconciliation phases are executed.
func TestInvalidateHostInEvent(t *testing.T) {
	*flags.FlagDisableCredentialsManagement = false
	// revoking of credentials should succeed
	auth.AuthServiceFactory = auth.AuthServiceMockFactory(t, false, false, false)

	// adding data of the Host that is going to be added
	uuID := loca_testing.ParseUUID(t, loca_testing.LocaDeviceRawUUID)

	// allowing Host discovery
	HostDiscovery = true

	// creating Site in Inventory
	site := loca_testing.PopulateInventoryWithSite(t, loca_testing.Tenant1, loca_testing.LocaSiteName)
	locaTS.SeedSiteResourceID(site.GetResourceId())
	// creating Lenovo provider
	lenovo := loca_testing.PopulateInventoryWithLOCAProvider(
		t, loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL())
	// creating Host resource and its components
	host, _, _, _, _, _ := loca_testing.PopulateInventoryWithHostResources(t, loca_testing.Tenant1, lenovo, true)
	// creating OS Resource and Host component resources
	instance, _ := loca_testing.PopulateInventoryWithInstanceAndOSResource(t, []*loca_testing.MockServer{locaTS},
		loca_testing.Tenant1, host, true)

	// bootstrapping production environment
	loca_testing.BootstrapProductionEnvironment(t, loca_testing.Tenant1, host.GetResourceId(), instance.GetResourceId())

	// read Hosts from Inventory and make sure there is exactly one Host
	// verifying that Host's Current state is ONBOARDED, Desired State is ONBOARDED (as set by testing helper function),
	// Onboarding Status and its Indicator correspond to the Device status 'active',
	// Host Status and its Indicator correspond to the 'Running'/IDLE.
	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaDeviceSN, uuID,
		computev1.HostState_HOST_STATE_ONBOARDED, computev1.HostState_HOST_STATE_ONBOARDED,
		loca_status.DeviceStatusActive.Status, loca_status.DeviceStatusActive.StatusIndicator,
		loca_testing.HostStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)

	// starting LOC-A manager
	lrm, err := NewLOCAManager(
		loca_testing.LocaRMClient,
		loca_testing.LocaRMEventsClient,
		loca_testing.TestReconciliationPeriod*2,
		&sync.WaitGroup{},
	)
	require.NoError(t, err)

	// starting provisioning cycle
	lrm.Start(nil)
	// stopping provisioning cycle
	t.Cleanup(func() { lrm.Stop() })

	// letting the synchronization phase to execute
	time.Sleep(loca_testing.TestReconciliationPeriod)

	// read Host from Inventory - there should be only changes related to the Host status 'staged',
	// i.e., Current state is ONBOARDED, Onboarding Status is 'Host is being provisioned',
	// Status Indication is 'IN_PROGRESS'. Host Status and its Indicator remained the same.
	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaDeviceSN, uuID,
		computev1.HostState_HOST_STATE_ONBOARDED, computev1.HostState_HOST_STATE_ONBOARDED,
		loca_status.DeviceStatusStaged.Status, loca_status.DeviceStatusStaged.StatusIndicator,
		loca_testing.HostStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)

	// Now Manager should be in the waiting phase, acting only on events.
	// Setting the Desired state of the Host to be UNTRUSTED
	loca_testing.InvalidateHost(t, loca_testing.Tenant1, host.GetResourceId())

	// letting the reconciliation event to be processed
	time.Sleep(100 * time.Millisecond)

	// read Hosts from Inventory and make sure there is exactly one Host
	// verifying that Host's Current state is UNTRUSTED, Desired State is UNTRUSTED,
	// Host Status is changed to 'Host is invalidated'/IDLE, Onboarding Status and
	// its Indicator remain the same.
	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaDeviceSN, uuID,
		computev1.HostState_HOST_STATE_UNTRUSTED, computev1.HostState_HOST_STATE_UNTRUSTED,
		loca_status.DeviceStatusStaged.Status, loca_status.DeviceStatusStaged.StatusIndicator,
		loca_status.HostStatusInvalidated.Status, loca_status.HostStatusInvalidated.StatusIndicator)
}

// This TC verifies that the Instance is being invalidated by event received from the NB,
// i.e., once synchronization and reconciliation phases are executed.
func TestInvalidateInstanceInEvent(t *testing.T) {
	*flags.FlagDisableCredentialsManagement = false

	// revoking of credentials should succeed
	auth.AuthServiceFactory = auth.AuthServiceMockFactory(t, false, false, false)

	// allowing Host discovery
	HostDiscovery = true

	// creating Lenovo provider
	lenovo := loca_testing.PopulateInventoryWithLOCAProvider(
		t, loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL())
	// creating Site in Inventory
	site := loca_testing.PopulateInventoryWithSite(t, loca_testing.Tenant1, loca_testing.LocaSiteName)
	locaTS.SeedSiteResourceID(site.GetResourceId())
	// creating Host resource and its components
	host, _, _, _, _, _ := loca_testing.PopulateInventoryWithHostResources(t, loca_testing.Tenant1, lenovo, true)
	// creating OS Resource and Host component resources
	instance, _ := loca_testing.PopulateInventoryWithInstanceAndOSResource(t, []*loca_testing.MockServer{locaTS},
		loca_testing.Tenant1, host, true)

	// bootstrapping production environment
	loca_testing.BootstrapProductionEnvironment(t, loca_testing.Tenant1, host.GetResourceId(), instance.GetResourceId())

	// starting LOC-A manager
	lrm, err := NewLOCAManager(
		loca_testing.LocaRMClient,
		loca_testing.LocaRMEventsClient,
		loca_testing.TestReconciliationPeriod*2,
		&sync.WaitGroup{},
	)
	require.NoError(t, err)

	// starting provisioning cycle
	lrm.Start(nil)
	// stopping provisioning cycle
	t.Cleanup(func() { lrm.Stop() })

	// letting the synchronization phase to execute
	time.Sleep(loca_testing.TestReconciliationPeriod)

	// read Instance from Inventory - there should be only one Instance corresponding to the status `Failed'
	// at stage `instance postconfigured`. The current state remains unchanged and equals `RUNNING`.
	// Instance Status and Status Indicator correspond
	// to the values that Node Agent previously reported (i.e., 'Running'/IDLE)
	loca_testing.AssertInstance(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaInstanceID,
		computev1.InstanceState_INSTANCE_STATE_RUNNING, computev1.InstanceState_INSTANCE_STATE_RUNNING,
		loca_status.InstanceStatusInstancePostconfiguredFailed.Status,
		loca_status.InstanceStatusInstancePostconfiguredFailed.StatusIndicator,
		loca_testing.InstanceStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)

	// Now Manager should be in the waiting phase, acting only on events.
	// setting desired state of the Instance to be UNTRUSTED
	loca_testing.InvalidateInstance(t, loca_testing.Tenant1, instance.GetResourceId())

	// letting the reconciliation event to be processed
	time.Sleep(100 * time.Millisecond)

	// Read Instance from Inventory and make sure that both, Desired and Current states, are UNTRUSTED.
	// The rest of the information remains the same.
	loca_testing.AssertInstance(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaInstanceID,
		computev1.InstanceState_INSTANCE_STATE_UNTRUSTED, computev1.InstanceState_INSTANCE_STATE_UNTRUSTED,
		loca_status.InstanceStatusInstancePostconfiguredFailed.Status,
		loca_status.InstanceStatusInstancePostconfiguredFailed.StatusIndicator,
		loca_status.InstanceStatusInvalidated.Status, loca_status.InstanceStatusInvalidated.StatusIndicator)
}

// This TC verifies that the Instance is being invalidated during the main control loop tick phase (not in the event).
func TestInvalidateInstanceInSynchronizationPhase(t *testing.T) {
	*flags.FlagDisableCredentialsManagement = false

	// revoking of credentials should succeed
	auth.AuthServiceFactory = auth.AuthServiceMockFactory(t, false, false, false)

	// allowing Host discovery
	HostDiscovery = true

	// creating Lenovo provider
	lenovo := loca_testing.PopulateInventoryWithLOCAProvider(
		t, loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL())
	// creating Site in Inventory
	site := loca_testing.PopulateInventoryWithSite(t, loca_testing.Tenant1, loca_testing.LocaSiteName)
	locaTS.SeedSiteResourceID(site.GetResourceId())
	// creating Host resource and its components
	host, _, _, _, _, _ := loca_testing.PopulateInventoryWithHostResources(t, loca_testing.Tenant1, lenovo, true)
	// creating OS Resource and Host component resources
	instance, _ := loca_testing.PopulateInventoryWithInstanceAndOSResource(t, []*loca_testing.MockServer{locaTS},
		loca_testing.Tenant1, host, true)

	// bootstrapping production environment
	loca_testing.BootstrapProductionEnvironment(t, loca_testing.Tenant1, host.GetResourceId(), instance.GetResourceId())

	// setting Desired state of the Instance to be UNTRUSTED
	loca_testing.InvalidateInstance(t, loca_testing.Tenant1, instance.GetResourceId())

	// ensuring that the Instance Desired State is UNTRUSTED, Current State is RUNNING (as in production environment),
	// Provisioning Status and Provisioning Status indicator correspond to 'Finished successfully' status at
	// stage 'installed' with operation 'Deploy', and Instance Status and its Indicator correspond to
	// the values that the Node Agent is setting in production (i.e., 'Running'/IDLE).
	loca_testing.AssertInstance(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaInstanceID,
		computev1.InstanceState_INSTANCE_STATE_UNTRUSTED, computev1.InstanceState_INSTANCE_STATE_RUNNING,
		loca_status.InstanceStatusInstalled.Status, loca_status.InstanceStatusInstalled.StatusIndicator,
		loca_testing.InstanceStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)

	// starting LOC-A manager
	lrm, err := NewLOCAManager(
		loca_testing.LocaRMClient,
		loca_testing.LocaRMEventsClient,
		loca_testing.TestReconciliationPeriod,
		&sync.WaitGroup{},
	)
	require.NoError(t, err)

	// starting provisioning cycle
	lrm.Start(nil)
	// stopping provisioning cycle
	t.Cleanup(func() { lrm.Stop() })

	// letting another synchronization and reconciliation cycles to pass.
	// Host is invalidated during synchronization
	time.Sleep(loca_testing.TestReconciliationPeriod)

	// read Instance from Inventory and make sure that both states, Current and Desired, are UNTRUSTED.
	// Provisioning Status and its Status Indicator correspond to status 'Failed' at stage 'instance postconfigured',
	// Instance Status and its Status Indicator to reflect Instance invalidation, i.e., became 'Instance is invalidated'/IDLE.
	loca_testing.AssertInstance(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaInstanceID,
		computev1.InstanceState_INSTANCE_STATE_UNTRUSTED, computev1.InstanceState_INSTANCE_STATE_UNTRUSTED,
		loca_status.InstanceStatusInstancePostconfiguredFailed.Status,
		loca_status.InstanceStatusInstancePostconfiguredFailed.StatusIndicator,
		loca_status.InstanceStatusInvalidated.Status, loca_status.InstanceStatusInvalidated.StatusIndicator)
}

// This TC verifies that the Instance is being removed during the main control loop tick phase (not in the event).
func TestRemoveInstanceInSynchronizationPhase(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	*flags.FlagDisableCredentialsManagement = false

	// starting Mock LOC-A server which does not report any Instances and Hosts
	testLocaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() { testLocaTS.StopDummyLOCAServer() })

	// revoking of credentials should succeed
	auth.AuthServiceFactory = auth.AuthServiceMockFactory(t, false, false, false)

	// allowing Host discovery
	HostDiscovery = true

	// creating Lenovo provider
	lenovo := loca_testing.PopulateInventoryWithLOCAProvider(
		t, loca_testing.Tenant1, loca_testing.DefaultProviderName, testLocaTS.GetURL())
	// creating Host resource and its components
	host, _, _, _, _, _ := loca_testing.PopulateInventoryWithHostResources(t, loca_testing.Tenant1, lenovo, true)
	// creating OS Resource and Host component resources
	instance, _ := loca_testing.PopulateInventoryWithInstanceAndOSResource(t, []*loca_testing.MockServer{testLocaTS},
		loca_testing.Tenant1, host, false)

	// bootstrapping production environment
	loca_testing.BootstrapProductionEnvironment(t, loca_testing.Tenant1, host.GetResourceId(), instance.GetResourceId())

	// setting Desired state of the Instance to be UNTRUSTED
	dao.DeleteResource(t, loca_testing.Tenant1, instance.GetResourceId())

	// ensuring that the Instance Desired State is DELETED, Current State is RUNNING (as in production environment),
	// Provisioning Status and Provisioning Status indicator correspond to 'Finished successfully' status at
	// stage 'installed' with operation 'Deploy', and Instance Status and its Indicator correspond to
	// the values that the Node Agent is setting in production (i.e., 'Running'/IDLE).
	loca_testing.AssertInstance(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaInstanceID,
		computev1.InstanceState_INSTANCE_STATE_DELETED, computev1.InstanceState_INSTANCE_STATE_RUNNING,
		loca_status.InstanceStatusInstalled.Status, loca_status.InstanceStatusInstalled.StatusIndicator,
		loca_testing.InstanceStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)

	// starting LOC-A manager
	lrm, err := NewLOCAManager(
		loca_testing.LocaRMClient,
		loca_testing.LocaRMEventsClient,
		loca_testing.TestReconciliationPeriod,
		&sync.WaitGroup{},
	)
	require.NoError(t, err)

	// starting provisioning cycle
	lrm.Start(nil)
	// stopping provisioning cycle
	t.Cleanup(func() { lrm.Stop() })

	// simulate the removal task in running state
	time.Sleep(2 * loca_testing.TestReconciliationPeriod)

	// switching the instance removal task to successful state
	testLocaTS.Override(loca_testing.DeploymentInstancesIDPath, loca_testing.DeletedInstanceFunc)
	testLocaTS.Override(loca_testing.TaskManagementTasksIDPath, loca_testing.SuccessfulGetTask)

	// letting synchronization and reconciliation cycles to pass.
	// Instance is deleted during synchronization
	time.Sleep(loca_testing.TestReconciliationPeriod)

	// read Instance from Inventory and make sure it was deleted
	loca_testing.RequireIsNotFound(t, loca_testing.Tenant1, instance.GetResourceId())
}

// This TC verifies that the Instance is being provisioned during the main control loop tick phase (not in the event).
func TestProvisionInstanceInSynchronizationPhase(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	*flags.FlagDisableCredentialsManagement = false

	// starting Mock LOC-A server which does not report any Instances and Hosts
	testLocaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() { testLocaTS.StopDummyLOCAServer() })

	// revoking of credentials should succeed
	auth.AuthServiceFactory = auth.AuthServiceMockFactory(t, false, false, false)

	// allowing Host discovery
	HostDiscovery = true

	// creating Site in Inventory
	site := loca_testing.PopulateInventoryWithSite(t, loca_testing.Tenant1, loca_testing.LocaSiteName)
	// creating Lenovo provider
	lenovo := loca_testing.PopulateInventoryWithLOCAProvider(
		t, loca_testing.Tenant1, loca_testing.DefaultProviderName, testLocaTS.GetURL())
	// creating Host resource and its components
	host, _, _, _, _, _ := loca_testing.PopulateInventoryWithHostResources(t, loca_testing.Tenant1, lenovo, true)
	// creating OS resource
	osRes := loca_testing.PopulateInventoryWithOSResource(t, []*loca_testing.MockServer{testLocaTS}, loca_testing.Tenant1)
	// creating Instance resource with dummy Instance name and RUNNING desired state
	instance := dao.CreateInstance(t, loca_testing.Tenant1, host, osRes)
	// associate Host with Site
	err = loca_testing.UpdateHostSite(t, loca_testing.Tenant1, host.GetResourceId(), site)
	require.NoError(t, err)
	// set Host Product Name - required for selecting the appropriate LOC-A template
	err = loca_testing.UpdateHostProductName(t, loca_testing.Tenant1, host.GetResourceId(), loca_testing.ServerModel)
	require.NoError(t, err)
	// seeding Site Resource ID in LOC-A site readiness response to match the Site Resource ID in Inventory
	testLocaTS.SeedSiteResourceID(site.GetResourceId())
	testLocaTS.Override(loca_testing.DeploymentInstancesCreate, func(writer http.ResponseWriter, request *http.Request) {
		loca_testing.WriteStructToResponse(writer, request, &model.DtoInstancesCreatedResponse{
			Data: &model.DtoInstanceCreatedListData{
				Count: 1,
				Results: []*model.DtoInstance{
					{
						ID: loca_testing.LocaInstanceID,
					},
				},
			},
		}, http.StatusCreated)
	}, http.MethodPost)

	// ensuring that the Instance Name is different from the LOC-A Instance ID
	require.NotEqualf(t, loca_testing.LocaInstanceID, instance.GetName(), "Instance name should be different")

	// starting LOC-A manager
	lrm, err := NewLOCAManager(
		loca_testing.LocaRMClient,
		loca_testing.LocaRMEventsClient,
		// increasing the reconciliation period to allow for the instance to be provisioned
		// TODO: adjust the reconciliation period after eliminating the need for the sleep in implementation
		loca_testing.TestReconciliationPeriod*8,
		&sync.WaitGroup{},
	)
	require.NoError(t, err)

	// starting one provisioning cycle to provision the Instance
	lrm.Start(nil)
	// stopping provisioning cycle
	t.Cleanup(func() { lrm.Stop() })

	// Ensuring that after the successful Instance provisioning, the Instance Name changed to the LOC-A Instance ID.
	// The Instance Desired State should remain unchanged (RUNNING), and the remaining fields
	// should correspond to UNSPECIFIED values.
	loca_testing.AssertInstance(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaInstanceID,
		computev1.InstanceState_INSTANCE_STATE_RUNNING, computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED,
		inv_status.DefaultProvisioningStatus, statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED,
		inv_status.DefaultInstanceStatus, statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)
}

// This TC verifies the case when the LOC-A fails to remove the Instance.
func TestRemoveInstanceInSynchronizationPhaseFail(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	*flags.FlagDisableCredentialsManagement = false

	// starting Mock LOC-A server which does not report any Instances and Hosts
	noResourcesLOCATS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(noResourcesLOCATS.StopDummyLOCAServer)
	locaTS.Override(loca_testing.DeploymentInstancesRemovePath, loca_testing.FailedRemoveInstancesFunc, http.MethodPost)

	// revoking of credentials should succeed
	auth.AuthServiceFactory = auth.AuthServiceMockFactory(t, false, false, false)

	// allowing Host discovery
	HostDiscovery = true

	// creating Lenovo provider
	lenovo := loca_testing.PopulateInventoryWithLOCAProvider(
		t, loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL())
	// creating Site in Inventory
	site := loca_testing.PopulateInventoryWithSite(t, loca_testing.Tenant1, loca_testing.LocaSiteName)
	locaTS.SeedSiteResourceID(site.GetResourceId())
	// creating Host resource and its components
	host, _, _, _, _, _ := loca_testing.PopulateInventoryWithHostResources(t, loca_testing.Tenant1, lenovo, true)
	// creating OS Resource and Host component resources
	instance, _ := loca_testing.PopulateInventoryWithInstanceAndOSResource(t, []*loca_testing.MockServer{locaTS},
		loca_testing.Tenant1, host, true)

	// bootstrapping production environment
	loca_testing.BootstrapProductionEnvironment(t, loca_testing.Tenant1, host.GetResourceId(), instance.GetResourceId())

	// setting Desired state of the Instance to be UNTRUSTED
	dao.DeleteResource(t, loca_testing.Tenant1, instance.GetResourceId())

	// ensuring that the Instance Desired State is DELETED, Current State is RUNNING (as in production environment),
	// Provisioning Status and Provisioning Status indicator correspond to 'Finished successfully' status at
	// stage 'installed' with operation 'Deploy', and Instance Status and its Indicator correspond to
	// the values that the Node Agent is setting in production (i.e., 'Running'/IDLE).
	loca_testing.AssertInstance(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaInstanceID,
		computev1.InstanceState_INSTANCE_STATE_DELETED, computev1.InstanceState_INSTANCE_STATE_RUNNING,
		loca_status.InstanceStatusInstalled.Status, loca_status.InstanceStatusInstalled.StatusIndicator,
		loca_testing.InstanceStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)

	// starting LOC-A manager
	lrm, err := NewLOCAManager(
		loca_testing.LocaRMClient,
		loca_testing.LocaRMEventsClient,
		loca_testing.TestReconciliationPeriod,
		&sync.WaitGroup{},
	)
	require.NoError(t, err)

	// starting provisioning cycle
	lrm.Start(nil)
	// stopping provisioning cycle
	t.Cleanup(func() { lrm.Stop() })

	// letting synchronization and reconciliation cycles to pass.
	// Instance is deleted during synchronization
	time.Sleep(loca_testing.TestReconciliationPeriod)

	// read Instance from Inventory and make sure that Desired State is DELETED, Current State remained unchanged,
	// Provisioning Status and its Status Indicator correspond to 'Failed to remove Instance from LOC-A'
	// Instance Status and its Status Indicator remained the same..
	loca_testing.AssertInstance(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaInstanceID,
		computev1.InstanceState_INSTANCE_STATE_DELETED, computev1.InstanceState_INSTANCE_STATE_RUNNING,
		util.StatusFailedToRemoveInstance, statusv1.StatusIndication_STATUS_INDICATION_ERROR,
		loca_testing.InstanceStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)
}

// This TC defines that the Host and Instance are cleaned up during the reconciliation cycle.
func TestDeleteHostAndInstanceInReconciliation(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	// starting Mock LOC-A server which does not report any Instances and Hosts
	noResourcesLOCATS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	noResourcesLOCATS.Override(loca_testing.InventoryDevicesPath, loca_testing.ReturnEmptyResponse)
	noResourcesLOCATS.Override(loca_testing.DeploymentInstancesPath, loca_testing.ReturnEmptyResponse)
	noResourcesLOCATS.Override(loca_testing.DeploymentInstancesIDPath, loca_testing.ReturnNoInstanceByInstanceID)
	t.Cleanup(func() { noResourcesLOCATS.StopDummyLOCAServer() })

	// adding data of the Host that is going to be added
	uuID := loca_testing.ParseUUID(t, loca_testing.LocaDeviceRawUUID)

	// allowing Host discovery
	HostDiscovery = true

	// creating Lenovo provider
	lenovo := loca_testing.PopulateInventoryWithLOCAProvider(
		t, loca_testing.Tenant1, loca_testing.DefaultProviderName, noResourcesLOCATS.GetURL())
	// creating Host resource and its components
	host, _, _, _, _, _ := loca_testing.PopulateInventoryWithHostResources(t, loca_testing.Tenant1, lenovo, false)
	// creating OS Resource and Host component resources
	instance, _ := loca_testing.PopulateInventoryWithInstanceAndOSResource(t, []*loca_testing.MockServer{noResourcesLOCATS},
		loca_testing.Tenant1, host, false)

	// Bootstrapping production environment
	loca_testing.BootstrapProductionEnvironment(t, loca_testing.Tenant1, host.GetResourceId(), instance.GetResourceId())

	// setting desired state of the Host to be deleted
	dao.DeleteResource(t, loca_testing.Tenant1, host.GetResourceId())
	// setting desired state of the Instance to be deleted
	dao.DeleteResource(t, loca_testing.Tenant1, instance.GetResourceId())

	// read Hosts from Inventory and make sure there is exactly one Host
	// verifying that Host's Current state is ONBOARDED (corresponds to the production environment),
	// Desired State is DELETED, Onboarding Status and its Indicator correspond to the Device status 'active',
	// Host Status is 'Running' and Host Status Indicator is IDLE
	// (corresponds to what the Node Agent sets when running in the production).
	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaDeviceSN, uuID,
		computev1.HostState_HOST_STATE_DELETED, computev1.HostState_HOST_STATE_ONBOARDED,
		loca_status.DeviceStatusActive.Status, loca_status.DeviceStatusActive.StatusIndicator,
		loca_testing.HostStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)

	// read Instances from Inventory and make sure there is exactly one Instance
	// verifying that Instance's Current state is RUNNING (corresponds to the production environment),
	// Desired State is DELETED, Provisioning Status and its Indicator correspond to the 'Finished successfully' status
	// at the stage 'installed' with operation 'Deploy', Instance Status is 'Running' and its Indicator is IDLE
	// (corresponds to what the Node Agent sets when running in the production).
	loca_testing.AssertInstance(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaInstanceID,
		computev1.InstanceState_INSTANCE_STATE_DELETED, computev1.InstanceState_INSTANCE_STATE_RUNNING,
		loca_status.InstanceStatusInstalled.Status, loca_status.InstanceStatusInstalled.StatusIndicator,
		loca_testing.InstanceStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)

	// starting LOC-A manager
	lrm, err := NewLOCAManager(
		loca_testing.LocaRMClient,
		loca_testing.LocaRMEventsClient,
		loca_testing.TestReconciliationPeriod,
		&sync.WaitGroup{},
	)
	require.NoError(t, err)

	// starting provisioning cycle
	lrm.Start(nil)
	// stopping provisioning cycle
	t.Cleanup(func() { lrm.Stop() })

	// Letting synchronization and reconciliation cycles to pass.
	// Instance is removed during synchronization, Host is removed during the reconciliation.
	time.Sleep(loca_testing.TestReconciliationPeriod)

	// Reading Hosts from Inventory back. There should be no Hosts present
	// (both states were set to be DELETED => it should be removed from Inventory)
	loca_testing.AssertNumberHostsForProvider(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), 0)
	// Reading Instances from Inventory back. There should be no Instances present
	// (both states were set to be DELETED => it should be removed from Inventory)
	loca_testing.AssertNumberInstancesForProvider(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), 0)
}

// This TC defines that the Host and Instance are cleaned up during the reconciliation cycle once they are removed
// from LOC-A.
//

func TestBottomUpDeleteHostAndInstanceInReconciliation(t *testing.T) {
	*flags.FlagDisableCredentialsManagement = false
	// revoking of credentials should succeed
	auth.AuthServiceFactory = auth.AuthServiceMockFactory(t, false, false, false)

	dao := inv_testing.NewInvResourceDAOOrFail(t)
	// starting Mock LOC-A server which does not report any Instances and Hosts
	noResourcesLOCATS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	noResourcesLOCATS.Override(loca_testing.InventoryDevicesPath, loca_testing.ReturnEmptyResponse)
	noResourcesLOCATS.Override(loca_testing.DeploymentInstancesPath, loca_testing.ReturnEmptyResponse)
	t.Cleanup(func() { noResourcesLOCATS.StopDummyLOCAServer() })

	// adding data of the Host that is going to be added
	uuID := loca_testing.ParseUUID(t, loca_testing.LocaDeviceRawUUID)

	// allowing Host discovery
	HostDiscovery = true

	// creating Lenovo provider
	lenovo := loca_testing.PopulateInventoryWithLOCAProvider(t,
		loca_testing.Tenant1, loca_testing.DefaultProviderName, noResourcesLOCATS.GetURL())
	// creating Host resource and its components
	host, _, _, _, _, _ := loca_testing.PopulateInventoryWithHostResources(t,
		loca_testing.Tenant1, lenovo, false)
	// creating OS Resource and Host component resources
	instance, _ := loca_testing.PopulateInventoryWithInstanceAndOSResource(t, []*loca_testing.MockServer{noResourcesLOCATS},
		loca_testing.Tenant1, host, false)

	// Bootstrapping production environment
	loca_testing.BootstrapProductionEnvironment(t,
		loca_testing.Tenant1, host.GetResourceId(), instance.GetResourceId())

	// read Hosts from Inventory and make sure there is exactly one Host
	// verifying that Host's Current state is ONBOARDED (corresponds to the production environment),
	// Desired State is ONBOARDED, Onboarding Status and its Indicator correspond to the Device status 'active',
	// Host Status is 'Running' and Host Status Indicator is IDLE
	// (corresponds to what the Node Agent sets when running in the production).
	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaDeviceSN, uuID,
		computev1.HostState_HOST_STATE_ONBOARDED, computev1.HostState_HOST_STATE_ONBOARDED,
		loca_status.DeviceStatusActive.Status, loca_status.DeviceStatusActive.StatusIndicator,
		loca_testing.HostStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)

	// read Instances from Inventory and make sure there is exactly one Instance
	// verifying that Instance's Current state is RUNNING (corresponds to the production environment),
	// Desired State is RUNNING, Provisioning Status and its Indicator correspond to the 'Finished successfully' status
	// at the stage 'installed' with operation 'Deploy', Instance Status is 'Running' and its Indicator is IDLE
	// (corresponds to what the Node Agent sets when running in the production).
	loca_testing.AssertInstance(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaInstanceID,
		computev1.InstanceState_INSTANCE_STATE_RUNNING, computev1.InstanceState_INSTANCE_STATE_RUNNING,
		loca_status.InstanceStatusInstalled.Status, loca_status.InstanceStatusInstalled.StatusIndicator,
		loca_testing.InstanceStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)

	// starting LOC-A manager
	lrm, err := NewLOCAManager(
		loca_testing.LocaRMClient,
		loca_testing.LocaRMEventsClient,
		loca_testing.TestReconciliationPeriod,
		&sync.WaitGroup{},
	)
	require.NoError(t, err)
	noResourcesLOCATS.Override(loca_testing.DeploymentInstancesIDPath, loca_testing.ReturnNoInstanceByInstanceID, http.MethodGet)

	// starting provisioning cycle
	lrm.Start(nil)
	// stopping provisioning cycle
	t.Cleanup(func() { lrm.Stop() })

	// First synchronization is done de-sync with reconciliation cycle.
	// Host and Instance statuses should be updated with regard to theirs absence in LOC-A.
	time.Sleep(loca_testing.TestReconciliationPeriod / 2)

	// read Hosts from Inventory and make sure there is exactly one Host
	// verifying that Host's Current state is ERROR (Device does not exist in LOC-A),
	// Desired State is ONBOARDED, the current state remains unchanged and equals `ONBOARDED`.
	// Onboarding Status and its Indicator correspond to the Device status 'active',
	// Host Status is 'Device does not exist in LOC-A' and Host Status Indicator is ERROR
	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaDeviceSN, uuID,
		computev1.HostState_HOST_STATE_ONBOARDED, computev1.HostState_HOST_STATE_ONBOARDED,
		loca_status.DeviceStatusDoesNotExist.Status, loca_status.DeviceStatusDoesNotExist.StatusIndicator,
		loca_testing.HostStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)

	// read Instances from Inventory and make sure there is exactly one Instance
	// verifying that Instance's Current state is ERROR (Instance does not exist in LOC-A),
	// Desired State is RUNNING, Provisioning Status and its Indicator correspond to the 'Finished successfully' status
	// at the stage 'installed' with operation 'Deploy', Instance Status is 'Instance does not exist in LOC-A'
	// The current state remains unchanged and equals `RUNNING` and its Indicator is ERROR.
	loca_testing.AssertInstance(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaInstanceID,
		computev1.InstanceState_INSTANCE_STATE_RUNNING, computev1.InstanceState_INSTANCE_STATE_RUNNING,
		loca_status.InstanceStatusDoesNotExist.Status, loca_status.InstanceStatusDoesNotExist.StatusIndicator,
		loca_testing.InstanceStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)

	// setting desired state of the Host to be deleted
	dao.DeleteResource(t, loca_testing.Tenant1, host.GetResourceId())
	// setting desired state of the Instance to be deleted
	dao.DeleteResource(t, loca_testing.Tenant1, instance.GetResourceId())

	// Letting another synchronization and reconciliation cycles to pass.
	// Instance is removed during synchronization, Host is removed during the reconciliation.
	time.Sleep(loca_testing.TestReconciliationPeriod)

	// Reading Hosts from Inventory back. There should be no Hosts present
	// (both states were set to be DELETED => it should be removed from Inventory)
	loca_testing.RequireIsNotFound(t, loca_testing.Tenant1, host.GetResourceId())
	// Reading Instances from Inventory back. There should be no Instances present
	// (both states were set to be DELETED => it should be removed from Inventory)
	loca_testing.RequireIsNotFound(t, loca_testing.Tenant1, instance.GetResourceId())
}

// This TC verifies full provisioning cycle (i.e., main control loop). Discovery and Current State and Status update
// are covered for both, Host and Instance.
// This TC also covers periodical updates conducted by the main control loop.
//
//nolint:funlen // this TC requires additional steps to set the prerequisites
func Test_ProvisioningCycle(t *testing.T) {
	*flags.FlagDisableCredentialsManagement = false
	// revoking of credentials should succeed
	auth.AuthServiceFactory = auth.AuthServiceMockFactory(t, false, false, false)

	// adding data of the Host that is going to be added
	uuID := loca_testing.ParseUUID(t, loca_testing.LocaDeviceRawUUID)

	// allowing Host discovery
	HostDiscovery = true

	// creating Lenovo provider
	lenovo := loca_testing.PopulateInventoryWithLOCAProvider(
		t, loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL())

	// creating OS resource
	loca_testing.PopulateInventoryWithOSResource(t, []*loca_testing.MockServer{locaTS}, loca_testing.Tenant1)

	// creating Site in Inventory
	site := loca_testing.PopulateInventoryWithSite(t, loca_testing.Tenant1, loca_testing.LocaSiteName)
	locaTS.SeedSiteResourceID(site.GetResourceId())

	// Ensure that there are no Hosts and Instances in Inventory
	loca_testing.AssertNumberHostsForProvider(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), 0)
	loca_testing.AssertNumberInstancesForProvider(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), 0)

	// starting LOC-A manager
	lrm, err := NewLOCAManager(
		loca_testing.LocaRMClient,
		loca_testing.LocaRMEventsClient,
		loca_testing.TestReconciliationPeriod,
		&sync.WaitGroup{},
	)
	require.NoError(t, err)

	// starting provisioning cycle
	lrm.Start(nil)
	t.Cleanup(func() {
		// cleaning up Instance at the end of the test
		loca_testing.InstanceCleanupByName(t, loca_testing.LocaRMClient, loca_testing.Tenant1, loca_testing.LocaInstanceID)
		// cleaning up Host at the end of the test
		loca_testing.HostCleanupByUUID(t, loca_testing.LocaRMClient, loca_testing.Tenant1, uuID)
	})
	// stopping provisioning cycle
	t.Cleanup(func() { lrm.Stop() })

	// Give enough room to perform a provisioning cycle. Provisioning happens at the very end of the sleep period.
	// Allowing to wait additionally for all provisioning budget, i.e., provisioningWeight [%].
	time.Sleep(loca_testing.TestReconciliationPeriod +
		loca_testing.TestReconciliationPeriod*loca_testing.ProvisioningWeight/loca_testing.TotalWeight)

	// Reading the Host from Inventory and making sure it corresponds to the `staged` status reported by the LOC-A.
	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaDeviceSN, uuID,
		computev1.HostState_HOST_STATE_UNSPECIFIED, computev1.HostState_HOST_STATE_ONBOARDED,
		// Onboarding Status and Onboarding Status Indicator are set by the main control loop
		loca_status.DeviceStatusStaged.Status, loca_status.DeviceStatusStaged.StatusIndicator,
		// Host Status and Host Status Indicator are unset - Node Agent is not running
		inv_status.DefaultHostStatus, statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)
	// Reading the Instance from Inventory and making sure it corresponds to the 'Failed' status at
	// `instance postconfigured` stage reported by the LOC-A.
	loca_testing.AssertInstance(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaInstanceID,
		computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED, computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED,
		// Provisioning Status and Provisioning Status Indicator are set by the main control loop
		loca_status.InstanceStatusInstancePostconfiguredFailed.Status,
		loca_status.InstanceStatusInstancePostconfiguredFailed.StatusIndicator,
		// Instance Status and Instance Status Indicator are unset - Node Agent is not running
		inv_status.DefaultInstanceStatus, statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)

	ctx, cancel := context.WithTimeout(context.Background(), loca_testing.TestTimeout5S)
	defer cancel()
	// save the variables for future manipulations
	hostsInv, err := inventory.ListAllHostsByLOCAProvider(
		ctx, loca_testing.LocaRMClient, loca_testing.Tenant1, lenovo.GetApiEndpoint())
	require.NoError(t, err)
	instancesInv, err := inventory.ListAllInstancesByLOCAProvider(
		ctx, loca_testing.LocaRMClient, loca_testing.Tenant1, lenovo.GetApiEndpoint())
	require.NoError(t, err)

	locaTS.Override(loca_testing.InventoryDevicesPath, loca_testing.ActiveDevice, http.MethodGet)
	// provisioning instance
	locaTS.Override(loca_testing.DeploymentInstancesIDPath, func(res http.ResponseWriter, req *http.Request) {
		loca_testing.InstancesByIDWithModify(res, req,
			func(_ http.ResponseWriter, instanceResponse *model.DtoInstanceQryResponse) {
				instanceResponse.Data.Operation = loca_testing.OperationDeploy
				instanceResponse.Data.Stage = loca_testing.StageInstalled
				instanceResponse.Data.Status = loca_testing.StatusFinishedSuccessfully
			}, instancesInv[0].DesiredOs.ResourceId)
	}, http.MethodGet)

	// at this point the node agent did not kick in, it will happen later
	// give enough room to perform 1 provisioning cycle (update)
	time.Sleep(loca_testing.TestReconciliationPeriod)

	// Read the Host and ensure that the Current State, Onboarding Status and Onboarding Status Indicator
	// have been updated to correspond to the 'active' status reported by LOC-A.
	// Host Status and Host Status Indicator are not set - Node Agent is not yet running.
	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaDeviceSN, uuID,
		computev1.HostState_HOST_STATE_UNSPECIFIED, computev1.HostState_HOST_STATE_ONBOARDED,
		loca_status.DeviceStatusActive.Status, loca_status.DeviceStatusActive.StatusIndicator,
		inv_status.DefaultHostStatus, statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)
	// Read the Instance and ensure that the Current State, Provisioning Status and Provisioning Status Indicator
	// have been updated to correspond to the 'Finished successfully' status at stage 'installed' reported by LOC-A.
	// Instance Status and Instance Status Indicator are not set - Node Agent is not yet running.
	loca_testing.AssertInstance(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaInstanceID,
		computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED, computev1.InstanceState_INSTANCE_STATE_RUNNING,
		loca_status.InstanceStatusInstalled.Status, loca_status.InstanceStatusInstalled.StatusIndicator,
		inv_status.DefaultInstanceStatus, statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)

	// simulating that the Node Agent kicks - it updates Host Status and Instance Status to be running
	loca_testing.SimulateNodeAgentAction(t, loca_testing.Tenant1, hostsInv[0].GetResourceId(), instancesInv[0].GetResourceId())

	// give enough room to perform 1 provisioning cycle (update)
	time.Sleep(loca_testing.TestReconciliationPeriod)

	// Read the Host and ensure that the Current State, Onboarding Status and Onboarding Status Indicator
	// have remained the same. Host Status and Host Status Indicator have been updated and correspond to 'Running'/IDLE.
	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaDeviceSN, uuID,
		computev1.HostState_HOST_STATE_UNSPECIFIED, computev1.HostState_HOST_STATE_ONBOARDED,
		util.DeviceStatusActiveDescription, statusv1.StatusIndication_STATUS_INDICATION_IDLE,
		loca_testing.HostStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)
	// Read the Instance and ensure that the Current State, Provisioning Status and Provisioning Status Indicator
	// have remained the same. Instance Status and Instance Status Indicator have been updated to 'Running'/IDLE
	loca_testing.AssertInstance(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaInstanceID,
		computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED, computev1.InstanceState_INSTANCE_STATE_RUNNING,
		loca_status.InstanceStatusInstalled.Status, loca_status.InstanceStatusInstalled.StatusIndicator,
		loca_testing.InstanceStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)

	// Deactivating device and bringing Instance back to the provisioning failed state
	locaTS.Override(loca_testing.InventoryDevicesPath, loca_testing.DevicesFunc, http.MethodGet)
	locaTS.SeedOSResourceID(instancesInv[0].DesiredOs.ResourceId)

	// Give enough room to perform 1 provisioning cycle (update)
	time.Sleep(loca_testing.TestReconciliationPeriod)

	// Read the Host and ensure that the Current State, Onboarding Status and Onboarding Status Indicator
	// have been updated to correspond to the 'active' status reported by LOC-A.
	// Host Status and Host Status Indicator have been updated and correspond to 'Running'/IDLE.
	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaDeviceSN, uuID,
		computev1.HostState_HOST_STATE_UNSPECIFIED, computev1.HostState_HOST_STATE_ONBOARDED,
		util.DeviceStatusStagedDescription, statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS,
		loca_testing.HostStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)
	// Read the Instance and ensure that the Current State, Provisioning Status and Provisioning Status Indicator
	// have been updated to correspond to the 'Finished successfully' status at stage 'installed' reported by LOC-A.
	// Instance Status and Instance Status Indicator have been updated to 'Running'/IDLE
	loca_testing.AssertInstance(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaInstanceID,
		computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED, computev1.InstanceState_INSTANCE_STATE_RUNNING,
		util.StageInstancePostconfiguredDescription, statusv1.StatusIndication_STATUS_INDICATION_ERROR,
		loca_testing.InstanceStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)
}

// This TC covers Host and Instance registration and update parts for multiple LOC-A instances.
//
//nolint:funlen // should be this long for tests
func Test_MultipleLOCAProvisioning(t *testing.T) {
	// revoking of credentials should succeed
	auth.AuthServiceFactory = auth.AuthServiceMockFactory(t, false, false, false)

	// adding data of the Host that is going to be added
	uuID := loca_testing.ParseUUID(t, loca_testing.LocaDeviceRawUUID)
	uuID2 := loca_testing.ParseUUID(t, loca_testing.SecondaryRawUUID)

	// allowing Host discovery
	HostDiscovery = true
	loca_testing.SitesCrudFuncs(locaTS, true, nil)

	// starting secondary LOC-A servers
	secondaryLOCATS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() {
		// gracefully cleaning up Mock LOC-A Server state
		secondaryLOCATS.StopDummyLOCAServer()
	})
	loca_testing.SitesCrudFuncs(secondaryLOCATS, true, nil)
	secondaryLOCATS.Override(loca_testing.DeploymentInstancesPath, func(writer http.ResponseWriter, request *http.Request) {
		loca_testing.WriteStructToResponse(writer, request, &model.DtoInstancesQryResponse{
			Data: &model.DtoInstanceList{
				Count: 1, Results: []*model.DtoInstanceInList{{ID: loca_testing.SecondaryInstanceID}},
			},
		}, http.StatusOK)
	})
	secondaryLOCATS.Override(loca_testing.InventoryDevicesPath, func(writer http.ResponseWriter, request *http.Request) {
		data := &model.DtoDeviceListResponse{
			Data: &model.DtoDeviceListData{
				Count: 1, Results: []*model.DtoDeviceListElement{
					{
						UUID:         loca_testing.SecondaryRawUUID,
						SerialNumber: loca_testing.SecondarySerialNumber,
						ID:           loca_testing.SecondaryInstanceID,
						DeviceType: &model.DtoDCIMType{
							Name: loca_testing.ServerModel,
						},
					},
				},
			},
		}

		loca_testing.WriteStructToResponse(writer, request, data, http.StatusOK)
	}, http.MethodGet)

	// creating two LOC-A providers
	locaProvider1 := loca_testing.PopulateInventoryWithLOCAProvider(
		t, loca_testing.Tenant1, "LOC-A#1", locaTS.GetURL())
	locaProvider2 := loca_testing.PopulateInventoryWithLOCAProvider(
		t, loca_testing.Tenant1, "LOC-A#2", secondaryLOCATS.GetURL())

	// creating Site
	site := loca_testing.PopulateInventoryWithSite(t, loca_testing.Tenant1, loca_testing.LocaSiteName)

	// seeding Site Resource ID for all three LOC-A Providers
	locaTS.SeedSiteResourceID(site.GetResourceId())
	secondaryLOCATS.SeedSiteResourceID(site.GetResourceId())

	// Seeding OS Resource
	osRes := loca_testing.PopulateInventoryWithOSResource(t, []*loca_testing.MockServer{
		locaTS,
		secondaryLOCATS,
	}, loca_testing.Tenant1)
	secondaryLOCATS.Override(loca_testing.DeploymentInstancesIDPath, func(writer http.ResponseWriter, request *http.Request) {
		data := &model.DtoInstanceQryResponse{Data: &model.DtoInstance{
			ID:    loca_testing.SecondaryInstanceID,
			Nodes: []*model.DtoNode{{SerialNumber: loca_testing.SecondarySerialNumber}},
			Template: &model.DtoTemplate{
				ExtraVars: map[string]any{
					loca_testing.ExtraVarsOSResourceID: osRes.GetResourceId(),
				},
			},
		}}

		loca_testing.WriteStructToResponse(writer, request, data, http.StatusOK)
	})
	// There should be no Hosts and no Instances created
	loca_testing.AssertNumberHostsForProvider(t, loca_testing.Tenant1, locaProvider1.GetApiEndpoint(), 0)
	loca_testing.AssertNumberInstancesForProvider(t, loca_testing.Tenant1, locaProvider1.GetApiEndpoint(), 0)

	loca_testing.AssertNumberHostsForProvider(t, loca_testing.Tenant1, locaProvider2.GetApiEndpoint(), 0)
	loca_testing.AssertNumberInstancesForProvider(t, loca_testing.Tenant1, locaProvider2.GetApiEndpoint(), 0)

	// starting LOC-A manager
	lrm, err := NewLOCAManager(
		loca_testing.LocaRMClient,
		loca_testing.LocaRMEventsClient,
		loca_testing.TestReconciliationPeriod,
		&sync.WaitGroup{},
	)
	require.NoError(t, err)

	// starting provisioning cycle
	lrm.Start(nil)
	t.Cleanup(func() {
		// cleaning up Instance reported by 1st LOC-A server
		loca_testing.InstanceCleanupByName(t, loca_testing.LocaRMClient, loca_testing.Tenant1, loca_testing.LocaInstanceID)
		// cleaning up Host reported by 1st LOC-A server
		loca_testing.HostCleanupByUUID(t, loca_testing.LocaRMClient, loca_testing.Tenant1, uuID)

		// cleaning up Instance reported by 2nd LOC-A server
		loca_testing.InstanceCleanupByName(t, loca_testing.LocaRMClient, loca_testing.Tenant1, loca_testing.SecondaryInstanceID)
		// cleaning up Host reported by 2nd LOC-A server
		loca_testing.HostCleanupByUUID(t, loca_testing.LocaRMClient, loca_testing.Tenant1, uuID2)
	})

	// Give enough room to perform a provisioning cycle. Provisioning happens at the very end of the sleep period.
	// Allowing to wait additionally for all provisioning budget, i.e., provisioningWeight [%].
	time.Sleep(loca_testing.TestReconciliationPeriod +
		loca_testing.TestReconciliationPeriod*loca_testing.ProvisioningWeight/loca_testing.TotalWeight)

	// Activating Device on the second LOC-A instance.
	secondaryLOCATS.Override(loca_testing.InventoryDevicesPath, func(writer http.ResponseWriter, request *http.Request) {
		data := &model.DtoDeviceListResponse{Data: &model.DtoDeviceListData{
			Count: 1, Results: []*model.DtoDeviceListElement{
				{
					ID: loca_testing.SecondaryInstanceID, UUID: loca_testing.SecondaryRawUUID,
					SerialNumber: loca_testing.SecondarySerialNumber, Status: loca_testing.StageActive,
				},
			},
		}}

		loca_testing.WriteStructToResponse(writer, request, data, http.StatusOK)
	})

	// Activating OS Instance on the second LOC-A instance.
	secondaryLOCATS.Override(loca_testing.DeploymentInstancesIDPath, func(writer http.ResponseWriter, request *http.Request) {
		data := &model.DtoInstanceQryResponse{Data: &model.DtoInstance{
			ID:    loca_testing.SecondaryInstanceID,
			Nodes: []*model.DtoNode{{SerialNumber: loca_testing.SecondarySerialNumber}},
			Template: &model.DtoTemplate{
				ExtraVars: map[string]any{
					loca_testing.ExtraVarsOSResourceID: osRes.ResourceId,
				},
			},
			Operation: loca_testing.OperationDeploy,
			Stage:     loca_testing.StageInstalled,
			Status:    loca_testing.StatusFinishedSuccessfully,
		}}

		loca_testing.WriteStructToResponse(writer, request, data, http.StatusOK)
	})

	ctx, cancel := context.WithTimeout(context.Background(), loca_testing.TestTimeout5S)
	defer cancel()
	// Refreshing variables (to be used later)
	hostsInv2, err := inventory.ListAllHostsByLOCAProvider(
		ctx, loca_testing.LocaRMClient, loca_testing.Tenant1, locaProvider2.GetApiEndpoint())
	require.NoError(t, err)
	assert.Equal(t, 1, len(hostsInv2))
	instancesInv2, err := inventory.ListAllInstancesByLOCAProvider(
		ctx, loca_testing.LocaRMClient, loca_testing.Tenant1, locaProvider2.GetApiEndpoint())
	require.NoError(t, err)
	assert.Equal(t, 1, len(instancesInv2))

	// Simulating that the Node Agent kicks in for the Instance deployed on the 2nd LOC-A server.
	loca_testing.SimulateNodeAgentAction(t,
		loca_testing.Tenant1, hostsInv2[0].GetResourceId(), instancesInv2[0].GetResourceId())

	// stopping provisioning cycle at the very end of this UT
	t.Cleanup(func() { lrm.Stop() })
	// allowing to perform one more cycle
	time.Sleep(loca_testing.TestReconciliationPeriod)

	// There should be created only one Host and one Instance per Provider.
	// Checking if, for the first LOC-A instance, the Host's Current State, Onboarding Status,
	// and Onboarding Status Indicator are updated and correspond to 'staged'. Host Status and
	// Host Status Indicator are not set - Node Agent is not running.
	loca_testing.AssertHost(t, loca_testing.Tenant1, locaProvider1.GetApiEndpoint(), loca_testing.LocaDeviceSN, uuID,
		computev1.HostState_HOST_STATE_UNSPECIFIED, computev1.HostState_HOST_STATE_ONBOARDED,
		loca_status.DeviceStatusStaged.Status, loca_status.DeviceStatusStaged.StatusIndicator,
		inv_status.DefaultHostStatus, statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)

	// Checking if, for the first LOC-A instance, the Instance's Current State, Provisioning Status,
	// and Provisioning Status Indicator are updated and correspond to 'Deploy' operation which 'Failed'
	// at stage 'instance post-configured'. Instance Status and Instance Status Indicator are not set -
	// Node Agent is not running.
	loca_testing.AssertInstance(t, loca_testing.Tenant1, locaProvider1.GetApiEndpoint(), loca_testing.LocaInstanceID,
		computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED, computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED,
		loca_status.InstanceStatusInstancePostconfiguredFailed.Status,
		loca_status.InstanceStatusInstancePostconfiguredFailed.StatusIndicator,
		inv_status.DefaultInstanceStatus, statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)

	// Checking if, for the second LOC-A instance, the Host Current State, Onboarding Status,
	// and Onboarding Status Indicator are updated and correspond to 'active' status.
	// Host Status and Host Status Indicator are updated by the Node Agent and correspond to 'Running'/IDLE.
	loca_testing.AssertHost(t, loca_testing.Tenant1, locaProvider2.GetApiEndpoint(), loca_testing.SecondarySerialNumber, uuID2,
		computev1.HostState_HOST_STATE_UNSPECIFIED, computev1.HostState_HOST_STATE_ONBOARDED,
		loca_status.DeviceStatusActive.Status, loca_status.DeviceStatusActive.StatusIndicator,
		loca_testing.HostStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)

	// Checking if, for the second LOC-A instance, the Instance Provisioning Status,
	// and Provisioning Status Indicator are updated and correspond to 'Deploy' operation which succeeded
	// to deploy an Instance. Instance Status and Instance Status Indicator are updated by the Node Agent
	// and correspond to 'Running'/IDLE, Current State is also updated and corresponds to the RUNNING.
	loca_testing.AssertInstance(t, loca_testing.Tenant1, locaProvider2.GetApiEndpoint(), loca_testing.SecondaryInstanceID,
		computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED, computev1.InstanceState_INSTANCE_STATE_RUNNING,
		loca_status.InstanceStatusInstalled.Status, loca_status.InstanceStatusInstalled.StatusIndicator,
		loca_testing.InstanceStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)
}

// This TC verifies top-down onboarding, when Host and Instance are onboarded from the NBI,
// and then onboarded in LOC-A.
func TestTopDownOnboarding(t *testing.T) {
	// Activating LOC-A Mock server to have onboarded Device and deployed OS Instance.
	locaTS.Override(loca_testing.InventoryDevicesPath, loca_testing.ActiveDevice)
	locaTS.Override(loca_testing.DeploymentInstancesIDPath, loca_testing.ProvisionInstanceFunc)

	// adding data of the Host that is going to be added
	uuID := loca_testing.ParseUUID(t, loca_testing.LocaDeviceRawUUID)

	// allowing Host discovery
	HostDiscovery = true

	// creating Lenovo provider
	lenovo := loca_testing.PopulateInventoryWithLOCAProvider(
		t,
		loca_testing.Tenant1,
		loca_testing.DefaultProviderName,
		locaTS.GetURL(),
	)
	// creating Site in Inventory
	site := loca_testing.PopulateInventoryWithSite(t, loca_testing.Tenant1, loca_testing.LocaSiteName)
	locaTS.SeedSiteResourceID(site.GetResourceId())
	// creating Host resource and its components
	host, _, _, _, _, _ := loca_testing.PopulateInventoryWithHostResources(t, loca_testing.Tenant1, lenovo, true)
	// creating OS Resource and Host component resources
	instance, _ := loca_testing.PopulateInventoryWithInstanceAndOSResource(t, []*loca_testing.MockServer{locaTS},
		loca_testing.Tenant1, host, true)

	// Read Hosts from Inventory and make sure there is exactly one Host.
	// Verifying that the Host's Current state is UNSPECIFIED, Desired State is ONBOARDED,
	// Onboarding Status Indicator is UNSPECIFIED and Onboarding Status is empty
	// (as set by Inventory testing helper function). Host Status and Host Status Indicator are not set.
	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaDeviceSN, uuID,
		computev1.HostState_HOST_STATE_ONBOARDED, computev1.HostState_HOST_STATE_UNSPECIFIED,
		inv_status.DefaultHostStatus, statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED,
		inv_status.DefaultHostStatus, statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)

	// Read Instances from Inventory and make sure there is exactly one Instance.
	// Verifying that the Instance's Current State is UNSPECIFIED, Desired State is RUNNING,
	// Provisioning Status Indicator is UNSPECIFIED and Provisioning Status is empty
	// (as set by Inventory testing helper function). Instance Status and Instance Status Indicator are not set.
	loca_testing.AssertInstance(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaInstanceID,
		computev1.InstanceState_INSTANCE_STATE_RUNNING, computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED,
		inv_status.DefaultProvisioningStatus, statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED,
		inv_status.DefaultInstanceStatus, statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)

	// starting LOC-A manager
	lrm, err := NewLOCAManager(
		loca_testing.LocaRMClient,
		loca_testing.LocaRMEventsClient,
		loca_testing.TestReconciliationPeriod,
		&sync.WaitGroup{},
	)
	require.NoError(t, err)

	// starting provisioning cycle
	lrm.Start(nil)
	// stopping provisioning cycle at the very end of the UT
	t.Cleanup(func() { lrm.Stop() })

	// First synchronization is done de-sync with reconciliation cycle.
	time.Sleep(loca_testing.TestReconciliationPeriod / 2)

	// This is to simulate the case when Device and Instance were successfully deployed in LOC-A
	// and the Node Agent kicks in and updates Host Status and Instance Status.
	loca_testing.SimulateNodeAgentAction(t, loca_testing.Tenant1, host.GetResourceId(), instance.GetResourceId())

	// Host and Instance were onboarded in both, LOC-A and Edge Infrastructure Manager (from the NBI).
	// Host Current State, Onboarding Status, and Onboarding Status Indicator should
	// correspond to Device status 'active'. Host Status and its Status Indicator are
	// updated by Node Agent to 'Running'/IDLE.
	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaDeviceSN, uuID,
		computev1.HostState_HOST_STATE_ONBOARDED, computev1.HostState_HOST_STATE_ONBOARDED,
		loca_status.DeviceStatusActive.Status, loca_status.DeviceStatusActive.StatusIndicator,
		loca_testing.HostStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)

	// Instance Provisioning Status, and Provisioning Status Indicator should
	// correspond to Instance status 'Finished successfully' at the stage 'installed' with operation 'Deploy'.
	// Current State is RUNNING as set by Node Agent.
	// Host Status and its Status Indicator are updated by Node Agent to 'Running'/IDLE.
	loca_testing.AssertInstance(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaInstanceID,
		computev1.InstanceState_INSTANCE_STATE_RUNNING, computev1.InstanceState_INSTANCE_STATE_RUNNING,
		loca_status.InstanceStatusInstalled.Status, loca_status.InstanceStatusInstalled.StatusIndicator,
		loca_testing.InstanceStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)
}

// This TC verifies that the Host can NOT be removed from Edge Infrastructure Manager until it has an Instance on top of it.
func TestDeleteHostWithInstance(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	// Starting Mock LOC-A server which does not report any Instances and Hosts
	noResourcesLOCATS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	noResourcesLOCATS.Override(loca_testing.DeploymentInstancesPath, loca_testing.ReturnEmptyResponse)
	noResourcesLOCATS.Override(loca_testing.DeploymentInstancesIDPath, loca_testing.ReturnNoInstanceByInstanceID)
	noResourcesLOCATS.Override(loca_testing.InventoryDevicesPath, loca_testing.ReturnEmptyResponse)
	t.Cleanup(func() { noResourcesLOCATS.StopDummyLOCAServer() })

	// adding data of the Host that is going to be added
	uuID := loca_testing.ParseUUID(t, loca_testing.LocaDeviceRawUUID)

	// allowing Host discovery
	HostDiscovery = true

	// creating Lenovo provider
	lenovo := loca_testing.PopulateInventoryWithLOCAProvider(
		t,
		loca_testing.Tenant1,
		loca_testing.DefaultProviderName,
		noResourcesLOCATS.GetURL(),
	)
	// creating Host resource and its components
	host, _, _, _, _, _ := loca_testing.PopulateInventoryWithHostResources(t, loca_testing.Tenant1, lenovo, false)
	// creating OS Resource and Host component resources
	instance, _ := loca_testing.PopulateInventoryWithInstanceAndOSResource(t, []*loca_testing.MockServer{noResourcesLOCATS},
		loca_testing.Tenant1, host, false)
	host.Instance = instance
	// Bootstrapping the production environment
	loca_testing.BootstrapProductionEnvironment(t, loca_testing.Tenant1, host.GetResourceId(), instance.GetResourceId())

	// setting the Desired state of the Host to be DELETED
	dao.DeleteResource(t, loca_testing.Tenant1, host.GetResourceId())

	// Read Hosts from Inventory and make sure there is exactly one Host.
	// Verifying that Host's Current state is ONBOARDED (matches the production environment value),
	// Desired State is DELETED (as set by Inventory testing helper function),
	// Onboarding Status and its Indicator correspond to the Device status 'active',
	// Host Status and its Indicator are set to 'Running'/IDLE.
	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaDeviceSN, uuID,
		computev1.HostState_HOST_STATE_DELETED, computev1.HostState_HOST_STATE_ONBOARDED,
		loca_status.DeviceStatusActive.Status, loca_status.DeviceStatusActive.StatusIndicator,
		loca_testing.HostStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)

	// Read Instances from Inventory and make sure there is exactly one Instance.
	// Verifying that Instance's Current state is RUNNING (matches the production environment value),
	// Desired State is RUNNING (as set by Inventory testing helper function),
	// Provisioning Status and its Indicator correspond to the 'Finished successfully' status at
	// stage 'installed' with operation 'Deploy', Instance Status and its Indicator are set to 'Running'/IDLE.
	loca_testing.AssertInstance(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaInstanceID,
		computev1.InstanceState_INSTANCE_STATE_RUNNING, computev1.InstanceState_INSTANCE_STATE_RUNNING,
		loca_status.InstanceStatusInstalled.Status, loca_status.InstanceStatusInstalled.StatusIndicator,
		loca_testing.InstanceStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)

	// starting LOC-A manager
	lrm, err := NewLOCAManager(
		loca_testing.LocaRMClient,
		loca_testing.LocaRMEventsClient,
		loca_testing.TestReconciliationPeriod*2,
		&sync.WaitGroup{},
	)
	require.NoError(t, err)

	// starting provisioning cycle
	lrm.Start(nil)
	// stopping provisioning cycle at the very end of the UT
	t.Cleanup(func() { lrm.Stop() })

	// letting synchronization cycle to pass
	time.Sleep(loca_testing.TestReconciliationPeriod)

	// Host should be updated with ERROR status due to Instance residing on it. Host deletion has failed.
	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaDeviceSN, uuID,
		computev1.HostState_HOST_STATE_DELETED, computev1.HostState_HOST_STATE_ONBOARDED,
		util.StatusWaitingOnInstanceRemoval, statusv1.StatusIndication_STATUS_INDICATION_ERROR,
		loca_testing.HostStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)

	// deleting an Instance
	dao.HardDeleteInstance(t, loca_testing.Tenant1, instance.GetResourceId())

	// Waiting for the second half of the reconciliation period and waiting for extra 100 milliseconds
	// to let another synchronization cycle to run and perform its job
	time.Sleep(loca_testing.TestReconciliationPeriod + 100*time.Millisecond)

	// Host should be gone by now.
	loca_testing.RequireIsNotFound(t, loca_testing.Tenant1, host.GetResourceId())
}

// Validates that with multiple providers from multiple tenants the main control loop is not working.
func TestLOCARMErrorsMultipleProviderTenantTick(t *testing.T) {
	*flags.FlagDisableCredentialsManagement = false
	// revoking of credentials should succeed
	auth.AuthServiceFactory = auth.AuthServiceMockFactory(t, false, false, false)

	// adding data of the Host that is going to be added
	uuID := loca_testing.ParseUUID(t, loca_testing.LocaDeviceRawUUID)

	// allowing Host discovery
	HostDiscovery = true

	lenovo := loca_testing.PopulateInventoryWithLOCAProvider(
		t, loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL())
	// LOCA provider tenant2
	loca_testing.PopulateInventoryWithLOCAProvider(
		t, loca_testing.Tenant2, loca_testing.DefaultProviderName, locaTS.GetURL())
	host, _, _, _, _, _ := loca_testing.PopulateInventoryWithHostResources(t, loca_testing.Tenant1, lenovo, true)
	instance, _ := loca_testing.PopulateInventoryWithInstanceAndOSResource(t, []*loca_testing.MockServer{locaTS},
		loca_testing.Tenant1, host, true)
	loca_testing.BootstrapProductionEnvironment(t, loca_testing.Tenant1, host.GetResourceId(), instance.GetResourceId())

	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaDeviceSN, uuID,
		computev1.HostState_HOST_STATE_ONBOARDED, computev1.HostState_HOST_STATE_ONBOARDED,
		loca_status.DeviceStatusActive.Status, loca_status.DeviceStatusActive.StatusIndicator,
		loca_testing.HostStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)

	// setting Desired state of the Host to be UNTRUSTED, current state should not change due to LOCA-RM.
	loca_testing.InvalidateHost(t, loca_testing.Tenant1, host.GetResourceId())

	lrm, err := NewLOCAManager(
		loca_testing.LocaRMClient,
		loca_testing.LocaRMEventsClient,
		loca_testing.TestReconciliationPeriod,
		&sync.WaitGroup{},
	)
	require.NoError(t, err)

	lrm.Start(nil)
	t.Cleanup(func() { lrm.Stop() })

	// letting another synchronization and reconciliation cycles to pass.
	// Host is invalidated during synchronization phase
	time.Sleep(loca_testing.TestReconciliationPeriod + 10*time.Millisecond)

	// read Hosts from Inventory - no changes apart from moving to the desired state UNTRUSTED.
	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaDeviceSN, uuID,
		computev1.HostState_HOST_STATE_UNTRUSTED, computev1.HostState_HOST_STATE_ONBOARDED,
		loca_status.DeviceStatusActive.Status, loca_status.DeviceStatusActive.StatusIndicator,
		loca_testing.HostStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)
}

// This TC verifies that the Host is being validated by event received from the NB, i.e., once synchronization
// and reconciliation phases are executed.
func TestLOCARMErrorsMultipleProviderTenantEvent(t *testing.T) {
	*flags.FlagDisableCredentialsManagement = false
	// revoking of credentials should succeed
	auth.AuthServiceFactory = auth.AuthServiceMockFactory(t, false, false, false)

	// adding data of the Host that is going to be added
	uuID := loca_testing.ParseUUID(t, loca_testing.LocaDeviceRawUUID)

	// allowing Host discovery
	HostDiscovery = true

	// creating Lenovo provider
	lenovo := loca_testing.PopulateInventoryWithLOCAProvider(
		t, loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL())
	// LOCA provider tenant2
	loca_testing.PopulateInventoryWithLOCAProvider(
		t, loca_testing.Tenant2, loca_testing.DefaultProviderName, locaTS.GetURL())
	host, _, _, _, _, _ := loca_testing.PopulateInventoryWithHostResources(t, loca_testing.Tenant1, lenovo, true)
	instance, _ := loca_testing.PopulateInventoryWithInstanceAndOSResource(t, []*loca_testing.MockServer{locaTS},
		loca_testing.Tenant1, host, true)

	// bootstrapping production environment
	loca_testing.BootstrapProductionEnvironment(t, loca_testing.Tenant1, host.GetResourceId(), instance.GetResourceId())

	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaDeviceSN, uuID,
		computev1.HostState_HOST_STATE_ONBOARDED, computev1.HostState_HOST_STATE_ONBOARDED,
		loca_status.DeviceStatusActive.Status, loca_status.DeviceStatusActive.StatusIndicator,
		loca_testing.HostStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)

	lrm, err := NewLOCAManager(
		loca_testing.LocaRMClient,
		loca_testing.LocaRMEventsClient,
		loca_testing.TestReconciliationPeriod*2,
		&sync.WaitGroup{},
	)
	require.NoError(t, err)

	lrm.Start(nil)
	t.Cleanup(func() { lrm.Stop() })

	// letting the synchronization phase to execute
	time.Sleep(loca_testing.TestReconciliationPeriod + 10*time.Millisecond)

	// read Host from Inventory - no changes, not even the full reconciler works with multiple providers from multiple tenants.
	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaDeviceSN, uuID,
		computev1.HostState_HOST_STATE_ONBOARDED, computev1.HostState_HOST_STATE_ONBOARDED,
		loca_status.DeviceStatusActive.Status, loca_status.DeviceStatusActive.StatusIndicator,
		loca_testing.HostStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)

	// setting Desired state of the Host to be UNTRUSTED, current state should not change due to LOCA-RM.
	loca_testing.InvalidateHost(t, loca_testing.Tenant1, host.GetResourceId())

	// letting the reconciliation event to be processed
	time.Sleep(110 * time.Millisecond)

	// read Hosts from Inventory - no changes apart from moving to the desired state UNTRUSTED.
	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), loca_testing.LocaDeviceSN, uuID,
		computev1.HostState_HOST_STATE_UNTRUSTED, computev1.HostState_HOST_STATE_ONBOARDED,
		loca_status.DeviceStatusActive.Status, loca_status.DeviceStatusActive.StatusIndicator,
		loca_testing.HostStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)
}

// This TC verifies the case when LOC-A fails to remove the Host.
func TestRemoveHostInSynchronizationPhaseFail(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	*flags.FlagDisableCredentialsManagement = false

	// revoking of credentials should succeed
	auth.AuthServiceFactory = auth.AuthServiceMockFactory(t, false, false, false)

	// allowing Host discovery
	HostDiscovery = true

	testLocaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	testLocaTS.Override(loca_testing.InventoryDevicesRemovePath, loca_testing.FailedRemoveDevicesFunc)
	t.Cleanup(func() {
		testLocaTS.StopDummyLOCAServer()
	})

	// creating Lenovo provider
	lenovo := loca_testing.PopulateInventoryWithLOCAProvider(
		t, loca_testing.Tenant1, loca_testing.DefaultProviderName, testLocaTS.GetURL())
	// creating Host resource and its components
	host, _, _, _, _, _ := loca_testing.PopulateInventoryWithHostResources(t, loca_testing.Tenant1, lenovo, true)

	// bootstrapping Host statuses to correspond to the production environment
	loca_testing.HostProvisioned(t, loca_testing.Tenant1, host.GetResourceId())

	// Setting Desired state of the Host to be DELETED
	dao.DeleteResource(t, loca_testing.Tenant1, host.GetResourceId())

	// ensuring that the Host Desired State is DELETED, Current State is ONBOARDED (as in production environment),
	// Onboarding Status and Onboarding Status indicator correspond to 'Device is active' status,
	// and Host Status and its Indicator are empty.
	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), host.GetSerialNumber(), host.GetUuid(),
		computev1.HostState_HOST_STATE_DELETED, computev1.HostState_HOST_STATE_ONBOARDED,
		loca_status.DeviceStatusActive.Status, loca_status.DeviceStatusActive.StatusIndicator,
		inv_status.DefaultHostStatus, statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)

	// starting LOC-A manager
	lrm, err := NewLOCAManager(
		loca_testing.LocaRMClient,
		loca_testing.LocaRMEventsClient,
		loca_testing.TestReconciliationPeriod,
		&sync.WaitGroup{},
	)
	require.NoError(t, err)

	// starting provisioning cycle
	lrm.Start(nil)
	// stopping provisioning cycle
	t.Cleanup(func() { lrm.Stop() })

	// letting another synchronization and reconciliation cycles to pass.
	// Host is invalidated during synchronization
	time.Sleep(loca_testing.TestReconciliationPeriod)

	// read Host from Inventory and make sure that both states remained the same
	// Onboarding Status and its Status Indicator report that Device has failed to be removed from LOC-A,
	// and Host Status and its Indicator are empty.
	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), host.GetSerialNumber(), host.GetUuid(),
		computev1.HostState_HOST_STATE_DELETED, computev1.HostState_HOST_STATE_ONBOARDED,
		util.StatusFailedToRemoveHostFromLOCA, statusv1.StatusIndication_STATUS_INDICATION_ERROR,
		inv_status.DefaultHostStatus, statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)
}

// This TC verifies the case when LOC-A RM removes the Host from LOC-A.
func TestRemoveHostInSynchronizationPhase(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	*flags.FlagDisableCredentialsManagement = false

	// revoking of credentials should succeed
	auth.AuthServiceFactory = auth.AuthServiceMockFactory(t, false, false, false)

	// allowing Host discovery
	HostDiscovery = true

	testLocaTS, err := loca_testing.StartDummyLOCAServer()
	assert.NoError(t, err)
	testLocaTS.Override(loca_testing.DeploymentInstancesPath, loca_testing.ReturnEmptyResponse, http.MethodGet)
	t.Cleanup(func() {
		testLocaTS.StopDummyLOCAServer()
	})

	// creating Lenovo provider
	lenovo := loca_testing.PopulateInventoryWithLOCAProvider(
		t, loca_testing.Tenant1, loca_testing.DefaultProviderName, testLocaTS.GetURL())
	// creating Host resource and its components
	host, _, _, _, _, _ := loca_testing.PopulateInventoryWithHostResources(t, loca_testing.Tenant1, lenovo, false)

	// bootstrapping Host statuses to correspond to the production environment
	loca_testing.HostProvisioned(t, loca_testing.Tenant1, host.GetResourceId())

	// Setting Desired state of the Host to be DELETED
	dao.DeleteResource(t, loca_testing.Tenant1, host.GetResourceId())

	// ensuring that the Host Desired State is DELETED, Current State is ONBOARDED (as in production environment),
	// Onboarding Status and Onboarding Status indicator correspond to 'Device is active' status,
	// and Host Status and its Indicator are empty.
	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovo.GetApiEndpoint(), host.GetSerialNumber(), host.GetUuid(),
		computev1.HostState_HOST_STATE_DELETED, computev1.HostState_HOST_STATE_ONBOARDED,
		loca_status.DeviceStatusActive.Status, loca_status.DeviceStatusActive.StatusIndicator,
		inv_status.DefaultHostStatus, statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)

	// starting LOC-A manager
	lrm, err := NewLOCAManager(
		loca_testing.LocaRMClient,
		loca_testing.LocaRMEventsClient,
		loca_testing.TestReconciliationPeriod,
		&sync.WaitGroup{},
	)
	require.NoError(t, err)

	// starting provisioning cycle
	lrm.Start(nil)
	// stopping provisioning cycle
	t.Cleanup(func() { lrm.Stop() })

	// simulate the removal task in running state
	time.Sleep(2 * loca_testing.TestReconciliationPeriod)

	// switching the device removal task to successful state
	testLocaTS.Override(loca_testing.InventoryDevicesPath, loca_testing.DeletedDevice)
	testLocaTS.Override(loca_testing.TaskManagementTasksIDPath, loca_testing.SuccessfulGetTask)

	// letting another synchronization and reconciliation cycles to pass.
	// Host is invalidated during synchronization
	time.Sleep(loca_testing.TestReconciliationPeriod)

	// read Host from Inventory and make sure that both states remained the same
	loca_testing.RequireIsNotFound(t, loca_testing.Tenant1, host.GetResourceId())
}

func TestLOCARM_synchronizeProvider_whenProviderIsNilShouldFailToInitializeClient(t *testing.T) {
	assertHook := util.NewTestAssertHook("Failed to initialize LOC-A client for endpoint")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}
	lrm := LOCARM{}

	lrm.synchronizeProvider(context.Background(), loca_testing.Tenant1, nil)
	assertHook.Assert(t)
}

func TestLOCARM_filterEvent_whenEventIsWithoutResourceKindThenShouldReturnError(t *testing.T) {
	assertHook := util.NewTestAssertHook("Unknown resource kind")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}
	lrm := LOCARM{}

	lrm.filterEvent(&inv_v1.SubscribeEventsResponse{})
	assertHook.Assert(t)
}

func TestLOCARM_reconcileResource_whenResourceIsWithoutResourceKindThenShouldReturnError(t *testing.T) {
	assertHook := util.NewTestAssertHook("Unknown resource kind")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}
	lrm := LOCARM{}

	lrm.ReconcileResource(loca_testing.Tenant1, "test")
	assertHook.Assert(t)
}

func TestLOCARM_reconcileResource_whenTheresNoReconcilerForResourceThenErrorShouldBeReturned(t *testing.T) {
	assertHook := util.NewTestAssertHook("Controller for resource doesn't exists")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}
	lrm := LOCARM{}

	lrm.ReconcileResource(loca_testing.Tenant1, "user-test")
	assertHook.Assert(t)
}

func TestLOCARM_handleSynchronizationCycle_whenNoProvidersConfiguredShouldSkipReconcile(t *testing.T) {
	assertHook := util.NewTestAssertHook("No LOCA providers found, skip")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}
	dao := inv_testing.NewInvResourceDAOOrFail(t)

	lrm := LOCARM{
		invClient:            dao.GetAPIClient(),
		reconciliationPeriod: time.Second,
	}

	err := lrm.handleSynchronizationCycle()
	assertHook.Assert(t)
	assert.NoError(t, err)
}

func TestLOCARM_handleSynchronizationCycle_whenErrorOccursThenItShouldBeReturned(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)

	lrm := LOCARM{
		invClient:            dao.GetAPIClient(),
		reconciliationPeriod: time.Duration(0),
	}

	err := lrm.handleSynchronizationCycle()
	assert.ErrorContains(t, err, "context deadline exceeded")
}

func TestLOCARM_UpdateHosts_whenErrorOccursShouldUpstreamIt(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)

	lrm := LOCARM{
		invClient: dao.GetAPIClient(),
	}

	lc := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)
	locaTS.Override(loca_testing.InventoryDevicesPath, func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusInternalServerError)
	})

	err := lrm.UpdateHosts(context.Background(), lc, loca_testing.Tenant1, &provider_v1.ProviderResource{})
	assert.ErrorContains(t, err, "[500]")
}

func TestLOCARM_processDeviceEntry_whenInvalidUuidProvidedThenErrorShouldBeReturned(t *testing.T) {
	lrm := LOCARM{}

	host, err := lrm.processDeviceEntry(&model.DtoDeviceListElement{UUID: "not-a-uuid"})
	assert.ErrorContains(t, err, "Failed to parse UUID")
	assert.Zero(t, host)
}

func TestLOCARM_processDeviceEntry_whenInvalidSerialNumberIsProvidedThenErrorShouldBeReturned(t *testing.T) {
	lrm := LOCARM{}

	host, err := lrm.processDeviceEntry(&model.DtoDeviceListElement{UUID: uuid.NewString()})
	assert.ErrorContains(t, err, "Empty Host UUID or Serial Number obtained")
	assert.Zero(t, host)
}
