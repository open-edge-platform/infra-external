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

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	computev1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/compute/v1"
	inv_v1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	provider_v1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/provider/v1"
	statusv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/status/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/auth"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/flags"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	inv_testing "github.com/open-edge-platform/infra-core/inventory/v2/pkg/testing"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/loca"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/secrets"
	loca_status "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/status"
	loca_testing "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/testing"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/util"
	rec_v2 "github.com/open-edge-platform/orch-library/go/pkg/controller/v2"
)

const clientName = "TestLOCARMReconcilerInventoryClient"

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

	loca_testing.StartMockSecretService()
	err = secrets.Init(context.Background(), []string{loca_testing.LocaSecret})
	if err != nil {
		panic(err)
	}
	locaTS := loca_testing.StartTestingEnvironment(policyPath, migrationsDir, clientName)
	loca_testing.StartMockSecretService()
	run := m.Run() // run all tests
	loca_testing.StopTestingEnvironment(locaTS, clientName)

	os.Exit(run)
}

func TestInvalidateHost(t *testing.T) {
	// enabling revoking of credentials
	*flags.FlagDisableCredentialsManagement = false
	// revoking of credentials should succeed
	auth.AuthServiceFactory = auth.AuthServiceMockFactory(t, false, false, false)

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() {
		locaTS.StopDummyLOCAServer()
	})

	lenovoProvider := loca_testing.PopulateInventoryWithLOCAProvider(
		t, loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL())
	//nolint:dogsled // no need to manipulate with additional resources
	host, _, _, _, _, _ := loca_testing.PopulateInventoryWithHostResources(
		t,
		loca_testing.Tenant1,
		lenovoProvider,
		true,
	)

	hostReconciler := NewHostReconciler(
		true, inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient())
	require.NotNil(t, hostReconciler)

	locaHostReconciler := rec_v2.NewController[ReconcilerID](
		hostReconciler.Reconcile,
		rec_v2.WithParallelism(1),
	)

	err = locaHostReconciler.Reconcile(NewReconcilerID(host.GetTenantId(), host.GetResourceId()))
	require.NoError(t, err, "Reconciliation failed")
	// letting the reconciler to perform its job
	time.Sleep(100 * time.Millisecond)

	// checking the Host - no update should happen
	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovoProvider.GetApiEndpoint(), host.GetSerialNumber(), host.GetUuid(),
		computev1.HostState_HOST_STATE_ONBOARDED, // Desired state set by the testing helper function
		computev1.HostState_HOST_STATE_UNSPECIFIED,
		// Onboarding status is not set - main control loop is not running
		"", statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED,
		// Host Status and Status Indicator are not yet set
		"", statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)

	// setting the Desired state of the Host to be UNTRUSTED
	loca_testing.InvalidateHost(t, loca_testing.Tenant1, host.GetResourceId())

	err = locaHostReconciler.Reconcile(NewReconcilerID(host.GetTenantId(), host.GetResourceId()))
	require.NoError(t, err, "Reconciliation failed")
	// letting the reconciler to perform its job
	time.Sleep(100 * time.Millisecond)

	// Host status should be updated - invalidated status is expected
	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovoProvider.GetApiEndpoint(), host.GetSerialNumber(), host.GetUuid(),
		computev1.HostState_HOST_STATE_UNTRUSTED, computev1.HostState_HOST_STATE_UNTRUSTED,
		loca_status.HostStatusUnknown.Status, loca_status.HostStatusUnknown.StatusIndicator,
		loca_status.HostStatusInvalidated.Status, loca_status.HostStatusInvalidated.StatusIndicator)
}

func TestHostReconcile(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	*flags.FlagDisableCredentialsManagement = false
	// revoking of credentials should succeed
	auth.AuthServiceFactory = auth.AuthServiceMockFactory(t, false, false, false)

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() {
		locaTS.StopDummyLOCAServer()
	})
	locaTS.Override(loca_testing.InventoryDevicesPath, loca_testing.ReturnEmptyResponse)

	lenovoProvider := loca_testing.PopulateInventoryWithLOCAProvider(
		t, loca_testing.Tenant1, loca_testing.DefaultProviderName, locaTS.GetURL())
	host, hostNic, nicIP, hostStorage, hostUsb, hostGpu := loca_testing.PopulateInventoryWithHostResources(
		t,
		loca_testing.Tenant1,
		lenovoProvider,
		false,
	)

	hostReconciler := NewHostReconciler(
		true, inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient())
	require.NotNil(t, hostReconciler)

	locaHostReconciler := rec_v2.NewController[ReconcilerID](
		hostReconciler.Reconcile,
		rec_v2.WithParallelism(1),
	)

	err = locaHostReconciler.Reconcile(NewReconcilerID(host.GetTenantId(), host.GetResourceId()))
	require.NoError(t, err, "Reconciliation failed")
	// letting the reconciler to perform its job
	time.Sleep(120 * time.Millisecond)

	// checking the Host
	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovoProvider.GetApiEndpoint(), host.GetSerialNumber(), host.GetUuid(),
		computev1.HostState_HOST_STATE_ONBOARDED, // Desired state set by the testing helper function
		computev1.HostState_HOST_STATE_UNSPECIFIED,
		// Onboarding status and Status Indicator are not set - main control loop is not running
		"", statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED,
		// Host Status and Status Indicator are not set - irrelevant for this test
		"", statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)
	dao.DeleteResource(t, loca_testing.Tenant1, host.GetResourceId())

	err = locaHostReconciler.Reconcile(NewReconcilerID(host.GetTenantId(), host.GetResourceId()))
	require.NoError(t, err, "Reconciliation failed")
	// letting the reconciler to perform its job
	time.Sleep(200 * time.Millisecond)

	loca_testing.RequireIsNotFound(t, loca_testing.Tenant1, host.GetResourceId())
	loca_testing.RequireIsNotFound(t, loca_testing.Tenant1, hostNic.GetResourceId())
	loca_testing.RequireIsNotFound(t, loca_testing.Tenant1, hostStorage.GetResourceId())
	loca_testing.RequireIsNotFound(t, loca_testing.Tenant1, hostUsb.GetResourceId())
	loca_testing.RequireIsNotFound(t, loca_testing.Tenant1, hostGpu.GetResourceId())
	loca_testing.RequireIsNotFound(t, loca_testing.Tenant1, nicIP.GetResourceId())
}

// This TC verifies that the Host with different from LOC-A provider (or no provider) would not be reconciled.
func TestHostNoProviderReconcile(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	host := dao.CreateHost(t, loca_testing.Tenant1)

	hostReconciler := NewHostReconciler(
		true, inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient())
	require.NotNil(t, hostReconciler)

	locaInstanceReconciler := rec_v2.NewController[ReconcilerID](
		hostReconciler.Reconcile,
		rec_v2.WithParallelism(1),
	)

	// checking the Host
	loca_testing.AssertHost(t, loca_testing.Tenant1, "", host.GetSerialNumber(), host.GetUuid(),
		computev1.HostState_HOST_STATE_ONBOARDED, // Desired state set by the testing helper function
		computev1.HostState_HOST_STATE_UNSPECIFIED,
		// Onboarding status and Status Indicator are not set - main control loop is not running
		"", statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED,
		// Host Status and Status Indicator are not set - irrelevant for this test
		"", statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)

	err := locaInstanceReconciler.Reconcile(NewReconcilerID(host.GetTenantId(), host.GetResourceId()))
	require.NoError(t, err, "Reconciliation failed")
	// letting the reconciler to perform its job
	time.Sleep(100 * time.Millisecond)

	// checking the Host - should be no changes
	loca_testing.AssertHost(t, loca_testing.Tenant1, "", host.GetSerialNumber(), host.GetUuid(),
		computev1.HostState_HOST_STATE_ONBOARDED,
		computev1.HostState_HOST_STATE_UNSPECIFIED,
		"", statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED,
		"", statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)
}

// This TC verifies that the reconciliation is skipped when the Desired state of the Host is equal to Current state.
func TestHostReconciliationSkipped(t *testing.T) {
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() {
		locaTS.StopDummyLOCAServer()
	})

	lenovoProvider := loca_testing.PopulateInventoryWithLOCAProvider(
		t,
		loca_testing.Tenant1,
		loca_testing.DefaultProviderName,
		locaTS.GetURL(),
	)
	//nolint:dogsled // no need in additional Host-related resource in this unit test
	host, _, _, _, _, _ := loca_testing.PopulateInventoryWithHostResources(
		t,
		loca_testing.Tenant1,
		lenovoProvider,
		true,
	)

	hostReconciler := NewHostReconciler(
		true, inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient())
	require.NotNil(t, hostReconciler)

	locaHostReconciler := rec_v2.NewController[ReconcilerID](
		hostReconciler.Reconcile,
		rec_v2.WithParallelism(1),
	)

	// setting Desired state to be equal to Current state
	_, err = inv_testing.TestClients[inv_testing.APIClient].GetTenantAwareInventoryClient().Update(
		context.Background(),
		loca_testing.Tenant1,
		host.GetResourceId(),
		&fieldmaskpb.FieldMask{Paths: []string{computev1.HostResourceFieldDesiredState}},
		&inv_v1.Resource{
			Resource: &inv_v1.Resource_Host{
				Host: &computev1.HostResource{
					DesiredState: host.GetCurrentState(),
				},
			},
		},
	)
	require.NoError(t, err)

	// checking the Host
	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovoProvider.GetApiEndpoint(), host.GetSerialNumber(), host.GetUuid(),
		computev1.HostState_HOST_STATE_UNSPECIFIED,
		computev1.HostState_HOST_STATE_UNSPECIFIED,
		// Onboarding status and Status Indicator are not set - main control loop is not running
		"", statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED,
		// Host Status and Status Indicator are not set - irrelevant for this test
		"", statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)

	err = locaHostReconciler.Reconcile(NewReconcilerID(host.GetTenantId(), host.GetResourceId()))
	require.NoError(t, err, "Reconciliation failed")
	// letting the reconciler to perform its job
	time.Sleep(100 * time.Millisecond)

	// checking the Host - should be no change
	loca_testing.AssertHost(t, loca_testing.Tenant1, lenovoProvider.GetApiEndpoint(), host.GetSerialNumber(), host.GetUuid(),
		computev1.HostState_HOST_STATE_UNSPECIFIED,
		computev1.HostState_HOST_STATE_UNSPECIFIED,
		"", statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED,
		"", statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)
}

func TestHostIsNotReconciledUntilInstanceIsNotRemoved(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() {
		locaTS.StopDummyLOCAServer()
	})
	locaTS.Override(loca_testing.InventoryDevicesPath, loca_testing.ReturnEmptyResponse)

	lenovoProvider := loca_testing.PopulateInventoryWithLOCAProvider(
		t,
		loca_testing.Tenant1,
		loca_testing.DefaultProviderName,
		locaTS.GetURL(),
	)
	//nolint:dogsled // no need in additional Host-related resource in this unit test
	host, _, _, _, _, _ := loca_testing.PopulateInventoryWithHostResources(
		t,
		loca_testing.Tenant1,
		lenovoProvider,
		false,
	)
	instance, _ := loca_testing.PopulateInventoryWithInstanceAndOSResource(t, []*loca_testing.MockServer{locaTS},
		loca_testing.Tenant1, host, false)
	host.Instance = instance

	hostReconciler := NewHostReconciler(
		true, inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient())
	require.NotNil(t, hostReconciler)

	locaHostReconciler := rec_v2.NewController[ReconcilerID](
		hostReconciler.Reconcile,
		rec_v2.WithParallelism(1),
	)

	// checking the Host
	loca_testing.AssertHost(t, loca_testing.Tenant1, locaTS.GetURL(), host.GetSerialNumber(), host.GetUuid(),
		computev1.HostState_HOST_STATE_ONBOARDED, // Desired state set by the testing helper function
		computev1.HostState_HOST_STATE_UNSPECIFIED,
		// Onboarding status and Status Indicator are not set - main control loop is not running
		"", statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED,
		// Host Status and Status Indicator are not set - irrelevant for this test
		"", statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)

	// Setting Desired state of the Host to be DELETED
	dao.DeleteResource(t, loca_testing.Tenant1, host.GetResourceId())

	// performing reconciliation
	err = locaHostReconciler.Reconcile(NewReconcilerID(host.GetTenantId(), host.GetResourceId()))
	require.NoError(t, err, "Reconciliation failed")
	// letting the reconciler to perform its job
	time.Sleep(100 * time.Millisecond)

	// checking the Host. Host is not reconciled due to Instance being present on Host.
	// The only changes should be in Onboarding Status.
	loca_testing.AssertHost(t, loca_testing.Tenant1, locaTS.GetURL(), host.GetSerialNumber(), host.GetUuid(),
		computev1.HostState_HOST_STATE_DELETED,
		computev1.HostState_HOST_STATE_UNSPECIFIED,
		// Onboarding Status and Status Indicator were updated by the reconciler
		util.StatusWaitingOnInstanceRemoval, statusv1.StatusIndication_STATUS_INDICATION_ERROR,
		// Host Status and Status Indicator are not touched
		"", statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)

	// removing instance completely from Inventory. Host should now be freed up
	dao.HardDeleteInstance(t, loca_testing.Tenant1, instance.GetResourceId())
	loca_testing.RequireIsNotFound(t, loca_testing.Tenant1, instance.GetResourceId())

	// performing reconciliation
	err = locaHostReconciler.Reconcile(NewReconcilerID(host.GetTenantId(), host.GetResourceId()))
	require.NoError(t, err, "Reconciliation failed")
	// letting the reconciler to perform its job
	time.Sleep(3 * time.Second)

	loca_testing.RequireIsNotFound(t, loca_testing.Tenant1, host.GetResourceId())
}

func TestRemoveHostInReconciliation(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	*flags.FlagDisableCredentialsManagement = false
	// revoking of credentials should succeed
	auth.AuthServiceFactory = auth.AuthServiceMockFactory(t, false, false, false)

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(locaTS.StopDummyLOCAServer)

	lenovoProvider := loca_testing.PopulateInventoryWithLOCAProvider(
		t,
		loca_testing.Tenant1,
		loca_testing.DefaultProviderName,
		locaTS.GetURL(),
	)
	//nolint:dogsled // no need in additional Host-related resource in this unit test
	host, _, _, _, _, _ := loca_testing.PopulateInventoryWithHostResources(
		t,
		loca_testing.Tenant1,
		lenovoProvider,
		false,
	)

	hostReconciler := NewHostReconciler(
		true, inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient())
	require.NotNil(t, hostReconciler)

	locaHostReconciler := rec_v2.NewController[ReconcilerID](
		hostReconciler.Reconcile,
		rec_v2.WithParallelism(1),
	)

	// checking the Host
	loca_testing.AssertHost(t, loca_testing.Tenant1, locaTS.GetURL(), host.GetSerialNumber(), host.GetUuid(),
		computev1.HostState_HOST_STATE_ONBOARDED, // Desired state set by the testing helper function
		computev1.HostState_HOST_STATE_UNSPECIFIED,
		// Onboarding status and Status Indicator are not set - main control loop is not running
		"", statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED,
		// Host Status and Status Indicator are not set - irrelevant for this test
		"", statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)

	// Setting Desired state of the Host to be DELETED
	dao.DeleteResource(t, loca_testing.Tenant1, host.GetResourceId())

	// performing reconciliation
	err = locaHostReconciler.Reconcile(NewReconcilerID(host.GetTenantId(), host.GetResourceId()))
	require.NoError(t, err, "Reconciliation failed")

	// simulate the device removal task in running state
	time.Sleep(250 * time.Millisecond)

	// switching the device removal task to successful state
	locaTS.Override(loca_testing.InventoryDevicesPath, loca_testing.DeletedDevice)
	locaTS.Override(loca_testing.TaskManagementTasksIDPath, loca_testing.SuccessfulGetTask)

	// letting the reconciler to perform its job assuming that reconciler will retry
	time.Sleep(250 * time.Millisecond)

	// checking the Host, it should be gone
	loca_testing.RequireIsNotFound(t, loca_testing.Tenant1, host.GetResourceId())
}

func TestHostReconcileFailedToRemoveHost(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	// Device remove attempt should fail
	locaTS.Override(loca_testing.InventoryDevicesRemovePath, loca_testing.FailedRemoveDevicesFunc)
	t.Cleanup(locaTS.StopDummyLOCAServer)

	lenovoProvider := loca_testing.PopulateInventoryWithLOCAProvider(
		t,
		loca_testing.Tenant1,
		loca_testing.DefaultProviderName,
		locaTS.GetURL(),
	)
	//nolint:dogsled // no need in additional Host-related resource in this unit test
	host, _, _, _, _, _ := loca_testing.PopulateInventoryWithHostResources(
		t,
		loca_testing.Tenant1,
		lenovoProvider,
		true,
	)

	hostReconciler := NewHostReconciler(
		true, inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient())
	require.NotNil(t, hostReconciler)

	locaHostReconciler := rec_v2.NewController[ReconcilerID](
		hostReconciler.Reconcile,
		rec_v2.WithParallelism(1),
	)

	// checking the Host
	loca_testing.AssertHost(t, loca_testing.Tenant1, locaTS.GetURL(), host.GetSerialNumber(), host.GetUuid(),
		computev1.HostState_HOST_STATE_ONBOARDED, // Desired state set by the testing helper function
		computev1.HostState_HOST_STATE_UNSPECIFIED,
		// Onboarding status and Status Indicator are not set - main control loop is not running
		"", statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED,
		// Host Status and Status Indicator are not set - irrelevant for this test
		"", statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)

	// Setting Desired state of the Host to be DELETED
	dao.DeleteResource(t, loca_testing.Tenant1, host.GetResourceId())

	// performing reconciliation
	err = locaHostReconciler.Reconcile(NewReconcilerID(host.GetTenantId(), host.GetResourceId()))
	require.NoError(t, err, "Reconciliation failed")
	// letting the reconciler to perform its job
	time.Sleep(100 * time.Millisecond)

	// checking the Host. Host is not reconciled due to Instance being present on Host.
	// The only changes should be in Onboarding Status.
	loca_testing.AssertHost(t, loca_testing.Tenant1, locaTS.GetURL(), host.GetSerialNumber(), host.GetUuid(),
		computev1.HostState_HOST_STATE_DELETED,
		computev1.HostState_HOST_STATE_UNSPECIFIED,
		// Onboarding Status and Status Indicator were updated by the reconciler
		util.StatusFailedToRemoveHostFromLOCA, statusv1.StatusIndication_STATUS_INDICATION_ERROR,
		// Host Status and Status Indicator are not touched
		"", statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)
}

func TestHostReconciler_invalidateHost_whenUnableToRevokeHostsCredentialsShouldRetryRequest(t *testing.T) {
	assertHook := util.NewTestAssertHook("Retry reconciliation")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	hr := NewHostReconciler(false, inv_testing.NewInvResourceDAOOrFail(t).GetAPIClient())
	host := &computev1.HostResource{Uuid: uuid.NewString(), TenantId: loca_testing.Tenant1}
	req := rec_v2.Request[ReconcilerID]{
		ID: "test",
	}

	hr.invalidateHost(context.TODO(), req, host)
	assertHook.Assert(t)
}

func TestHostReconciler_deleteHost_whenUnableToCreateClientShouldReturnError(t *testing.T) {
	assertHook := util.NewTestAssertHook("Failed to initialize LOC-A client for endpoint")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	hr := NewHostReconciler(false, inv_testing.NewInvResourceDAOOrFail(t).GetAPIClient())
	host := &computev1.HostResource{Uuid: uuid.NewString(), TenantId: loca_testing.Tenant1}
	req := rec_v2.Request[ReconcilerID]{
		ID: "test",
	}

	hr.deleteHost(context.TODO(), req, host)
	assertHook.Assert(t)
}

func TestHostReconciler_deleteHost_whenTaskTrackerIsNotAbleToCheckTaskThenErrorShouldBeReturned(t *testing.T) {
	assertHook := util.NewTestAssertHook("Failed to check if a task is running for Host")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() {
		locaTS.StopDummyLOCAServer()
	})
	locaTS.Override(loca_testing.TaskManagementTasksIDPath, func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusInternalServerError)
	})

	loca_testing.StartMockSecretService()
	hr := NewHostReconciler(false, inv_testing.NewInvResourceDAOOrFail(t).GetAPIClient())
	host := &computev1.HostResource{
		Uuid:     uuid.NewString(),
		TenantId: loca_testing.Tenant1,
		Provider: &provider_v1.ProviderResource{ApiEndpoint: locaTS.GetURL(), ApiCredentials: []string{loca_testing.LocaSecret}},
	}
	req := rec_v2.Request[ReconcilerID]{
		ID: "test",
	}
	err = loca.DefaultTaskTracker.TrackTask(host.GetResourceId(), []string{"task-id"})
	assert.NoError(t, err)

	hr.deleteHost(context.TODO(), req, host)
	assertHook.Assert(t)
}
