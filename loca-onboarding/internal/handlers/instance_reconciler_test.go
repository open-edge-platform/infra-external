// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	computev1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/compute/v1"
	provider_v1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/provider/v1"
	statusv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/status/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/auth"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/flags"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	inv_status "github.com/open-edge-platform/infra-core/inventory/v2/pkg/status"
	inv_testing "github.com/open-edge-platform/infra-core/inventory/v2/pkg/testing"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/model"
	loca_status "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/status"
	loca_testing "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/testing"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/util"
	rec_v2 "github.com/open-edge-platform/orch-library/go/pkg/controller/v2"
)

func TestInstanceReconcile(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
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
	//nolint:dogsled // no need to test additional HW parameters
	host, _, _, _, _, _ := loca_testing.PopulateInventoryWithHostResources(t, loca_testing.Tenant1, lenovoProvider, true)
	instance, _ := loca_testing.PopulateInventoryWithInstanceAndOSResource(t, []*loca_testing.MockServer{locaTS},
		loca_testing.Tenant1, host, false)
	// bootstrapping a production environment
	loca_testing.BootstrapProductionEnvironment(t, loca_testing.Tenant1, host.GetResourceId(), instance.GetResourceId())

	instanceReconciler := NewInstanceReconciler(
		true, inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient())
	require.NotNil(t, instanceReconciler)

	locaInstanceReconciler := rec_v2.NewController[ReconcilerID](
		instanceReconciler.Reconcile,
		rec_v2.WithParallelism(1),
	)

	err = locaInstanceReconciler.Reconcile(NewReconcilerID(instance.GetTenantId(), instance.GetResourceId()))
	require.NoError(t, err, "Reconciliation failed")
	// letting the reconciler to perform its job
	time.Sleep(100 * time.Millisecond)

	// checking the Instance
	loca_testing.AssertInstance(t, loca_testing.Tenant1, lenovoProvider.GetApiEndpoint(), instance.GetName(),
		computev1.InstanceState_INSTANCE_STATE_RUNNING, // Desired state set by the testing helper function
		computev1.InstanceState_INSTANCE_STATE_RUNNING, // Current state corresponds to the running production environment
		// Provisioning Status and Status Indicator correspond to what is reported in running production environment
		loca_status.InstanceStatusInstalled.Status, loca_status.InstanceStatusInstalled.StatusIndicator,
		// Instance Status and Status Indicator are set according to Node Agent running in production
		loca_testing.InstanceStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)

	// setting desired state of the Instance to be deleted
	dao.DeleteResource(t, loca_testing.Tenant1, instance.GetResourceId())

	err = locaInstanceReconciler.Reconcile(NewReconcilerID(instance.GetTenantId(), instance.GetResourceId()))
	require.NoError(t, err, "Reconciliation failed")

	// switching the instance removal task to successful state
	locaTS.Override(loca_testing.DeploymentInstancesIDPath, loca_testing.DeletedInstanceFunc)
	locaTS.Override(loca_testing.TaskManagementTasksIDPath, loca_testing.SuccessfulGetTask)

	// letting the reconciler to perform its job
	time.Sleep(100 * time.Millisecond)

	loca_testing.RequireIsNotFound(t, loca_testing.Tenant1, instance.GetResourceId())
}

func TestInvalidateInstance(t *testing.T) {
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
	//nolint:dogsled // no need to test additional HW parameters
	host, _, _, _, _, _ := loca_testing.PopulateInventoryWithHostResources(t, loca_testing.Tenant1, lenovoProvider, true)
	instance, _ := loca_testing.PopulateInventoryWithInstanceAndOSResource(t, []*loca_testing.MockServer{locaTS},
		loca_testing.Tenant1, host, true)
	// bootstrapping a production environment
	loca_testing.BootstrapProductionEnvironment(t, loca_testing.Tenant1, host.GetResourceId(), instance.GetResourceId())

	instanceReconciler := NewInstanceReconciler(
		true, inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient())
	require.NotNil(t, instanceReconciler)

	locaInstanceReconciler := rec_v2.NewController[ReconcilerID](
		instanceReconciler.Reconcile,
		rec_v2.WithParallelism(1),
	)

	err = locaInstanceReconciler.Reconcile(NewReconcilerID(instance.GetTenantId(), instance.GetResourceId()))
	require.NoError(t, err, "Reconciliation failed")
	// letting the reconciler to perform its job
	time.Sleep(100 * time.Millisecond)

	// checking the Instance
	loca_testing.AssertInstance(t, loca_testing.Tenant1, lenovoProvider.GetApiEndpoint(), instance.GetName(),
		computev1.InstanceState_INSTANCE_STATE_RUNNING, // Desired state set by the testing helper function
		computev1.InstanceState_INSTANCE_STATE_RUNNING, // Current state corresponds to the running production environment
		// Provisioning Status and Status Indicator correspond to what is reported in running production environment
		loca_status.InstanceStatusInstalled.Status, loca_status.InstanceStatusInstalled.StatusIndicator,
		// Instance Status and Status Indicator are set according to the Node Agents running in production
		loca_testing.InstanceStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)

	// setting desired state of the Instance to be UNTRUSTED
	loca_testing.InvalidateInstance(t, loca_testing.Tenant1, instance.GetResourceId())

	err = locaInstanceReconciler.Reconcile(NewReconcilerID(instance.GetTenantId(), instance.GetResourceId()))
	require.NoError(t, err, "Reconciliation failed")
	// letting the reconciler to perform its job
	time.Sleep(100 * time.Millisecond)

	// checking the Instance
	loca_testing.AssertInstance(t, loca_testing.Tenant1, lenovoProvider.GetApiEndpoint(), instance.GetName(),
		computev1.InstanceState_INSTANCE_STATE_UNTRUSTED, computev1.InstanceState_INSTANCE_STATE_UNTRUSTED,
		loca_status.InstanceStatusInstalled.Status, loca_status.InstanceStatusInstalled.StatusIndicator,
		// Instance Status and Status Indicator are updated during reconciliation
		loca_status.InstanceStatusInvalidated.Status, loca_status.InstanceStatusInvalidated.StatusIndicator)
}

// This TC verifies that the Instance with different from LOC-A provider (or no provider) would not be reconciled.
func TestInstanceNoProviderReconcile(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	host := dao.CreateHost(t, loca_testing.Tenant1)
	osRes := dao.CreateOs(t, loca_testing.Tenant1)
	instance := dao.CreateInstance(t, loca_testing.Tenant1, host, osRes)

	instanceReconciler := NewInstanceReconciler(
		true, inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient())
	require.NotNil(t, instanceReconciler)

	locaInstanceReconciler := rec_v2.NewController[ReconcilerID](
		instanceReconciler.Reconcile,
		rec_v2.WithParallelism(1),
	)

	// checking the Instance
	loca_testing.AssertInstance(t, loca_testing.Tenant1, "", instance.GetName(),
		computev1.InstanceState_INSTANCE_STATE_RUNNING, // Desired state set by the testing helper function
		computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED,
		// Default values for Provisioning and Instance Statuses
		inv_status.DefaultProvisioningStatus, statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED,
		inv_status.DefaultInstanceStatus, statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)

	err := locaInstanceReconciler.Reconcile(NewReconcilerID(instance.GetTenantId(), instance.GetResourceId()))
	require.NoError(t, err, "Reconciliation failed")
	// letting the reconciler to perform its job
	time.Sleep(100 * time.Millisecond)

	// checking the Instance - should be no changes
	loca_testing.AssertInstance(t, loca_testing.Tenant1, "", instance.GetName(),
		computev1.InstanceState_INSTANCE_STATE_RUNNING, // Desired state set by the testing helper function
		computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED,
		// Both statuses should stay untouched - Instance shouldn't be reconciled
		inv_status.DefaultProvisioningStatus, statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED,
		inv_status.DefaultInstanceStatus, statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)
}

// This TC verifies that the reconciliation is skipped when the Desired state of the Instance is equal to Current state.
func TestInstanceReconciliationSkipped(t *testing.T) {
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
	// Sets Instance Desired State to RUNNING
	instance, _ := loca_testing.PopulateInventoryWithInstanceAndOSResource(t,
		[]*loca_testing.MockServer{locaTS}, loca_testing.Tenant1, host, true)
	// bootstrapping production environment - sets Instance Current State to RUNNING
	loca_testing.BootstrapProductionEnvironment(t, loca_testing.Tenant1, host.GetResourceId(), instance.GetResourceId())

	instanceReconciler := NewInstanceReconciler(
		true, inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient())
	require.NotNil(t, instanceReconciler)

	locaInstanceReconciler := rec_v2.NewController[ReconcilerID](
		instanceReconciler.Reconcile,
		rec_v2.WithParallelism(1),
	)

	// checking the Instance
	loca_testing.AssertInstance(t, loca_testing.Tenant1, lenovoProvider.GetApiEndpoint(), instance.GetName(),
		computev1.InstanceState_INSTANCE_STATE_RUNNING, computev1.InstanceState_INSTANCE_STATE_RUNNING,
		// Provisioning Status and Status Indicator correspond to what is reported in running production environment
		loca_status.InstanceStatusInstalled.Status, loca_status.InstanceStatusInstalled.StatusIndicator,
		// Instance Status and Status Indicator correspond to the Node Agents values set in the running production
		loca_testing.InstanceStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)

	err = locaInstanceReconciler.Reconcile(NewReconcilerID(instance.GetTenantId(), instance.GetResourceId()))
	require.NoError(t, err, "Reconciliation failed")
	// letting the reconciler perform its job
	time.Sleep(100 * time.Millisecond)

	// checking the Instance - should be no change
	loca_testing.AssertInstance(t, loca_testing.Tenant1, lenovoProvider.GetApiEndpoint(), instance.GetName(),
		computev1.InstanceState_INSTANCE_STATE_RUNNING, computev1.InstanceState_INSTANCE_STATE_RUNNING,
		loca_status.InstanceStatusInstalled.Status, loca_status.InstanceStatusInstalled.StatusIndicator,
		loca_testing.InstanceStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)
}

func TestDeleteInstanceFromLOCA(t *testing.T) {
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() {
		locaTS.StopDummyLOCAServer()
	})
	locaTS.Override(loca_testing.DeploymentInstancesRemovePath, loca_testing.RemoveInstancesFunc, "POST")

	dao := inv_testing.NewInvResourceDAOOrFail(t)

	// creating provider
	lenovoProvider := loca_testing.PopulateInventoryWithLOCAProvider(
		t,
		loca_testing.Tenant1,
		loca_testing.DefaultProviderName,
		locaTS.GetURL(),
	)
	//nolint:dogsled // no need to test additional HW parameters
	host, _, _, _, _, _ := loca_testing.PopulateInventoryWithHostResources(t, loca_testing.Tenant1, lenovoProvider, true)
	instance, _ := loca_testing.PopulateInventoryWithInstanceAndOSResource(t, []*loca_testing.MockServer{locaTS},
		loca_testing.Tenant1, host, false)
	// bootstrapping a production environment
	loca_testing.BootstrapProductionEnvironment(t, loca_testing.Tenant1, host.GetResourceId(), instance.GetResourceId())

	instanceReconciler := NewInstanceReconciler(
		true, inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient())
	require.NotNil(t, instanceReconciler)

	locaInstanceReconciler := rec_v2.NewController[ReconcilerID](
		instanceReconciler.Reconcile,
		rec_v2.WithParallelism(1),
	)

	err = locaInstanceReconciler.Reconcile(NewReconcilerID(instance.GetTenantId(), instance.GetResourceId()))
	require.NoError(t, err, "Reconciliation failed")
	// letting the reconciler to perform its job
	time.Sleep(100 * time.Millisecond)

	// checking the Instance
	loca_testing.AssertInstance(t, loca_testing.Tenant1, lenovoProvider.GetApiEndpoint(), instance.GetName(),
		computev1.InstanceState_INSTANCE_STATE_RUNNING, // Desired state set by the testing helper function
		computev1.InstanceState_INSTANCE_STATE_RUNNING, // Current state corresponds to the running production environment
		// Provisioning Status and Status Indicator correspond to what is reported in running production environment
		loca_status.InstanceStatusInstalled.Status, loca_status.InstanceStatusInstalled.StatusIndicator,
		// Instance Status and Status Indicator are set according to the Node Agents running in production
		loca_testing.InstanceStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)

	// setting desired state of the Instance to be DELETED
	dao.DeleteResource(t, loca_testing.Tenant1, instance.GetResourceId())

	err = locaInstanceReconciler.Reconcile(NewReconcilerID(instance.GetTenantId(), instance.GetResourceId()))
	require.NoError(t, err, "Reconciliation failed")

	// simulate the removal task in running state
	time.Sleep(100 * time.Millisecond)

	// switching the instance removal task to successful state
	locaTS.Override(loca_testing.DeploymentInstancesIDPath, loca_testing.DeletedInstanceFunc)
	locaTS.Override(loca_testing.TaskManagementTasksIDPath, loca_testing.SuccessfulGetTask)

	// letting the reconciler to perform its job assuming that reconciler will retry. First retry should succeed.
	time.Sleep(100 * time.Millisecond)

	// checking that Instance was removed
	loca_testing.RequireIsNotFound(t, loca_testing.Tenant1, instance.GetResourceId())
}

func TestDeleteInstanceFromLOCAFail(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	// setting Mock to fail the Instance removal
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() {
		locaTS.StopDummyLOCAServer()
	})
	locaTS.Override(loca_testing.DeploymentInstancesRemovePath, loca_testing.FailedRemoveInstancesFunc, http.MethodPost)

	// creating provider
	lenovoProvider := loca_testing.PopulateInventoryWithLOCAProvider(
		t,
		loca_testing.Tenant1,
		loca_testing.DefaultProviderName,
		locaTS.GetURL(),
	)
	//nolint:dogsled // no need to test additional HW parameters
	host, _, _, _, _, _ := loca_testing.PopulateInventoryWithHostResources(t, loca_testing.Tenant1, lenovoProvider, true)
	instance, _ := loca_testing.PopulateInventoryWithInstanceAndOSResource(t, []*loca_testing.MockServer{locaTS},
		loca_testing.Tenant1, host, true)
	// bootstrapping a production environment
	loca_testing.BootstrapProductionEnvironment(t, loca_testing.Tenant1, host.GetResourceId(), instance.GetResourceId())

	instanceReconciler := NewInstanceReconciler(
		true, inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient())
	require.NotNil(t, instanceReconciler)

	locaInstanceReconciler := rec_v2.NewController[ReconcilerID](
		instanceReconciler.Reconcile,
		rec_v2.WithParallelism(1),
	)

	err = locaInstanceReconciler.Reconcile(NewReconcilerID(instance.GetTenantId(), instance.GetResourceId()))
	require.NoError(t, err, "Reconciliation failed")
	// letting the reconciler to perform its job
	time.Sleep(100 * time.Millisecond)

	// checking the Instance
	loca_testing.AssertInstance(t, loca_testing.Tenant1, lenovoProvider.GetApiEndpoint(), instance.GetName(),
		computev1.InstanceState_INSTANCE_STATE_RUNNING, // Desired state set by the testing helper function
		computev1.InstanceState_INSTANCE_STATE_RUNNING, // Current state corresponds to the running production environment
		// Provisioning Status and Status Indicator correspond to what is reported in running production environment
		loca_status.InstanceStatusInstalled.Status, loca_status.InstanceStatusInstalled.StatusIndicator,
		// Instance Status and Status Indicator are set according to the Node Agents running in production
		loca_testing.InstanceStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)

	// setting desired state of the Instance to be DELETED
	dao.DeleteResource(t, loca_testing.Tenant1, instance.GetResourceId())

	err = locaInstanceReconciler.Reconcile(NewReconcilerID(instance.GetTenantId(), instance.GetResourceId()))
	require.NoError(t, err, "Reconciliation failed")
	// letting the reconciler to perform its job
	time.Sleep(100 * time.Millisecond)

	// checking the Instance
	loca_testing.AssertInstance(t, loca_testing.Tenant1, lenovoProvider.GetApiEndpoint(), instance.GetName(),
		computev1.InstanceState_INSTANCE_STATE_DELETED, computev1.InstanceState_INSTANCE_STATE_RUNNING,
		util.StatusFailedToRemoveInstance, statusv1.StatusIndication_STATUS_INDICATION_ERROR,
		// Instance Status and Status Indicator are NOT updated
		loca_testing.InstanceStatusRunning, statusv1.StatusIndication_STATUS_INDICATION_IDLE)
}

// This TC verifies that a new Instance is provisioned in LOC-A when the Instance desired state is set to RUNNING
// and the Instance is not present in LOC-A.
func TestProvisionInstanceInLOCA(t *testing.T) {
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() {
		locaTS.StopDummyLOCAServer()
	})
	dao := inv_testing.NewInvResourceDAOOrFail(t)

	// creating provider
	lenovoProvider := loca_testing.PopulateInventoryWithLOCAProvider(
		t,
		loca_testing.Tenant1,
		loca_testing.DefaultProviderName,
		locaTS.GetURL(),
	)
	// creating Site in Inventory
	site := loca_testing.PopulateInventoryWithSite(t, loca_testing.Tenant1, loca_testing.LocaSiteName)
	//nolint:dogsled // no need to test additional HW parameters
	host, _, _, _, _, _ := loca_testing.PopulateInventoryWithHostResources(t, loca_testing.Tenant1, lenovoProvider, true)
	// creating OS resource
	osRes := loca_testing.PopulateInventoryWithOSResource(t, []*loca_testing.MockServer{locaTS},
		loca_testing.Tenant1)
	// creating Instance resource with dummy Instance name and RUNNING desired state
	instance := dao.CreateInstance(t, loca_testing.Tenant1, host, osRes)
	// associate Host with Site
	err = loca_testing.UpdateHostSite(t, loca_testing.Tenant1, host.GetResourceId(), site)
	require.NoError(t, err)
	// set Host Product Name - required for selecting the appropriate LOC-A template
	err = loca_testing.UpdateHostProductName(t, loca_testing.Tenant1, host.GetResourceId(), loca_testing.ServerModel)
	require.NoError(t, err)

	// seeding Site Resource ID in LOC-A site readiness response to match the Site Resource ID in Inventory
	locaTS.SeedSiteResourceID(site.GetResourceId())
	// set the mock to return a "not found" Instance
	locaTS.Override(loca_testing.DeploymentInstancesCreate, loca_testing.DeploymentInstancesCreated, http.MethodPost)
	locaTS.Override(loca_testing.DeploymentInstancesDeploy, loca_testing.DeploymentInstancesDeployFunc, http.MethodPost)
	locaTS.Override(loca_testing.DeploymentInstancesIDPath, loca_testing.ReturnNoInstanceByInstanceID)

	// ensuring that the Instance Name is different from the LOC-A Instance ID
	require.NotEqualf(t, loca_testing.LocaInstanceID, instance.GetName(), "Instance name should be different")

	instanceReconciler := NewInstanceReconciler(
		true, inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient())
	require.NotNil(t, instanceReconciler)

	locaInstanceReconciler := rec_v2.NewController[ReconcilerID](
		instanceReconciler.Reconcile,
		rec_v2.WithParallelism(1),
	)
	defer locaInstanceReconciler.Stop()

	err = locaInstanceReconciler.Reconcile(NewReconcilerID(instance.GetTenantId(), instance.GetResourceId()))
	require.NoError(t, err, "Reconciliation failed")
	// letting the reconciler to perform its job
	time.Sleep(100 * time.Millisecond)

	// Ensuring that after the successful Instance provisioning, the Instance Name changed to the LOC-A Instance ID.
	// The Instance Desired State should remain unchanged (RUNNING), and the remaining fields
	// should correspond to UNSPECIFIED values.
	loca_testing.AssertInstance(t, loca_testing.Tenant1, lenovoProvider.GetApiEndpoint(), loca_testing.LocaInstanceID,
		computev1.InstanceState_INSTANCE_STATE_RUNNING, computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED,
		inv_status.DefaultProvisioningStatus, statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED,
		inv_status.DefaultInstanceStatus, statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)
}

func TestInstanceReconciler_onboardInstance_whenUnableToCreateClientShouldReturnError(t *testing.T) {
	assertHook := util.NewTestAssertHook("Failed to initialize LOC-A client for endpoint")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	ir := NewInstanceReconciler(false, inv_testing.NewInvResourceDAOOrFail(t).GetAPIClient())
	host := &computev1.InstanceResource{TenantId: loca_testing.Tenant1}
	req := rec_v2.Request[ReconcilerID]{
		ID: "test",
	}

	ir.onboardInstance(context.TODO(), req, host)
	assertHook.Assert(t)
}

func TestInstanceReconciler_onboardInstance_whenGotErrorFromLocaShouldRetryRequest(t *testing.T) {
	assertHook := util.NewTestAssertHook("Failed to retrieve from LOC-A Instance by its ID")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	loca_testing.StartMockSecretService()
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() {
		locaTS.StopDummyLOCAServer()
	})
	locaTS.Override(loca_testing.DeploymentInstancesIDPath, func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusInternalServerError)
	})

	ir := NewInstanceReconciler(false, inv_testing.NewInvResourceDAOOrFail(t).GetAPIClient())
	host := &computev1.InstanceResource{
		TenantId: loca_testing.Tenant1,
		Host: &computev1.HostResource{
			Provider: &provider_v1.ProviderResource{
				ApiCredentials: []string{loca_testing.LocaSecret},
				ApiEndpoint:    locaTS.GetURL(),
			},
		},
	}
	req := rec_v2.Request[ReconcilerID]{
		ID: "test",
	}

	directive := ir.onboardInstance(context.TODO(), req, host)
	assertHook.Assert(t)
	assert.NotEmpty(t, directive)
}

func TestInstanceReconciler_onboardInstance_whenInstanceIsAlreadyOnboardedShouldSkip(t *testing.T) {
	assertHook := util.NewTestAssertHook("already present in LOC-A")
	zlogInst = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	loca_testing.StartMockSecretService()
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	t.Cleanup(func() {
		locaTS.StopDummyLOCAServer()
	})
	locaTS.Override("/api/v1/deployment/instances/{id}", func(writer http.ResponseWriter, request *http.Request) {
		loca_testing.WriteStructToResponse(writer, request, &model.DtoInstanceQryResponse{}, http.StatusOK)
	})

	ir := NewInstanceReconciler(false, inv_testing.NewInvResourceDAOOrFail(t).GetAPIClient())
	host := &computev1.InstanceResource{
		Name:     "test",
		TenantId: loca_testing.Tenant1,
		Host: &computev1.HostResource{
			Provider: &provider_v1.ProviderResource{
				ApiCredentials: []string{loca_testing.LocaSecret},
				ApiEndpoint:    locaTS.GetURL(),
			},
		},
	}
	req := rec_v2.Request[ReconcilerID]{
		ID: "test",
	}

	directive := ir.onboardInstance(context.TODO(), req, host)
	assertHook.Assert(t)
	assert.NotEmpty(t, directive)
}
