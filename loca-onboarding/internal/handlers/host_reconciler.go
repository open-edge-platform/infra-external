// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"

	computev1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/compute/v1"
	providerv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/provider/v1"
	statusv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/status/v1"
	kk_auth "github.com/open-edge-platform/infra-core/inventory/v2/pkg/auth"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/tracing"
	inv_util "github.com/open-edge-platform/infra-core/inventory/v2/pkg/util"
	loca_inventory "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/client/inventory"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/model"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/inventory"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/loca"
	loca_status "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/status"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/util"
	rec_v2 "github.com/open-edge-platform/orch-library/go/pkg/controller/v2"
)

const (
	loggerName = "HostReconciler"
)

// Misc variables.
var (
	zlog = logging.GetLogger(loggerName)
)

type HostReconciler struct {
	tracingEnabled bool
	invClient      client.TenantAwareInventoryClient
}

func NewHostReconciler(tracingEnabled bool, invClient client.TenantAwareInventoryClient) *HostReconciler {
	return &HostReconciler{
		tracingEnabled: tracingEnabled,
		invClient:      invClient,
	}
}

func (hr *HostReconciler) Reconcile(ctx context.Context, request rec_v2.Request[ReconcilerID]) rec_v2.Directive[ReconcilerID] {
	if hr.tracingEnabled {
		ctx = tracing.StartTrace(ctx, "LOC-A RM", "HostReconciler")
		defer tracing.StopTrace(ctx)
	}

	resourceID := request.ID.GetResourceID()
	tenantID := request.ID.GetTenantID()

	zlog.Info().Msgf("Reconciling Host: %s", request.ID)

	host, err := inventory.GetHostResourceByResourceID(ctx, hr.invClient, tenantID, resourceID)
	if directive := HandleInventoryError(err, request); directive != nil {
		return directive
	}

	if host.GetProvider() == nil ||
		host.GetProvider().GetProviderVendor() != providerv1.ProviderVendor_PROVIDER_VENDOR_LENOVO_LOCA {
		// no need to do anything
		zlog.Info().Msgf("Host (%s) does not have LOC-A provider, it should be reconciled within the other RM",
			host.GetResourceId())
		return request.Ack()
	}

	if host.GetDesiredState() == host.GetCurrentState() {
		zlog.Debug().Msgf("Host %s reconciliation skipped", resourceID)
		return request.Ack()
	}

	return hr.reconcileHost(ctx, request, host)
}

func (hr *HostReconciler) reconcileHost(
	ctx context.Context,
	request rec_v2.Request[ReconcilerID],
	host *computev1.HostResource,
) rec_v2.Directive[ReconcilerID] {
	zlog.Debug().Msgf("Reconciling host with %s, with Current state: %v, Desired state: %v.",
		inventory.FormatTenantResourceID(host.GetTenantId(), host.GetResourceId()),
		host.GetCurrentState(), host.GetDesiredState())

	// Handle Host deleted events
	switch host.GetDesiredState() {
	case computev1.HostState_HOST_STATE_DELETED:
		return hr.deleteHost(ctx, request, host)
	case computev1.HostState_HOST_STATE_UNTRUSTED:
		return hr.invalidateHost(ctx, request, host)
	default:
		return request.Ack()
	}
}

func (hr *HostReconciler) invalidateHost(
	ctx context.Context, request rec_v2.Request[ReconcilerID], host *computev1.HostResource,
) rec_v2.Directive[ReconcilerID] {
	// The Current state will be updated to UNTRUSTED anyway
	// even if the Keycloak/Vault communication is disabled.
	zlog.InfraSec().Debug().Msgf("Invalidating Host (%s)", host.GetResourceId())
	// invalidating Device
	err := kk_auth.RevokeHostCredentials(ctx, host.GetTenantId(), host.GetUuid())
	if directive := HandleInventoryError(err, request); directive != nil {
		return directive
	}
	// setting current state of the Host to be UNTRUSTED
	host.CurrentState = computev1.HostState_HOST_STATE_UNTRUSTED
	host.HostStatus = loca_status.HostStatusInvalidated.Status
	host.HostStatusIndicator = loca_status.HostStatusInvalidated.StatusIndicator
	host.HostStatusTimestamp, err = inv_util.Int64ToUint64(time.Now().Unix())
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to parse current time")
		// this error is unlikely, but in such case, set timestamp = 0
		host.OnboardingStatusTimestamp = 0
	}
	host.OnboardingStatus = loca_status.HostStatusUnknown.Status
	host.OnboardingStatusIndicator = loca_status.HostStatusUnknown.StatusIndicator
	host.OnboardingStatusTimestamp, err = inv_util.Int64ToUint64(time.Now().Unix())
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to parse current time")
		host.OnboardingStatusTimestamp = 0
	}
	host.RegistrationStatus = loca_status.HostStatusUnknown.Status
	host.RegistrationStatusIndicator = loca_status.HostStatusUnknown.StatusIndicator
	host.RegistrationStatusTimestamp, err = inv_util.Int64ToUint64(time.Now().Unix())
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to parse current time")
		host.RegistrationStatusTimestamp = 0
	}
	err = inventory.UpdateInvResourceFields(ctx, hr.invClient, host.GetTenantId(), host, []string{
		computev1.HostResourceFieldCurrentState, computev1.HostResourceFieldHostStatus,
		computev1.HostResourceFieldHostStatusIndicator, computev1.HostResourceFieldHostStatusTimestamp,
		computev1.HostResourceFieldOnboardingStatus, computev1.HostResourceFieldOnboardingStatusIndicator,
		computev1.HostResourceFieldOnboardingStatusTimestamp, computev1.HostResourceFieldRegistrationStatus,
		computev1.HostResourceFieldRegistrationStatusIndicator, computev1.HostResourceFieldRegistrationStatusTimestamp,
	})
	if directive := HandleInventoryError(err, request); directive != nil {
		return directive
	}
	return nil
}

func (hr *HostReconciler) deleteHost(
	ctx context.Context, request rec_v2.Request[ReconcilerID], host *computev1.HostResource,
) rec_v2.Directive[ReconcilerID] {
	err := util.CheckIfInstanceIsAssociated(ctx, hr.invClient, host.GetTenantId(), host)
	if directive := HandleInventoryError(err, request); directive != nil {
		return directive
	}
	// check if Host is present in LOC-A:
	// - if yes, throw an error => Host should be removed from LOC-A and then reconciled
	// - if no, update current state to be deleted
	locaClient, err := loca.InitialiseLOCAClient(
		host.GetProvider().GetApiEndpoint(),
		host.GetProvider().GetApiCredentials(),
	)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to initialize LOC-A client for endpoint: %s",
			host.GetProvider().GetApiEndpoint())
		return request.Retry(err).With(rec_v2.ExponentialBackoff(minDelay, maxDelay))
	}

	// Verify if a removal task for the Host is already running in LOC-A
	taskRunning, errTracker := loca.DefaultTaskTracker.TaskIsRunningFor(locaClient, host.GetResourceId())
	if errTracker != nil {
		zlog.InfraSec().InfraErr(errTracker).Msgf("Failed to check if a task is running for Host (%s)", host.GetResourceId())
		err = errors.Errorfc(codes.FailedPrecondition, "Failed to check if a task is running for Host (%s)",
			host.GetResourceId())
		return request.Retry(err).With(rec_v2.ExponentialBackoff(minDelay, maxDelay))
	}
	if taskRunning {
		// Device remove task is created, waiting on its delete
		zlog.Debug().Msgf(
			"Remove LOC-A device (%s) task is already running, waiting on its completion",
			host.GetResourceId())
		return request.Requeue()
	}

	devices, err := locaClient.LocaAPI.Inventory.GetAPIV1InventoryDevices(
		&loca_inventory.GetAPIV1InventoryDevicesParams{Context: ctx}, locaClient.AuthWriter)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to retrieve Devices from LOC-A (endpoint: %s)",
			host.GetProvider().GetApiEndpoint())
		return request.Retry(err).With(rec_v2.ExponentialBackoff(minDelay, maxDelay))
	}
	locaHost, exists := util.FindDeviceInLOCAHostList(host, devices.Payload.Data.Results)
	if exists {
		return hr.removeHostFromLOCA(ctx, request, host, locaClient, locaHost)
	}
	// Host is NOT found, reconciling it
	err = inventory.RemoveHost(ctx, hr.invClient, host.GetTenantId(), host)
	if directive := HandleInventoryError(err, request); directive != nil {
		return directive
	}
	zlog.Debug().Msgf("Host (%s) has been deleted", host.GetResourceId())
	return request.Ack()
}

func (hr *HostReconciler) removeHostFromLOCA(
	ctx context.Context, request rec_v2.Request[ReconcilerID],
	host *computev1.HostResource, locaClient *loca.LocaCli,
	locaHost *model.DtoDeviceListElement,
) rec_v2.Directive[ReconcilerID] {
	// Host is found, removing it from LOC-A
	zlog.Info().Msgf("Removing Host (%s) from LOC-A (%s/%s)", host.GetUuid(),
		host.GetProvider().GetName(), host.GetProvider().GetApiEndpoint())
	resp, respErr := locaClient.LocaAPI.Inventory.PostAPIV1InventoryDevicesRemove(
		&loca_inventory.PostAPIV1InventoryDevicesRemoveParams{Context: ctx, Body: []string{locaHost.ID}},
		locaClient.AuthWriter)
	if respErr != nil {
		var tsErr error
		// Failed to remove Host from LOC-A
		err := errors.Errorfc(codes.FailedPrecondition, "Failed to remove Host (%s) from LOC-A (%s/%s)",
			host.GetResourceId(), host.GetProvider().GetName(), host.GetProvider().GetApiEndpoint())
		zlog.InfraSec().InfraErr(respErr).Msgf("Failed to remove Host (%s) from LOC-A (endpoint: %s) - can't reconcile it",
			host.GetResourceId(), host.GetProvider().GetApiEndpoint())

		// updating onboarding status to reflect the failure in the UI
		host.OnboardingStatus = util.StatusFailedToRemoveHostFromLOCA
		host.OnboardingStatusIndicator = statusv1.StatusIndication_STATUS_INDICATION_ERROR
		host.OnboardingStatusTimestamp, tsErr = inv_util.Int64ToUint64(time.Now().Unix())
		if tsErr != nil {
			zlog.InfraSec().InfraErr(tsErr).Msgf("Failed to parse current time")
			// this error is unlikely, but in such case, set timestamp = 0
			host.OnboardingStatusTimestamp = 0
		}
		// update host status
		errUpdate := inventory.UpdateHostOnboardingStatus(ctx, hr.invClient, host.GetTenantId(), host)
		if errUpdate != nil {
			zlog.InfraSec().InfraErr(errUpdate).Msgf("Failed to update Host Onboarding Status")
			request.Retry(errUpdate).With(rec_v2.ExponentialBackoff(minDelay, maxDelay))
		}
		return request.Retry(err).With(rec_v2.ExponentialBackoff(minDelay, maxDelay))
	}

	// Tracking the remove device task
	errTracker := loca.DefaultTaskTracker.TrackTask(host.GetResourceId(), resp.Payload.Data.TaskUUID)
	if errTracker != nil {
		zlog.InfraSec().InfraErr(errTracker).Msgf("Failed to track task (%s) for Host (%s)", resp.Payload.Data.TaskUUID,
			host.GetResourceId())
		err := errors.Errorfc(codes.FailedPrecondition, "Failed to track task (%s) for Host (%s)",
			resp.Payload.Data.TaskUUID, host.GetResourceId())
		return request.Retry(err).With(rec_v2.ExponentialBackoff(minDelay, maxDelay))
	}

	// Device remove task is created, waiting on its delete
	zlog.Debug().Msgf("Remove Device task (%s) is created, waiting on its completion",
		resp.Payload.Data.TaskUUID)
	return request.Requeue()
}
