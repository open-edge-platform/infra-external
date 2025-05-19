// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"strings"
	"time"

	"google.golang.org/grpc/codes"

	computev1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/compute/v1"
	providerv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/provider/v1"
	statusv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/status/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/tracing"
	inv_util "github.com/open-edge-platform/infra-core/inventory/v2/pkg/util"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/client/deployment"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/model"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/inventory"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/loca"
	loca_status "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/status"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/util"
	rec_v2 "github.com/open-edge-platform/orch-library/go/pkg/controller/v2"
)

const (
	instanceReconcilerLoggerName = "InstanceReconciler"
)

// Misc variables.
var (
	zlogInst = logging.GetLogger(instanceReconcilerLoggerName)
)

type InstanceReconciler struct {
	tracingEnabled bool
	invClient      client.TenantAwareInventoryClient
}

func NewInstanceReconciler(tracingEnabled bool, invClient client.TenantAwareInventoryClient) *InstanceReconciler {
	return &InstanceReconciler{
		tracingEnabled: tracingEnabled,
		invClient:      invClient,
	}
}

func (ir *InstanceReconciler) Reconcile(
	ctx context.Context, request rec_v2.Request[ReconcilerID],
) rec_v2.Directive[ReconcilerID] {
	if ir.tracingEnabled {
		ctx = tracing.StartTrace(ctx, "LOC-A RM", "InstanceReconciler")
		defer tracing.StopTrace(ctx)
	}
	resourceID := request.ID.GetResourceID()
	tenantID := request.ID.GetTenantID()

	zlogInst.Info().Msgf("Reconciling Instance (%s)", request.ID)

	instance, err := inventory.GetInstanceResourceByResourceID(ctx, ir.invClient, tenantID, resourceID)
	if directive := HandleInventoryError(err, request); directive != nil {
		return directive
	}

	if instance.GetHost().GetProvider() == nil ||
		instance.GetHost().GetProvider().GetProviderVendor() != providerv1.ProviderVendor_PROVIDER_VENDOR_LENOVO_LOCA {
		// no need to do anything
		zlogInst.Info().Msgf("Instance (%s) does not have LOC-A provider, it should be reconciled within the other RM",
			instance.GetResourceId())
		return request.Ack()
	}

	if instance.GetDesiredState() == instance.GetCurrentState() {
		zlogInst.Debug().Msgf("Instance (%s) reconciliation skipped", resourceID)
		return request.Ack()
	}

	if directive := ir.handleHostDeauthorized(ctx, instance, request, resourceID); directive != nil {
		return directive
	}

	return ir.reconcileInstance(ctx, request, instance)
}

func checkStatusIdle(instance *computev1.InstanceResource,
) bool {
	idleCheck := true
	// Check if all statuses in instance are idle
	if instance.GetInstanceStatusIndicator() != statusv1.StatusIndication_STATUS_INDICATION_IDLE &&
		instance.GetInstanceStatusIndicator() != statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED {
		idleCheck = false
	}
	if instance.GetProvisioningStatusIndicator() != statusv1.StatusIndication_STATUS_INDICATION_IDLE &&
		instance.GetProvisioningStatusIndicator() != statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED {
		idleCheck = false
	}
	if instance.GetUpdateStatusIndicator() != statusv1.StatusIndication_STATUS_INDICATION_IDLE &&
		instance.GetUpdateStatusIndicator() != statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED {
		idleCheck = false
	}
	if instance.GetTrustedAttestationStatusIndicator() != statusv1.StatusIndication_STATUS_INDICATION_IDLE &&
		instance.GetTrustedAttestationStatusIndicator() != statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED {
		idleCheck = false
	}
	return idleCheck
}

func (ir *InstanceReconciler) handleHostDeauthorized(ctx context.Context, instance *computev1.InstanceResource,
	request rec_v2.Request[ReconcilerID], resourceID string,
) rec_v2.Directive[ReconcilerID] {
	if instance.GetHost().GetCurrentState() == computev1.HostState_HOST_STATE_UNTRUSTED ||
		instance.GetHost().GetDesiredState() == computev1.HostState_HOST_STATE_UNTRUSTED {
		// Check that all statuses and indicators have been updated
		if !checkStatusIdle(instance) {
			zlogInst.Info().Msgf("Host associated with Instance (%s) has been deauthorized. "+
				"Forcing reconciliation to update Instance status.", resourceID)
			instance.InstanceStatus = loca_status.InstanceStatusUnknown.Status
			instance.InstanceStatusIndicator = loca_status.InstanceStatusUnknown.StatusIndicator
			instance.InstanceStatusDetail = ""
			instance.ProvisioningStatus = loca_status.InstanceStatusUnknown.Status
			instance.ProvisioningStatusIndicator = loca_status.InstanceStatusUnknown.StatusIndicator
			instance.UpdateStatus = loca_status.InstanceStatusUnknown.Status
			instance.UpdateStatusIndicator = loca_status.InstanceStatusUnknown.StatusIndicator
			instance.UpdateStatusDetail = ""
			instance.TrustedAttestationStatus = loca_status.InstanceStatusUnknown.Status
			instance.TrustedAttestationStatusIndicator = loca_status.InstanceStatusUnknown.StatusIndicator
			return ir.reconcileInstance(ctx, request, instance)
		}
		zlogInst.Debug().Msgf("Instance (%s) reconciliation skipped - host has been deauthorized.", resourceID)
		return request.Ack()
	}
	return nil
}

func (ir *InstanceReconciler) reconcileInstance(
	ctx context.Context,
	request rec_v2.Request[ReconcilerID],
	instance *computev1.InstanceResource,
) rec_v2.Directive[ReconcilerID] {
	zlogInst.Debug().Msgf("Reconciling Instance with ID %s, with Current state: %v, Desired state: %v.",
		inventory.FormatTenantResourceID(instance.GetTenantId(), instance.GetResourceId()),
		instance.GetCurrentState(), instance.GetDesiredState())

	switch {
	case instance.GetDesiredState() == computev1.InstanceState_INSTANCE_STATE_DELETED:
		return ir.deleteInstance(ctx, request, instance)
	case instance.GetDesiredState() == computev1.InstanceState_INSTANCE_STATE_UNTRUSTED:
		return ir.invalidateInstance(ctx, request, instance)
	case instance.GetDesiredState() == computev1.InstanceState_INSTANCE_STATE_RUNNING &&
		instance.GetCurrentState() == computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED:
		return ir.onboardInstance(ctx, request, instance)
	default:
		return request.Ack()
	}
}

func (ir *InstanceReconciler) onboardInstance(
	ctx context.Context, request rec_v2.Request[ReconcilerID], instance *computev1.InstanceResource,
) rec_v2.Directive[ReconcilerID] {
	// handle nTouch provisioning for instances with a RUNNING desired state in Inventory but not found in LOC-A
	zlog.InfraSec().Info().Msgf("Starting instance (%s) execution", instance.GetResourceId())

	locaClient, err := loca.InitialiseLOCAClient(
		instance.GetHost().GetProvider().GetApiEndpoint(),
		instance.GetHost().GetProvider().GetApiCredentials(),
	)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to initialize LOC-A client for endpoint: %s",
			instance.GetHost().GetProvider().GetApiEndpoint())
		return request.Retry(err).With(rec_v2.ExponentialBackoff(minDelay, maxDelay))
	}

	locaInstance, err := locaClient.LocaAPI.Deployment.GetAPIV1DeploymentInstancesID(
		&deployment.GetAPIV1DeploymentInstancesIDParams{ID: instance.GetName()}, locaClient.AuthWriter)
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "not found") &&
		!strings.Contains(strings.ToLower(err.Error()), strings.ToLower("the provided hex string is not a valid ObjectID")) {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to retrieve from LOC-A Instance by its ID (%s)", instance.GetName())
		return request.Retry(err).With(rec_v2.ExponentialBackoff(minDelay, maxDelay))
	}

	if locaInstance != nil {
		zlogInst.Info().Msgf("Instance (%s) is already present in LOC-A", instance.GetResourceId())
		return request.Ack()
	}

	// get OS Resource ID and Server Model from Instance
	osResID := instance.GetDesiredOs().GetResourceId()
	serverModel := instance.GetHost().GetProductName()

	// get template name based on the OS Resource ID and Server Model
	templateName := util.GetTemplateName(osResID, serverModel)

	// get host serial number, host UUID and site ID
	hostSN := instance.GetHost().GetSerialNumber()
	hostUUID := instance.GetHost().GetUuid()
	siteName := instance.GetHost().GetSite().GetName()
	locaInstanceID, err := locaClient.ProvisionInstance(ctx, templateName, hostSN, hostUUID, siteName)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to provision Instance (%s) in LOC-A", instance.GetResourceId())
		return request.Retry(err).With(rec_v2.ExponentialBackoff(minDelay, maxDelay))
	}

	// update instance name in the inventory
	//nolint:errcheck // no need to report error, it is logged in the inner function
	_ = inventory.UpdateInstanceName(ctx, ir.invClient, instance.GetTenantId(), instance, locaInstanceID)

	zlog.InfraSec().Info().Msgf("Created Instance (%s) in LOC-A", locaInstanceID)
	return nil
}

func (ir *InstanceReconciler) invalidateInstance(
	ctx context.Context, request rec_v2.Request[ReconcilerID], instance *computev1.InstanceResource,
) rec_v2.Directive[ReconcilerID] {
	var err error
	instance.CurrentState = computev1.InstanceState_INSTANCE_STATE_UNTRUSTED
	instance.InstanceStatus = loca_status.InstanceStatusInvalidated.Status
	instance.InstanceStatusIndicator = loca_status.InstanceStatusInvalidated.StatusIndicator
	instance.InstanceStatusTimestamp, err = inv_util.Int64ToUint64(time.Now().Unix())
	if err != nil {
		zlogInst.InfraSec().InfraErr(err).Msgf("Failed to parse current time")
		// this error is unlikely, but in such case, set timestamp = 0
		instance.InstanceStatusTimestamp = 0
	}
	err = inventory.UpdateInstanceStatus(ctx, ir.invClient, instance.GetTenantId(), instance)
	if directive := HandleInventoryError(err, request); directive != nil {
		return directive
	}
	zlogInst.Debug().Msgf("Instance (%s) has been invalidated", instance.GetResourceId())
	return request.Ack()
}

func (ir *InstanceReconciler) deleteInstance(
	ctx context.Context, request rec_v2.Request[ReconcilerID], instance *computev1.InstanceResource,
) rec_v2.Directive[ReconcilerID] {
	// check if Instance is present in LOC-A:
	// - if yes, throw an error => Instance should be removed from LOC-A and then reconciled
	// - if no, update current state to be deleted
	locaClient, err := loca.InitialiseLOCAClient(
		instance.GetHost().GetProvider().GetApiEndpoint(),
		instance.GetHost().GetProvider().GetApiCredentials(),
	)
	if err != nil {
		zlogInst.InfraSec().InfraErr(err).Msgf("Failed to initialize LOC-A client for endpoint: %s",
			instance.GetHost().GetProvider().GetApiEndpoint())
		return request.Retry(err).With(rec_v2.ExponentialBackoff(minDelay, maxDelay))
	}

	// verify if a removal task for the Instance is already in progress in LOC-A
	taskRunning, errTracker := loca.DefaultTaskTracker.TaskIsRunningFor(locaClient, instance.GetResourceId())
	if errTracker != nil {
		zlogInst.InfraSec().InfraErr(errTracker).Msgf("Failed to check if a task is running for Instance (%s)",
			instance.GetResourceId())
		err = errors.Errorfc(codes.FailedPrecondition, "Failed to check if a task is running for Instance (%s)",
			instance.GetResourceId())
		return request.Retry(err).With(rec_v2.ExponentialBackoff(minDelay, maxDelay))
	}
	if taskRunning {
		// Instance remove task is created, waiting on its delete
		zlogInst.Debug().Msgf("Remove Instance (%s) task is already running, waiting on its completion",
			instance.GetResourceId())
		return request.Requeue()
	}

	locaInstance, err := locaClient.LocaAPI.Deployment.GetAPIV1DeploymentInstancesID(
		&deployment.GetAPIV1DeploymentInstancesIDParams{Context: ctx, ID: instance.GetName()}, locaClient.AuthWriter)
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "not found") {
		// handle only remaining errors; "not found" is expected if the instance has already been deleted
		zlogInst.InfraSec().InfraErr(err).Msgf("Couldn't retrieve from LOC-A (%s/%s) Instance by its ID (%s)",
			instance.GetHost().GetProvider().GetName(), instance.GetHost().GetProvider().GetApiEndpoint(), instance.GetName())
		return request.Retry(err).With(rec_v2.ExponentialBackoff(minDelay, maxDelay))
	}
	if locaInstance != nil {
		return ir.deleteInstanceFromLoca(ctx, request, instance, locaClient, locaInstance.Payload.Data.ID)
	}
	// Instance is NOT present in LOC-A, reconciling it
	err = inventory.UpdateInstanceCurrentState(
		ctx,
		ir.invClient,
		instance.GetTenantId(),
		instance,
		computev1.InstanceState_INSTANCE_STATE_DELETED,
	)
	if directive := HandleInventoryError(err, request); directive != nil {
		return directive
	}
	zlogInst.Debug().Msgf("Instance (%s) has been deleted", instance.GetResourceId())
	return request.Ack()
}

func (ir *InstanceReconciler) deleteInstanceFromLoca(
	ctx context.Context, request rec_v2.Request[ReconcilerID], instance *computev1.InstanceResource,
	locaClient *loca.LocaCli, instanceID string,
) rec_v2.Directive[ReconcilerID] {
	// Instance is present in LOC-A, attempting to remove it first
	var err error
	resp, respErr := locaClient.LocaAPI.Deployment.PostAPIV1DeploymentInstancesRemove(
		&deployment.PostAPIV1DeploymentInstancesRemoveParams{
			Context: ctx,
			Body:    &model.ModelsRemoveInstancesRequest{Ids: []string{instanceID}},
		}, locaClient.AuthWriter)
	if respErr != nil {
		// Failed to remove Instance
		zlogInst.InfraErr(respErr).Msgf("Failed to remove Instance (%s) from LOC-A (%s/%s)",
			instance.GetResourceId(), instance.GetHost().GetProvider().GetName(),
			instance.GetHost().GetProvider().GetApiEndpoint())

		// Updating Provisioning status to reflect changes in the UI
		instance.ProvisioningStatus = util.StatusFailedToRemoveInstance
		instance.ProvisioningStatusIndicator = statusv1.StatusIndication_STATUS_INDICATION_ERROR
		instance.ProvisioningStatusTimestamp, err = inv_util.Int64ToUint64(time.Now().Unix())
		if err != nil {
			zlogInst.InfraSec().InfraErr(err).Msgf("Failed to parse current time")
			// this error is unlikely, but in such case, set timestamp = 0
			instance.ProvisioningStatusTimestamp = 0
		}
		// Update Instance status
		err = inventory.UpdateInstanceProvisioningStatus(ctx, ir.invClient, instance.GetTenantId(), instance)
		if err != nil {
			zlogInst.InfraSec().InfraErr(err).Msgf("Failed to update Instance Provisioning Status")
		}
		// crafting new error - previous one was overwritten
		newErr := errors.Errorfc(codes.FailedPrecondition, "Failed to remove Instance (%s) from LOC-A (%s)",
			instance.GetResourceId(), instance.GetHost().GetProvider().GetApiEndpoint())
		return request.Retry(newErr).With(rec_v2.ExponentialBackoff(minDelay, maxDelay))
	}

	// Tracking the remove instance task
	errTracker := loca.DefaultTaskTracker.TrackTask(instance.GetResourceId(), resp.Payload.Data.TaskUUID)
	if errTracker != nil {
		zlogInst.InfraSec().InfraErr(errTracker).Msgf("Failed to track task (%s) for Instance (%s)",
			resp.Payload.Data.TaskUUID, instance.GetResourceId())
		err = errors.Errorfc(codes.FailedPrecondition, "Failed to track task (%s) for Instance (%s)",
			resp.Payload.Data.TaskUUID, instance.GetResourceId())
		return request.Retry(err).With(rec_v2.ExponentialBackoff(minDelay, maxDelay))
	}

	// Instance remove task is created, waiting on its delete
	zlogInst.Debug().Msgf("Remove Instance task (%s) is created in LOC-A, waiting on its completion",
		resp.Payload.Data.TaskUUID)
	return request.Requeue()
}
