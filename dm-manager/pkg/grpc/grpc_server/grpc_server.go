// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package grpcserver

import (
	"context"

	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	computev1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/compute/v1"
	inventoryv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/policy/rbac"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/secretprovider"
	inv_tenant "github.com/open-edge-platform/infra-core/inventory/v2/pkg/tenant"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/validator"
	pb "github.com/open-edge-platform/infra-external/dm-manager/pkg/api/dm-manager"
	"github.com/open-edge-platform/infra-external/dm-manager/pkg/status"
)

const (
	AmtPasswordSecretName = "amt-password"
	passwordKey           = "password"
)

var (
	name = "DeviceManagementService"
	zlog = logging.GetLogger(name)
)

type InventoryClientService struct {
	invClient      client.TenantAwareInventoryClient
	SecretProvider secretprovider.SecretProvider
}

type (
	DeviceManagementService struct {
		pb.UnimplementedDeviceManagementServer
		InventoryClientService
		rbac        *rbac.Policy
		authEnabled bool
	}
)

func (dms *DeviceManagementService) updateHost(
	ctx context.Context, tenantID, invResourceID string, fieldMask *fieldmaskpb.FieldMask, invHost *computev1.HostResource,
) error {
	if invHost == nil {
		err := errors.Errorfc(codes.InvalidArgument, "no resource provided")
		zlog.InfraSec().InfraErr(err).Msg("Empty resource is provided")
		return err
	}

	if len(fieldMask.Paths) == 0 {
		zlog.InfraSec().Debug().
			Msgf("Skipping, no fields selected to update for an inventory resource: %v, tenantID=%s",
				invHost.GetResourceId(), tenantID)
		return nil
	}

	var err error

	_, err = dms.invClient.Update(ctx, tenantID, invResourceID, fieldMask, &inventoryv1.Resource{
		Resource: &inventoryv1.Resource_Host{
			Host: invHost,
		},
	})
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to update resource (%s) for tenantID=%s", invResourceID, tenantID)
		return err
	}

	return nil
}

func NewDeviceManagementService(invClient client.TenantAwareInventoryClient,
	inventoryAdr string, _ bool,
	enableAuth bool, rbacRules string,
) (*DeviceManagementService, error) {
	var rbacPolicy *rbac.Policy
	var err error
	if enableAuth {
		zlog.Info().Msgf("Authentication is enabled, starting RBAC server for DeviceManagement Service")
		// start OPA server with policies
		rbacPolicy, err = rbac.New(rbacRules)
		if err != nil {
			zlog.Fatal().Msg("Failed to start RBAC OPA server")
		}
	}

	if inventoryAdr == "" {
		zlog.Warn().Msg("inventoryAdr is empty")
	}

	return &DeviceManagementService{
		InventoryClientService: InventoryClientService{
			invClient: invClient,
		},
		rbac:        rbacPolicy,
		authEnabled: enableAuth,
	}, nil
}

func (dms *DeviceManagementService) ReportAMTStatus(
	ctx context.Context, req *pb.AMTStatusRequest,
) (*pb.AMTStatusResponse, error) {
	zlog.Debug().Msgf("ReportAMTStatus started")

	if dms.authEnabled {
		if !dms.rbac.IsRequestAuthorized(ctx, rbac.CreateKey) {
			err := errors.Errorfc(codes.PermissionDenied, "Request is blocked by RBAC")
			zlog.InfraSec().InfraErr(err).Msgf("Request Device management is not authenticated")
			return nil, err
		}
	}

	tenantID, present := inv_tenant.GetTenantIDFromContext(ctx)
	if !present {
		err := errors.Errorfc(codes.Unauthenticated, "Tenant ID is missing from context")
		zlog.InfraSec().InfraErr(err).Msgf("Request Nodes is not authenticated")
		return nil, err
	}
	zlog.Debug().Msgf("ReportAMTStatus: tenantID=%s", tenantID)

	hostInv, err := dms.invClient.GetHostByUUID(ctx, tenantID, req.HostId)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to get host by UUID %s", req.HostId)
		if errors.IsNotFound(err) {
			zlog.Debug().Msgf("Node Doesn't Exist for UUID %s and tID=%s\n",
				req.HostId, tenantID)
			return nil, errors.Errorfc(codes.NotFound, "Host with UUID %s not found", req.HostId)
		}
	}
	if err = validator.ValidateMessage(hostInv); err != nil {
		zlog.InfraSec().InfraErr(err).Msg("")
		return nil, errors.Wrap(err)
	}
	zlog.Debug().Msgf("Request from PMA=%s", req.GetStatus().String())
	zlog.Debug().Msgf("hostInv AMTStatus=%s", hostInv.AmtStatus)
	if req.GetStatus() == pb.AMTStatus_ENABLED {
		err = dms.updateHost(ctx, hostInv.GetTenantId(), hostInv.GetResourceId(),
			&fieldmaskpb.FieldMask{Paths: []string{
				computev1.HostResourceFieldAmtStatus,
				computev1.HostResourceFieldAmtStatusIndicator,
			}}, &computev1.HostResource{
				AmtStatus:          status.AMTStatusEnabled.Status,
				AmtStatusIndicator: status.AMTStatusEnabled.StatusIndicator,
			})
		if err != nil {
			zlog.InfraSec().InfraErr(err).Msgf("Failed to update AMT status for host %s", hostInv.GetResourceId())
			return nil, errors.Errorfc(codes.Internal, "Failed to update AMT status: %v", err)
		}
	} else {
		err = dms.updateHost(ctx, hostInv.GetTenantId(), hostInv.GetResourceId(),
			&fieldmaskpb.FieldMask{Paths: []string{
				computev1.HostResourceFieldAmtStatus,
				computev1.HostResourceFieldAmtStatusIndicator,
			}}, &computev1.HostResource{
				AmtStatus:          status.AMTStatusDisabled.Status,
				AmtStatusIndicator: status.AMTStatusDisabled.StatusIndicator,
			})
		if err != nil {
			zlog.InfraSec().InfraErr(err).Msgf("Failed to update AMT status for host %s", hostInv.GetResourceId())
			return nil, errors.Errorfc(codes.Internal, "Failed to update AMT status: %v", err)
		}
	}
	return &pb.AMTStatusResponse{}, nil
}

//nolint:cyclop // high cyclomatic complexity because of the conditional logic.
func (dms *DeviceManagementService) RetrieveActivationDetails(
	ctx context.Context, req *pb.ActivationRequest,
) (*pb.ActivationDetailsResponse, error) {
	zlog.Info().Msgf("RetrieveActivationDetails")

	if dms.authEnabled {
		if !dms.rbac.IsRequestAuthorized(ctx, rbac.CreateKey) {
			err := errors.Errorfc(codes.PermissionDenied, "Request is blocked by RBAC")
			zlog.InfraSec().InfraErr(err).Msgf("Request Device management is not authenticated")
			return nil, err
		}
	}

	tenantID, present := inv_tenant.GetTenantIDFromContext(ctx)
	if !present {
		err := errors.Errorfc(codes.Unauthenticated, "Tenant ID is missing from context")
		zlog.InfraSec().InfraErr(err).Msgf("Request Nodes is not authenticated")
		return nil, err
	}
	zlog.Debug().Msgf("ReportAMTStatus: tenantID=%s", tenantID)

	var response *pb.ActivationDetailsResponse
	hostInv, err := dms.invClient.GetHostByUUID(ctx, tenantID, req.HostId)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to get host by UUID %s", req.HostId)
		if errors.IsNotFound(err) {
			zlog.Debug().Msgf("Node Doesn't Exist for UUID %s and tID=%s\n",
				req.HostId, tenantID)
			return nil, errors.Errorfc(codes.NotFound, "Host with UUID %s not found", req.HostId)
		}
	}
	if err = validator.ValidateMessage(hostInv); err != nil {
		zlog.InfraSec().InfraErr(err).Msg("")
		return nil, errors.Wrap(err)
	}

	zlog.Debug().Msgf("DesiredAmtState %s ", hostInv.DesiredAmtState.String())
	zlog.Debug().Msgf("CurrentAmtState %s ", hostInv.CurrentAmtState.String())

	if hostInv.DesiredAmtState == computev1.AmtState_AMT_STATE_PROVISIONED &&
		(hostInv.CurrentAmtState == computev1.AmtState_AMT_STATE_UNPROVISIONED ||
			hostInv.CurrentAmtState == computev1.AmtState_AMT_STATE_UNSPECIFIED) {
		zlog.Debug().Msgf("Send activation request for Host %s ", req.HostId)
		amtPassword := dms.SecretProvider.GetSecret(AmtPasswordSecretName, passwordKey)
		if amtPassword == "" {
			log.Error().Msgf("Couldn't get password from secret provider for host %s", req.HostId)
			return nil, errors.Errorfc(codes.Internal, "Failed to retrieve AMT password from secret provider")
		}
		response = &pb.ActivationDetailsResponse{
			Operation:      pb.OperationType_ACTIVATE,
			HostId:         req.HostId,
			ProfileName:    tenantID,
			ActionPassword: amtPassword,
		}
	} else {
		zlog.Debug().Msgf("Node is provisioned for UUID %s and tID=%s\n",
			req.HostId, tenantID)
		return nil, errors.Errorfc(codes.FailedPrecondition,
			"current state is %s or activation not requested by user %v", hostInv.CurrentAmtState, err)
	}

	return response, nil
}

//nolint:cyclop // high cyclomatic complexity because of the switch-case.
func (dms *DeviceManagementService) ReportActivationResults(
	ctx context.Context, req *pb.ActivationResultRequest,
) (*pb.ActivationResultResponse, error) {
	zlog.Info().Msgf("ReportActivationResults")

	if dms.authEnabled {
		if !dms.rbac.IsRequestAuthorized(ctx, rbac.CreateKey) {
			err := errors.Errorfc(codes.PermissionDenied, "Request is blocked by RBAC")
			zlog.InfraSec().InfraErr(err).Msgf("Request Device management is not authenticated")
			return nil, err
		}
	}

	tenantID, err := dms.getTenantFromContext(ctx)
	if err != nil {
		return nil, err
	}

	hostInv, err := dms.getHostByUUID(ctx, tenantID, req.HostId)
	if err != nil {
		return nil, err
	}
	if err = validator.ValidateMessage(hostInv); err != nil {
		zlog.InfraSec().InfraErr(err).Msg("")
		return nil, errors.Wrap(err)
	}
	// TODO: currently activation status is handled by dm-manager
	if hostInv.DesiredAmtState == computev1.AmtState_AMT_STATE_PROVISIONED {
		switch req.ActivationStatus {
		case pb.ActivationStatus_ACTIVATING:
			if hostInv.AmtStatus == status.AMTActivationStatusInProgress.Status {
				zlog.Debug().Msgf("Host %s AMT activation is already in progress", req.HostId)
				return nil, errors.Errorfc(codes.FailedPrecondition, "AMT activation is already in progress")
			}
			zlog.Debug().Msgf("Host %s AMT status is provisioning", req.HostId)
			err = dms.updateHost(ctx, hostInv.GetTenantId(), hostInv.GetResourceId(),
				&fieldmaskpb.FieldMask{Paths: []string{
					computev1.HostResourceFieldAmtStatus,
					computev1.HostResourceFieldAmtStatusIndicator,
				}}, &computev1.HostResource{
					AmtStatus:          status.AMTActivationStatusInProgress.Status,
					AmtStatusIndicator: status.AMTActivationStatusInProgress.StatusIndicator,
				})
			if err != nil {
				zlog.InfraSec().InfraErr(err).Msgf("Failed to update AMT state for host %s", hostInv.GetResourceId())
				return nil, errors.Errorfc(codes.Internal, "Failed to update AMT state: %v", err)
			}
		case pb.ActivationStatus_ACTIVATED:
			if hostInv.AmtStatus == status.AMTActivationStatusDone.Status &&
				hostInv.CurrentAmtState == computev1.AmtState_AMT_STATE_PROVISIONED {
				zlog.Debug().Msgf("Host %s AMT activation is already completed", req.HostId)
				return nil, errors.Errorfc(codes.FailedPrecondition, "AMT activation is already completed")
			}
			zlog.Debug().Msgf("Host %s AMT current is provisioned", req.HostId)
			err = dms.updateHost(ctx, hostInv.GetTenantId(), hostInv.GetResourceId(),
				&fieldmaskpb.FieldMask{Paths: []string{
					computev1.HostResourceFieldCurrentAmtState,
					computev1.HostResourceFieldAmtStatus,
					computev1.HostResourceFieldAmtStatusIndicator,
				}}, &computev1.HostResource{
					CurrentAmtState:    computev1.AmtState_AMT_STATE_PROVISIONED,
					AmtStatus:          status.AMTActivationStatusDone.Status,
					AmtStatusIndicator: status.AMTActivationStatusDone.StatusIndicator,
				})
			if err != nil {
				zlog.InfraSec().InfraErr(err).Msgf("Failed to update AMT state for host %s", hostInv.GetResourceId())
				return nil, errors.Errorfc(codes.Internal, "Failed to update AMT state: %v", err)
			}
		case pb.ActivationStatus_ACTIVATION_FAILED:
			if hostInv.AmtStatus == status.AMTActivationStatusFailed.Status &&
				hostInv.CurrentAmtState == computev1.AmtState_AMT_STATE_UNPROVISIONED {
				zlog.Debug().Msgf("Host %s AMT activation is already in failed state", req.HostId)
				return nil, errors.Errorfc(codes.FailedPrecondition, "AMT activation is already in failed state")
			}
			zlog.Debug().Msgf("Host %s AMT activation is Failed", req.HostId)
			err = dms.updateHost(ctx, hostInv.GetTenantId(), hostInv.GetResourceId(),
				&fieldmaskpb.FieldMask{Paths: []string{
					computev1.HostResourceFieldCurrentAmtState,
					computev1.HostResourceFieldAmtStatus,
					computev1.HostResourceFieldAmtStatusIndicator,
				}}, &computev1.HostResource{
					CurrentAmtState:    computev1.AmtState_AMT_STATE_UNPROVISIONED,
					AmtStatus:          status.AMTActivationStatusFailed.Status,
					AmtStatusIndicator: status.AMTActivationStatusFailed.StatusIndicator,
				})
			if err != nil {
				zlog.InfraSec().InfraErr(err).Msgf("Failed to update AMT state for host %s", hostInv.GetResourceId())
				return nil, errors.Errorfc(codes.Internal, "Failed to update AMT state: %v", err)
			}
		default:
			return nil, errors.Errorfc(codes.InvalidArgument, "Invalid activation status: %s", req.ActivationStatus)
		}
		zlog.Debug().Msgf("Host %s AMT activation result reported successfully", req.HostId)
		return &pb.ActivationResultResponse{}, nil
	}

	return nil, errors.Errorfc(codes.FailedPrecondition,
		"AMT is trying to set existing current state: %s", hostInv.CurrentAmtState)
}

func (dms *DeviceManagementService) getTenantFromContext(ctx context.Context) (string, error) {
	tenantID, present := inv_tenant.GetTenantIDFromContext(ctx)
	if !present {
		err := errors.Errorfc(codes.Unauthenticated, "Tenant ID is missing from context")
		zlog.InfraSec().InfraErr(err).Msgf("Request Nodes is not authenticated")
		return "", err
	}
	return tenantID, nil
}

func (dms *DeviceManagementService) getHostByUUID(ctx context.Context, tenantID, hostID string) (*computev1.HostResource, error) {
	hostInv, err := dms.invClient.GetHostByUUID(ctx, tenantID, hostID)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to get host by UUID %s", hostID)
		if errors.IsNotFound(err) {
			return nil, errors.Errorfc(codes.NotFound, "Host with UUID %s not found", hostID)
		}
		return nil, err
	}
	return hostInv, nil
}
