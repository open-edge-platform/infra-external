package grpcserver

import (
	"context"

	computev1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/compute/v1"
	inventoryv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	inv_errors "github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	inv_tenant "github.com/open-edge-platform/infra-core/inventory/v2/pkg/tenant"
	pb "github.com/open-edge-platform/infra-external/dm-manager/pkg/api/dm-manager"

	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/policy/rbac"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

var (
	name = "DeviceManagementService"
	zlog = logging.GetLogger(name)
)

type InventoryClientService struct {
	invClient client.TenantAwareInventoryClient
}

type (
	DeviceManagementService struct {
		pb.UnimplementedDeviceManagementServer
		InventoryClientService
		rbac        *rbac.Policy
		authEnabled bool
	}
)

func (dms *DeviceManagementService) checkRBACAuth(ctx context.Context) error {
	if dms.authEnabled {
		if !dms.rbac.IsRequestAuthorized(ctx, rbac.CreateKey) {
			err := inv_errors.Errorfc(codes.PermissionDenied, "Request is blocked by RBAC")
			zlog.InfraSec().InfraErr(err).Msgf("Request Device management is not authenticated")
			return err
		}
	}
	return nil
}

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

func NewDeviceManagementService(invClient *client.TenantAwareInventoryClient,
	inventoryAdr string, enableTracing bool,
	enableAuth bool, rbacRules string) (*DeviceManagementService, error) {
	if invClient == nil {
		return nil, inv_errors.Errorf("invClient is nil in NewInteractiveOnboardingService")
	}

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
			invClient: *invClient,
		},
		rbac:        rbacPolicy,
		authEnabled: enableAuth,
	}, nil
}

func (dms *DeviceManagementService) ReportAMTStatus(ctx context.Context, req *pb.AMTStatusRequest) (*pb.AMTStatusResponse, error) {

	zlog.Debug().Msgf("ReportAMTStatus started")

	err := dms.checkRBACAuth(ctx)
	if err != nil {
		return nil, err
	}

	tenantID, present := inv_tenant.GetTenantIDFromContext(ctx)
	if !present {
		err := inv_errors.Errorfc(codes.Unauthenticated, "Tenant ID is missing from context")
		zlog.InfraSec().InfraErr(err).Msgf("Request CreateNodes is not authenticated")
		return nil, err
	}
	zlog.Debug().Msgf("ReportAMTStatus: tenantID=%s", tenantID)

	hostInv, err := dms.invClient.GetHostByUUID(ctx, tenantID, req.HostId)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to get host by UUID %s", req.HostId)
		if inv_errors.IsNotFound(err) {
			zlog.Debug().Msgf("Node Doesn't Exist for UUID %s and tID=%s\n",
				req.HostId, tenantID)
			return nil, inv_errors.Errorfc(codes.NotFound, "Host with UUID %s not found", req.HostId)
		}
	}
	if hostInv.AmtStatus != req.GetStatus().String() {
		err = dms.updateHost(ctx, hostInv.GetTenantId(), hostInv.GetResourceId(),
			&fieldmaskpb.FieldMask{Paths: []string{
				computev1.HostResourceFieldAmtStatus,
			}}, &computev1.HostResource{
				AmtStatus: hostInv.AmtStatus,
			})
		if err != nil {
			zlog.InfraSec().InfraErr(err).Msgf("Failed to update AMT status for host %s", hostInv.GetResourceId())
			return nil, inv_errors.Errorfc(codes.Internal, "Failed to update AMT status: %v", err)
		}
	}
	return nil, inv_errors.Errorfc(codes.FailedPrecondition, "AMT status is already set to %s", hostInv.AmtStatus)
}

func (dms *DeviceManagementService) RetrieveActivationDetails(ctx context.Context, req *pb.ActivationRequest) (*pb.ActivationDetailsResponse, error) {

	zlog.Info().Msgf("RetrieveActivationDetails")

	// err := dms.checkRBACAuth(ctx)
	// if err != nil {
	// 	return nil, err
	// }

	tenantID, present := inv_tenant.GetTenantIDFromContext(ctx)
	if !present {
		err := inv_errors.Errorfc(codes.Unauthenticated, "Tenant ID is missing from context")
		zlog.InfraSec().InfraErr(err).Msgf("Request CreateNodes is not authenticated")
		return nil, err
	}
	zlog.Debug().Msgf("ReportAMTStatus: tenantID=%s", tenantID)

	var hostInv *computev1.HostResource
	var response *pb.ActivationDetailsResponse
	hostInv, err := dms.invClient.GetHostByUUID(ctx, tenantID, req.HostId)
	switch {
	case inv_errors.IsNotFound(err):
		zlog.Debug().Msgf("Node Doesn't Exist for UUID %s and tID=%s\n",
			req.HostId, tenantID)
	case err == nil:
		if hostInv.CurrentAmtState == computev1.AmtState_AMT_STATE_PROVISIONED {
			zlog.Debug().Msgf("Host %s AMT is provisioned", req.HostId)
			return nil, nil

		} else {
			response = &pb.ActivationDetailsResponse{
				Operation:   pb.OperationType_ACTIVATE,
				HostId:      req.HostId,
				ProfileName: tenantID,
			}
			hostInv.CurrentAmtState = computev1.AmtState_AMT_STATE_UNPROVISIONED
			hostInv.DesiredAmtState = computev1.AmtState_AMT_STATE_PROVISIONED
		}
	}
	err = dms.updateHost(ctx, hostInv.GetTenantId(), hostInv.GetResourceId(),
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.HostResourceFieldCurrentAmtState,
			computev1.HostResourceFieldDesiredAmtState,
		}}, &computev1.HostResource{
			CurrentAmtState: hostInv.CurrentAmtState,
			DesiredAmtState: hostInv.DesiredAmtState,
		})

	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to update AMT state for host %s", hostInv.GetResourceId())
		return nil, inv_errors.Errorfc(codes.Internal, "Failed to update AMT state: %v", err)
	}

	return response, nil
}

func (dms *DeviceManagementService) ReportActivationResults(ctx context.Context, req *pb.ActivationResultRequest) (*pb.ActivationResultResponse, error) {

	zlog.Info().Msgf("ReportActivationResults")

	// err := dms.checkRBACAuth(ctx)
	// if err != nil {
	// 	return nil, err
	// }

	tenantID, present := inv_tenant.GetTenantIDFromContext(ctx)
	if !present {
		err := inv_errors.Errorfc(codes.Unauthenticated, "Tenant ID is missing from context")
		zlog.InfraSec().InfraErr(err).Msgf("Request CreateNodes is not authenticated")
		return nil, err
	}
	zlog.Debug().Msgf("ReportAMTStatus: tenantID=%s", tenantID)

	var hostInv *computev1.HostResource
	hostInv, err := dms.invClient.GetHostByUUID(ctx, tenantID, req.HostId)
	switch {
	case inv_errors.IsNotFound(err):
		zlog.Debug().Msgf("Node Doesn't Exist for UUID %s and tID=%s\n",
			req.HostId, tenantID)
	case err == nil:
		if req.ActivationStatus.String() == computev1.AmtState_AMT_STATE_PROVISIONED.String() {
			zlog.Debug().Msgf("Host %s AMT is enabled", req.HostId)
			hostInv.CurrentAmtState = computev1.AmtState_AMT_STATE_PROVISIONED

		} else {
			zlog.Debug().Msgf("Host %s AMT is not Unprovisioned", req.HostId)
			hostInv.CurrentAmtState = computev1.AmtState_AMT_STATE_UNPROVISIONED
		}
	}
	err = dms.updateHost(ctx, hostInv.GetTenantId(), hostInv.GetResourceId(),
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.HostResourceFieldCurrentAmtState,
		}}, &computev1.HostResource{
			CurrentAmtState: hostInv.CurrentAmtState,
		})

	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to update AMT state for host %s", hostInv.GetResourceId())
		return nil, inv_errors.Errorfc(codes.Internal, "Failed to update AMT state: %v", err)
	}
	return &pb.ActivationResultResponse{}, nil

}
