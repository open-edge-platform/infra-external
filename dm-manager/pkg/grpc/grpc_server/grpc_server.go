package grpcserver

import (
	"context"

	"github.com/intel-innersource/frameworks.edge.one-intel-edge.maestro-infra.services.inventory/v2/pkg/logging"
	computev1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/compute/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	inv_errors "github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/policy/rbac"
	inv_tenant "github.com/open-edge-platform/infra-core/inventory/v2/pkg/tenant"
	pb "github.com/open-edge-platform/infra-external/dm-manager/pkg/api/dm-manager"
	"google.golang.org/grpc/codes"
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

func CopyNodeReqToNodeData(req *pb.AMTStatusRequest, tenantID string) (*computev1.HostResource, error) {
	if req == nil {
		return nil, inv_errors.Errorf("AMTStatusRequest is nil")
	}

	if req.HostId == "" {
		return nil, inv_errors.Errorf("HostId is required in AMTStatusRequest")
	}

	hostres := &computev1.HostResource{
		Uuid:      req.HostId, // Using HostId as UUID
		AmtStatus: req.Status.String(),
		TenantId:  tenantID,
		// You can add more fields here based on your requirements
	}

	zlog.Debug().Msgf("Adding HostResource: %v", hostres)

	return hostres, nil
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

	zlog.Info().Msgf("ReportAMTStatus")

	if dms.authEnabled {
		// checking if JWT contains write permission
		if !dms.rbac.IsRequestAuthorized(ctx, rbac.CreateKey) {
			err := inv_errors.Errorfc(codes.PermissionDenied, "Request is blocked by RBAC")
			zlog.InfraSec().InfraErr(err).Msgf("Request CreateNodes is not authenticated")
			return nil, err
		}
	}

	tenantID, present := inv_tenant.GetTenantIDFromContext(ctx)
	if !present {
		err := inv_errors.Errorfc(codes.Unauthenticated, "Tenant ID is missing from context")
		zlog.InfraSec().InfraErr(err).Msgf("Request CreateNodes is not authenticated")
		return nil, err
	}
	zlog.Debug().Msgf("ReportAMTStatus: tenantID=%s", tenantID)

	hostresdata, err := CopyNodeReqToNodeData(req, tenantID)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("CopyNodeReqToNodeData error: %v", err)
		return nil, err
	}

	var hostInv *computev1.HostResource
	hostInv, err = dms.invClient.GetHostByUUID(ctx, tenantID, hostresdata.Uuid)
	switch {
	case inv_errors.IsNotFound(err):
		zlog.Debug().Msgf("Node Doesn't Exist for UUID %s and tID=%s\n",
			hostresdata.Uuid, tenantID)
	case err == nil:
		hostInv.AmtStatus = hostresdata.AmtStatus

	}
	return &pb.AMTStatusResponse{}, nil

}
