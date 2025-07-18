package grpcserver

import (
	"context"

	"github.com/intel-innersource/frameworks.edge.one-intel-edge.maestro-infra.services.inventory/v2/pkg/logging"
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

}

func (dms *DeviceManagementService) ReportAMTStatus(ctx context.Context, req *pb.AMTStatusRequest) (*pb.AMTStatusResponse, error) {

	zlog.Info().Msgf("CreateNodes")

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
	zlog.Debug().Msgf("CreateNodes: tenantID=%s", tenantID)

}
