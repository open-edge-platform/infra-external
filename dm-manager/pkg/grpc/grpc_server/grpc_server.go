package grpcserver

import (
	pb "github.com/open-edge-platform/infra-external/dm-manager/pkg/api/dm-manager"
	"github.com/open-edge-platform/infra-onboarding/onboarding-manager/internal/invclient"
)

type InventoryClientService struct {
	invClient    *invclient.OnboardingInventoryClient
	invClientAPI *invclient.OnboardingInventoryClient
}

type (
	DeviceManagement struct {
		pb.UnimplementedDeviceManagementServer
		InventoryClientService
	}
)
