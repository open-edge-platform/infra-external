// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package grpcserver_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	computev1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/compute/v1"
	inventoryv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	inv_errors "github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	inv_tenant "github.com/open-edge-platform/infra-core/inventory/v2/pkg/tenant"
	pb "github.com/open-edge-platform/infra-external/dm-manager/pkg/api/dm-manager"
	grpcserver "github.com/open-edge-platform/infra-external/dm-manager/pkg/grpc/grpc_server"
)

// MockInventoryClient is a mock implementation of TenantAwareInventoryClient.
type MockInventoryClient struct {
	mock.Mock
	client.TenantAwareInventoryClient
}

func (m *MockInventoryClient) GetHostByUUID(ctx context.Context, tenantID, hostUUID string) (*computev1.HostResource, error) {
	args := m.Called(ctx, tenantID, hostUUID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	result, ok := args.Get(0).(*computev1.HostResource)
	if !ok {
		return nil, args.Error(1)
	}
	return result, args.Error(1)
}

func (m *MockInventoryClient) Update(ctx context.Context, tenantID,
	resourceID string, fieldMask *fieldmaskpb.FieldMask,
	resource *inventoryv1.Resource,
) (*inventoryv1.Resource, error) {
	args := m.Called(ctx, tenantID, resourceID, fieldMask, resource)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	result, ok := args.Get(0).(*inventoryv1.Resource)
	if !ok {
		return nil, args.Error(1)
	}
	return result, args.Error(1)
}

// MockRBACPolicy is a mock implementation of RBAC Policy.
type MockRBACPolicy struct {
	mock.Mock
}

func (m *MockRBACPolicy) IsRequestAuthorized(ctx context.Context, action string) bool {
	args := m.Called(ctx, action)
	return args.Bool(0)
}

func (m *MockRBACPolicy) Verify(ctx context.Context, operation string) error {
	args := m.Called(ctx, operation)
	return args.Error(0)
}

// Helper function to create context with tenant ID.
func createContextWithTenant(_ string) context.Context {
	return inv_tenant.AddTenantIDToContext(context.Background(), "tenant-123")
}

// Helper function to create context without tenant ID.
func createContextWithoutTenant() context.Context {
	return context.Background()
}

func TestReportAMTStatus(t *testing.T) {
	tests := []struct {
		name           string
		setupMocks     func(*MockInventoryClient, *MockRBACPolicy)
		context        context.Context
		request        *pb.AMTStatusRequest
		authEnabled    bool
		expectedError  codes.Code
		expectedResult bool
	}{
		{
			name: "successful AMT status report",
			setupMocks: func(mockInvClient *MockInventoryClient, _ *MockRBACPolicy) {
				hostResource := &computev1.HostResource{
					ResourceId: "host-123",
					Name:       "test-host",
					Uuid:       "host-uuid-123",
					TenantId:   "tenant-123",
				}
				mockInvClient.On("GetHostByUUID", mock.Anything, "tenant-123", "host-123").Return(hostResource, nil)
				mockInvClient.On("Update", mock.Anything, "tenant-123", "host-123",
					mock.Anything, mock.Anything).Return(&inventoryv1.Resource{}, nil)
			},
			context: createContextWithTenant("tenant-123"),
			request: &pb.AMTStatusRequest{
				HostId: "host-123",
				Status: pb.AMTStatus_ENABLED,
			},
			authEnabled:    false,
			expectedError:  codes.OK,
			expectedResult: true,
		},
		{
			name: "missing tenant ID",
			setupMocks: func(_ *MockInventoryClient, _ *MockRBACPolicy) {
				// No setup needed as tenant validation happens first
			},
			context: createContextWithoutTenant(),
			request: &pb.AMTStatusRequest{
				HostId: "host-123",
				Status: pb.AMTStatus_ENABLED,
			},
			authEnabled:    false,
			expectedError:  codes.Unauthenticated,
			expectedResult: false,
		},
		{
			name: "host not found",
			setupMocks: func(mockInvClient *MockInventoryClient, _ *MockRBACPolicy) {
				mockInvClient.On("GetHostByUUID", mock.Anything, "tenant-123",
					"host-123").Return(nil, inv_errors.Errorfc(codes.NotFound, "host not found"))
			},
			context: createContextWithTenant("tenant-123"),
			request: &pb.AMTStatusRequest{
				HostId: "host-123",
				Status: pb.AMTStatus_ENABLED,
			},
			authEnabled:    false,
			expectedError:  codes.NotFound,
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockInvClient := &MockInventoryClient{}
			mockRBAC := &MockRBACPolicy{}
			tt.setupMocks(mockInvClient, mockRBAC)

			// Create a service instance for testing with proper interface implementation
			var invClient client.TenantAwareInventoryClient = mockInvClient
			service, err := grpcserver.NewDeviceManagementService(
				invClient,
				"test-address",
				false, // enableTracing
				tt.authEnabled,
				"test-rbac",
			)
			if err != nil {
				t.Fatalf("Failed to create service: %v", err)
			}

			response, err := service.ReportAMTStatus(tt.context, tt.request)

			if tt.expectedError == codes.OK {
				assert.NoError(t, err)
				if tt.expectedResult {
					assert.NotNil(t, response)
				}
			} else {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, status.Code(err))
			}

			mockInvClient.AssertExpectations(t)
			mockRBAC.AssertExpectations(t)
		})
	}
}

func TestRetrieveActivationDetails(t *testing.T) {
	tests := []struct {
		name           string
		setupMocks     func(*MockInventoryClient, *MockRBACPolicy)
		context        context.Context
		request        *pb.ActivationRequest
		authEnabled    bool
		expectedError  codes.Code
		expectedResult *pb.ActivationDetailsResponse
	}{
		{
			name: "successful activation details retrieval",
			setupMocks: func(mockInvClient *MockInventoryClient, _ *MockRBACPolicy) {
				hostResource := &computev1.HostResource{
					ResourceId:      "host-123",
					Name:            "test-host",
					Uuid:            "host-uuid-123",
					TenantId:        "tenant-123",
					DesiredAmtState: computev1.AmtState_AMT_STATE_PROVISIONED,
					CurrentAmtState: computev1.AmtState_AMT_STATE_UNPROVISIONED,
				}
				mockInvClient.On("GetHostByUUID", mock.Anything, "tenant-123", "host-123").Return(hostResource, nil)
			},
			context: createContextWithTenant("tenant-123"),
			request: &pb.ActivationRequest{
				HostId: "host-123",
			},
			authEnabled:   false,
			expectedError: codes.OK,
			expectedResult: &pb.ActivationDetailsResponse{
				HostId:      "host-123",
				Operation:   pb.OperationType_ACTIVATE,
				ProfileName: "tenant-123",
			},
		},
		{
			name: "missing tenant ID",
			setupMocks: func(_ *MockInventoryClient, _ *MockRBACPolicy) {
				// No setup needed as tenant validation happens first
			},
			context: createContextWithoutTenant(),
			request: &pb.ActivationRequest{
				HostId: "host-123",
			},
			authEnabled:    false,
			expectedError:  codes.Unauthenticated,
			expectedResult: nil,
		},
		{
			name: "host not found",
			setupMocks: func(mockInvClient *MockInventoryClient, _ *MockRBACPolicy) {
				mockInvClient.On("GetHostByUUID", mock.Anything, "tenant-123",
					"host-123").Return(nil, inv_errors.Errorfc(codes.NotFound, "host not found"))
			},
			context: createContextWithTenant("tenant-123"),
			request: &pb.ActivationRequest{
				HostId: "host-123",
			},
			authEnabled:    false,
			expectedError:  codes.NotFound,
			expectedResult: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockInvClient := &MockInventoryClient{}
			mockRBAC := &MockRBACPolicy{}
			tt.setupMocks(mockInvClient, mockRBAC)

			var invClient client.TenantAwareInventoryClient = mockInvClient
			service, err := grpcserver.NewDeviceManagementService(
				invClient,
				"test-address",
				false, // enableTracing
				tt.authEnabled,
				"test-rbac",
			)
			if err != nil {
				t.Fatalf("Failed to create service: %v", err)
			}

			response, err := service.RetrieveActivationDetails(tt.context, tt.request)

			if tt.expectedError == codes.OK {
				assert.NoError(t, err)
				assert.NotNil(t, response)
				if tt.expectedResult != nil {
					assert.Equal(t, tt.expectedResult.HostId, response.HostId)
					assert.Equal(t, tt.expectedResult.Operation, response.Operation)
					assert.Equal(t, tt.expectedResult.ProfileName, response.ProfileName)
				}
			} else {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, status.Code(err))
				assert.Nil(t, response)
			}

			mockInvClient.AssertExpectations(t)
			mockRBAC.AssertExpectations(t)
		})
	}
}

func TestReportActivationResults(t *testing.T) {
	tests := []struct {
		name           string
		setupMocks     func(*MockInventoryClient, *MockRBACPolicy)
		context        context.Context
		request        *pb.ActivationResultRequest
		authEnabled    bool
		expectedError  codes.Code
		expectedResult bool
	}{
		{
			name: "successful activation result report",
			setupMocks: func(mockInvClient *MockInventoryClient, _ *MockRBACPolicy) {
				hostResource := &computev1.HostResource{
					ResourceId: "host-123",
					Name:       "test-host",
					Uuid:       "host-uuid-123",
					TenantId:   "tenant-123",
				}
				mockInvClient.On("GetHostByUUID", mock.Anything, "tenant-123", "host-123").Return(hostResource, nil)
				mockInvClient.On("Update", mock.Anything, "tenant-123",
					"host-123", mock.Anything,
					mock.Anything).Return(&inventoryv1.Resource{}, nil)
			},
			context: createContextWithTenant("tenant-123"),
			request: &pb.ActivationResultRequest{
				HostId:           "host-123",
				ActivationStatus: pb.ActivationStatus_PROVISIONED,
			},
			authEnabled:    false,
			expectedError:  codes.OK,
			expectedResult: true,
		},
		{
			name: "missing tenant ID",
			setupMocks: func(_ *MockInventoryClient, _ *MockRBACPolicy) {
				// No setup needed as tenant validation happens first
			},
			context: createContextWithoutTenant(),
			request: &pb.ActivationResultRequest{
				HostId:           "host-123",
				ActivationStatus: pb.ActivationStatus_PROVISIONED,
			},
			authEnabled:    false,
			expectedError:  codes.Unauthenticated,
			expectedResult: false,
		},
		{
			name: "host not found",
			setupMocks: func(mockInvClient *MockInventoryClient, _ *MockRBACPolicy) {
				mockInvClient.On("GetHostByUUID", mock.Anything,
					"tenant-123", "host-123").Return(nil,
					inv_errors.Errorfc(codes.NotFound, "host not found"))
			},
			context: createContextWithTenant("tenant-123"),
			request: &pb.ActivationResultRequest{
				HostId:           "host-123",
				ActivationStatus: pb.ActivationStatus_PROVISIONED,
			},
			authEnabled:    false,
			expectedError:  codes.NotFound,
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockInvClient := &MockInventoryClient{}
			mockRBAC := &MockRBACPolicy{}
			tt.setupMocks(mockInvClient, mockRBAC)

			var invClient client.TenantAwareInventoryClient = mockInvClient
			service, err := grpcserver.NewDeviceManagementService(
				invClient,
				"test-address",
				false, // enableTracing
				tt.authEnabled,
				"test-rbac",
			)
			if err != nil {
				t.Fatalf("Failed to create service: %v", err)
			}

			response, err := service.ReportActivationResults(tt.context, tt.request)

			if tt.expectedError == codes.OK {
				assert.NoError(t, err)
				if tt.expectedResult {
					assert.NotNil(t, response)
				}
			} else {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError, status.Code(err))
			}

			mockInvClient.AssertExpectations(t)
			mockRBAC.AssertExpectations(t)
		})
	}
}
