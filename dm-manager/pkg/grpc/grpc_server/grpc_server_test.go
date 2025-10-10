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
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/flags"
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

// MockSecretProvider is a mock implementation of SecretProvider.
type MockSecretProvider struct {
	mock.Mock
}

func (m *MockSecretProvider) GetSecret(secretName, key string) string {
	args := m.Called(secretName, key)
	return args.String(0)
}

func (m *MockSecretProvider) Init(ctx context.Context, args []string) error {
	mockArgs := m.Called(ctx, args)
	return mockArgs.Error(0)
}

// Helper function to create context with test tenant ID.
func createContextWithTenant() context.Context {
	return inv_tenant.AddTenantIDToContext(context.Background(), "bdd62a25-d5fe-4d65-8c5d-60508b2b7b7d")
}

// Helper function to create context without tenant ID.
func createContextWithoutTenant() context.Context {
	return context.Background()
}

// Helper function to create a service instance for testing.
func createTestService(mockInvClient *MockInventoryClient, authEnabled bool) (*grpcserver.DeviceManagementService, error) {
	// Disable credentials management for testing
	*flags.FlagDisableCredentialsManagement = true

	var invClient client.TenantAwareInventoryClient = mockInvClient
	service, err := grpcserver.NewDeviceManagementService(
		invClient,
		"test-address",
		false, // enableTracing
		authEnabled,
		"test-rbac",
	)
	if err != nil {
		return nil, err
	}

	// Set up mock secret provider
	mockSecretProvider := &MockSecretProvider{}
	mockSecretProvider.On("GetSecret", "amt-password", "password").Return("test-password")
	service.SecretProvider = mockSecretProvider

	return service, nil
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
					ResourceId: "host-12345678",
					Name:       "test-host",
					Uuid:       "bdd62a25-d5fe-4d65-8c5d-60508b2b7b7d",
					TenantId:   "bdd62a25-d5fe-4d65-8c5d-60508b2b7b7d",
				}
				mockInvClient.On("GetHostByUUID", mock.Anything,
					"bdd62a25-d5fe-4d65-8c5d-60508b2b7b7d", "host-12345678").Return(hostResource, nil)
				mockInvClient.On("Update", mock.Anything, "bdd62a25-d5fe-4d65-8c5d-60508b2b7b7d", "host-12345678",
					mock.Anything, mock.Anything).Return(&inventoryv1.Resource{}, nil)
			},
			context: createContextWithTenant(),
			request: &pb.AMTStatusRequest{
				HostId:  "host-12345678",
				Status:  pb.AMTStatus_ENABLED,
				Feature: "AMT",
			},
			authEnabled:    false,
			expectedError:  codes.OK,
			expectedResult: true,
		},
		{
			name: "successful ISM status report",
			setupMocks: func(mockInvClient *MockInventoryClient, _ *MockRBACPolicy) {
				hostResource := &computev1.HostResource{
					ResourceId: "host-12345678",
					Name:       "test-host",
					Uuid:       "bdd62a25-d5fe-4d65-8c5d-60508b2b7b7d",
					TenantId:   "bdd62a25-d5fe-4d65-8c5d-60508b2b7b7d",
				}
				mockInvClient.On("GetHostByUUID", mock.Anything,
					"bdd62a25-d5fe-4d65-8c5d-60508b2b7b7d", "host-12345678").Return(hostResource, nil)
				mockInvClient.On("Update", mock.Anything, "bdd62a25-d5fe-4d65-8c5d-60508b2b7b7d", "host-12345678",
					mock.Anything, mock.Anything).Return(&inventoryv1.Resource{}, nil)
			},
			context: createContextWithTenant(),
			request: &pb.AMTStatusRequest{
				HostId:  "host-12345678",
				Status:  pb.AMTStatus_ENABLED,
				Feature: "ISM",
			},
			authEnabled:    false,
			expectedError:  codes.OK,
			expectedResult: true,
		},
		{
			name: "Empty string for Feature field",
			setupMocks: func(mockInvClient *MockInventoryClient, _ *MockRBACPolicy) {
				hostResource := &computev1.HostResource{
					ResourceId: "host-12345678",
					Name:       "test-host",
					Uuid:       "bdd62a25-d5fe-4d65-8c5d-60508b2b7b7d",
					TenantId:   "bdd62a25-d5fe-4d65-8c5d-60508b2b7b7d",
				}
				mockInvClient.On("GetHostByUUID", mock.Anything,
					"bdd62a25-d5fe-4d65-8c5d-60508b2b7b7d", "host-12345678").Return(hostResource, nil)
				// No Update mock expectation since the function should return an error before calling Update
			},
			context: createContextWithTenant(),
			request: &pb.AMTStatusRequest{
				HostId:  "host-12345678",
				Status:  pb.AMTStatus_ENABLED,
				Feature: "",
			},
			authEnabled:    false,
			expectedError:  codes.InvalidArgument,
			expectedResult: false,
		},
		{
			name: "missing tenant ID",
			setupMocks: func(_ *MockInventoryClient, _ *MockRBACPolicy) {
				// No setup needed as tenant validation happens first
			},
			context: createContextWithoutTenant(),
			request: &pb.AMTStatusRequest{
				HostId: "host-12345678",
				Status: pb.AMTStatus_ENABLED,
			},
			authEnabled:    false,
			expectedError:  codes.Unauthenticated,
			expectedResult: false,
		},
		{
			name: "host not found",
			setupMocks: func(mockInvClient *MockInventoryClient, _ *MockRBACPolicy) {
				mockInvClient.On("GetHostByUUID", mock.Anything, "bdd62a25-d5fe-4d65-8c5d-60508b2b7b7d",
					"host-12345678").Return(nil, inv_errors.Errorfc(codes.NotFound, "host not found"))
			},
			context: createContextWithTenant(),
			request: &pb.AMTStatusRequest{
				HostId: "host-12345678",
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

			service, err := createTestService(mockInvClient, tt.authEnabled)
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
					ResourceId:      "host-12345678",
					Name:            "test-host",
					Uuid:            "bdd62a25-d5fe-4d65-8c5d-60508b2b7b7d",
					TenantId:        "bdd62a25-d5fe-4d65-8c5d-60508b2b7b7d",
					DesiredAmtState: computev1.AmtState_AMT_STATE_PROVISIONED,
					CurrentAmtState: computev1.AmtState_AMT_STATE_UNPROVISIONED,
					AmtStatus:       "ENABLED",
				}
				mockInvClient.On("GetHostByUUID", mock.Anything,
					"bdd62a25-d5fe-4d65-8c5d-60508b2b7b7d", "host-12345678").Return(hostResource, nil)
			},
			context: createContextWithTenant(),
			request: &pb.ActivationRequest{
				HostId: "host-12345678",
			},
			authEnabled:   false,
			expectedError: codes.OK,
			expectedResult: &pb.ActivationDetailsResponse{
				HostId:      "host-12345678",
				Operation:   pb.OperationType_ACTIVATE,
				ProfileName: "bdd62a25-d5fe-4d65-8c5d-60508b2b7b7d",
			},
		},
		{
			name: "missing tenant ID",
			setupMocks: func(_ *MockInventoryClient, _ *MockRBACPolicy) {
				// No setup needed as tenant validation happens first
			},
			context: createContextWithoutTenant(),
			request: &pb.ActivationRequest{
				HostId: "host-12345678",
			},
			authEnabled:    false,
			expectedError:  codes.Unauthenticated,
			expectedResult: nil,
		},
		{
			name: "host not found",
			setupMocks: func(mockInvClient *MockInventoryClient, _ *MockRBACPolicy) {
				mockInvClient.On("GetHostByUUID", mock.Anything, "bdd62a25-d5fe-4d65-8c5d-60508b2b7b7d",
					"host-12345678").Return(nil, inv_errors.Errorfc(codes.NotFound, "host not found"))
			},
			context: createContextWithTenant(),
			request: &pb.ActivationRequest{
				HostId: "host-12345678",
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

			service, err := createTestService(mockInvClient, tt.authEnabled)
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
					ResourceId:      "host-12345678",
					Name:            "test-host",
					Uuid:            "bdd62a25-d5fe-4d65-8c5d-60508b2b7b7d",
					TenantId:        "bdd62a25-d5fe-4d65-8c5d-60508b2b7b7d",
					DesiredAmtState: computev1.AmtState_AMT_STATE_PROVISIONED,
				}
				mockInvClient.On("GetHostByUUID", mock.Anything,
					"bdd62a25-d5fe-4d65-8c5d-60508b2b7b7d", "host-12345678").Return(hostResource, nil)
				mockInvClient.On("Update", mock.Anything, "bdd62a25-d5fe-4d65-8c5d-60508b2b7b7d",
					"host-12345678", mock.Anything,
					mock.Anything).Return(&inventoryv1.Resource{}, nil)
			},
			context: createContextWithTenant(),
			request: &pb.ActivationResultRequest{
				HostId:           "host-12345678",
				ActivationStatus: pb.ActivationStatus_ACTIVATED,
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
				HostId:           "host-12345678",
				ActivationStatus: pb.ActivationStatus_ACTIVATED,
			},
			authEnabled:    false,
			expectedError:  codes.Unauthenticated,
			expectedResult: false,
		},
		{
			name: "host not found",
			setupMocks: func(mockInvClient *MockInventoryClient, _ *MockRBACPolicy) {
				mockInvClient.On("GetHostByUUID", mock.Anything,
					"bdd62a25-d5fe-4d65-8c5d-60508b2b7b7d", "host-12345678").Return(nil,
					inv_errors.Errorfc(codes.NotFound, "host not found"))
			},
			context: createContextWithTenant(),
			request: &pb.ActivationResultRequest{
				HostId:           "host-12345678",
				ActivationStatus: pb.ActivationStatus_ACTIVATED,
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

			service, err := createTestService(mockInvClient, tt.authEnabled)
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
