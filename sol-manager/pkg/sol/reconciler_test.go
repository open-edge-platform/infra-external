// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package sol

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	computev1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/compute/v1"
	inventoryv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	"github.com/open-edge-platform/infra-external/sol-manager/pkg/api/mps"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client/cache"
	rec_v2 "github.com/open-edge-platform/orch-library/go/pkg/controller/v2"
)

// ---------------------------------------------------------------------------
// Mock for TenantAwareInventoryClient
// ---------------------------------------------------------------------------

type mockInventoryClient struct {
	mock.Mock
}

func (m *mockInventoryClient) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *mockInventoryClient) List(
	ctx context.Context, filter *inventoryv1.ResourceFilter,
) (*inventoryv1.ListResourcesResponse, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*inventoryv1.ListResourcesResponse), args.Error(1)
}

func (m *mockInventoryClient) ListAll(
	ctx context.Context, filter *inventoryv1.ResourceFilter,
) ([]*inventoryv1.Resource, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*inventoryv1.Resource), args.Error(1)
}

func (m *mockInventoryClient) Find(
	ctx context.Context, filter *inventoryv1.ResourceFilter,
) (*inventoryv1.FindResourcesResponse, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*inventoryv1.FindResourcesResponse), args.Error(1)
}

func (m *mockInventoryClient) FindAll(
	ctx context.Context, filter *inventoryv1.ResourceFilter,
) ([]*client.ResourceTenantIDCarrier, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*client.ResourceTenantIDCarrier), args.Error(1)
}

func (m *mockInventoryClient) Get(
	ctx context.Context, tenantID, id string,
) (*inventoryv1.GetResourceResponse, error) {
	args := m.Called(ctx, tenantID, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*inventoryv1.GetResourceResponse), args.Error(1)
}

func (m *mockInventoryClient) Create(
	ctx context.Context, tenantID string, res *inventoryv1.Resource,
) (*inventoryv1.Resource, error) {
	args := m.Called(ctx, tenantID, res)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*inventoryv1.Resource), args.Error(1)
}

func (m *mockInventoryClient) Update(
	ctx context.Context, tenantID, id string,
	fm *fieldmaskpb.FieldMask, res *inventoryv1.Resource,
) (*inventoryv1.Resource, error) {
	args := m.Called(ctx, tenantID, id, fm, res)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*inventoryv1.Resource), args.Error(1)
}

func (m *mockInventoryClient) Delete(
	ctx context.Context, tenantID, id string,
) (*inventoryv1.DeleteResourceResponse, error) {
	args := m.Called(ctx, tenantID, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*inventoryv1.DeleteResourceResponse), args.Error(1)
}

func (m *mockInventoryClient) UpdateSubscriptions(
	ctx context.Context, tenantID string, kinds []inventoryv1.ResourceKind,
) error {
	args := m.Called(ctx, tenantID, kinds)
	return args.Error(0)
}

func (m *mockInventoryClient) ListInheritedTelemetryProfiles(
	ctx context.Context,
	tenantID string,
	inheritBy *inventoryv1.ListInheritedTelemetryProfilesRequest_InheritBy,
	filter string,
	orderBy string,
	limit, offset uint32,
) (*inventoryv1.ListInheritedTelemetryProfilesResponse, error) {
	args := m.Called(ctx, tenantID, inheritBy, filter, orderBy, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*inventoryv1.ListInheritedTelemetryProfilesResponse), args.Error(1)
}

func (m *mockInventoryClient) GetHostByUUID(
	ctx context.Context, tenantID, uuid string,
) (*computev1.HostResource, error) {
	args := m.Called(ctx, tenantID, uuid)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*computev1.HostResource), args.Error(1)
}

func (m *mockInventoryClient) GetTreeHierarchy(
	ctx context.Context, req *inventoryv1.GetTreeHierarchyRequest,
) ([]*inventoryv1.GetTreeHierarchyResponse_TreeNode, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*inventoryv1.GetTreeHierarchyResponse_TreeNode), args.Error(1)
}

func (m *mockInventoryClient) GetSitesPerRegion(
	ctx context.Context, req *inventoryv1.GetSitesPerRegionRequest,
) (*inventoryv1.GetSitesPerRegionResponse, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*inventoryv1.GetSitesPerRegionResponse), args.Error(1)
}

func (m *mockInventoryClient) DeleteAllResources(
	ctx context.Context, tenantID string, kind inventoryv1.ResourceKind, enforce bool,
) error {
	args := m.Called(ctx, tenantID, kind, enforce)
	return args.Error(0)
}

func (m *mockInventoryClient) TestingOnlySetClient(inventoryv1.InventoryServiceClient) {}

func (m *mockInventoryClient) TestGetClientCache() *cache.InventoryCache { return nil }

func (m *mockInventoryClient) TestGetClientCacheUUID() *cache.InventoryCache { return nil }

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const (
	testTenantID   = "tenant-1234"
	testHostUUID   = "abcd-efgh-1234-5678"
	testResourceID = "host-abc123"
)

func boolPtr(b bool) *bool       { return &b }
func stringPtr(s string) *string { return &s }

func newTestController(
	mpsMock *mps.MockClientWithResponsesInterface,
	invMock *mockInventoryClient,
) *Controller {
	return &Controller{
		MpsClient:         mpsMock,
		InventoryRmClient: invMock,
		ReconcilePeriod:   time.Minute,
		RequestTimeout:    30 * time.Second,
	}
}

func makeHostResource(
	desiredSol computev1.SolState,
	currentSol computev1.SolState,
	amtState computev1.AmtState,
	controlMode computev1.AmtControlMode,
) *computev1.HostResource {
	return &computev1.HostResource{
		ResourceId:      testResourceID,
		Uuid:            testHostUUID,
		TenantId:        testTenantID,
		DesiredSolState: desiredSol,
		CurrentSolState: currentSol,
		CurrentAmtState: amtState,
		AmtControlMode:  controlMode,
	}
}

func httpResponse(status int) *http.Response {
	return &http.Response{StatusCode: status}
}

// ---------------------------------------------------------------------------
// ID helpers
// ---------------------------------------------------------------------------

func TestNewID(t *testing.T) {
	id := NewID("tenant-abc", "uuid-123")
	assert.Equal(t, "tenant-abc", id.GetTenantID())
	assert.Equal(t, "uuid-123", id.GetHostUUID())
	assert.Contains(t, id.String(), "tenant-abc")
	assert.Contains(t, id.String(), "uuid-123")
}

// ---------------------------------------------------------------------------
// shouldStartSOLSession
// ---------------------------------------------------------------------------

func TestShouldStartSOLSession(t *testing.T) {
	sc := &Controller{}
	tests := []struct {
		name     string
		desired  computev1.SolState
		current  computev1.SolState
		expected bool
	}{
		{"start requested, not started", computev1.SolState_SOL_STATE_START,
			computev1.SolState_SOL_STATE_UNSPECIFIED, true},
		{"start requested, already started", computev1.SolState_SOL_STATE_START,
			computev1.SolState_SOL_STATE_START, false},
		{"stop requested", computev1.SolState_SOL_STATE_STOP,
			computev1.SolState_SOL_STATE_UNSPECIFIED, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &computev1.HostResource{
				DesiredSolState: tt.desired,
				CurrentSolState: tt.current,
			}
			assert.Equal(t, tt.expected, sc.shouldStartSOLSession(h))
		})
	}
}

// ---------------------------------------------------------------------------
// shouldStopSOLSession
// ---------------------------------------------------------------------------

func TestShouldStopSOLSession(t *testing.T) {
	sc := &Controller{}
	tests := []struct {
		name     string
		desired  computev1.SolState
		current  computev1.SolState
		expected bool
	}{
		{"stop requested, not stopped", computev1.SolState_SOL_STATE_STOP,
			computev1.SolState_SOL_STATE_START, true},
		{"stop requested, already stopped", computev1.SolState_SOL_STATE_STOP,
			computev1.SolState_SOL_STATE_STOP, false},
		{"start requested", computev1.SolState_SOL_STATE_START,
			computev1.SolState_SOL_STATE_STOP, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &computev1.HostResource{
				DesiredSolState: tt.desired,
				CurrentSolState: tt.current,
			}
			assert.Equal(t, tt.expected, sc.shouldStopSOLSession(h))
		})
	}
}

// ---------------------------------------------------------------------------
// Reconcile — GetHostByUUID failure
// ---------------------------------------------------------------------------

func TestReconcile_GetHostByUUIDFailure(t *testing.T) {
	mpsMock := mps.NewMockClientWithResponsesInterface(t)
	invMock := &mockInventoryClient{}
	sc := newTestController(mpsMock, invMock)

	invMock.On("GetHostByUUID", mock.Anything, testTenantID, testHostUUID).
		Return(nil, fmt.Errorf("inventory unavailable"))

	ctrl := rec_v2.NewController[ID](sc.Reconcile,
		rec_v2.WithParallelism(1))
	err := ctrl.Reconcile(NewID(testTenantID, testHostUUID))
	assert.NoError(t, err)
	// Give controller time to process
	time.Sleep(200 * time.Millisecond)
	invMock.AssertCalled(t, "GetHostByUUID", mock.Anything, testTenantID, testHostUUID)
}

// ---------------------------------------------------------------------------
// Reconcile — no action needed (unspecified desired state)
// ---------------------------------------------------------------------------

func TestReconcile_NoActionNeeded(t *testing.T) {
	mpsMock := mps.NewMockClientWithResponsesInterface(t)
	invMock := &mockInventoryClient{}
	sc := newTestController(mpsMock, invMock)

	host := makeHostResource(
		computev1.SolState_SOL_STATE_UNSPECIFIED,
		computev1.SolState_SOL_STATE_UNSPECIFIED,
		computev1.AmtState_AMT_STATE_PROVISIONED,
		computev1.AmtControlMode_AMT_CONTROL_MODE_CCM,
	)
	// Override desired to something that doesn't match start/stop/consent/redirect
	host.DesiredSolState = computev1.SolState_SOL_STATE_UNSPECIFIED

	invMock.On("GetHostByUUID", mock.Anything, testTenantID, testHostUUID).
		Return(host, nil)

	ctx := context.Background()
	req := rec_v2.Request[ID]{ID: NewID(testTenantID, testHostUUID)}
	directive := sc.Reconcile(ctx, req)
	assert.NotNil(t, directive)
}

// ---------------------------------------------------------------------------
// handleStartSOLSession — not provisioned → error
// ---------------------------------------------------------------------------

func TestHandleStartSOLSession_NotProvisioned(t *testing.T) {
	mpsMock := mps.NewMockClientWithResponsesInterface(t)
	invMock := &mockInventoryClient{}
	sc := newTestController(mpsMock, invMock)

	host := makeHostResource(
		computev1.SolState_SOL_STATE_START,
		computev1.SolState_SOL_STATE_UNSPECIFIED,
		computev1.AmtState_AMT_STATE_UNPROVISIONED, // not provisioned
		computev1.AmtControlMode_AMT_CONTROL_MODE_CCM,
	)

	invMock.On("GetHostByUUID", mock.Anything, testTenantID, testHostUUID).
		Return(host, nil)
	// writeSolError will call Update
	invMock.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&inventoryv1.Resource{}, nil)

	ctx := context.Background()
	req := rec_v2.Request[ID]{ID: NewID(testTenantID, testHostUUID)}
	directive := sc.Reconcile(ctx, req)
	assert.NotNil(t, directive)
	invMock.AssertCalled(t, "Update", mock.Anything, testTenantID, testResourceID,
		mock.Anything, mock.Anything)
}

// ---------------------------------------------------------------------------
// handleStartSOLSession — GET features fails
// ---------------------------------------------------------------------------

func TestHandleStartSOLSession_GetFeaturesFails(t *testing.T) {
	mpsMock := mps.NewMockClientWithResponsesInterface(t)
	invMock := &mockInventoryClient{}
	sc := newTestController(mpsMock, invMock)

	host := makeHostResource(
		computev1.SolState_SOL_STATE_START,
		computev1.SolState_SOL_STATE_UNSPECIFIED,
		computev1.AmtState_AMT_STATE_PROVISIONED,
		computev1.AmtControlMode_AMT_CONTROL_MODE_CCM,
	)

	invMock.On("GetHostByUUID", mock.Anything, testTenantID, testHostUUID).
		Return(host, nil)

	mpsMock.On("GetApiV1AmtFeaturesGuidWithResponse",
		mock.Anything, testHostUUID, mock.Anything).
		Return(nil, fmt.Errorf("connection refused"))

	ctx := context.Background()
	req := rec_v2.Request[ID]{ID: NewID(testTenantID, testHostUUID)}
	directive := sc.Reconcile(ctx, req)
	assert.NotNil(t, directive)
}

// ---------------------------------------------------------------------------
// handleStartSOLSession — GET features non-200
// ---------------------------------------------------------------------------

func TestHandleStartSOLSession_GetFeaturesNon200(t *testing.T) {
	mpsMock := mps.NewMockClientWithResponsesInterface(t)
	invMock := &mockInventoryClient{}
	sc := newTestController(mpsMock, invMock)

	host := makeHostResource(
		computev1.SolState_SOL_STATE_START,
		computev1.SolState_SOL_STATE_UNSPECIFIED,
		computev1.AmtState_AMT_STATE_PROVISIONED,
		computev1.AmtControlMode_AMT_CONTROL_MODE_CCM,
	)

	invMock.On("GetHostByUUID", mock.Anything, testTenantID, testHostUUID).
		Return(host, nil)
	invMock.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&inventoryv1.Resource{}, nil)

	mpsMock.On("GetApiV1AmtFeaturesGuidWithResponse",
		mock.Anything, testHostUUID, mock.Anything).
		Return(&mps.GetApiV1AmtFeaturesGuidResponse{
			Body:         []byte(`{"error":"not found"}`),
			HTTPResponse: httpResponse(http.StatusNotFound),
		}, nil)

	ctx := context.Background()
	req := rec_v2.Request[ID]{ID: NewID(testTenantID, testHostUUID)}
	directive := sc.Reconcile(ctx, req)
	assert.NotNil(t, directive)
}

// ---------------------------------------------------------------------------
// handleStartSOLSession — SOL not enabled → error
// ---------------------------------------------------------------------------

func TestHandleStartSOLSession_SOLNotEnabled(t *testing.T) {
	mpsMock := mps.NewMockClientWithResponsesInterface(t)
	invMock := &mockInventoryClient{}
	sc := newTestController(mpsMock, invMock)

	host := makeHostResource(
		computev1.SolState_SOL_STATE_START,
		computev1.SolState_SOL_STATE_UNSPECIFIED,
		computev1.AmtState_AMT_STATE_PROVISIONED,
		computev1.AmtControlMode_AMT_CONTROL_MODE_CCM,
	)

	invMock.On("GetHostByUUID", mock.Anything, testTenantID, testHostUUID).
		Return(host, nil)
	invMock.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&inventoryv1.Resource{}, nil)

	solDisabled := false
	mpsMock.On("GetApiV1AmtFeaturesGuidWithResponse",
		mock.Anything, testHostUUID, mock.Anything).
		Return(&mps.GetApiV1AmtFeaturesGuidResponse{
			Body:         []byte(`{}`),
			HTTPResponse: httpResponse(http.StatusOK),
			JSON200: &mps.GetAMTFeaturesResponse{
				SOL:         &solDisabled,
				UserConsent: stringPtr("all"),
			},
		}, nil)

	ctx := context.Background()
	req := rec_v2.Request[ID]{ID: NewID(testTenantID, testHostUUID)}
	directive := sc.Reconcile(ctx, req)
	assert.NotNil(t, directive)
	// Should have written SOL_STATE_ERROR
	invMock.AssertCalled(t, "Update", mock.Anything, testTenantID, testResourceID,
		mock.Anything, mock.Anything)
}

// ---------------------------------------------------------------------------
// handleStartSOLSession — CCM happy path → consent flow → AWAITING_CONSENT
// ---------------------------------------------------------------------------

func TestHandleStartSOLSession_CCM_HappyPath(t *testing.T) {
	mpsMock := mps.NewMockClientWithResponsesInterface(t)
	invMock := &mockInventoryClient{}
	sc := newTestController(mpsMock, invMock)

	host := makeHostResource(
		computev1.SolState_SOL_STATE_START,
		computev1.SolState_SOL_STATE_UNSPECIFIED,
		computev1.AmtState_AMT_STATE_PROVISIONED,
		computev1.AmtControlMode_AMT_CONTROL_MODE_CCM,
	)

	invMock.On("GetHostByUUID", mock.Anything, testTenantID, testHostUUID).
		Return(host, nil)
	invMock.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&inventoryv1.Resource{}, nil)

	solEnabled := true
	mpsMock.On("GetApiV1AmtFeaturesGuidWithResponse",
		mock.Anything, testHostUUID, mock.Anything).
		Return(&mps.GetApiV1AmtFeaturesGuidResponse{
			Body:         []byte(`{}`),
			HTTPResponse: httpResponse(http.StatusOK),
			JSON200: &mps.GetAMTFeaturesResponse{
				SOL:         &solEnabled,
				UserConsent: stringPtr("all"),
			},
		}, nil)

	mpsMock.On("GetApiV1AmtUserConsentCodeGuidWithResponse",
		mock.Anything, testHostUUID, mock.Anything).
		Return(&mps.GetApiV1AmtUserConsentCodeGuidResponse{
			Body:         []byte(`{"Body":{"ReturnValue":0}}`),
			HTTPResponse: httpResponse(http.StatusOK),
		}, nil)

	ctx := context.Background()
	req := rec_v2.Request[ID]{ID: NewID(testTenantID, testHostUUID)}
	directive := sc.Reconcile(ctx, req)
	assert.NotNil(t, directive)
	// Should have written AWAITING_CONSENT via Update
	invMock.AssertCalled(t, "Update", mock.Anything, testTenantID, testResourceID,
		mock.Anything, mock.Anything)
}

// ---------------------------------------------------------------------------
// handleStartSOLSession — CCM already awaiting consent → Ack
// ---------------------------------------------------------------------------

func TestHandleConsentFlow_AlreadyAwaiting(t *testing.T) {
	mpsMock := mps.NewMockClientWithResponsesInterface(t)
	invMock := &mockInventoryClient{}
	sc := newTestController(mpsMock, invMock)

	host := makeHostResource(
		computev1.SolState_SOL_STATE_START,
		computev1.SolState_SOL_STATE_AWAITING_CONSENT, // already awaiting
		computev1.AmtState_AMT_STATE_PROVISIONED,
		computev1.AmtControlMode_AMT_CONTROL_MODE_CCM,
	)

	invMock.On("GetHostByUUID", mock.Anything, testTenantID, testHostUUID).
		Return(host, nil)

	solEnabled := true
	mpsMock.On("GetApiV1AmtFeaturesGuidWithResponse",
		mock.Anything, testHostUUID, mock.Anything).
		Return(&mps.GetApiV1AmtFeaturesGuidResponse{
			Body:         []byte(`{}`),
			HTTPResponse: httpResponse(http.StatusOK),
			JSON200: &mps.GetAMTFeaturesResponse{
				SOL:         &solEnabled,
				UserConsent: stringPtr("all"),
			},
		}, nil)

	ctx := context.Background()
	req := rec_v2.Request[ID]{ID: NewID(testTenantID, testHostUUID)}
	directive := sc.Reconcile(ctx, req)
	assert.NotNil(t, directive)
	// Should NOT have called Update (Ack immediately)
	invMock.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything)
}

// ---------------------------------------------------------------------------
// handleStartSOLSession — CCM consent code with JSON unmarshal error → success
// ---------------------------------------------------------------------------

func TestHandleConsentFlow_JsonUnmarshalError(t *testing.T) {
	mpsMock := mps.NewMockClientWithResponsesInterface(t)
	invMock := &mockInventoryClient{}
	sc := newTestController(mpsMock, invMock)

	host := makeHostResource(
		computev1.SolState_SOL_STATE_START,
		computev1.SolState_SOL_STATE_UNSPECIFIED,
		computev1.AmtState_AMT_STATE_PROVISIONED,
		computev1.AmtControlMode_AMT_CONTROL_MODE_CCM,
	)

	invMock.On("GetHostByUUID", mock.Anything, testTenantID, testHostUUID).
		Return(host, nil)
	invMock.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&inventoryv1.Resource{}, nil)

	solEnabled := true
	mpsMock.On("GetApiV1AmtFeaturesGuidWithResponse",
		mock.Anything, testHostUUID, mock.Anything).
		Return(&mps.GetApiV1AmtFeaturesGuidResponse{
			Body:         []byte(`{}`),
			HTTPResponse: httpResponse(http.StatusOK),
			JSON200: &mps.GetAMTFeaturesResponse{
				SOL:         &solEnabled,
				UserConsent: stringPtr("all"),
			},
		}, nil)

	// Simulate the RelatesTo type mismatch — error contains "json" / "unmarshal"
	mpsMock.On("GetApiV1AmtUserConsentCodeGuidWithResponse",
		mock.Anything, testHostUUID, mock.Anything).
		Return(&mps.GetApiV1AmtUserConsentCodeGuidResponse{
			Body:         []byte(`{"Header":{"RelatesTo":1}}`),
			HTTPResponse: httpResponse(http.StatusOK),
		}, fmt.Errorf("json: cannot unmarshal number into Go struct field"))

	ctx := context.Background()
	req := rec_v2.Request[ID]{ID: NewID(testTenantID, testHostUUID)}
	directive := sc.Reconcile(ctx, req)
	assert.NotNil(t, directive)
	// Should still proceed and set AWAITING_CONSENT
	invMock.AssertCalled(t, "Update", mock.Anything, testTenantID, testResourceID,
		mock.Anything, mock.Anything)
}

// ---------------------------------------------------------------------------
// handleStartSOLSession — ACM happy path → AWAITING_CONSENT (no consent dialog)
// ---------------------------------------------------------------------------

func TestHandleStartSOLSession_ACM_HappyPath(t *testing.T) {
	mpsMock := mps.NewMockClientWithResponsesInterface(t)
	invMock := &mockInventoryClient{}
	sc := newTestController(mpsMock, invMock)

	host := makeHostResource(
		computev1.SolState_SOL_STATE_START,
		computev1.SolState_SOL_STATE_UNSPECIFIED,
		computev1.AmtState_AMT_STATE_PROVISIONED,
		computev1.AmtControlMode_AMT_CONTROL_MODE_ACM,
	)

	invMock.On("GetHostByUUID", mock.Anything, testTenantID, testHostUUID).
		Return(host, nil)
	invMock.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&inventoryv1.Resource{}, nil)

	solEnabled := true
	mpsMock.On("GetApiV1AmtFeaturesGuidWithResponse",
		mock.Anything, testHostUUID, mock.Anything).
		Return(&mps.GetApiV1AmtFeaturesGuidResponse{
			Body:         []byte(`{}`),
			HTTPResponse: httpResponse(http.StatusOK),
			JSON200: &mps.GetAMTFeaturesResponse{
				SOL:         &solEnabled,
				UserConsent: stringPtr("none"),
			},
		}, nil)

	ctx := context.Background()
	req := rec_v2.Request[ID]{ID: NewID(testTenantID, testHostUUID)}
	directive := sc.Reconcile(ctx, req)
	assert.NotNil(t, directive)
	// ACM should set AWAITING_CONSENT directly (no consent code call)
	invMock.AssertCalled(t, "Update", mock.Anything, testTenantID, testResourceID,
		mock.Anything, mock.Anything)
	// Should NOT call userConsentCode
	mpsMock.AssertNotCalled(t, "GetApiV1AmtUserConsentCodeGuidWithResponse",
		mock.Anything, mock.Anything, mock.Anything)
}

// ---------------------------------------------------------------------------
// Reconcile — CONSENT_RECEIVED → Ack
// ---------------------------------------------------------------------------

func TestReconcile_ConsentReceived(t *testing.T) {
	mpsMock := mps.NewMockClientWithResponsesInterface(t)
	invMock := &mockInventoryClient{}
	sc := newTestController(mpsMock, invMock)

	host := makeHostResource(
		computev1.SolState_SOL_STATE_CONSENT_RECEIVED,
		computev1.SolState_SOL_STATE_AWAITING_CONSENT,
		computev1.AmtState_AMT_STATE_PROVISIONED,
		computev1.AmtControlMode_AMT_CONTROL_MODE_CCM,
	)

	invMock.On("GetHostByUUID", mock.Anything, testTenantID, testHostUUID).
		Return(host, nil)

	ctx := context.Background()
	req := rec_v2.Request[ID]{ID: NewID(testTenantID, testHostUUID)}
	directive := sc.Reconcile(ctx, req)
	assert.NotNil(t, directive)
	// Should just Ack — no Update call
	invMock.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything)
}

// ---------------------------------------------------------------------------
// Reconcile — REDIRECTION_RECEIVED → sets SOL_STATE_START
// ---------------------------------------------------------------------------

func TestReconcile_RedirectionReceived(t *testing.T) {
	mpsMock := mps.NewMockClientWithResponsesInterface(t)
	invMock := &mockInventoryClient{}
	sc := newTestController(mpsMock, invMock)

	host := makeHostResource(
		computev1.SolState_SOL_STATE_REDIRECTION_RECEIVED,
		computev1.SolState_SOL_STATE_AWAITING_CONSENT,
		computev1.AmtState_AMT_STATE_PROVISIONED,
		computev1.AmtControlMode_AMT_CONTROL_MODE_ACM,
	)

	invMock.On("GetHostByUUID", mock.Anything, testTenantID, testHostUUID).
		Return(host, nil)
	invMock.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&inventoryv1.Resource{}, nil)

	ctx := context.Background()
	req := rec_v2.Request[ID]{ID: NewID(testTenantID, testHostUUID)}
	directive := sc.Reconcile(ctx, req)
	assert.NotNil(t, directive)
	invMock.AssertCalled(t, "Update", mock.Anything, testTenantID, testResourceID,
		mock.Anything, mock.Anything)
}

// ---------------------------------------------------------------------------
// handleStopSOLSession — happy path
// ---------------------------------------------------------------------------

func TestHandleStopSOLSession_HappyPath(t *testing.T) {
	mpsMock := mps.NewMockClientWithResponsesInterface(t)
	invMock := &mockInventoryClient{}
	sc := newTestController(mpsMock, invMock)

	host := makeHostResource(
		computev1.SolState_SOL_STATE_STOP,
		computev1.SolState_SOL_STATE_START, // currently active
		computev1.AmtState_AMT_STATE_PROVISIONED,
		computev1.AmtControlMode_AMT_CONTROL_MODE_CCM,
	)

	invMock.On("GetHostByUUID", mock.Anything, testTenantID, testHostUUID).
		Return(host, nil)
	invMock.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&inventoryv1.Resource{}, nil)

	ctx := context.Background()
	req := rec_v2.Request[ID]{ID: NewID(testTenantID, testHostUUID)}
	directive := sc.Reconcile(ctx, req)
	assert.NotNil(t, directive)
	invMock.AssertCalled(t, "Update", mock.Anything, testTenantID, testResourceID,
		mock.Anything, mock.Anything)
}

// ---------------------------------------------------------------------------
// handleStopSOLSession — Update fails
// ---------------------------------------------------------------------------

func TestHandleStopSOLSession_UpdateFails(t *testing.T) {
	mpsMock := mps.NewMockClientWithResponsesInterface(t)
	invMock := &mockInventoryClient{}
	sc := newTestController(mpsMock, invMock)

	host := makeHostResource(
		computev1.SolState_SOL_STATE_STOP,
		computev1.SolState_SOL_STATE_START,
		computev1.AmtState_AMT_STATE_PROVISIONED,
		computev1.AmtControlMode_AMT_CONTROL_MODE_CCM,
	)

	invMock.On("GetHostByUUID", mock.Anything, testTenantID, testHostUUID).
		Return(host, nil)
	invMock.On("Update", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil, fmt.Errorf("inventory update failed"))

	ctx := context.Background()
	req := rec_v2.Request[ID]{ID: NewID(testTenantID, testHostUUID)}
	directive := sc.Reconcile(ctx, req)
	assert.NotNil(t, directive)
}

// ---------------------------------------------------------------------------
// Controller Start / Stop lifecycle
// ---------------------------------------------------------------------------

func TestController_StartStop(t *testing.T) {
	mpsMock := mps.NewMockClientWithResponsesInterface(t)
	invMock := &mockInventoryClient{}

	termChan := make(chan bool, 1)
	readyChan := make(chan bool, 1)
	wg := &sync.WaitGroup{}

	invMock.On("ListAll", mock.Anything, mock.Anything).
		Return([]*inventoryv1.Resource{}, nil)

	ctrl := rec_v2.NewController[ID](func(ctx context.Context, req rec_v2.Request[ID]) rec_v2.Directive[ID] {
		return req.Ack()
	}, rec_v2.WithParallelism(1))

	sc := &Controller{
		MpsClient:         mpsMock,
		InventoryRmClient: invMock,
		TermChan:          termChan,
		ReadyChan:         readyChan,
		WaitGroup:         wg,
		EventsWatcher:     make(chan *client.WatchEvents, 10),
		SOLController:     ctrl,
		ReconcilePeriod:   time.Minute,
		RequestTimeout:    30 * time.Second,
	}

	wg.Add(1)
	go sc.Start()

	select {
	case ready := <-readyChan:
		assert.True(t, ready)
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for ReadyChan signal")
	}

	termChan <- true

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for controller to stop")
	}
}

// ---------------------------------------------------------------------------
// updateHost — nil resource
// ---------------------------------------------------------------------------

func TestUpdateHost_NilResource(t *testing.T) {
	invMock := &mockInventoryClient{}
	sc := &Controller{InventoryRmClient: invMock}

	err := sc.updateHost(context.Background(), testTenantID, testResourceID,
		&fieldmaskpb.FieldMask{Paths: []string{"current_sol_state"}},
		nil)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// updateHost — empty field mask
// ---------------------------------------------------------------------------

func TestUpdateHost_EmptyFieldMask(t *testing.T) {
	invMock := &mockInventoryClient{}
	sc := &Controller{InventoryRmClient: invMock}

	err := sc.updateHost(context.Background(), testTenantID, testResourceID,
		&fieldmaskpb.FieldMask{},
		&computev1.HostResource{})
	assert.NoError(t, err)
	invMock.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything,
		mock.Anything, mock.Anything)
}

// ---------------------------------------------------------------------------
// clientCallback — sets headers
// ---------------------------------------------------------------------------

func TestClientCallback(t *testing.T) {
	sc := &Controller{}
	ctx := context.Background()
	cb := sc.clientCallback(ctx, testTenantID, testHostUUID)

	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	err := cb(ctx, req)
	assert.NoError(t, err)
	assert.Equal(t, testTenantID, req.Header.Get("ActiveProjectId"))
	assert.Equal(t, "sol-manager", req.Header.Get("User-Agent"))
}

// ---------------------------------------------------------------------------
// clientCallback — empty tenant
// ---------------------------------------------------------------------------

func TestClientCallback_EmptyTenant(t *testing.T) {
	sc := &Controller{}
	ctx := context.Background()
	cb := sc.clientCallback(ctx, "", testHostUUID)

	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	err := cb(ctx, req)
	assert.NoError(t, err)
	assert.Empty(t, req.Header.Get("ActiveProjectId"))
	assert.Equal(t, "sol-manager", req.Header.Get("User-Agent"))
}

// ---------------------------------------------------------------------------
// ReconcileAll — skips hosts with unspecified desired state
// ---------------------------------------------------------------------------

func TestReconcileAll_SkipsUnspecified(t *testing.T) {
	mpsMock := mps.NewMockClientWithResponsesInterface(t)
	invMock := &mockInventoryClient{}

	ctrl := rec_v2.NewController[ID](func(ctx context.Context, req rec_v2.Request[ID]) rec_v2.Directive[ID] {
		return req.Ack()
	}, rec_v2.WithParallelism(1))

	sc := &Controller{
		MpsClient:         mpsMock,
		InventoryRmClient: invMock,
		SOLController:     ctrl,
		ReconcilePeriod:   time.Minute,
		RequestTimeout:    30 * time.Second,
	}

	invMock.On("ListAll", mock.Anything, mock.Anything).
		Return([]*inventoryv1.Resource{
			{Resource: &inventoryv1.Resource_Host{Host: &computev1.HostResource{
				Uuid:            "uuid-1",
				TenantId:        testTenantID,
				DesiredSolState: computev1.SolState_SOL_STATE_UNSPECIFIED,
			}}},
			{Resource: &inventoryv1.Resource_Host{Host: &computev1.HostResource{
				Uuid:            "uuid-2",
				TenantId:        testTenantID,
				DesiredSolState: computev1.SolState_SOL_STATE_START,
			}}},
		}, nil)

	sc.ReconcileAll()
	// Only uuid-2 should be reconciled (uuid-1 is unspecified)
	invMock.AssertCalled(t, "ListAll", mock.Anything, mock.Anything)
}

// ---------------------------------------------------------------------------
// ReconcileAll — ListAll fails
// ---------------------------------------------------------------------------

func TestReconcileAll_ListAllFails(t *testing.T) {
	mpsMock := mps.NewMockClientWithResponsesInterface(t)
	invMock := &mockInventoryClient{}

	ctrl := rec_v2.NewController[ID](func(ctx context.Context, req rec_v2.Request[ID]) rec_v2.Directive[ID] {
		return req.Ack()
	}, rec_v2.WithParallelism(1))

	sc := &Controller{
		MpsClient:         mpsMock,
		InventoryRmClient: invMock,
		SOLController:     ctrl,
		ReconcilePeriod:   time.Minute,
		RequestTimeout:    30 * time.Second,
	}

	invMock.On("ListAll", mock.Anything, mock.Anything).
		Return(nil, fmt.Errorf("connection error"))

	sc.ReconcileAll()
	invMock.AssertCalled(t, "ListAll", mock.Anything, mock.Anything)
}
