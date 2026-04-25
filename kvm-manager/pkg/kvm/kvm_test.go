// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package kvm_test

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	computev1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/compute/v1"
	inventoryv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client/cache"
	"github.com/open-edge-platform/infra-external/kvm-manager/pkg/api/mps"
	"github.com/open-edge-platform/infra-external/kvm-manager/pkg/kvm"
	rec_v2 "github.com/open-edge-platform/orch-library/go/pkg/controller/v2"
)

// mockInventoryClient implements client.TenantAwareInventoryClient using testify/mock.
type mockInventoryClient struct{ mock.Mock }

func (m *mockInventoryClient) Close() error {
	return m.Called().Error(0)
}

func (m *mockInventoryClient) List(
	ctx context.Context, f *inventoryv1.ResourceFilter,
) (*inventoryv1.ListResourcesResponse, error) {
	args := m.Called(ctx, f)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*inventoryv1.ListResourcesResponse), args.Error(1)
}

func (m *mockInventoryClient) ListAll(ctx context.Context, f *inventoryv1.ResourceFilter) ([]*inventoryv1.Resource, error) {
	args := m.Called(ctx, f)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*inventoryv1.Resource), args.Error(1)
}

func (m *mockInventoryClient) Find(
	ctx context.Context, f *inventoryv1.ResourceFilter,
) (*inventoryv1.FindResourcesResponse, error) {
	args := m.Called(ctx, f)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*inventoryv1.FindResourcesResponse), args.Error(1)
}

func (m *mockInventoryClient) FindAll(
	ctx context.Context, f *inventoryv1.ResourceFilter,
) ([]*client.ResourceTenantIDCarrier, error) {
	args := m.Called(ctx, f)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*client.ResourceTenantIDCarrier), args.Error(1)
}

func (m *mockInventoryClient) Get(ctx context.Context, tenantID, id string) (*inventoryv1.GetResourceResponse, error) {
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

func (m *mockInventoryClient) Delete(ctx context.Context, tenantID, id string) (*inventoryv1.DeleteResourceResponse, error) {
	args := m.Called(ctx, tenantID, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*inventoryv1.DeleteResourceResponse), args.Error(1)
}

func (m *mockInventoryClient) UpdateSubscriptions(ctx context.Context, tenantID string, kinds []inventoryv1.ResourceKind) error {
	return m.Called(ctx, tenantID, kinds).Error(0)
}

func (m *mockInventoryClient) ListInheritedTelemetryProfiles(ctx context.Context, tenantID string,
	inheritBy *inventoryv1.ListInheritedTelemetryProfilesRequest_InheritBy,
	filter, orderBy string, limit, offset uint32,
) (*inventoryv1.ListInheritedTelemetryProfilesResponse, error) {
	args := m.Called(ctx, tenantID, inheritBy, filter, orderBy, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*inventoryv1.ListInheritedTelemetryProfilesResponse), args.Error(1)
}

func (m *mockInventoryClient) GetHostByUUID(ctx context.Context, tenantID, uuid string) (*computev1.HostResource, error) {
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
	return m.Called(ctx, tenantID, kind, enforce).Error(0)
}

func (m *mockInventoryClient) TestingOnlySetClient(inventoryv1.InventoryServiceClient) {}
func (m *mockInventoryClient) TestGetClientCache() *cache.InventoryCache               { return nil }
func (m *mockInventoryClient) TestGetClientCacheUUID() *cache.InventoryCache           { return nil }

const (
	testTenantID   = "00000000-0000-0000-0000-000000000001"
	testHostUUID   = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	testResourceID = "host-test-resource-001"
)

func boolPtr(b bool) *bool { return &b }

func makeHost(
	desired, current computev1.KvmState, amtState computev1.AmtState, mode computev1.AmtControlMode,
) *computev1.HostResource {
	return &computev1.HostResource{
		ResourceId: testResourceID, Uuid: testHostUUID, TenantId: testTenantID,
		DesiredKvmState: desired, CurrentKvmState: current,
		CurrentAmtState: amtState, AmtControlMode: mode,
	}
}

func newController(t *testing.T, inv *mockInventoryClient, mpsM *mps.MockClientWithResponsesInterface) *kvm.Controller {
	t.Helper()
	c := &kvm.Controller{
		MpsClient: mpsM, InventoryRmClient: inv,
		RequestTimeout: 5 * time.Second, ReconcilePeriod: time.Minute,
		ReadyChan: make(chan bool, 2),
	}
	c.KvmController = rec_v2.NewController[kvm.ID](c.Reconcile)
	return c
}

func reconcile(t *testing.T, ctrl *kvm.Controller) {
	t.Helper()
	ctrl.Reconcile(context.Background(), rec_v2.Request[kvm.ID]{ID: kvm.NewID(testTenantID, testHostUUID)})
}

func TestNewID(t *testing.T) {
	t.Parallel()
	id := kvm.NewID("tenant1", "host-uuid-1")
	assert.Equal(t, "tenant1", id.GetTenantID())
	assert.Equal(t, "host-uuid-1", id.GetHostUUID())
	assert.Contains(t, id.String(), "tenant1")
	assert.Contains(t, id.String(), "host-uuid-1")
}

func TestNewID_Empty(t *testing.T) {
	t.Parallel()
	id := kvm.NewID("", "")
	assert.Empty(t, id.GetTenantID())
	assert.Empty(t, id.GetHostUUID())
}

func TestReconcile_NoAction_Unspecified(t *testing.T) {
	t.Parallel()
	inv := &mockInventoryClient{}
	ctrl := newController(t, inv, mps.NewMockClientWithResponsesInterface(t))
	inv.On("GetHostByUUID", mock.Anything, testTenantID, testHostUUID).
		Return(makeHost(computev1.KvmState_KVM_STATE_UNSPECIFIED, computev1.KvmState_KVM_STATE_UNSPECIFIED,
			computev1.AmtState_AMT_STATE_PROVISIONED, computev1.AmtControlMode_AMT_CONTROL_MODE_ACM), nil)
	reconcile(t, ctrl)
	inv.AssertNotCalled(t, "Update")
}

func TestReconcile_StartKVM_ACM_SetsAwaitingConsent(t *testing.T) {
	t.Parallel()
	inv := &mockInventoryClient{}
	mpsMock := mps.NewMockClientWithResponsesInterface(t)
	ctrl := newController(t, inv, mpsMock)

	inv.On("GetHostByUUID", mock.Anything, testTenantID, testHostUUID).
		Return(makeHost(computev1.KvmState_KVM_STATE_START, computev1.KvmState_KVM_STATE_UNSPECIFIED,
			computev1.AmtState_AMT_STATE_PROVISIONED, computev1.AmtControlMode_AMT_CONTROL_MODE_ACM), nil)
	mpsMock.On("GetApiV1AmtFeaturesGuidWithResponse", mock.Anything, testHostUUID, mock.Anything).
		Return(&mps.GetApiV1AmtFeaturesGuidResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200:      &mps.GetAMTFeaturesResponse{KVM: boolPtr(true)},
		}, nil)

	var captured *computev1.HostResource
	inv.On("Update", mock.Anything, testTenantID, testResourceID, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { captured = args.Get(4).(*inventoryv1.Resource).GetHost() }).
		Return(nil, nil)

	reconcile(t, ctrl)

	require.NotNil(t, captured)
	assert.Equal(t, computev1.KvmState_KVM_STATE_AWAITING_CONSENT, captured.GetCurrentKvmState())
}

func TestReconcile_StartKVM_NotProvisioned_WritesError(t *testing.T) {
	t.Parallel()
	inv := &mockInventoryClient{}
	ctrl := newController(t, inv, mps.NewMockClientWithResponsesInterface(t))

	inv.On("GetHostByUUID", mock.Anything, testTenantID, testHostUUID).
		Return(makeHost(computev1.KvmState_KVM_STATE_START, computev1.KvmState_KVM_STATE_UNSPECIFIED,
			computev1.AmtState_AMT_STATE_UNSPECIFIED, computev1.AmtControlMode_AMT_CONTROL_MODE_ACM), nil)

	var captured *computev1.HostResource
	inv.On("Update", mock.Anything, testTenantID, testResourceID, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { captured = args.Get(4).(*inventoryv1.Resource).GetHost() }).
		Return(nil, nil)

	reconcile(t, ctrl)

	require.NotNil(t, captured)
	assert.Equal(t, computev1.KvmState_KVM_STATE_ERROR, captured.GetCurrentKvmState())
	assert.Contains(t, captured.GetKvmSessionStatus(), "AMT_STATE_PROVISIONED")
}

func TestReconcile_ConsentReceived_Ack(t *testing.T) {
	t.Parallel()
	inv := &mockInventoryClient{}
	ctrl := newController(t, inv, mps.NewMockClientWithResponsesInterface(t))
	inv.On("GetHostByUUID", mock.Anything, testTenantID, testHostUUID).
		Return(makeHost(computev1.KvmState_KVM_STATE_CONSENT_RECEIVED, computev1.KvmState_KVM_STATE_AWAITING_CONSENT,
			computev1.AmtState_AMT_STATE_PROVISIONED, computev1.AmtControlMode_AMT_CONTROL_MODE_CCM), nil)
	reconcile(t, ctrl)
	inv.AssertNotCalled(t, "Update")
}

func TestReconcile_RedirectionReceived_SetsStart(t *testing.T) {
	t.Parallel()
	inv := &mockInventoryClient{}
	ctrl := newController(t, inv, mps.NewMockClientWithResponsesInterface(t))

	inv.On("GetHostByUUID", mock.Anything, testTenantID, testHostUUID).
		Return(makeHost(computev1.KvmState_KVM_STATE_REDIRECTION_RECEIVED, computev1.KvmState_KVM_STATE_AWAITING_CONSENT,
			computev1.AmtState_AMT_STATE_PROVISIONED, computev1.AmtControlMode_AMT_CONTROL_MODE_ACM), nil)

	var captured *computev1.HostResource
	inv.On("Update", mock.Anything, testTenantID, testResourceID, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { captured = args.Get(4).(*inventoryv1.Resource).GetHost() }).
		Return(nil, nil)

	reconcile(t, ctrl)

	require.NotNil(t, captured)
	assert.Equal(t, computev1.KvmState_KVM_STATE_START, captured.GetCurrentKvmState())
	assert.Equal(t, computev1.KvmStatus_KVM_STATUS_ACTIVATED, captured.GetKvmStatus())
}

func TestReconcile_StopKVM_SetsStop(t *testing.T) {
	t.Parallel()
	inv := &mockInventoryClient{}
	ctrl := newController(t, inv, mps.NewMockClientWithResponsesInterface(t))

	inv.On("GetHostByUUID", mock.Anything, testTenantID, testHostUUID).
		Return(makeHost(computev1.KvmState_KVM_STATE_STOP, computev1.KvmState_KVM_STATE_START,
			computev1.AmtState_AMT_STATE_PROVISIONED, computev1.AmtControlMode_AMT_CONTROL_MODE_ACM), nil)

	var captured *computev1.HostResource
	inv.On("Update", mock.Anything, testTenantID, testResourceID, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) { captured = args.Get(4).(*inventoryv1.Resource).GetHost() }).
		Return(nil, nil)

	reconcile(t, ctrl)

	require.NotNil(t, captured)
	assert.Equal(t, computev1.KvmState_KVM_STATE_STOP, captured.GetCurrentKvmState())
	assert.Equal(t, computev1.KvmStatus_KVM_STATUS_DEACTIVATED, captured.GetKvmStatus())
}

func TestReconcile_StopKVM_AlreadyStopped_NoWrite(t *testing.T) {
	t.Parallel()
	inv := &mockInventoryClient{}
	ctrl := newController(t, inv, mps.NewMockClientWithResponsesInterface(t))
	inv.On("GetHostByUUID", mock.Anything, testTenantID, testHostUUID).
		Return(makeHost(computev1.KvmState_KVM_STATE_STOP, computev1.KvmState_KVM_STATE_STOP,
			computev1.AmtState_AMT_STATE_PROVISIONED, computev1.AmtControlMode_AMT_CONTROL_MODE_ACM), nil)
	reconcile(t, ctrl)
	inv.AssertNotCalled(t, "Update")
}

func TestController_Start_Stop(t *testing.T) {
	t.Parallel()
	inv := &mockInventoryClient{}
	mpsMock := mps.NewMockClientWithResponsesInterface(t)
	inv.On("ListAll", mock.Anything, mock.Anything).Return([]*inventoryv1.Resource{}, nil)

	termChan := make(chan bool, 1)
	readyChan := make(chan bool, 1)
	wg := &sync.WaitGroup{}

	ctrl := &kvm.Controller{
		MpsClient: mpsMock, InventoryRmClient: inv,
		TermChan: termChan, ReadyChan: readyChan,
		ReconcilePeriod: time.Minute, RequestTimeout: 5 * time.Second,
		WaitGroup: wg,
	}
	ctrl.KvmController = rec_v2.NewController[kvm.ID](ctrl.Reconcile)

	wg.Add(1)
	go ctrl.Start()

	select {
	case ready := <-readyChan:
		assert.True(t, ready)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for ReadyChan")
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	termChan <- true

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for controller to stop")
	}
}
