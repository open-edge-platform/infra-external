// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package kvm_test

import (
	"context"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	computev1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/compute/v1"
	inventoryv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	inv_testing "github.com/open-edge-platform/infra-core/inventory/v2/pkg/testing"
	"github.com/open-edge-platform/infra-external/kvm-manager/pkg/api/mps"
	"github.com/open-edge-platform/infra-external/kvm-manager/pkg/kvm"
	rec_v2 "github.com/open-edge-platform/orch-library/go/pkg/controller/v2"
)

func TestMain(m *testing.M) {
	tmpDir, err := os.MkdirTemp(os.TempDir(), "kvm-manager-test-")
	if err != nil {
		panic("failed to create temp dir: " + err.Error())
	}
	inv_testing.StartTestingEnvironment(tmpDir, "", tmpDir)
	os.Exit(m.Run())
}

func newHost(t *testing.T,
	dao *inv_testing.InvResourceDAO,
	desired computev1.KvmState,
	current computev1.KvmState,
	amtState computev1.AmtState,
	controlMode computev1.AmtControlMode,
) (string, string) {
	t.Helper()
	hostUUID := uuid.NewString()
	host := dao.CreateHostWithOpts(t, client.FakeTenantID, true, func(c *computev1.HostResource) {
		c.Uuid = hostUUID
		c.DesiredKvmState = desired
		c.AmtControlMode = controlMode
	})
	// flush current state via Update so inventory reflects it
	_, err := dao.GetRMClient().Update(
		context.Background(),
		host.GetTenantId(),
		host.GetResourceId(),
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.HostResourceFieldCurrentAmtState,
			computev1.HostResourceFieldCurrentKvmState,
		}},
		&inventoryv1.Resource{
			Resource: &inventoryv1.Resource_Host{
				Host: &computev1.HostResource{
					CurrentAmtState: amtState,
					CurrentKvmState: current,
				},
			},
		},
	)
	require.NoError(t, err)
	return hostUUID, host.GetResourceId()
}

func newController(t *testing.T, dao *inv_testing.InvResourceDAO) (*kvm.Controller, *mps.MockClientWithResponsesInterface) {
	t.Helper()
	mpsMock := mps.NewMockClientWithResponsesInterface(t)
	ctrl := &kvm.Controller{
		MpsClient:         mpsMock,
		InventoryRmClient: dao.GetRMClient(),
		RequestTimeout:    5 * time.Second,
		ReconcilePeriod:   time.Minute,
		ReadyChan:         make(chan bool, 2),
	}
	kvmCtrl := rec_v2.NewController[kvm.ID](ctrl.Reconcile)
	ctrl.KvmController = kvmCtrl
	return ctrl, mpsMock
}

func reconcile(t *testing.T, ctrl *kvm.Controller, hostUUID string) {
	t.Helper()
	ctrl.Reconcile(context.Background(), rec_v2.Request[kvm.ID]{
		ID: kvm.NewID(client.FakeTenantID, hostUUID),
	})
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
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	ctrl, _ := newController(t, dao)

	hostUUID, _ := newHost(t, dao,
		computev1.KvmState_KVM_STATE_UNSPECIFIED,
		computev1.KvmState_KVM_STATE_UNSPECIFIED,
		computev1.AmtState_AMT_STATE_PROVISIONED,
		computev1.AmtControlMode_AMT_CONTROL_MODE_ACM,
	)
	reconcile(t, ctrl, hostUUID)
}

func TestReconcile_StartKVM_ACM_SetsAwaitingConsent(t *testing.T) {
	t.Parallel()
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	ctrl, mpsMock := newController(t, dao)

	hostUUID, _ := newHost(t, dao,
		computev1.KvmState_KVM_STATE_START,
		computev1.KvmState_KVM_STATE_UNSPECIFIED,
		computev1.AmtState_AMT_STATE_PROVISIONED,
		computev1.AmtControlMode_AMT_CONTROL_MODE_ACM,
	)

	mpsMock.On("GetApiV1AmtFeaturesGuidWithResponse", mock.Anything, mock.Anything, mock.Anything).
		Return(&mps.GetApiV1AmtFeaturesGuidResponse{
			HTTPResponse: &http.Response{StatusCode: http.StatusOK},
			JSON200:      &mps.GetAMTFeaturesResponse{KVM: boolPtr(true)},
		}, nil)

	reconcile(t, ctrl, hostUUID)

	host, err := dao.GetRMClient().GetHostByUUID(context.Background(), client.FakeTenantID, hostUUID)
	require.NoError(t, err)
	assert.Equal(t, computev1.KvmState_KVM_STATE_AWAITING_CONSENT, host.GetCurrentKvmState())
}

func TestReconcile_StartKVM_NotProvisioned_WritesError(t *testing.T) {
	t.Parallel()
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	ctrl, _ := newController(t, dao)

	hostUUID, _ := newHost(t, dao,
		computev1.KvmState_KVM_STATE_START,
		computev1.KvmState_KVM_STATE_UNSPECIFIED,
		computev1.AmtState_AMT_STATE_UNSPECIFIED, // not provisioned
		computev1.AmtControlMode_AMT_CONTROL_MODE_ACM,
	)

	reconcile(t, ctrl, hostUUID)

	host, err := dao.GetRMClient().GetHostByUUID(context.Background(), client.FakeTenantID, hostUUID)
	require.NoError(t, err)
	assert.Equal(t, computev1.KvmState_KVM_STATE_ERROR, host.GetCurrentKvmState())
	assert.Contains(t, host.GetKvmSessionStatus(), "AMT_STATE_PROVISIONED")
}

func TestReconcile_ConsentReceived_Ack(t *testing.T) {
	t.Parallel()
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	ctrl, _ := newController(t, dao)

	hostUUID, _ := newHost(t, dao,
		computev1.KvmState_KVM_STATE_CONSENT_RECEIVED,
		computev1.KvmState_KVM_STATE_AWAITING_CONSENT,
		computev1.AmtState_AMT_STATE_PROVISIONED,
		computev1.AmtControlMode_AMT_CONTROL_MODE_CCM,
	)

	reconcile(t, ctrl, hostUUID) // should ack consent without error
}

func TestReconcile_RedirectionReceived_SetsStart(t *testing.T) {
	t.Parallel()
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	ctrl, _ := newController(t, dao)

	hostUUID, _ := newHost(t, dao,
		computev1.KvmState_KVM_STATE_REDIRECTION_RECEIVED,
		computev1.KvmState_KVM_STATE_AWAITING_CONSENT,
		computev1.AmtState_AMT_STATE_PROVISIONED,
		computev1.AmtControlMode_AMT_CONTROL_MODE_ACM,
	)

	reconcile(t, ctrl, hostUUID)

	host, err := dao.GetRMClient().GetHostByUUID(context.Background(), client.FakeTenantID, hostUUID)
	require.NoError(t, err)
	assert.Equal(t, computev1.KvmState_KVM_STATE_START, host.GetCurrentKvmState())
	assert.Equal(t, computev1.KvmStatus_KVM_STATUS_ACTIVATED, host.GetKvmStatus())
}

func TestReconcile_StopKVM_SetsStop(t *testing.T) {
	t.Parallel()
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	ctrl, _ := newController(t, dao)

	hostUUID, _ := newHost(t, dao,
		computev1.KvmState_KVM_STATE_STOP,
		computev1.KvmState_KVM_STATE_START,
		computev1.AmtState_AMT_STATE_PROVISIONED,
		computev1.AmtControlMode_AMT_CONTROL_MODE_ACM,
	)

	reconcile(t, ctrl, hostUUID)

	host, err := dao.GetRMClient().GetHostByUUID(context.Background(), client.FakeTenantID, hostUUID)
	require.NoError(t, err)
	assert.Equal(t, computev1.KvmState_KVM_STATE_STOP, host.GetCurrentKvmState())
	assert.Equal(t, computev1.KvmStatus_KVM_STATUS_DEACTIVATED, host.GetKvmStatus())
}

func TestReconcile_StopKVM_AlreadyStopped_NoWrite(t *testing.T) {
	t.Parallel()
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	ctrl, _ := newController(t, dao)

	hostUUID, _ := newHost(t, dao,
		computev1.KvmState_KVM_STATE_STOP,
		computev1.KvmState_KVM_STATE_STOP, // already stopped
		computev1.AmtState_AMT_STATE_PROVISIONED,
		computev1.AmtControlMode_AMT_CONTROL_MODE_ACM,
	)

	reconcile(t, ctrl, hostUUID) // shouldStopKVMSession returns false
}

func TestReconcile_BlocksDisruptivePowerOp_DuringStart(t *testing.T) {
	t.Parallel()
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	ctrl, _ := newController(t, dao)

	hostUUID, resourceID := newHost(t, dao,
		computev1.KvmState_KVM_STATE_START,
		computev1.KvmState_KVM_STATE_UNSPECIFIED,
		computev1.AmtState_AMT_STATE_PROVISIONED,
		computev1.AmtControlMode_AMT_CONTROL_MODE_ACM,
	)

	// patch desired_power_state = POWER_STATE_OFF
	_, err := dao.GetRMClient().Update(
		context.Background(), client.FakeTenantID, resourceID,
		&fieldmaskpb.FieldMask{Paths: []string{computev1.HostResourceFieldDesiredPowerState}},
		&inventoryv1.Resource{Resource: &inventoryv1.Resource_Host{
			Host: &computev1.HostResource{DesiredPowerState: computev1.PowerState_POWER_STATE_OFF},
		}},
	)
	require.NoError(t, err)

	reconcile(t, ctrl, hostUUID)

	host, err := dao.GetRMClient().GetHostByUUID(context.Background(), client.FakeTenantID, hostUUID)
	require.NoError(t, err)
	// power op must be reset
	assert.Equal(t, computev1.PowerState_POWER_STATE_UNSPECIFIED, host.GetDesiredPowerState())
	assert.Contains(t, host.GetKvmSessionStatus(), "power operation")
}

func TestController_Start_Stop(t *testing.T) {
	t.Parallel()
	termChan := make(chan bool, 1)
	readyChan := make(chan bool, 1)
	wg := &sync.WaitGroup{}

	ctrl := &kvm.Controller{
		InventoryRmClient: inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient(),
		TermChan:          termChan,
		ReadyChan:         readyChan,
		ReconcilePeriod:   time.Minute,
		RequestTimeout:    time.Second,
		WaitGroup:         wg,
	}
	kvmCtrl := rec_v2.NewController[kvm.ID](ctrl.Reconcile)
	ctrl.KvmController = kvmCtrl

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

func boolPtr(b bool) *bool { return &b }
