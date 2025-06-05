// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package devices

import (
	"context"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	computev1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/compute/v1"
	inventoryv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	inv_testing "github.com/open-edge-platform/infra-core/inventory/v2/pkg/testing"
	"github.com/open-edge-platform/infra-external/dm-manager/pkg/api/mps"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/util"
	rec_v2 "github.com/open-edge-platform/orch-library/go/pkg/controller/v2"
)

func TestMain(m *testing.M) {
	tmpDir, err := os.MkdirTemp(os.TempDir(), "dm-manager-test-")
	if err != nil {
		log.Fatal().Err(err).Msgf("Failed to create temporary directory")
	}
	inv_testing.StartTestingEnvironment(tmpDir, "", tmpDir)

	run := m.Run() // run all tests

	os.Exit(run)
}

func TestNewDeviceID(t *testing.T) {
	deviceID := NewDeviceID("tenant1", "host1")
	assert.Equal(t, "tenant1", deviceID.GetTenantID())
	assert.Equal(t, "host1", deviceID.GetHostUUID())

	deviceID = NewDeviceID("zxc", "")
	assert.Equal(t, "zxc", deviceID.GetTenantID())
	assert.Equal(t, "", deviceID.GetHostUUID())

	deviceID = NewDeviceID("", "asd")
	assert.Equal(t, "", deviceID.GetTenantID())
	assert.Equal(t, "asd", deviceID.GetHostUUID())
}

func TestDeviceController_Reconcile_poweredOffSystemShouldTurnOn(t *testing.T) {
	dao, hostUUID, mpsMock, deviceReconciller := prepareEnv(t,
		computev1.PowerState_POWER_STATE_ON, computev1.PowerState_POWER_STATE_OFF)

	mpsMock.On("GetApiV1DevicesGuidWithResponse", mock.Anything, mock.Anything).
		Return(&mps.GetApiV1DevicesGuidResponse{}, nil)
	mpsMock.On("PostApiV1AmtPowerActionGuidWithResponse", mock.Anything, mock.Anything, mock.Anything).
		Return(&mps.PostApiV1AmtPowerActionGuidResponse{
			HTTPResponse: &http.Response{
				StatusCode: http.StatusOK,
			},
			Body: []byte(`{"ReturnValue":0,"ReturnValueStr":"SUCCESS"}`),
		}, nil)

	deviceReconciller.Reconcile(context.Background(), rec_v2.Request[HostID]{ID: NewDeviceID(client.FakeTenantID, hostUUID)})

	host, err := dao.GetRMClient().GetHostByUUID(context.Background(), client.FakeTenantID, hostUUID)
	assert.NoError(t, err)
	assert.Equal(t, computev1.PowerState_POWER_STATE_ON, host.CurrentPowerState)
}

func TestDeviceController_Reconcile_powerCycleShouldRebootAndChangeToPowerOn(t *testing.T) {
	dao, hostUUID, mpsMock, deviceReconciller := prepareEnv(t,
		computev1.PowerState_POWER_STATE_RESET, computev1.PowerState_POWER_STATE_HIBERNATE)

	mpsMock.On("GetApiV1DevicesGuidWithResponse", mock.Anything, mock.Anything).
		Return(&mps.GetApiV1DevicesGuidResponse{}, nil)
	mpsMock.On("PostApiV1AmtPowerActionGuidWithResponse", mock.Anything, mock.Anything, mock.Anything).
		Return(&mps.PostApiV1AmtPowerActionGuidResponse{
			HTTPResponse: &http.Response{
				StatusCode: http.StatusOK,
			},
			Body: []byte(`{"ReturnValue":0,"ReturnValueStr":"SUCCESS"}`),
		}, nil)

	deviceReconciller.Reconcile(context.Background(), rec_v2.Request[HostID]{ID: NewDeviceID(client.FakeTenantID, hostUUID)})

	host, err := dao.GetRMClient().GetHostByUUID(context.Background(), client.FakeTenantID, hostUUID)
	assert.NoError(t, err)
	assert.Equal(t, computev1.PowerState_POWER_STATE_ON, host.CurrentPowerState)
	assert.Equal(t, computev1.PowerState_POWER_STATE_ON, host.DesiredPowerState)
}

func prepareEnv(
	t *testing.T, desiredPowerState, currentPowerState computev1.PowerState,
) (*inv_testing.InvResourceDAO, string, *mps.MockClientWithResponsesInterface, DeviceController) {
	t.Helper()
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	hostUUID := uuid.NewString()
	host := dao.CreateHostWithOpts(t, client.FakeTenantID, true, func(c *computev1.HostResource) {
		c.DesiredPowerState = desiredPowerState
		c.DesiredAmtState = computev1.AmtState_AMT_STATE_PROVISIONED
		c.Uuid = hostUUID
	})

	_, err := dao.GetRMClient().Update(context.Background(), host.GetTenantId(), host.GetResourceId(), &fieldmaskpb.FieldMask{
		Paths: []string{
			computev1.HostResourceFieldCurrentAmtState, computev1.HostResourceFieldCurrentPowerState,
		},
	}, &inventoryv1.Resource{
		Resource: &inventoryv1.Resource_Host{
			Host: &computev1.HostResource{
				CurrentPowerState: currentPowerState,
				CurrentAmtState:   computev1.AmtState_AMT_STATE_PROVISIONED,
			},
		},
	})
	assert.NoError(t, err)

	mpsMock := new(mps.MockClientWithResponsesInterface)

	deviceReconciller := DeviceController{
		MpsClient:          mpsMock,
		InventoryRmClient:  dao.GetRMClient(),
		InventoryAPIClient: dao.GetAPIClient(),
		RequestTimeout:     time.Second,
	}
	deviceController := rec_v2.NewController[HostID](
		deviceReconciller.Reconcile)
	deviceReconciller.DeviceController = deviceController
	return dao, hostUUID, mpsMock, deviceReconciller
}

func TestDeviceController_Start(t *testing.T) {
	termChan := make(chan bool, 1)
	readyChan := make(chan bool, 1)
	wg := &sync.WaitGroup{}
	dc := &DeviceController{
		InventoryAPIClient: inv_testing.TestClients[inv_testing.APIClient].GetTenantAwareInventoryClient(),
		InventoryRmClient:  inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient(),
		TermChan:           termChan,
		ReadyChan:          readyChan,
		ReconcilePeriod:    time.Minute,
		RequestTimeout:     time.Second,
		WaitGroup:          wg,
	}

	wg.Add(1)
	go dc.Start()

	select {
	case readyEvent := <-readyChan:
		assert.True(t, readyEvent)
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for ReadyChan signal")
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	termChan <- true

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for reconciler to stop")
	}

	assert.True(t, true, "Manager stopped successfully")
}

func TestDeviceController_Reconcile_desiredAndActualStatesAreEqualShouldDoNothing(t *testing.T) {
	dao, hostUUID, _, deviceReconciller := prepareEnv(t, computev1.PowerState_POWER_STATE_ON, computev1.PowerState_POWER_STATE_ON)

	hook := util.NewTestAssertHook("desired state is equal to current state ")
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(hook)}

	deviceReconciller.Reconcile(context.Background(), rec_v2.Request[HostID]{ID: NewDeviceID(client.FakeTenantID, hostUUID)})

	host, err := dao.GetRMClient().GetHostByUUID(context.Background(), client.FakeTenantID, hostUUID)
	assert.NoError(t, err)
	assert.Equal(t, computev1.PowerState_POWER_STATE_ON, host.CurrentPowerState)
	assert.Equal(t, computev1.PowerState_POWER_STATE_ON, host.DesiredPowerState)
	hook.Assert(t)
}

func TestDeviceController_ReconcileAll_shouldContinueOnErrorInReconcile(t *testing.T) {
	_, _, mpsMock, deviceReconciller := prepareEnv(t, computev1.PowerState_POWER_STATE_ON, computev1.PowerState_POWER_STATE_OFF)

	powerHook := util.NewTestAssertHook("failed to send power action to MPS")
	reconcileHook := util.NewTestAssertHook("reconciliation of devices is done")
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(powerHook, reconcileHook)}

	mpsMock.On("PostApiV1AmtPowerActionGuidWithResponse", mock.Anything, mock.Anything, mock.Anything).
		Return(&mps.PostApiV1AmtPowerActionGuidResponse{}, errors.Errorf("mocked error"))

	deviceReconciller.ReconcileAll()

	time.Sleep(time.Second)

	powerHook.Assert(t)
	reconcileHook.Assert(t)
}
