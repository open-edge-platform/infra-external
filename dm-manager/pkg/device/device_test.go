// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package device

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
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
	statusv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/status/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	inv_testing "github.com/open-edge-platform/infra-core/inventory/v2/pkg/testing"
	"github.com/open-edge-platform/infra-external/dm-manager/pkg/api/mps"
	"github.com/open-edge-platform/infra-external/dm-manager/pkg/tenant"
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
	deviceID := NewID("tenant1", "host1")
	assert.Equal(t, "tenant1", deviceID.GetTenantID())
	assert.Equal(t, "host1", deviceID.GetHostUUID())

	deviceID = NewID("zxc", "")
	assert.Equal(t, "zxc", deviceID.GetTenantID())
	assert.Equal(t, "", deviceID.GetHostUUID())

	deviceID = NewID("", "asd")
	assert.Equal(t, "", deviceID.GetTenantID())
	assert.Equal(t, "asd", deviceID.GetHostUUID())
}

func TestDeviceController_Reconcile_poweredOffSystemShouldTurnOn(t *testing.T) {
	dao, hostUUID, mpsMock, deviceReconciller := prepareEnv(t, computev1.PowerState_POWER_STATE_OFF)

	mpsMock.On("GetApiV1DevicesGuidWithResponse", mock.Anything, mock.Anything).
		Return(&mps.GetApiV1DevicesGuidResponse{}, nil)
	mpsMock.On("PostApiV1AmtPowerActionGuidWithResponse", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&mps.PostApiV1AmtPowerActionGuidResponse{
			HTTPResponse: &http.Response{
				StatusCode: http.StatusOK,
			},
			JSON200: &mps.PowerActionResponse{
				Body: &struct {
					ReturnValue    *int    `json:"ReturnValue,omitempty"`
					ReturnValueStr *string `json:"ReturnValueStr,omitempty"`
				}{
					ReturnValueStr: tenant.Ptr("SUCCESS"),
				},
			},
			Body: []byte(`{"ReturnValue":0,"ReturnValueStr":"SUCCESS"}`),
		}, nil)

	deviceReconciller.Reconcile(context.Background(), rec_v2.Request[ID]{ID: NewID(client.FakeTenantID, hostUUID)})

	host, err := dao.GetRMClient().GetHostByUUID(context.Background(), client.FakeTenantID, hostUUID)
	assert.NoError(t, err)
	assert.Equal(t, computev1.PowerState_POWER_STATE_ON, host.CurrentPowerState)
}

func prepareEnv(
	t *testing.T, currentPowerState computev1.PowerState,
) (*inv_testing.InvResourceDAO, string, *mps.MockClientWithResponsesInterface, Controller) {
	t.Helper()
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	hostUUID := uuid.NewString()
	host := dao.CreateHostWithOpts(t, client.FakeTenantID, true, func(c *computev1.HostResource) {
		c.DesiredPowerState = computev1.PowerState_POWER_STATE_ON
		c.DesiredAmtState = computev1.AmtState_AMT_STATE_PROVISIONED
		//nolint: gosec // overflow is not going to happen
		c.PowerStatusTimestamp = uint64(time.Unix(1750058683, 0).Unix()) // Ensuring that status in tests will always be updated
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

	deviceReconciller := Controller{
		MpsClient:         mpsMock,
		InventoryRmClient: dao.GetRMClient(),
		RequestTimeout:    time.Second,
		ReconcilePeriod:   time.Minute,
		ReadyChan:         make(chan bool, 1),
	}
	deviceController := rec_v2.NewController[ID](
		deviceReconciller.Reconcile)
	deviceReconciller.DeviceController = deviceController
	return dao, hostUUID, mpsMock, deviceReconciller
}

func prepareAMTEnv(
	t *testing.T, currentAMTState computev1.AmtState,
) (*inv_testing.InvResourceDAO, string, *mps.MockClientWithResponsesInterface, Controller) {
	t.Helper()
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	hostUUID := uuid.NewString()
	host := dao.CreateHostWithOpts(t, client.FakeTenantID, true, func(c *computev1.HostResource) {
		c.CurrentAmtState = computev1.AmtState_AMT_STATE_UNSPECIFIED
		//nolint: gosec // overflow is not going to happen
		c.AmtStatusTimestamp = uint64(time.Unix(1750058683, 0).Unix()) // Ensuring that status in tests will always be updated
		c.Uuid = hostUUID
	})

	_, err := dao.GetRMClient().Update(context.Background(), host.GetTenantId(), host.GetResourceId(), &fieldmaskpb.FieldMask{
		Paths: []string{
			computev1.HostResourceFieldCurrentAmtState, computev1.HostResourceFieldCurrentPowerState,
		},
	}, &inventoryv1.Resource{
		Resource: &inventoryv1.Resource_Host{
			Host: &computev1.HostResource{
				CurrentAmtState: currentAMTState,
			},
		},
	})
	assert.NoError(t, err)

	mpsMock := new(mps.MockClientWithResponsesInterface)

	deviceReconciller := Controller{
		MpsClient:         mpsMock,
		InventoryRmClient: dao.GetRMClient(),
		RequestTimeout:    time.Second,
		ReconcilePeriod:   time.Minute,
		ReadyChan:         make(chan bool, 1),
	}
	deviceController := rec_v2.NewController[ID](
		deviceReconciller.Reconcile)
	deviceReconciller.DeviceController = deviceController
	return dao, hostUUID, mpsMock, deviceReconciller
}

func TestDeviceController_Start(t *testing.T) {
	termChan := make(chan bool, 1)
	readyChan := make(chan bool, 1)
	wg := &sync.WaitGroup{}
	dc := &Controller{
		InventoryRmClient: inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient(),
		TermChan:          termChan,
		ReadyChan:         readyChan,
		ReconcilePeriod:   time.Minute,
		RequestTimeout:    time.Second,
		WaitGroup:         wg,
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

func TestDeviceController_ReconcileAll_shouldContinueOnErrorInReconcile(t *testing.T) {
	_, _, mpsMock, deviceReconciller := prepareEnv(t, computev1.PowerState_POWER_STATE_OFF)

	powerHook := util.NewTestAssertHook("failed to send power action to MPS")
	reconcileHook := util.NewTestAssertHook("reconciliation of devices is done")
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(powerHook, reconcileHook)}

	mpsMock.On("PostApiV1AmtPowerActionGuidWithResponse", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&mps.PostApiV1AmtPowerActionGuidResponse{}, errors.Errorf("mocked error"))

	deviceReconciller.ReconcileAll()

	powerHook.AssertWithTimeout(t, time.Second)
	reconcileHook.AssertWithTimeout(t, time.Second)
}

func TestDeviceController_Start_shouldHandleEvents(t *testing.T) {
	eventsWatcher := make(chan *client.WatchEvents, 10)
	wg := &sync.WaitGroup{}
	_, hostUUID, mpsMock, deviceReconciller := prepareEnv(t, computev1.PowerState_POWER_STATE_ON)

	mpsMock.On("GetApiV1AmtPowerStateGuidWithResponse", mock.Anything, mock.Anything, mock.Anything).
		Return(&mps.GetApiV1AmtPowerStateGuidResponse{
			HTTPResponse: &http.Response{
				StatusCode: http.StatusOK,
			},
			JSON200: &mps.PowerStateResponse{
				Powerstate: tenant.Ptr(int(powerOn)),
			},
		}, nil)

	deviceReconciller.EventsWatcher = eventsWatcher

	eventHook := util.NewTestAssertHook(fmt.Sprintf("received %v event",
		inventoryv1.SubscribeEventsResponse_EVENT_KIND_CREATED.String()))
	reconcileHook := util.NewTestAssertHook("desired state is equal to current state ")
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(eventHook, reconcileHook)}

	wg.Add(1)
	go deviceReconciller.Start()

	eventsWatcher <- &client.WatchEvents{
		Event: &inventoryv1.SubscribeEventsResponse{
			EventKind: inventoryv1.SubscribeEventsResponse_EVENT_KIND_CREATED,
			Resource: &inventoryv1.Resource{
				Resource: &inventoryv1.Resource_Host{
					Host: &computev1.HostResource{
						TenantId: client.FakeTenantID,
						Uuid:     hostUUID,
					},
				},
			},
		},
	}

	eventHook.AssertWithTimeout(t, time.Second)
	reconcileHook.AssertWithTimeout(t, time.Second)
}

func TestController_checkPowerState_ifDesiredIsPowerOnButDeviceIsPoweredOffThenShouldForcePowerOn(t *testing.T) {
	dao, hostUUID, mpsMock, deviceReconciller := prepareEnv(t, computev1.PowerState_POWER_STATE_POWER_CYCLE)
	deviceReconciller.StatusChangeGracePeriod = 0

	mpsMock.On("GetApiV1AmtPowerStateGuidWithResponse", mock.Anything, mock.Anything, mock.Anything).
		Return(&mps.GetApiV1AmtPowerStateGuidResponse{
			HTTPResponse: &http.Response{
				StatusCode: http.StatusOK,
			},
			JSON200: &mps.PowerStateResponse{
				Powerstate: tenant.Ptr(int(powerOff)),
			},
		}, nil)
	mpsMock.On("PostApiV1AmtPowerActionGuidWithResponse", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&mps.PostApiV1AmtPowerActionGuidResponse{
			HTTPResponse: &http.Response{
				StatusCode: http.StatusOK,
			},
			Body: []byte(`{"ReturnValue":0,"ReturnValueStr":"SUCCESS"}`),
		}, nil)

	invHost, err := dao.GetRMClient().GetHostByUUID(context.Background(), client.FakeTenantID, hostUUID)
	assert.NoError(t, err)
	assert.Equal(t, statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED, invHost.PowerStatusIndicator)

	powerHook := util.NewTestAssertHook(fmt.Sprintf("but current power state is %v", 8))
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(powerHook)}

	deviceReconciller.syncPowerStatus(context.Background(),
		rec_v2.Request[ID]{ID: NewID(client.FakeTenantID, hostUUID)}, invHost)

	powerHook.AssertWithTimeout(t, time.Second)
	invHost, err = dao.GetRMClient().GetHostByUUID(context.Background(), client.FakeTenantID, hostUUID)
	assert.NoError(t, err)
	assert.Equal(t, computev1.PowerState_POWER_STATE_OFF.String(), invHost.CurrentPowerState.String())
	assert.Equal(t, statusv1.StatusIndication_STATUS_INDICATION_ERROR.String(), invHost.PowerStatusIndicator.String())
}

func TestController_checkPowerState_ifDesiredIsPowerOnAndDeviceIsPoweredOnThenShouldChangeStatusToIdle(t *testing.T) {
	dao, hostUUID, mpsMock, deviceReconciller := prepareEnv(t, computev1.PowerState_POWER_STATE_ON)

	mpsMock.On("GetApiV1AmtPowerStateGuidWithResponse", mock.Anything, mock.Anything, mock.Anything).
		Return(&mps.GetApiV1AmtPowerStateGuidResponse{
			HTTPResponse: &http.Response{
				StatusCode: http.StatusOK,
			},
			JSON200: &mps.PowerStateResponse{
				Powerstate: tenant.Ptr(int(powerOn)),
			},
		}, nil)

	invHost, err := dao.GetRMClient().GetHostByUUID(context.Background(), client.FakeTenantID, hostUUID)
	assert.NoError(t, err)
	assert.Equal(t, statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED, invHost.PowerStatusIndicator)

	powerHook := util.NewTestAssertHook("which matches current power state")
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(powerHook)}

	assert.Equal(t, statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED.String(), invHost.GetPowerStatusIndicator().String())

	deviceReconciller.syncPowerStatus(context.Background(),
		rec_v2.Request[ID]{ID: NewID(client.FakeTenantID, hostUUID)}, invHost)

	powerHook.AssertWithTimeout(t, time.Second)
	invHost, err = dao.GetRMClient().GetHostByUUID(context.Background(), client.FakeTenantID, hostUUID)
	assert.NoError(t, err)
	assert.Equal(t, computev1.PowerState_POWER_STATE_ON, invHost.CurrentPowerState)
	assert.Equal(t, statusv1.StatusIndication_STATUS_INDICATION_IDLE.String(), invHost.GetPowerStatusIndicator().String())
}

func TestController_checkPowerState_ifDeviceIsNotConnectedThenShouldRetryReconcile(t *testing.T) {
	dao, hostUUID, mpsMock, deviceReconciller := prepareEnv(t, computev1.PowerState_POWER_STATE_ON)

	mpsMock.On("GetApiV1AmtPowerStateGuidWithResponse", mock.Anything, mock.Anything, mock.Anything).
		Return(&mps.GetApiV1AmtPowerStateGuidResponse{
			HTTPResponse: &http.Response{
				StatusCode: http.StatusNotFound,
			},
		}, nil)

	invHost, err := dao.GetRMClient().GetHostByUUID(context.Background(), client.FakeTenantID, hostUUID)
	assert.NoError(t, err)
	assert.Equal(t, statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED, invHost.PowerStatusIndicator)

	powerHook := util.NewTestAssertHook("expected to get 2XX, but got 404")
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(powerHook)}

	deviceReconciller.syncPowerStatus(context.Background(),
		rec_v2.Request[ID]{ID: NewID(client.FakeTenantID, hostUUID)}, invHost)

	powerHook.AssertWithTimeout(t, time.Second)
	invHost, err = dao.GetRMClient().GetHostByUUID(context.Background(), client.FakeTenantID, hostUUID)
	assert.NoError(t, err)
	assert.Equal(t, computev1.PowerState_POWER_STATE_ON, invHost.CurrentPowerState)
}

func TestDeviceController_Reconcile_ifReceivedNotFoundDuringRequestThenShouldRetryRequest(t *testing.T) {
	_, hostUUID, mpsMock, deviceReconciller := prepareEnv(t, computev1.PowerState_POWER_STATE_OFF)

	mpsMock.On("GetApiV1DevicesGuidWithResponse", mock.Anything, mock.Anything).
		Return(&mps.GetApiV1DevicesGuidResponse{}, nil)
	mpsMock.On("PostApiV1AmtPowerActionGuidWithResponse", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&mps.PostApiV1AmtPowerActionGuidResponse{
			HTTPResponse: &http.Response{
				StatusCode: http.StatusNotFound,
			},
		}, nil)

	powerHook := util.NewTestAssertHook("expected to get 2XX, but got 404")
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(powerHook)}

	deviceReconciller.Reconcile(context.Background(), rec_v2.Request[ID]{ID: NewID(client.FakeTenantID, hostUUID)})

	powerHook.AssertWithTimeout(t, time.Second)
}

func TestDeviceController_Reconcile_ifResponseHasNotReadyThenShouldFailRequest(t *testing.T) {
	_, hostUUID, mpsMock, deviceReconciller := prepareEnv(t, computev1.PowerState_POWER_STATE_OFF)

	mpsMock.On("GetApiV1DevicesGuidWithResponse", mock.Anything, mock.Anything).
		Return(&mps.GetApiV1DevicesGuidResponse{}, nil)
	mpsMock.On("PostApiV1AmtPowerActionGuidWithResponse", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&mps.PostApiV1AmtPowerActionGuidResponse{
			HTTPResponse: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"ReturnValue":2,"ReturnValueStr":"NOT_READY"}`)),
			},
			JSON200: &mps.PowerActionResponse{Body: &struct {
				ReturnValue    *int    `json:"ReturnValue,omitempty"`
				ReturnValueStr *string `json:"ReturnValueStr,omitempty"`
			}{ReturnValue: tenant.Ptr(2), ReturnValueStr: tenant.Ptr("NOT_READY")}},
		}, nil)

	powerHook := util.NewTestAssertHook("expected to receive SUCCESS, but got")
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(powerHook)}

	deviceReconciller.Reconcile(context.Background(), rec_v2.Request[ID]{ID: NewID(client.FakeTenantID, hostUUID)})

	powerHook.AssertWithTimeout(t, time.Second)
}

func TestDeviceController_Reconcile_AmtCapable(t *testing.T) {
	dao, hostUUID, _, deviceReconciller := prepareAMTEnv(t, computev1.AmtState_AMT_STATE_UNPROVISIONED)

	deviceReconciller.Reconcile(context.Background(), rec_v2.Request[ID]{ID: NewID(client.FakeTenantID, hostUUID)})

	host, err := dao.GetRMClient().GetHostByUUID(context.Background(), client.FakeTenantID, hostUUID)
	assert.NoError(t, err)
	assert.Equal(t, computev1.AmtState_AMT_STATE_UNPROVISIONED, host.CurrentAmtState)
}

func TestDeviceController_Reconcile_AmtActivation(t *testing.T) {
	dao, hostUUID, _, deviceReconciller := prepareAMTEnv(t, computev1.AmtState_AMT_STATE_PROVISIONED)

	deviceReconciller.Reconcile(context.Background(), rec_v2.Request[ID]{ID: NewID(client.FakeTenantID, hostUUID)})

	host, err := dao.GetRMClient().GetHostByUUID(context.Background(), client.FakeTenantID, hostUUID)
	assert.NoError(t, err)
	assert.Equal(t, computev1.AmtState_AMT_STATE_PROVISIONED, host.CurrentAmtState)
}

func TestDeviceController_Reconcile_AmtDeactivation(t *testing.T) {
	dao, hostUUID, _, deviceReconciller := prepareAMTEnv(t, computev1.AmtState(computev1.AmtState_AMT_STATE_UNPROVISIONED))

	deviceReconciller.Reconcile(context.Background(), rec_v2.Request[ID]{ID: NewID(client.FakeTenantID, hostUUID)})

	host, err := dao.GetRMClient().GetHostByUUID(context.Background(), client.FakeTenantID, hostUUID)
	assert.NoError(t, err)
	assert.Equal(t, computev1.AmtState_AMT_STATE_UNPROVISIONED, host.CurrentAmtState)
}
