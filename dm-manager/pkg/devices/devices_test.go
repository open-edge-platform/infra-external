// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package devices

import (
	"context"
	"net/http"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	computev1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/compute/v1"
	inventoryv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	inv_testing "github.com/open-edge-platform/infra-core/inventory/v2/pkg/testing"
	"github.com/open-edge-platform/infra-external/dm-manager/pkg/api/mps"
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
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	hostUUID := uuid.NewString()
	host := dao.CreateHostWithOpts(t, client.FakeTenantID, true, func(c *computev1.HostResource) {
		c.DesiredPowerState = computev1.PowerState_POWER_STATE_ON
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
				CurrentPowerState: computev1.PowerState_POWER_STATE_OFF,
				CurrentAmtState:   computev1.AmtState_AMT_STATE_PROVISIONED,
			},
		},
	})
	assert.NoError(t, err)

	mpsMock := new(mps.MockClientWithResponsesInterface)

	deviceReconciller := DeviceController{
		MpsClient: mpsMock, InventoryRmClient: dao.GetRMClient(), InventoryAPIClient: dao.GetAPIClient(),
	}
	deviceController := rec_v2.NewController[HostID](
		deviceReconciller.Reconcile)
	deviceReconciller.DeviceController = deviceController

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

	host, err = dao.GetRMClient().GetHostByUUID(context.Background(), client.FakeTenantID, hostUUID)
	assert.NoError(t, err)
	assert.Equal(t, computev1.PowerState_POWER_STATE_ON, host.CurrentPowerState)
}

func TestDeviceController_Reconcile_powerCycleShouldRebootAndChangeToPowerOn(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	hostUUID := uuid.NewString()
	host := dao.CreateHostWithOpts(t, client.FakeTenantID, true, func(c *computev1.HostResource) {
		c.DesiredPowerState = computev1.PowerState_POWER_STATE_RESET
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
				CurrentPowerState: computev1.PowerState_POWER_STATE_HIBERNATE,
				CurrentAmtState:   computev1.AmtState_AMT_STATE_PROVISIONED,
			},
		},
	})
	assert.NoError(t, err)

	mpsMock := new(mps.MockClientWithResponsesInterface)

	deviceReconciller := DeviceController{
		MpsClient: mpsMock, InventoryRmClient: dao.GetRMClient(), InventoryAPIClient: dao.GetAPIClient(),
	}
	deviceController := rec_v2.NewController[HostID](
		deviceReconciller.Reconcile)
	deviceReconciller.DeviceController = deviceController

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

	host, err = dao.GetRMClient().GetHostByUUID(context.Background(), client.FakeTenantID, hostUUID)
	assert.NoError(t, err)
	assert.Equal(t, computev1.PowerState_POWER_STATE_ON, host.CurrentPowerState)
	assert.Equal(t, computev1.PowerState_POWER_STATE_ON, host.DesiredPowerState)
}
