// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package testing_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/client/deployment"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/client/inventory"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/model"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/loca"
	loca_testing "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/testing"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/util"
)

func TestMain(m *testing.M) {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	projectRoot := filepath.Dir(filepath.Dir(wd))
	err = os.Setenv(loca.CaCertPath, projectRoot+"/secrets")
	if err != nil {
		panic(err)
	}

	run := m.Run() // run all tests

	os.Exit(run)
}

func Test_MockServerUnavailable(t *testing.T) {
	ts, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer ts.StopDummyLOCAServer()
	ts.Override(loca_testing.InventoryDevicesPath, func(res http.ResponseWriter, req *http.Request) {
		loca_testing.WriteStructToResponse(res, req, &model.DtoDeviceListResponse{}, http.StatusServiceUnavailable)
	})
	// creating client
	cli := loca.InitialiseTestLocaClient(ts.GetURL(), loca_testing.LocaSecret)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// error is expected
	devices, err := cli.LocaAPI.Inventory.GetAPIV1InventoryDevices(
		&inventory.GetAPIV1InventoryDevicesParams{Context: ctx}, cli.AuthWriter)
	require.Error(t, err)
	require.Nil(t, devices)
}

func Test_MockServerReturnsEmptyResponse(t *testing.T) {
	ts, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer ts.StopDummyLOCAServer()
	ts.Override(loca_testing.DeploymentInstancesIDPath, func(res http.ResponseWriter, req *http.Request) {
		loca_testing.WriteStructToResponse(res, req, &model.DtoInstanceQryResponse{}, http.StatusOK)
	})

	// creating client
	cli := loca.InitialiseTestLocaClient(ts.GetURL(), loca_testing.LocaSecret)

	// error is expected
	instance, err := cli.LocaAPI.Deployment.GetAPIV1DeploymentInstancesID(
		&deployment.GetAPIV1DeploymentInstancesIDParams{Context: context.Background(), ID: loca_testing.LocaInstanceID},
		cli.AuthWriter)
	require.NoError(t, err)
	require.Nil(t, instance.Payload.Data)
}

func Test_MockServerNoInstances(t *testing.T) {
	ts, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer ts.StopDummyLOCAServer()
	ts.Override(loca_testing.DeploymentInstancesIDPath, func(res http.ResponseWriter, req *http.Request) {
		loca_testing.WriteStructToResponse(res, req, &model.DtoInstanceQryResponse{}, http.StatusNotFound)
	})

	// creating client
	cli := loca.InitialiseTestLocaClient(ts.GetURL(), loca_testing.LocaSecret)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// no error
	devices, err := cli.LocaAPI.Inventory.GetAPIV1InventoryDevices(
		&inventory.GetAPIV1InventoryDevicesParams{Context: ctx}, cli.AuthWriter)
	require.NoError(t, err)
	require.NotNil(t, devices)

	// not found error and nil instance
	instance, err := cli.LocaAPI.Deployment.GetAPIV1DeploymentInstancesID(
		&deployment.GetAPIV1DeploymentInstancesIDParams{Context: ctx, ID: loca_testing.LocaInstanceID},
		cli.AuthWriter)
	require.ErrorContains(t, err, "(status 404)")
	require.Nil(t, instance)
}

func Test_MockServerCorruptedResponse(t *testing.T) {
	ts, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer ts.StopDummyLOCAServer()
	ts.Override(loca_testing.InventoryDevicesPath, func(res http.ResponseWriter, req *http.Request) {
		loca_testing.WriteStructToResponse(res, req, &model.DtoDeviceListResponse{}, http.StatusBadRequest)
	})
	ts.Override(loca_testing.DeploymentInstancesPath, func(res http.ResponseWriter, req *http.Request) {
		loca_testing.WriteStructToResponse(res, req, &model.DtoInstancesQryResponse{}, http.StatusNotFound)
	})
	ts.Override(loca_testing.DeploymentInstancesIDPath, func(res http.ResponseWriter, req *http.Request) {
		loca_testing.WriteStructToResponse(res, req, &model.DtoInstanceQryResponse{}, http.StatusInternalServerError)
	})
	// creating client
	cli := loca.InitialiseTestLocaClient(ts.GetURL(), loca_testing.LocaSecret)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// error is expected
	devices, err := cli.LocaAPI.Inventory.GetAPIV1InventoryDevices(
		&inventory.GetAPIV1InventoryDevicesParams{Context: ctx}, cli.AuthWriter)
	require.Error(t, err)
	require.Nil(t, devices)

	// error is expected
	instances, err := cli.LocaAPI.Deployment.GetAPIV1DeploymentInstances(
		&deployment.GetAPIV1DeploymentInstancesParams{Context: ctx}, cli.AuthWriter)
	require.Error(t, err)
	require.Nil(t, instances)

	// error is expected
	instance, err := cli.LocaAPI.Deployment.GetAPIV1DeploymentInstancesID(
		&deployment.GetAPIV1DeploymentInstancesIDParams{Context: ctx, ID: loca_testing.LocaInstanceID},
		cli.AuthWriter)
	require.Error(t, err)
	require.Nil(t, instance)
}

// This TC verifies that the device status was changed from "staged" to "active" and back.
func TestMockServerDeviceTransition(t *testing.T) {
	ts, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer ts.StopDummyLOCAServer()

	// creating client
	cli := loca.InitialiseTestLocaClient(ts.GetURL(), loca_testing.LocaSecret)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// no error
	devices, err := cli.LocaAPI.Inventory.GetAPIV1InventoryDevices(
		&inventory.GetAPIV1InventoryDevicesParams{Context: ctx}, cli.AuthWriter)
	require.NoError(t, err)
	require.NotNil(t, devices)
	assert.Equal(t, "staged", devices.Payload.Data.Results[0].Status)

	// transit device to active state
	ts.Override(loca_testing.InventoryDevicesPath, loca_testing.ActiveDevice)

	// no error
	devices2, err := cli.LocaAPI.Inventory.GetAPIV1InventoryDevices(
		&inventory.GetAPIV1InventoryDevicesParams{Context: ctx}, cli.AuthWriter)
	require.NoError(t, err)
	require.NotNil(t, devices2)
	assert.Equal(t, "active", devices2.Payload.Data.Results[0].Status)

	// transit device to staged state
	ts.Override(loca_testing.InventoryDevicesPath, loca_testing.DevicesFunc)

	// no error
	devices3, err := cli.LocaAPI.Inventory.GetAPIV1InventoryDevices(
		&inventory.GetAPIV1InventoryDevicesParams{Context: ctx}, cli.AuthWriter)
	require.NoError(t, err)
	require.NotNil(t, devices3)
	assert.Equal(t, "staged", devices3.Payload.Data.Results[0].Status)
}

// This TC verifies that the instance status and stage was changed from "Failed" and "instance post-configuring" to
// "Finished successfully" and "installed" and back.
func TestMockServerInstanceTransition(t *testing.T) {
	ts, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer ts.StopDummyLOCAServer()

	// creating client
	cli := loca.InitialiseTestLocaClient(ts.GetURL(), loca_testing.LocaSecret)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// no error
	instance, err := cli.LocaAPI.Deployment.GetAPIV1DeploymentInstancesID(
		&deployment.GetAPIV1DeploymentInstancesIDParams{Context: ctx, ID: loca_testing.LocaInstanceID},
		cli.AuthWriter)
	require.NoError(t, err)
	require.NotNil(t, instance)
	assert.Equal(t, "Deploy", instance.Payload.Data.Operation)
	assert.Equal(t, "instance post-configuring", instance.Payload.Data.Stage)
	assert.Equal(t, "Failed", instance.Payload.Data.Status)

	// transit instance to "installed" stage with "Finished successfully" status
	ts.Override(loca_testing.DeploymentInstancesIDPath, loca_testing.ProvisionInstanceFunc)

	// no error
	instance2, err := cli.LocaAPI.Deployment.GetAPIV1DeploymentInstancesID(
		&deployment.GetAPIV1DeploymentInstancesIDParams{Context: ctx, ID: loca_testing.LocaInstanceID},
		cli.AuthWriter)
	require.NoError(t, err)
	require.NotNil(t, instance2)
	assert.Equal(t, "Deploy", instance2.Payload.Data.Operation)
	assert.Equal(t, "installed", instance2.Payload.Data.Stage)
	assert.Equal(t, "Finished successfully", instance2.Payload.Data.Status)

	// transit instance to Failed state
	ts.Override(loca_testing.DeploymentInstancesIDPath, loca_testing.InstancesByIDFunc)

	// no error
	instance3, err := cli.LocaAPI.Deployment.GetAPIV1DeploymentInstancesID(
		&deployment.GetAPIV1DeploymentInstancesIDParams{Context: ctx, ID: loca_testing.LocaInstanceID},
		cli.AuthWriter)
	require.NoError(t, err)
	require.NotNil(t, instance3)
	assert.Equal(t, "Deploy", instance3.Payload.Data.Operation)
	assert.Equal(t, "instance post-configuring", instance3.Payload.Data.Stage)
	assert.Equal(t, "Failed", instance3.Payload.Data.Status)
}

func Test_TwoMockServersSimultaneously(t *testing.T) {
	locaTS1, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer locaTS1.StopDummyLOCAServer()

	locaTS2, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer locaTS2.StopDummyLOCAServer()

	locaTS1.Override(loca_testing.DeploymentInstancesIDPath, func(writer http.ResponseWriter, request *http.Request) {
		vars := mux.Vars(request)
		if vars["id"] == loca_testing.LocaInstanceID {
			loca_testing.WriteStructToResponse(writer, request, &model.DtoInstanceQryResponse{
				Data: &model.DtoInstance{
					Operation: loca_testing.OperationDeploy, Stage: util.StageInstancePostconfiguring, Status: util.StatusFailed,
				},
			}, http.StatusOK)
		} else {
			loca_testing.WriteStructToResponse(writer, request, &model.DtoErrResponse{}, http.StatusNotFound)
		}
	})

	// creating client
	cli1 := loca.InitialiseTestLocaClient(locaTS1.GetURL(), loca_testing.LocaSecret)
	// creating client
	cli2 := loca.InitialiseTestLocaClient(locaTS2.GetURL(), loca_testing.LocaSecret)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// no error
	instance1, err := cli1.LocaAPI.Deployment.GetAPIV1DeploymentInstancesID(
		&deployment.GetAPIV1DeploymentInstancesIDParams{Context: ctx, ID: loca_testing.LocaInstanceID},
		cli1.AuthWriter)
	require.NoError(t, err)
	require.NotNil(t, instance1)
	assert.Equal(t, "Deploy", instance1.Payload.Data.Operation)
	assert.Equal(t, "instance post-configuring", instance1.Payload.Data.Stage)
	assert.Equal(t, "Failed", instance1.Payload.Data.Status)

	// no error
	instance2, err := cli2.LocaAPI.Deployment.GetAPIV1DeploymentInstancesID(
		&deployment.GetAPIV1DeploymentInstancesIDParams{Context: ctx, ID: loca_testing.SecondaryInstanceID},
		cli2.AuthWriter)
	require.NoError(t, err)
	require.NotNil(t, instance2)
	assert.Equal(t, "Deploy", instance2.Payload.Data.Operation)
	assert.Equal(t, "instance post-configuring", instance2.Payload.Data.Stage)
	assert.Equal(t, "Failed", instance2.Payload.Data.Status)
}
