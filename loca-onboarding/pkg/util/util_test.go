// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package util_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpc_status "google.golang.org/grpc/status"

	computev1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/compute/v1"
	locationv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/location/v1"
	statusv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/status/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	inv_testing "github.com/open-edge-platform/infra-core/inventory/v2/pkg/testing"
	inv_utils "github.com/open-edge-platform/infra-core/inventory/v2/pkg/util"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/model"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/inventory"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/loca"
	loca_testing "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/testing"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/util"
)

const clientName = "TestLOCARMInventoryClient"

const statusCode0 = 0

const testOSResourceID = "os-abcd1234"

func TestMain(m *testing.M) {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	projectRoot := filepath.Dir(filepath.Dir(wd))
	policyPath := projectRoot + "/out"
	migrationsDir := projectRoot + "/out"
	err = os.Setenv(loca.CaCertPath, projectRoot+"/secrets")
	if err != nil {
		panic(err)
	}

	locaTS := loca_testing.StartTestingEnvironment(policyPath, migrationsDir, clientName)
	run := m.Run() // run all tests
	loca_testing.StopTestingEnvironment(locaTS, clientName)

	os.Exit(run)
}

const path = "pkg/examples/"

func getAbsolutePath() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	projectRoot := filepath.Dir(filepath.Dir(wd))

	return projectRoot, nil
}

func readFileAndGetBytes(path, filename string) ([]byte, error) {
	wd, err := getAbsolutePath()
	if err != nil {
		return nil, err
	}

	// reading the file first
	content, err := os.ReadFile(wd + "/" + path + filename)
	if err != nil {
		return nil, err
	}

	return content, nil
}

func loadJSONAsGetDeploymentInstances(path, filename string) (*model.DtoInstancesQryResponse, error) {
	// reading the api call response from a file
	bytes, err := readFileAndGetBytes(path, filename)
	if err != nil {
		return nil, err
	}

	// unmarshalling JSON data into interface
	var data *model.DtoInstancesQryResponse
	data, err = util.ParseJSONBytesIntoStruct(bytes, data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func loadJSONAsGetDeploymentInstancesByID(path, filename string) (*model.DtoInstanceQryResponse, error) {
	// reading the api call response from a file
	bytes, err := readFileAndGetBytes(path, filename)
	if err != nil {
		return nil, err
	}

	// unmarshalling JSON data into interface
	var data *model.DtoInstanceQryResponse
	data, err = util.ParseJSONBytesIntoStruct(bytes, data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func loadJSONAsGetInventoryDevices(path, filename string) (*model.DtoDeviceListResponse, error) {
	// reading the api call response from a file
	bytes, err := readFileAndGetBytes(path, filename)
	if err != nil {
		return nil, err
	}

	// unmarshalling JSON data into interface
	var data *model.DtoDeviceListResponse
	data, err = util.ParseJSONBytesIntoStruct(bytes, data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func loadJSONAsAuthentication(path, filename string) (*model.DtoUserLoginResponse, error) {
	// reading the api call response from a file
	bytes, err := readFileAndGetBytes(path, filename)
	if err != nil {
		return nil, err
	}

	// unmarshalling JSON data into interface
	var data *model.DtoUserLoginResponse
	data, err = util.ParseJSONBytesIntoStruct(bytes, data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func Test_LoadAndParseJSONDeploymentInstances(t *testing.T) {
	filename := "loca_api_deployment_instances.json"

	response, err := loadJSONAsGetDeploymentInstances(path, filename)
	require.NoError(t, err)

	assert.Equal(t, response.StatusCode, int64(statusCode0))
	assert.Equal(t, response.Message, "OK")
	assert.Equal(t, response.Data.Count, int64(1))
	assert.Equal(t, response.Data.Results[0].ID, "658c483ef445a55d541460db")
	assert.Equal(t, response.Data.Results[0].Flavor, "Edge Manageability Framework")
	assert.Equal(t, response.Data.Results[0].Status, "Failed")
	assert.Equal(t, response.Data.Results[0].Stage, "instance post-configuring")
	assert.Equal(t, response.Data.Results[0].Operation, "Deploy")
}

func Test_LoadAndParseJSONDeploymentInstanceByID(t *testing.T) {
	filename := "loca_api_deployment_instances_id.json"

	response, err := loadJSONAsGetDeploymentInstancesByID(path, filename)
	require.NoError(t, err)

	assert.Equal(t, response.StatusCode, int64(statusCode0))
	assert.Equal(t, response.Message, "ok")
	assert.Equal(t, response.Data.ID, "658c483ef445a55d541460db")
	assert.Equal(t, response.Data.Status, "Failed")
	assert.Equal(t, response.Data.Stage, "instance post-configuring")
	assert.Equal(t, response.Data.Operation, "Deploy")
	assert.Equal(t, response.Data.Flavor, "Edge Manageability Framework")
	assert.Equal(t,
		response.Data.Template.InstanceInfo.FlavorOptions.Version,
		"Ubuntu 22.04.3")
	assert.Equal(t,
		response.Data.Template.InstanceInfo.FlavorOptions.Version,
		"Ubuntu 22.04.3")
	assert.Equal(t, len(response.Data.Nodes), 1)
	assert.Equal(t, response.Data.Nodes[0].SerialNumber, "J900VN44")
}

func Test_LoadAndParseJSONInventoryDevices(t *testing.T) {
	filename := "loca_api_inventory_devices.json"

	response, err := loadJSONAsGetInventoryDevices(path, filename)
	require.NoError(t, err)

	assert.Equal(t, response.StatusCode, int64(statusCode0))
	assert.Equal(t, response.Message, "OK")
	assert.Equal(t, response.Data.Count, int64(1))
	assert.Equal(t, response.Data.Results[0].ID, "658c3b86f445a55d541460cf")
	assert.Equal(t, response.Data.Results[0].SerialNumber, "J900VN44")
	assert.Equal(t, response.Data.Results[0].UUID, "57ED598C4B9411EE806C3A7C7693AAC3")
}

func Test_LoadAndParseJSONAuthentication(t *testing.T) {
	filename := "loca_api_auth.json"

	response, err := loadJSONAsAuthentication(path, filename)
	require.NoError(t, err)

	assert.Equal(t, response.StatusCode, int64(statusCode0))
	assert.Equal(t, response.Message, "Authentication success.")
	assert.Equal(t, response.Data.Token, "some-valid-dummy-authentication-token")
	assert.Equal(t, response.Data.RefreshToken, "some-dummy-refresh-token")
}

func Test_loadAndParseJSONUnauthenticatedRequest(t *testing.T) {
	filename := "loca_api_unauthenticated_response.json"

	response1, err := loadJSONAsAuthentication(path, filename)
	require.NoError(t, err)

	assert.Equal(t, response1.StatusCode, int64(http.StatusUnauthorized))
	assert.Equal(t, response1.Message, "Token is invalid.")

	response2, err := loadJSONAsGetInventoryDevices(path, filename)
	require.NoError(t, err)

	assert.Equal(t, response2.StatusCode, int64(http.StatusUnauthorized))
	assert.Equal(t, response2.Message, "Token is invalid.")

	response3, err := loadJSONAsGetDeploymentInstances(path, filename)
	require.NoError(t, err)

	assert.Equal(t, response3.StatusCode, int64(http.StatusUnauthorized))
	assert.Equal(t, response3.Message, "Token is invalid.")

	response4, err := loadJSONAsGetDeploymentInstancesByID(path, filename)
	require.NoError(t, err)

	assert.Equal(t, response4.StatusCode, int64(http.StatusUnauthorized))
	assert.Equal(t, response4.Message, "Token is invalid.")
}

func Test_ParseEmptyJSONBytes(t *testing.T) {
	// unmarshalling empty JSON data into interface
	var data *model.DtoDeviceListResponse
	data, err := util.ParseJSONBytesIntoStruct(nil, data)
	require.NoError(t, err)
	require.Nil(t, data)
}

func Test_ConvertUUIDToFMInventoryUUID(t *testing.T) {
	uuidIncorrect := "57ED598C4B9411EE806C3A7C7693AAC3"

	convertedUUID, err := util.ConvertUUIDToFMInventoryUUID(uuidIncorrect)
	require.NoError(t, err)
	assert.Equal(t, convertedUUID, "57ed598c-4b94-11ee-806c-3a7c7693aac3")

	_, err = util.ConvertUUIDToFMInventoryUUID("bla-bla")
	require.Error(t, err)
}

func Test_ConvertUUIDToLOCAUUID(t *testing.T) {
	uuidCorrect := "071995e7-264a-4adb-9669-5eff59951bf1"

	convertedIncorrectUUID := util.ConvertUUIDToLOCAUUID(uuidCorrect)
	assert.Equal(t, convertedIncorrectUUID, "071995E7264A4ADB96695EFF59951BF1")
}

func Test_ConvertBothWays(t *testing.T) {
	uuidIncorrect := "57ED598C4B9411EE806C3A7C7693AAC3"

	convertedUUID, err := util.ConvertUUIDToFMInventoryUUID(uuidIncorrect)
	require.NoError(t, err)
	assert.Equal(t, convertedUUID, "57ed598c-4b94-11ee-806c-3a7c7693aac3")

	uuidIncorrectBack := util.ConvertUUIDToLOCAUUID(uuidIncorrect)
	assert.Equal(t, uuidIncorrect, uuidIncorrectBack)

	// now let's do the same but with correc UUID
	uuidCorrect := "071995e7-264a-4adb-9669-5eff59951bf1"

	convertedIncorrectUUID := util.ConvertUUIDToLOCAUUID(uuidCorrect)
	assert.Equal(t, convertedIncorrectUUID, "071995E7264A4ADB96695EFF59951BF1")

	uuidCorrectBack, err := util.ConvertUUIDToFMInventoryUUID(convertedIncorrectUUID)
	require.NoError(t, err)
	assert.Equal(t, uuidCorrect, uuidCorrectBack)
}

//nolint:funlen // this is a matrix-driven TC
func Test_InstanceStateAndStatusConversionFromLOCA(t *testing.T) {
	tests := map[string]struct {
		operation string
		stage     string
		status    string
		valid     bool
		assertion func(
			t *testing.T, state *computev1.InstanceState,
			provisioningStatus string, statusIndicator statusv1.StatusIndication,
		)
	}{
		"FailExpand": {
			operation: "Expand",
			stage:     "unknown",
			status:    "Unknown",
			valid:     false,
		},
		"FailUndefinedOperation": {
			operation: "Undefined",
			stage:     "unknown",
			status:    "Unknown",
			valid:     false,
		},
		"FailDeployOnboardedUnexpectedStatus": {
			operation: "Deploy",
			stage:     "onboarded",
			status:    "Unexpected status",
			valid:     false,
		},
		"FailDeployUnexpectedStageOnboarded": {
			operation: "Deploy",
			stage:     "unexpected stage",
			status:    "Onboarded",
			valid:     false,
		},
		"DeployOnboardedOnboarded": {
			operation: "Deploy",
			stage:     "onboarded",
			status:    "Onboarded",
			valid:     true,
			assertion: func(t *testing.T, state *computev1.InstanceState, provisioningStatus string,
				statusIndicator statusv1.StatusIndication,
			) {
				t.Helper()

				assert.Equal(t, computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED, *state)
				assert.Equal(t, util.StatusInstanceOnboarded, provisioningStatus)
				assert.Equal(t, statusv1.StatusIndication_STATUS_INDICATION_IDLE, statusIndicator)
			},
		},
		"DeployOnboardedInProgress": {
			operation: "Deploy",
			stage:     "onboarded",
			status:    "In progress",
			valid:     true,
			assertion: func(t *testing.T, state *computev1.InstanceState, provisioningStatus string,
				statusIndicator statusv1.StatusIndication,
			) {
				t.Helper()

				assert.Equal(t, computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED, *state)
				assert.Equal(t, util.StageOnboardedDescription, provisioningStatus)
				assert.Equal(t, statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS, statusIndicator)
			},
		},
		"DeployDeviceProfileApplyingInProgress": {
			operation: "Deploy",
			stage:     "device profile applying",
			status:    "In progress",
			valid:     true,
			assertion: func(t *testing.T, state *computev1.InstanceState, provisioningStatus string,
				statusIndicator statusv1.StatusIndication,
			) {
				t.Helper()

				assert.Equal(t, computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED, *state)
				assert.Equal(t, util.StageDeviceProfileApplyingDescription, provisioningStatus)
				assert.Equal(t, statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS, statusIndicator)
			},
		},
		"DeployInstanceConfiguringInProgress": {
			operation: "Deploy",
			stage:     "instance configuring",
			status:    "In progress",
			valid:     true,
			assertion: func(t *testing.T, state *computev1.InstanceState, provisioningStatus string,
				statusIndicator statusv1.StatusIndication,
			) {
				t.Helper()

				assert.Equal(t, computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED, *state)
				assert.Equal(t, util.StageInstanceConfiguringDescription, provisioningStatus)
				assert.Equal(t, statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS, statusIndicator)
			},
		},
		"DeployOSInstallingInProgress": {
			operation: "Deploy",
			stage:     "os installing",
			status:    "In progress",
			valid:     true,
			assertion: func(t *testing.T, state *computev1.InstanceState, provisioningStatus string,
				statusIndicator statusv1.StatusIndication,
			) {
				t.Helper()

				assert.Equal(t, computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED, *state)
				assert.Equal(t, util.StageOsInstallingDescription, provisioningStatus)
				assert.Equal(t, statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS, statusIndicator)
			},
		},
		"DeployInstanceInstallingInProgress": {
			operation: "Deploy",
			stage:     "instance installing",
			status:    "In progress",
			valid:     true,
			assertion: func(t *testing.T, state *computev1.InstanceState, provisioningStatus string,
				statusIndicator statusv1.StatusIndication,
			) {
				t.Helper()

				assert.Equal(t, computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED, *state)
				assert.Equal(t, util.StageInstanceInstallingDescription, provisioningStatus)
				assert.Equal(t, statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS, statusIndicator)
			},
		},
		"DeployInstancePostconfiguredInProgress": {
			operation: "Deploy",
			stage:     "instance post-configuring",
			status:    "In progress",
			valid:     true,
			assertion: func(t *testing.T, state *computev1.InstanceState, provisioningStatus string,
				statusIndicator statusv1.StatusIndication,
			) {
				t.Helper()

				assert.Equal(t, computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED, *state)
				assert.Equal(t, util.StageInstancePostconfiguredDescription, provisioningStatus)
				assert.Equal(t, statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS, statusIndicator)
			},
		},
		"DeployConfiguringInProgress": {
			operation: "Deploy",
			stage:     "configuring",
			status:    "In progress",
			valid:     true,
			assertion: func(t *testing.T, state *computev1.InstanceState, provisioningStatus string,
				statusIndicator statusv1.StatusIndication,
			) {
				t.Helper()

				assert.Equal(t, computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED, *state)
				assert.Equal(t, util.StageConfiguringDescription, provisioningStatus)
				assert.Equal(t, statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS, statusIndicator)
			},
		},
		"FailDeployInstancePreconfiguredInProgress": {
			operation: "Deploy",
			stage:     "instance pre-configuring",
			status:    "In progress",
			valid:     false,
		},
		"DeployInstalledFinishedSuccessfully": {
			operation: "Deploy",
			stage:     "installed",
			status:    "Finished successfully",
			valid:     true,
			assertion: func(t *testing.T, state *computev1.InstanceState, provisioningStatus string,
				statusIndicator statusv1.StatusIndication,
			) {
				t.Helper()

				assert.Equal(t, computev1.InstanceState_INSTANCE_STATE_RUNNING, *state)
				assert.Equal(t, util.StatusInstanceProvisioned, provisioningStatus)
				assert.Equal(t, statusv1.StatusIndication_STATUS_INDICATION_IDLE, statusIndicator)
			},
		},
		"DeployInstanceInstallingFinishedSuccessfully": {
			operation: "Deploy",
			stage:     "instance installing",
			status:    "Finished successfully",
			valid:     false,
		},
		"DeployOnboardedFailed": {
			operation: "Deploy",
			stage:     "onboarded",
			status:    "Failed",
			valid:     true,
			assertion: func(t *testing.T, state *computev1.InstanceState, provisioningStatus string,
				statusIndicator statusv1.StatusIndication,
			) {
				t.Helper()

				assert.Nil(t, state)
				assert.Equal(t, util.StageOnboardedDescription, provisioningStatus)
				assert.Equal(t, statusv1.StatusIndication_STATUS_INDICATION_ERROR, statusIndicator)
			},
		},
		"DeployOsInstallingFailed": {
			operation: "Deploy",
			stage:     "os installing",
			status:    "Failed",
			valid:     true,
			assertion: func(t *testing.T, state *computev1.InstanceState, provisioningStatus string,
				statusIndicator statusv1.StatusIndication,
			) {
				t.Helper()

				assert.Nil(t, state)
				assert.Equal(t, util.StageOsInstallingDescription, provisioningStatus)
				assert.Equal(t, statusv1.StatusIndication_STATUS_INDICATION_ERROR, statusIndicator)
			},
		},
		"DeployDeviceProfileApplyingFailed": {
			operation: "Deploy",
			stage:     "device profile applying",
			status:    "Failed",
			valid:     true,
			assertion: func(t *testing.T, state *computev1.InstanceState, provisioningStatus string,
				statusIndicator statusv1.StatusIndication,
			) {
				t.Helper()

				assert.Nil(t, state)
				assert.Equal(t, util.StageDeviceProfileApplyingDescription, provisioningStatus)
				assert.Equal(t, statusv1.StatusIndication_STATUS_INDICATION_ERROR, statusIndicator)
			},
		},
		"DeployInstanceConfiguringFailed": {
			operation: "Deploy",
			stage:     "instance configuring",
			status:    "Failed",
			valid:     true,
			assertion: func(t *testing.T, state *computev1.InstanceState, provisioningStatus string,
				statusIndicator statusv1.StatusIndication,
			) {
				t.Helper()

				assert.Nil(t, state)
				assert.Equal(t, util.StageInstanceConfiguringDescription, provisioningStatus)
				assert.Equal(t, statusv1.StatusIndication_STATUS_INDICATION_ERROR, statusIndicator)
			},
		},
		"DeployInstanceInstallingFailed": {
			operation: "Deploy",
			stage:     "instance installing",
			status:    "Failed",
			valid:     true,
			assertion: func(t *testing.T, state *computev1.InstanceState, provisioningStatus string,
				statusIndicator statusv1.StatusIndication,
			) {
				t.Helper()

				assert.Nil(t, state)
				assert.Equal(t, util.StageInstanceInstallingDescription, provisioningStatus)
				assert.Equal(t, statusv1.StatusIndication_STATUS_INDICATION_ERROR, statusIndicator)
			},
		},
		"DeployInstancePostconfiguredFailed": {
			operation: "Deploy",
			stage:     "instance post-configuring",
			status:    "Failed",
			valid:     true,
			assertion: func(t *testing.T, state *computev1.InstanceState, provisioningStatus string,
				statusIndicator statusv1.StatusIndication,
			) {
				t.Helper()

				assert.Nil(t, state)
				assert.Equal(t, util.StageInstancePostconfiguredDescription, provisioningStatus)
				assert.Equal(t, statusv1.StatusIndication_STATUS_INDICATION_ERROR, statusIndicator)
			},
		},
		"DeployConfiguringFailed": {
			operation: "Deploy",
			stage:     "configuring",
			status:    "Failed",
			valid:     true,
			assertion: func(t *testing.T, state *computev1.InstanceState, provisioningStatus string,
				statusIndicator statusv1.StatusIndication,
			) {
				t.Helper()

				assert.Nil(t, state)
				assert.Equal(t, util.StageConfiguringDescription, provisioningStatus)
				assert.Equal(t, statusv1.StatusIndication_STATUS_INDICATION_ERROR, statusIndicator)
			},
		},
		"DeployInstalledFailed": {
			operation: "Deploy",
			stage:     "installed",
			status:    "Failed",
			valid:     false,
		},
		"DeployUnexpectedStageFailed": {
			operation: "Deploy",
			stage:     "unexpected stage",
			status:    "Failed",
			valid:     false,
		},
		"DeployUnexpectedStageUnexpectedStatus": {
			operation: "Deploy",
			stage:     "unexpected stage",
			status:    "Unexpected status",
			valid:     false,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			state, status, details, err := util.ConvertLOCAInstanceStateAndStatusToFMStateAndStatus(
				tc.operation, tc.stage, tc.status)
			if tc.valid && err != nil {
				t.Errorf("%s has failed, but should have succeeded", name)
				t.FailNow()
			} else if !tc.valid && err == nil {
				t.Errorf("%s has succeeded, but should have failed", name)
				t.FailNow()
			}
			if tc.valid && !t.Failed() {
				tc.assertion(t, state, status, details)
			}
		})
	}
}

func Test_HostStateAndStatusConversionFromLOCA(t *testing.T) {
	statusInventory := "inventory"
	statusStaged := "staged"
	statusActive := "active"
	invalidInput := "invalid input"

	state, onboardingStatus, statusIndication, err := util.ConvertLOCADeviceStatusToFMStateAndStatus(statusInventory)
	assert.NoError(t, err)
	assert.Equal(t, computev1.HostState_HOST_STATE_ONBOARDED, *state)
	assert.Equal(t, statusv1.StatusIndication_STATUS_INDICATION_IDLE, statusIndication)
	assert.Equal(t, util.DeviceStatusInventoryDescription, onboardingStatus)

	state, onboardingStatus, statusIndication, err = util.ConvertLOCADeviceStatusToFMStateAndStatus(statusStaged)
	assert.NoError(t, err)
	assert.Equal(t, computev1.HostState_HOST_STATE_ONBOARDED, *state)
	assert.Equal(t, statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS, statusIndication)
	assert.Equal(t, util.DeviceStatusStagedDescription, onboardingStatus)

	state, onboardingStatus, statusIndication, err = util.ConvertLOCADeviceStatusToFMStateAndStatus(statusActive)
	assert.NoError(t, err)
	assert.Equal(t, computev1.HostState_HOST_STATE_ONBOARDED, *state)
	assert.Equal(t, statusv1.StatusIndication_STATUS_INDICATION_IDLE, statusIndication)
	assert.Equal(t, util.DeviceStatusActiveDescription, onboardingStatus)

	// testing the error test case
	state, onboardingStatus, statusIndication, err = util.ConvertLOCADeviceStatusToFMStateAndStatus(invalidInput)
	assert.Error(t, err)
	assert.Nil(t, state)
	assert.Equal(t, statusv1.StatusIndication_STATUS_INDICATION_ERROR, statusIndication)
	assert.Equal(t, "Host is invalid input", onboardingStatus)

	// testing the second error test case
	state, onboardingStatus, statusIndication, err = util.ConvertLOCADeviceStatusToFMStateAndStatus("")
	assert.Error(t, err)
	assert.Nil(t, state)
	assert.Equal(t, statusv1.StatusIndication_STATUS_INDICATION_ERROR, statusIndication)
	assert.Equal(t, "Host status is unknown", onboardingStatus)
}

func Test_findHostInList(t *testing.T) {
	host1 := util.BuildNewHost(uuid.NewString(), "1234567abc")
	host1.ResourceId = "host-12345678"
	host2 := util.BuildNewHost(uuid.NewString(), "ABC12345")
	host2.ResourceId = "host-abc12345"
	host3 := util.BuildNewHost(uuid.NewString(), "JY1974DB")
	host3.ResourceId = "host-ab1974db"
	host4 := util.BuildNewHost(uuid.NewString(), "BCD983ABC98")
	host4.ResourceId = "host-abcdef78"

	hostList := []*computev1.HostResource{
		host1, host2, host3,
	}

	// Searching for Host, which exists
	foundHost, exist, err := util.FindHostInList(host3, hostList)
	require.NoError(t, err)
	require.NotNil(t, foundHost)
	assert.True(t, exist)
	assert.Equal(t, host3, foundHost)

	// Searching for Host which does NOT exist
	_, exist, err = util.FindHostInList(host4, hostList)
	require.NoError(t, err)
	assert.False(t, exist)

	hostList = append(hostList, host4)

	// Performing an inconsistency check - different Resource IDs
	host5 := util.BuildNewHost(host2.GetUuid(), host3.GetSerialNumber())
	_, exist, err = util.FindHostInList(host5, hostList)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Host data are inconsistent")
	assert.False(t, exist)

	// performing an inconsistency check - inconsistent UUID
	// no Host exist with provided UUID, but a Host with provided Serial Number exists
	host6 := util.BuildNewHost(uuid.NewString(), host3.GetSerialNumber())
	_, exist, err = util.FindHostInList(host6, hostList)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Inconsistent Host UUID")
	assert.False(t, exist)

	// performing an inconsistency check - inconsistent Serial Numbers
	// no Host exist with provided Serial Number, but a Host with provided UUID exists
	host7 := util.BuildNewHost(host2.GetUuid(), "1111AAAA")
	_, exist, err = util.FindHostInList(host7, hostList)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Inconsistent Host Serial Number")
	assert.False(t, exist)
}

//nolint:dupl // this UT tests different function
func Test_findHostInLOCAHostList(t *testing.T) {
	host1 := &model.DtoDeviceListElement{
		UUID:         inv_utils.ConvertInventoryUUIDToLenovoUUID(uuid.NewString()),
		SerialNumber: "1234567abc",
	}
	host2 := &model.DtoDeviceListElement{
		UUID:         inv_utils.ConvertInventoryUUIDToLenovoUUID(uuid.NewString()),
		SerialNumber: "ABC12345",
	}
	host3 := &model.DtoDeviceListElement{
		UUID:         inv_utils.ConvertInventoryUUIDToLenovoUUID(uuid.NewString()),
		SerialNumber: "JY1974DBC",
	}
	host3Inv := util.BuildNewHost(host3.UUID, host3.SerialNumber)
	host4Inv := util.BuildNewHost(
		inv_utils.ConvertInventoryUUIDToLenovoUUID(uuid.NewString()),
		"BCD983ABC98",
	)

	hostList := []*model.DtoDeviceListElement{
		host1, host2, host3,
	}

	foundHost, exist := util.FindHostInLOCAHostList(host3Inv, hostList)
	assert.True(t, exist)
	assert.Equal(t, host3Inv, foundHost)

	_, exist = util.FindHostInLOCAHostList(host4Inv, hostList)
	assert.False(t, exist)
}

//nolint:dupl // this UT tests different function
func Test_FindDeviceInLOCAHostList(t *testing.T) {
	host1 := &model.DtoDeviceListElement{
		UUID:         inv_utils.ConvertInventoryUUIDToLenovoUUID(uuid.NewString()),
		SerialNumber: "1234567abc",
	}
	host2 := &model.DtoDeviceListElement{
		UUID:         inv_utils.ConvertInventoryUUIDToLenovoUUID(uuid.NewString()),
		SerialNumber: "ABC12345",
	}
	host3 := &model.DtoDeviceListElement{
		UUID:         inv_utils.ConvertInventoryUUIDToLenovoUUID(uuid.NewString()),
		SerialNumber: "JY1974DBC",
	}
	host3Inv := util.BuildNewHost(host3.UUID, host3.SerialNumber)
	host4Inv := util.BuildNewHost(
		inv_utils.ConvertInventoryUUIDToLenovoUUID(uuid.NewString()),
		"BCD983ABC98",
	)

	hostList := []*model.DtoDeviceListElement{
		host1, host2, host3,
	}

	foundLocaHost, exist := util.FindDeviceInLOCAHostList(host3Inv, hostList)
	assert.True(t, exist)
	assert.Equal(t, host3, foundLocaHost)

	_, exist = util.FindDeviceInLOCAHostList(host4Inv, hostList)
	assert.False(t, exist)
}

func Test_findInstanceInList(t *testing.T) {
	extraVars := map[string]interface{}{
		"os_resource_id": testOSResourceID,
	}

	inst1, err := util.BuildNewInstance(&model.DtoInstance{
		ID: uuid.NewString(),
		Template: &model.DtoTemplate{
			ExtraVars: extraVars,
		},
	})
	require.NoError(t, err)
	inst2, err := util.BuildNewInstance(&model.DtoInstance{
		ID: uuid.NewString(),
		Template: &model.DtoTemplate{
			ExtraVars: extraVars,
		},
	})
	require.NoError(t, err)
	inst3, err := util.BuildNewInstance(&model.DtoInstance{
		ID: uuid.NewString(),
		Template: &model.DtoTemplate{
			ExtraVars: extraVars,
		},
	})
	require.NoError(t, err)
	inst4, err := util.BuildNewInstance(&model.DtoInstance{
		ID: uuid.NewString(),
		Template: &model.DtoTemplate{
			ExtraVars: extraVars,
		},
	})
	require.NoError(t, err)

	instList := []*computev1.InstanceResource{
		inst1, inst2, inst3,
	}

	foundInstance, exist := util.FindInstanceInList(inst3, instList)
	assert.True(t, exist)
	assert.Equal(t, inst3, foundInstance)

	_, exist = util.FindInstanceInList(inst4, instList)
	assert.False(t, exist)
}

//nolint:dupl // this TC tests different function
func Test_FindInstanceInLOCAInstanceList(t *testing.T) {
	extraVars := map[string]interface{}{
		"os_resource_id": testOSResourceID,
	}

	inst1 := &model.DtoInstance{
		ID: uuid.NewString(),
		Template: &model.DtoTemplate{
			ExtraVars: extraVars,
		},
	}
	inst2 := &model.DtoInstance{
		ID: uuid.NewString(),
		Template: &model.DtoTemplate{
			ExtraVars: extraVars,
		},
	}
	inst3 := &model.DtoInstance{
		ID: uuid.NewString(),
		Template: &model.DtoTemplate{
			ExtraVars: extraVars,
		},
	}
	inst4 := &model.DtoInstance{
		ID: uuid.NewString(),
		Template: &model.DtoTemplate{
			ExtraVars: extraVars,
		},
	}
	inst3Inv, err := util.BuildNewInstance(inst3)
	require.NoError(t, err)
	inst4Inv, err := util.BuildNewInstance(inst4)
	require.NoError(t, err)

	instList := []*model.DtoInstance{
		inst1, inst2, inst3,
	}

	foundInstance, exist := util.FindInstanceInLOCAInstanceList(inst3Inv, instList)
	assert.True(t, exist)
	assert.Equal(t, inst3Inv, foundInstance)

	_, exist = util.FindInstanceInLOCAInstanceList(inst4Inv, instList)
	assert.False(t, exist)
}

//nolint:dupl // this TC tests different function
func Test_FindLOCAInstanceInLOCAInstanceList(t *testing.T) {
	correctExtraVars := map[string]interface{}{
		"os_resource_id": testOSResourceID,
	}

	inst1 := &model.DtoInstance{
		ID: uuid.NewString(),
		Template: &model.DtoTemplate{
			ExtraVars: correctExtraVars,
		},
	}
	inst2 := &model.DtoInstance{
		ID: uuid.NewString(),
		Template: &model.DtoTemplate{
			ExtraVars: correctExtraVars,
		},
	}
	inst3 := &model.DtoInstance{
		ID: uuid.NewString(),
		Template: &model.DtoTemplate{
			ExtraVars: correctExtraVars,
		},
	}
	inst4 := &model.DtoInstance{
		ID: uuid.NewString(),
		Template: &model.DtoTemplate{
			ExtraVars: correctExtraVars,
		},
	}

	inst3Inv, err := util.BuildNewInstance(inst3)
	require.NoError(t, err)
	inst4Inv, err := util.BuildNewInstance(inst4)
	require.NoError(t, err)

	instList := []*model.DtoInstance{
		inst1, inst2, inst3,
	}

	foundInstance, exist := util.FindLOCAInstanceInLOCAInstanceList(inst3Inv, instList)
	assert.True(t, exist)
	assert.Equal(t, inst3, foundInstance)

	_, exist = util.FindInstanceInLOCAInstanceList(inst4Inv, instList)
	assert.False(t, exist)
}

func Test_GetOSSHA256FromOsNameAndOsVersion(t *testing.T) {
	osName := "OS#1"
	osVersion := "v1"

	checksum := util.GetOSSHA256FromOsNameAndOsVersion(osName, osVersion)
	assert.Equal(t, "297e088b98483e60b5961016a4bc1ce98e131d877fc0a7ea85198a1c8b780d21", checksum)
}

func Test_CheckIfInstanceIsAssociated(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	host := dao.CreateHost(t, loca_testing.Tenant1)
	osRes := dao.CreateOs(t, loca_testing.Tenant1)
	instance := dao.CreateInstanceNoCleanup(t, loca_testing.Tenant1, host, osRes)
	host.Instance = instance

	err := util.CheckIfInstanceIsAssociated(
		context.Background(),
		inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient(),
		loca_testing.Tenant1,
		host,
	)
	require.Error(t, err)
	assert.Equal(t, errors.ErrorToString(err),
		fmt.Sprintf("Instance %s is still assigned to Host %s, waiting for Instance to be deleted first",
			host.GetInstance().GetResourceId(), host.GetResourceId()))

	// checking that the Host onboarding status has changed
	loca_testing.AssertHost(t, loca_testing.Tenant1, "", host.GetSerialNumber(), host.GetUuid(),
		host.GetDesiredState(), host.GetCurrentState(), util.StatusWaitingOnInstanceRemoval,
		statusv1.StatusIndication_STATUS_INDICATION_ERROR,
		// Host Status and Status Indicator are not set in this unit test
		"", statusv1.StatusIndication_STATUS_INDICATION_UNSPECIFIED)

	// removing Instance
	dao.HardDeleteInstance(t, loca_testing.Tenant1, instance.GetResourceId())

	// letting the Inventory to process the events
	time.Sleep(100 * time.Millisecond)

	// obtaining updated Host resource
	host, err = inventory.GetHostResourceByResourceID(context.Background(),
		inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient(), loca_testing.Tenant1, host.GetResourceId())
	require.NoError(t, err)

	err = util.CheckIfInstanceIsAssociated(
		context.Background(),
		inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient(),
		loca_testing.Tenant1,
		host,
	)
	require.NoError(t, err)
}

//nolint:gosec // this TC verifies parsing of the credentials
func TestBase64Decoder(t *testing.T) {
	base64Username := "YWRtaW4="         // corresponds to 'admin'
	base64Password := "RWRnZWluZnJhMTI=" // corresponds to 'Edgeinfra12'

	username, ok := util.DecodeBase64(base64Username)
	assert.True(t, ok)
	assert.Equal(t, "admin", username)

	password, ok := util.DecodeBase64(base64Password)
	assert.True(t, ok)
	assert.Equal(t, "Edgeinfra12", password)

	// negative case - decoding valid string
	str, ok := util.DecodeBase64("admin")
	require.False(t, ok)
	assert.Equal(t, str, "")
}

func TestConvertGPSStringToLatLng(t *testing.T) {
	tests := map[string]struct {
		gpsCoordinates string
		latitude       int32
		longtitude     int32
		valid          bool
	}{
		"CorrectInputData#1": {
			latitude:       373541070,
			longtitude:     -1219552380,
			gpsCoordinates: "37.354107,-121.955238",
			valid:          true,
		},
		"CorrectInputData#2": { // GPS coordinates contain few numbers after floating point
			latitude:       12740000,
			longtitude:     -32500,
			gpsCoordinates: "1.274,-0.00325",
			valid:          true,
		},
		"CorrectInputData#3": { // GPS coordinates contain more numbers after floating point, precision should be lost
			latitude:       -897165483,
			longtitude:     1211395523,
			gpsCoordinates: "-89.716548369,121.1395523865",
			valid:          true,
		},
		"CorrectInputData#4": {
			latitude:       373541070,
			longtitude:     -1219552380,
			gpsCoordinates: "37.354107,-121.955238",
			valid:          true,
		},
		"IncorrectLattitude": {
			latitude:       1373541070, // exceeded top boundary, i.e., 90*10^7
			longtitude:     -1219552380,
			gpsCoordinates: "137.354107,-121.955238",
			valid:          false,
		},
		"IncorrectLongtitude": {
			latitude:       373541070,
			longtitude:     -1919552380, // exceeded lower boundary, i.e., -180*10^7
			gpsCoordinates: "37.354107,-191.955238",
			valid:          false,
		},
		"IncorrectInputData#1": {
			latitude:       0,
			longtitude:     0,
			gpsCoordinates: "37.354107", // only one value provided instead of two
			valid:          false,
		},
		"IncorrectInputData#2": {
			latitude:       1373541070,
			longtitude:     -1919552380,
			gpsCoordinates: "",
			valid:          false,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			lat, lng, err := util.ConvertGPSStringToLatLng(tc.gpsCoordinates)
			if tc.valid && err != nil {
				t.Errorf("%s has failed, but should have succeeded: %v", name, err)
				t.FailNow()
			} else if !tc.valid && err == nil {
				t.Errorf("%s has succeeded, but should have failed", name)
				t.FailNow()
			}
			if tc.valid && !t.Failed() {
				assert.Equal(t, tc.latitude, lat)
				assert.Equal(t, tc.longtitude, lng)
			}
		})
	}
}

func TestConvertLatLngToGPSString(t *testing.T) {
	tests := map[string]struct {
		latitude       int32
		longtitude     int32
		gpsCoordinates string
		valid          bool
	}{
		"CorrectInputData#1": {
			latitude:       373541070,
			longtitude:     -1219552380,
			gpsCoordinates: "37.3541070,-121.9552380",
			valid:          true,
		},
		"CorrectInputData#2": { // GPS coordinates contain few numbers after floating point, trailing zeros should be added
			latitude:       12740000,
			longtitude:     -32500,
			gpsCoordinates: "1.2740000,-0.0032500",
			valid:          true,
		},
		"IncorrectLattitude": {
			latitude:       1373541070, // exceeded top boundary, i.e., 90*10^7
			longtitude:     -1219552380,
			gpsCoordinates: "",
			valid:          false,
		},
		"IncorrectLongtitude": {
			latitude:       373541070,
			longtitude:     -1919552380, // exceeded lower boundary, i.e., -180*10^7
			gpsCoordinates: "",
			valid:          false,
		},
		"IncorrectInputData": {
			latitude:       1373541070,  // exceeded top boundary, i.e., 90*10^7
			longtitude:     -1919552380, // exceeded lower boundary, i.e., -180*10^7
			gpsCoordinates: "",
			valid:          false,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			gps, err := util.ConvertLatLngToGPSString(tc.latitude, tc.longtitude)
			if tc.valid && err != nil {
				t.Errorf("%s has failed, but should have succeeded: %v", name, err)
				t.FailNow()
			} else if !tc.valid && err == nil {
				t.Errorf("%s has succeeded, but should have failed", name)
				t.FailNow()
			}
			if tc.valid && !t.Failed() {
				assert.Equal(t, tc.gpsCoordinates, gps)
			}
		})
	}
}

func TestConvertLOCASiteToSiteResource(t *testing.T) {
	locaSite := &model.DtoSite{
		Name:           "SANTA-CLARA",
		Address:        "2191,Laurelwood Road",
		GpsCoordinates: "37.354107,-121.955238",
	}

	lat, lng, err := util.ConvertGPSStringToLatLng(locaSite.GpsCoordinates)
	assert.NoError(t, err)

	siteRes, err := util.ConvertLOCASiteToSiteResource(locaSite)
	assert.NoError(t, err)
	assert.Equal(t, locaSite.Name, siteRes.GetName())
	assert.Equal(t, locaSite.Address, siteRes.GetAddress())
	assert.Equal(t, lat, siteRes.GetSiteLat())
	assert.Equal(t, lng, siteRes.GetSiteLng())
}

func TestConvertSiteResourceToLOCASite(t *testing.T) {
	siteRes := &locationv1.SiteResource{
		ResourceId: "site-1234abcd",
		Name:       "SANTA-CLARA",
		Address:    "2191,Laurelwood Road",
		SiteLat:    373541070,
		SiteLng:    -1219552380,
	}

	gpsCoordinates, err := util.ConvertLatLngToGPSString(siteRes.GetSiteLat(), siteRes.GetSiteLng())
	assert.NoError(t, err)

	locaSite, err := util.ConvertSiteResourceToLOCASite(siteRes)
	assert.NoError(t, err)
	assert.Equal(t, siteRes.GetName(), locaSite.Name)
	assert.Equal(t, siteRes.GetAddress(), locaSite.Address)
	assert.Equal(t, gpsCoordinates, locaSite.GpsCoordinates)
	assert.Equal(t, siteRes.GetResourceId(), locaSite.SiteCode)
}

func TestExtractProfileNameAndVersion(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	// creating OS
	os1 := dao.CreateOs(t, loca_testing.Tenant1)

	correctExtraVars := map[string]interface{}{
		"os_resource_id": os1.GetResourceId(),
	}
	incorrectExtraVars1 := map[string]interface{}{
		"name":        "image_id",
		"displayName": os1.GetImageId(),
	}
	incorrectExtraVars2 := map[string]interface{}{
		"os_resource_id": "",
	}

	correctTemplate1 := &model.DtoTemplate{
		Name:      "Correct Template #1",
		ExtraVars: correctExtraVars,
	}
	incorrectTemplate1 := &model.DtoTemplate{
		Name:      "Incorrect Template #1",
		ExtraVars: incorrectExtraVars1,
	}
	incorrectTemplate2 := &model.DtoTemplate{
		Name:      "Incorrect Template #2",
		ExtraVars: incorrectExtraVars2,
	}

	testCases := map[string]struct {
		template   *model.DtoTemplate
		resourceID string
		valid      bool
		expError   codes.Code
	}{
		"CorrectTemplate#1": {
			template:   correctTemplate1,
			resourceID: os1.GetResourceId(),
			valid:      true,
		},
		"IncorrectTemplate#1": {
			template: incorrectTemplate1,
			valid:    false,
			expError: codes.NotFound,
		},
		"IncorrectTemplate#2": {
			template: incorrectTemplate2,
			valid:    false,
			expError: codes.NotFound,
		},
		"EmptyTemplate": {
			template: &model.DtoTemplate{
				Name: "Empty Template",
			},
			valid:    false,
			expError: codes.NotFound,
		},
	}
	for tName, tc := range testCases {
		t.Run(tName, func(t *testing.T) {
			resourceID, err := util.ExtractOSResourceIDFromTemplate(tc.template)
			if !tc.valid {
				require.Error(t, err)
				assert.Equal(t, tc.expError, grpc_status.Code(err))
			} else {
				require.NoError(t, err, errors.ErrorToStringWithDetails(err))
				assert.Equal(t, tc.resourceID, resourceID)
			}
		})
	}
}

func TestFindWhichCloudServiceAttachedToSite(t *testing.T) {
	siteName1 := "new-site"
	siteName2 := "another-site"
	siteName3 := "some-site"
	cs1 := &model.DtoCloudServiceListElement{
		Name:            siteName1,
		SiteAssociation: []string{siteName1, siteName2},
	}
	cs2 := &model.DtoCloudServiceListElement{
		Name:            siteName2,
		SiteAssociation: []string{siteName2},
	}
	cs3 := &model.DtoCloudServiceListElement{
		Name:            siteName3,
		SiteAssociation: []string{siteName3},
	}
	csNoSiteAssociation := &model.DtoCloudServiceListElement{
		Name:            "No association Cloud Service",
		SiteAssociation: make([]string, 0),
	}
	list1 := make([]*model.DtoCloudServiceListElement, 0)
	list1 = append(list1, cs1, cs2, cs3, csNoSiteAssociation)

	list2 := make([]*model.DtoCloudServiceListElement, 0)
	list2 = append(list2, cs1, csNoSiteAssociation)

	_, found := util.FindWhichCloudServiceAttachedToSite(siteName3, list1)
	assert.True(t, found)

	_, found = util.FindWhichCloudServiceAttachedToSite(siteName3, list2)
	assert.False(t, found)
}

func TestCreateCloudServiceTemplate(t *testing.T) {
	siteName := "new-site"
	fqdn := "kind.internal"

	wd, err := os.Getwd()
	require.NoError(t, err)
	projectRoot := filepath.Dir(filepath.Dir(wd))
	tinkCAPath := projectRoot + "/secrets"

	// FAIL: no prerequisites are set
	res, err := util.CreateCloudServiceTemplate(siteName)
	require.Error(t, err)
	require.Nil(t, res)

	// FAIL: setting FQDN and reading from default pass, which doesn't exist in testing environment
	t.Setenv(util.ClusterDomain, fqdn)
	res, err = util.CreateCloudServiceTemplate(siteName)
	require.Error(t, err)
	require.Nil(t, res)

	// FAIL: setting CA path to valid one, but containing more certificates than 1
	t.Setenv(util.TinkCAPath, tinkCAPath)
	res, err = util.CreateCloudServiceTemplate(siteName)
	require.Error(t, err)
	require.Nil(t, res)

	// linking function to the folder containing precisely 1 certificate
	t.Setenv(util.TinkCAPath, tinkCAPath+"/garbage")
	res, err = util.CreateCloudServiceTemplate(siteName)
	require.NoError(t, err)
	require.NotNil(t, res)

	assert.Equal(t, siteName+"", *res.Name)
	assert.Equal(t, fqdn, *res.ServiceAddress)
}
