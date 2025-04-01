// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package testing

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/google/uuid"

	invv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	locationv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/location/v1"
	inv_testing "github.com/open-edge-platform/infra-core/inventory/v2/pkg/testing"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/model"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/inventory"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/util"
)

func readFileAndGetBytes(filename string) ([]byte, error) {
	// reading the file first
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return content, nil
}

func instancesFuncWithModify(res http.ResponseWriter, _ *http.Request, modifyFunc func([]byte)) {
	res.WriteHeader(http.StatusOK)

	bytes, ok := Responses[instancesResponse]
	if !ok {
		zlog.Fatal().Msgf("Failed to get response for %s", instancesResponse)
	}

	modifyFunc(bytes)

	res.Write(bytes)
}

func instancesFunc(res http.ResponseWriter, req *http.Request) {
	instancesFuncWithModify(res, req, func(_ []byte) {
		// intentionally left blank
	})
}

func authFunc(res http.ResponseWriter, req *http.Request) {
	// checking credentials
	// extracting body from the request first
	body, err := io.ReadAll(req.Body)
	if err != nil {
		zlog.Fatal().Msgf("An error occurred while reading Body of the response: %v", err)
	}
	defer req.Body.Close()

	// parsing credentials
	var data *Credentials
	data, err = util.ParseJSONBytesIntoStruct(body, data)
	if err != nil {
		zlog.Fatal().Msgf("Can't parse JSON bytes: %v", err)
	}

	if data.Username != DefaultUsername || data.Password != DefaultPassword {
		zlog.Debug().Msgf("Provided credentials are invalid, authorization denyed")
		// deny request, authentication unsuccessful
		createUnauthenticatedResponse(res)
		return
	}
	zlog.Debug().Msgf("Provided credentials are valid, authorizing")
	// authorization is successful, returning valid token
	response := &model.DtoUserLoginResponse{
		StatusCode: 0,
		Message:    "Authentication success.",
		Data: &model.DtoUserLoginResponseData{
			Token:        ValidToken,
			RefreshToken: RefreshToken,
		},
	}

	bytes, err := json.Marshal(response)
	if err != nil {
		zlog.Fatal().Msgf("Failed to marshal successful authentication response to JSON bytes: %v", err)
	}
	res.WriteHeader(http.StatusOK)

	res.Write(bytes)
}

func removeInstancesFunc(res http.ResponseWriter, _ *http.Request, modifyFunc func(_ *model.DtoCreatedWorkflowResponse)) {
	zlog.Debug().Msgf("Removing Instances")

	// craft the success response - mimics LOC-A v3.2 behavior
	response := &model.DtoCreatedWorkflowResponse{
		StatusCode: 0,
		Message:    "The task of instance deletion has been created success",
		Data: &model.DtoCreatedWorkflowDetails{
			Workflow: "Remove Instances",
			TaskUUID: []string{LocaTaskUUID},
		},
	}

	modifyFunc(response)

	// marshaling back to JSON bytes
	bytes, err := json.Marshal(response)
	if err != nil {
		zlog.Fatal().Msgf("Failed to marshal JSON bytes: %v", err)
	}
	res.Write(bytes)
}

func RemoveInstancesFunc(res http.ResponseWriter, req *http.Request) {
	removeInstancesFunc(res, req, func(_ *model.DtoCreatedWorkflowResponse) {
		res.WriteHeader(http.StatusCreated)
	})
}

func FailedRemoveInstancesFunc(res http.ResponseWriter, req *http.Request) {
	removeInstancesFunc(res, req, func(response *model.DtoCreatedWorkflowResponse) {
		zlog.Debug().Msgf("Failed to remove instance")
		response.Data = nil
		response.Message = "id: " + LocaInstanceID + " is not found" // generic response message
		response.StatusCode = 500

		res.WriteHeader(http.StatusInternalServerError)
	})
}

func ReturnNoInstanceByInstanceID(res http.ResponseWriter, _ *http.Request) {
	res.WriteHeader(http.StatusBadRequest)

	// valid token in the header, proceeding
	bytes := Responses[InstancesByIDResponse]

	var data *model.DtoInstanceQryResponse
	data, err := util.ParseJSONBytesIntoStruct(bytes, data)
	if err != nil {
		zlog.Fatal().Msgf("Can't parse JSON bytes: %v", err)
	}

	data.StatusCode = 3003
	data.Message = "id: " + LocaInstanceID + " is not found" // generic response message
	data.Data = nil

	// marshaling back to JSON bytes
	bytes, err = json.Marshal(data)
	if err != nil {
		zlog.Fatal().Msgf("Failed to marshal JSON bytes: %v", err)
	}

	res.Write(bytes)
}

func InstancesByIDWithModify(
	res http.ResponseWriter, _ *http.Request,
	modifyFunc func(res http.ResponseWriter, instanceResponse *model.DtoInstanceQryResponse), osResourceID string,
) {
	// valid token in the header, proceeding
	bytes := Responses[InstancesByIDResponse]

	var data *model.DtoInstanceQryResponse
	data, err := util.ParseJSONBytesIntoStruct(bytes, data)
	if err != nil {
		zlog.Fatal().Msgf("Can't parse JSON bytes: %v", err)
	}

	extraVarsWithOSResourceID := map[string]any{
		ExtraVarsOSResourceID: osResourceID,
	}

	data.Data.Template.ExtraVars = extraVarsWithOSResourceID
	modifyFunc(res, data)

	// marshaling back to JSON bytes
	bytes, err = json.Marshal(data)
	if err != nil {
		zlog.Fatal().Msgf("Failed to marshal JSON bytes: %v", err)
	}

	res.Write(bytes)
}

func InstancesByIDFunc(res http.ResponseWriter, req *http.Request) {
	InstancesByIDWithModify(res, req, func(_ http.ResponseWriter, _ *model.DtoInstanceQryResponse) {
		// intentionally left empty
	}, "")
}

func ProvisionInstanceFunc(res http.ResponseWriter, req *http.Request) {
	InstancesByIDWithModify(res, req, func(_ http.ResponseWriter, instanceResponse *model.DtoInstanceQryResponse) {
		instanceResponse.Data.Operation = OperationDeploy
		instanceResponse.Data.Stage = StageInstalled
		instanceResponse.Data.Status = StatusFinishedSuccessfully
		zlog.Debug().Msgf("Instance is provisioned")
	}, "")
}

func DeletedInstanceFunc(res http.ResponseWriter, req *http.Request) {
	InstancesByIDWithModify(res, req, func(res http.ResponseWriter, instanceResponse *model.DtoInstanceQryResponse) {
		// returning empty response
		instanceResponse.StatusCode = 3003
		instanceResponse.Message = LocaInstanceID + " is not found"
		instanceResponse.Data = nil

		// set 400 status code when instance is not found
		res.WriteHeader(http.StatusBadRequest)
	}, "")
}

func devicesFuncWithModify(res http.ResponseWriter, _ *http.Request, modifyFunc func(data *model.DtoDeviceListResponse)) {
	res.WriteHeader(http.StatusOK)

	// valid token in the header, proceeding
	bytes := Responses[devicesResponse]

	var data *model.DtoDeviceListResponse
	data, err := util.ParseJSONBytesIntoStruct(bytes, data)
	if err != nil {
		zlog.Fatal().Msgf("Can't parse JSON bytes: %v", err)
	}

	modifyFunc(data)

	// marshaling back to JSON bytes
	bytes, err = json.Marshal(data)
	if err != nil {
		zlog.Fatal().Msgf("Failed to marshal JSON bytes: %v", err)
	}
	res.Write(bytes)
}

func ActiveDevice(res http.ResponseWriter, req *http.Request) {
	devicesFuncWithModify(res, req, func(data *model.DtoDeviceListResponse) {
		data.Data.Results[0].Status = StageActive
		zlog.Debug().Msgf("Device is active")
	})
}

func DeletedDevice(res http.ResponseWriter, req *http.Request) {
	devicesFuncWithModify(res, req, func(data *model.DtoDeviceListResponse) {
		data.Data.Count = 0
		data.Data.Results = nil
	})
}

func DevicesFunc(res http.ResponseWriter, req *http.Request) {
	devicesFuncWithModify(res, req, func(_ *model.DtoDeviceListResponse) {
		// intentionally empty - we want to get response from hardcoded JSON file
	})
}

func deviceUpdate(res http.ResponseWriter, req *http.Request) {
	WriteFileToResponse(res, req, &model.DtoDeviceUpdateResponse{}, deviceUpdateResponse, http.StatusOK)
}

func createUnauthenticatedResponse(res http.ResponseWriter) {
	res.WriteHeader(http.StatusUnauthorized)

	response := &model.DtoUserLoginResponse{
		StatusCode: http.StatusUnauthorized,
		Message:    "Token is invalid.",
		Data:       nil,
	}

	bytes, err := json.Marshal(response)
	if err != nil {
		zlog.Fatal().Msgf("Failed to marshal unauthenticated response into JSON bytes: %v", err)
	}

	res.Write(bytes)
}

func ReturnEmptyResponse(res http.ResponseWriter, _ *http.Request) {
	res.WriteHeader(http.StatusOK)

	// valid token in the header, proceeding
	bytes := Responses[instancesResponse]

	var data *model.DtoInstancesQryResponse
	data, err := util.ParseJSONBytesIntoStruct(bytes, data)
	if err != nil {
		zlog.Fatal().Msgf("Can't parse JSON bytes: %v", err)
	}

	data.Data.Results = nil
	data.Data.Count = 0

	// marshaling back to JSON bytes
	bytes, err = json.Marshal(data)
	if err != nil {
		zlog.Fatal().Msgf("Failed to marshal JSON bytes: %v", err)
	}

	res.Write(bytes)
}

func ReturnServerUnavailable(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(http.StatusServiceUnavailable)

	res.Write([]byte(req.Method + " request on URL (" + req.URL.String() + ") has failed"))
}

func SetupTenantGetterTest() {
	tenantGetterClientKind := inv_testing.ClientType("TenantGetterClient")
	err := inv_testing.CreateClient(
		tenantGetterClientKind,
		invv1.ClientKind_CLIENT_KIND_RESOURCE_MANAGER,
		[]invv1.ResourceKind{invv1.ResourceKind_RESOURCE_KIND_PROVIDER},
		"")
	if err != nil {
		panic(err)
	}
	inventory.TestInitTenantGetter(
		inv_testing.TestClients[tenantGetterClientKind].GetTenantAwareInventoryClient(),
		inv_testing.TestClientsEvents[tenantGetterClientKind],
	)
	err = inventory.StartTenantGetter()
	if err != nil {
		panic(err)
	}
}

func cloudServices2XX(res http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet {
		GetCloudServices2XX(res, req)
	} else {
		postCloudServices2XX(res, req)
	}
}

func CloudServicesByID2XX(res http.ResponseWriter, req *http.Request) {
	WriteFileToResponse(res, req, &model.DtoCloudServiceResponse{}, InventoryCloudServicesByIDGet, http.StatusOK)
}

func cloudServicesRemove2XX(res http.ResponseWriter, req *http.Request) {
	postCloudServicesRemove2XX(res, req)
}

func templateRemove(res http.ResponseWriter, req *http.Request) {
	WriteFileToResponse(res, req, &model.DtoResponseBase{}, deploymentTemplateRemoveResponse, http.StatusOK)
}

func credentialPolicyRemove(res http.ResponseWriter, req *http.Request) {
	WriteFileToResponse(res, req, &model.DtoCredentialPolicyResponse{}, secretsCredentialPolicyRemoveResponse, http.StatusCreated)
}

func getInventoryRepository(res http.ResponseWriter, req *http.Request) {
	WriteFileToResponse(res, req, &model.DtoMiniImagesQryResponse{}, inventoryRepositoryResponse, http.StatusOK)
}

func GetCloudServices2XX(res http.ResponseWriter, req *http.Request) {
	WriteFileToResponse(res, req, &model.DtoCloudServiceListResponse{}, inventoryCloudServicesGet, http.StatusOK)
}

func postCloudServices2XX(res http.ResponseWriter, req *http.Request) {
	WriteFileToResponse(res, req, &model.DtoCloudServicesCreatedResponse{}, InventoryCloudServicesPost, http.StatusCreated)
}

func postCloudServicesRemove2XX(res http.ResponseWriter, req *http.Request) {
	WriteFileToResponse(res, req, &model.DtoResponseCUD{}, inventoryCloudServicesRemove, http.StatusCreated)
}

func postDeploymentInstances(res http.ResponseWriter, req *http.Request) {
	WriteFileToResponse(res, req, &model.DtoCreatedWorkflowResponse{}, instancesResponsePost, http.StatusCreated)
}

func DeploymentInstancesCreated(res http.ResponseWriter, req *http.Request) {
	WriteStructToResponse(res, req, &model.DtoInstancesCreatedResponse{
		Data: &model.DtoInstanceCreatedListData{
			Count: 1,
			Results: []*model.DtoInstance{
				{
					ID: LocaInstanceID,
				},
			},
		},
	}, http.StatusCreated)
}

func DeploymentInstancesDeployFunc(res http.ResponseWriter, req *http.Request) {
	WriteStructToResponse(res, req, &model.DtoCreatedWorkflowResponse{
		Data: &model.DtoCreatedWorkflowDetails{
			TaskUUID: []string{uuid.NewString()},
		},
	}, http.StatusOK)
}

func DeploymentInstancesPlanning(res http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet {
		WriteFileToResponse(res, req, &model.DtoInstancePlanningsQryResponse{}, deploymentInstancesPlanningGet, http.StatusOK)
	} else {
		WriteFileToResponse(res, req, &model.DtoCreatedWorkflowResponse{}, deploymentInstancesPlanningPost, http.StatusCreated)
	}
}

func postDeploymentReadiness(res http.ResponseWriter, req *http.Request) {
	WriteFileToResponse(res, req, &model.DtoCreatedWorkflowResponse{}, deploymentReadinessPost, http.StatusCreated)
}

func getDeploymentReadinessWithModify(
	res http.ResponseWriter, req *http.Request, modifyFunc func(*model.DtoReadinessesQryResponse),
) {
	WriteFileToResponseWithModify(res, req, &model.DtoReadinessesQryResponse{}, deploymentReadinessGet, modifyFunc)
}

func getDeploymentReadiness(res http.ResponseWriter, req *http.Request) {
	getDeploymentReadinessWithModify(res, req, func(_ *model.DtoReadinessesQryResponse) {
		// intentionally left blank
	})
}

func getDeviceProfiles(res http.ResponseWriter, req *http.Request) {
	WriteFileToResponse(res, req, &model.DtoDeviceProfileListResponse{}, deviceProfilesResponse, http.StatusOK)
}

func WriteStructToResponse[t any](res http.ResponseWriter, _ *http.Request, data *t, statusCode int) {
	res.WriteHeader(statusCode)
	// marshaling back to JSON bytes
	bytes, err := json.Marshal(data)
	if err != nil {
		zlog.Fatal().Msgf("Failed to marshal JSON bytes: %v", err)
	}

	_, err = res.Write(bytes)
	if err != nil {
		panic(err)
	}
}

func WriteFileToResponse[t any](res http.ResponseWriter, _ *http.Request, data *t, filename string, statusCode int) {
	res.WriteHeader(statusCode)
	bytes := Responses[filename]

	data, err := util.ParseJSONBytesIntoStruct(bytes, data)
	if err != nil {
		zlog.Fatal().Msgf("Can't parse JSON bytes: %v", err)
	}

	// marshaling back to JSON bytes
	bytes, err = json.Marshal(data)
	if err != nil {
		zlog.Fatal().Msgf("Failed to marshal JSON bytes: %v", err)
	}

	_, err = res.Write(bytes)
	if err != nil {
		panic(err)
	}
}

func WriteFileToResponseWithModify[t any](
	res http.ResponseWriter, _ *http.Request, data *t, filename string, modifyFunc func(*t),
) {
	bytes := Responses[filename]

	data, err := util.ParseJSONBytesIntoStruct(bytes, data)
	if err != nil {
		zlog.Fatal().Msgf("Can't parse JSON bytes: %v", err)
	}

	modifyFunc(data)

	// marshaling back to JSON bytes
	bytes, err = json.Marshal(data)
	if err != nil {
		zlog.Fatal().Msgf("Failed to marshal JSON bytes: %v", err)
	}

	_, err = res.Write(bytes)
	if err != nil {
		panic(err)
	}
}

func createRandomID() string {
	return strings.ReplaceAll(uuid.New().String(), "-", "")
}

func getStorageServerKeyFromRequest(req *http.Request) string {
	return req.Host
}

func getResourceIDFromRequest(req *http.Request) string {
	idx := strings.LastIndex(req.URL.String(), "/")
	if idx == -1 {
		zlog.Fatal().Msgf("Request URL is wrong: %v", req.URL)
	}
	// extracting Site ID
	locaResourceID := req.URL.String()[idx+1:]
	return locaResourceID
}

func extractBodyFromTheRequest(req *http.Request) ([]byte, error) {
	defer req.Body.Close()
	body, err := io.ReadAll(req.Body)
	if err != nil {
		zlog.InfraErr(err).Msgf("An error occurred while reading Body of the response")
		return nil, err
	}
	req.Body.Close()

	return body, nil
}

// findSiteInTheStore function returns a match by Site Name in the Site store for LOC-A Instance.
// LOC-A permits to create the Site with the same name.
func findSiteInTheStore(locaSite *model.DtoSites, locaSiteMap *sync.Map) bool {
	// if Site exists, then returning a failure
	exist := false
	locaSiteMap.Range(func(key, value interface{}) bool {
		site := parseSiteBytesFromTheStore(key, value)
		if site == nil {
			return true // returning true to continue iterating over sites
		}
		if locaSite.Name == site.Name {
			// Site already exists, throwing an error
			exist = true
			return false
		}
		return true // returning true to continue iterating over sites
	})
	return exist
}

// findCSInTheStore function returns a match by CS Name in the CS store for LOC-A Instance.
func findCSInTheStore(locaCS *model.DtoCloudServiceCreateRequest, locaCSMap *sync.Map) bool {
	// if CS exists, then returning a failure
	exist := false
	locaCSMap.Range(func(key, value interface{}) bool {
		cs := parseCSBytesFromTheStore(key, value)
		if cs == nil {
			return true // returning true to continue iterating over css
		}
		if *locaCS.Name == cs.Name {
			// CS already exists, throwing an error
			exist = true
			return false
		}
		return true // returning true to continue iterating over css
	})
	return exist
}

// parseSiteBytesFromTheStore function parses Site bytes stored in the LOC-A store to the *model.DtoSites
// structure.
func parseSiteBytesFromTheStore(key interface{}, value any) *model.DtoSites {
	siteBytes, ok := value.([]byte)
	if !ok {
		// failed to cast store value to bytes, skipping iteration
		zlog.Error().Msgf("Casting Site %v to []byte failed", key)
		return nil
	}
	// obtaining protobuf struct
	var site *model.DtoSites
	site, err := util.ParseJSONBytesIntoStruct(siteBytes, site)
	if err != nil {
		zlog.Fatal().Msgf("Can't parse JSON bytes: %v", err)
		return nil
	}
	return site
}

// parseCSBytesFromTheStore function parses CS bytes stored in the LOC-A store to the *model.DtoService
// structure.
func parseCSBytesFromTheStore(key interface{}, value any) *model.DtoCloudServiceListElement {
	csBytes, ok := value.([]byte)
	if !ok {
		// failed to cast store value to bytes, skipping iteration
		zlog.Error().Msgf("Casting CS %v to []byte failed", key)
		return nil
	}
	// obtaining protobuf struct
	var cs *model.DtoCloudServiceSingleElement
	cs, err := util.ParseJSONBytesIntoStruct(csBytes, cs)
	if err != nil {
		zlog.Fatal().Msgf("Can't parse JSON bytes: %v", err)
		return nil
	}
	return &model.DtoCloudServiceListElement{
		Name:            cs.Name,
		PlatformType:    cs.PlatformType,
		ServiceAddress:  cs.ServiceAddress,
		SiteAssociation: cs.SiteAssociation,
		Status:          cs.Status,
		ID:              cs.ID,
	}
}

// appendListOfSitesToTheResponse appends Sites from the store for the given LOC-A instance to the
// pre-filled response structure.
func appendListOfSitesToTheResponse(response *model.DtoSitesQueryResponse,
	locaSiteMap *sync.Map, siteResourceID string,
) *model.DtoSitesQueryResponse {
	var i int64
	// map is initialized, adding sites to the body of the response
	locaSiteMap.Range(func(key, value interface{}) bool {
		site := parseSiteBytesFromTheStore(key, value)
		if site == nil {
			return true // returning true to continue iterating over sites
		}
		if siteResourceID != "" {
			// seeding SiteCode to the predefined value
			site.SiteCode = siteResourceID
		}
		zlog.Debug().Msgf("Appending Site (%s) to the Site list", key)
		// appending site to the result
		response.Data.Results = append(response.Data.Results, site)
		i++
		return true // returning true to continue iterating over sites
	})
	zlog.Debug().Msgf("Returning %d Sites for LOC-A", i)
	response.Data.Count = i
	return response
}

// appendListOfCSsToTheResponse appends CSs from the store for the given LOC-A instance to the
// pre-filled response structure.
func appendListOfCSSToTheResponse(response *model.DtoCloudServiceListResponse,
	locaCSMap *sync.Map,
) *model.DtoCloudServiceListResponse {
	var i int64
	// map is initialized, adding css to the body of the response
	locaCSMap.Range(func(key, value interface{}) bool {
		cs := parseCSBytesFromTheStore(key, value)
		if cs == nil {
			return true // returning true to continue iterating over css
		}
		zlog.Debug().Msgf("Appending CS (%s) to the CS list", key)
		// appending cs to the result
		response.Data.Results = append(response.Data.Results, cs)
		i++
		return true // returning true to continue iterating over css
	})
	zlog.Debug().Msgf("Returning %d CSs for LOC-A", i)
	response.Data.Count = i
	return response
}

func checkAllSiteInputDataPresent(locaSite *model.DtoSites) bool {
	if locaSite == nil {
		zlog.Error().Msg("Site is nil")
		return false
	}
	if locaSite.Name == "" {
		zlog.Error().Msg("Name must be set for the Site")
		return false
	}
	if locaSite.SiteCode == "" {
		zlog.Error().Msg("SiteCode must be set for the Site")
		return false
	}
	if locaSite.Geo == "" {
		zlog.Error().Msg("Geo must be set for the Site")
		return false
	}
	if locaSite.Country == "" {
		zlog.Error().Msg("Country must be set for the Site")
		return false
	}
	if locaSite.Province == "" {
		zlog.Error().Msg("Province must be set for the Site")
		return false
	}
	if locaSite.City == "" {
		zlog.Error().Msg("City must be set for the Site")
		return false
	}
	if locaSite.CloudType == "" {
		zlog.Error().Msg("CloudType must be set for the Site")
		return false
	}
	return true
}

func checkAllCSInputDataPresent(locaCS *model.DtoCloudServiceCreateRequest) bool {
	if locaCS == nil {
		zlog.Error().Msg("CS is nil")
		return false
	}
	if *locaCS.Name == "" {
		zlog.Error().Msg("Name must be set for the CS")
		return false
	}
	if *locaCS.PlatformType == "" {
		zlog.Error().Msg("PlatformType must be set for the CS")
		return false
	}
	if *locaCS.Role == "" {
		zlog.Error().Msg("Role must be set for the CS")
		return false
	}
	if *locaCS.ServiceAddress == "" {
		zlog.Error().Msg("ServiceAddress must be set for the CS")
		return false
	}
	if *locaCS.SiteAssociation == "" {
		zlog.Error().Msg("SiteAssociation must be set for the CS")
		return false
	}
	if *locaCS.Status == "" {
		zlog.Error().Msg("Status must be set for the CS")
		return false
	}
	return true
}

// addSiteToTheStore adds Site to the initialized LOC-A store.
func addSiteToTheStore(locaSite *model.DtoSites, locaSiteMap *sync.Map) {
	// creating randomized Site ID
	locaSite.ID = createRandomID()
	// marshaling structure back into bytes, that would be stored in the map
	locaSiteBytes, err := json.Marshal(locaSite)
	if err != nil {
		zlog.Fatal().Msgf("Failed to marshal JSON bytes: %v", err)
	}
	// storing JSON bytes in the Store
	locaSiteMap.Store(locaSite.ID, locaSiteBytes)
}

// addCSToTheStore adds CS to the initialized LOC-A store.
func addCSToTheStore(locaCS *model.DtoCloudServiceCreateRequest, locaCSMap *sync.Map) {
	cs := &model.DtoCloudServiceSingleElement{}
	// creating randomized CS ID
	cs.ID = createRandomID()
	cs.Name = *locaCS.Name
	cs.PlatformType = *locaCS.PlatformType
	cs.ServiceAddress = *locaCS.ServiceAddress
	cs.ServiceSettings = locaCS.ServiceSettings
	cs.SiteAssociation = []string{*locaCS.SiteAssociation}
	// marshaling structure back into bytes, that would be stored in the map
	csBytes, err := json.Marshal(cs)
	if err != nil {
		zlog.Fatal().Msgf("Failed to marshal JSON bytes: %v", err)
	}
	// storing JSON bytes in the Store
	locaCSMap.Store(cs.ID, csBytes)
}

func craftSiteByIDNotFoundResponse(response *model.DtoSiteQueryResponse, locaSiteID string) []byte {
	response.StatusCode = 3003
	response.Message = locaSiteID + " is not found"
	response.Data = nil
	// marshaling back to JSON bytes
	bytes, err := json.Marshal(response)
	if err != nil {
		zlog.Fatal().Msgf("Failed to marshal JSON bytes: %v", err)
	}
	return bytes
}

func craftDeleteSiteNotFoundResponse(response *model.DtoResponseCUD, locaSiteID string) []byte {
	response.StatusCode = 3003
	response.Message = locaSiteID + " is not found"
	response.Data = nil
	// marshaling back to JSON bytes
	bytes, err := json.Marshal(response)
	if err != nil {
		zlog.Fatal().Msgf("Failed to marshal JSON bytes: %v", err)
	}
	return bytes
}

func craftCSNotFoundResponse(response *model.DtoCloudServiceResponse, locaCSID string) []byte {
	response.StatusCode = 3003
	response.Message = locaCSID + " is not found"
	response.Data = nil
	// marshaling back to JSON bytes
	bytes, err := json.Marshal(response)
	if err != nil {
		zlog.Fatal().Msgf("Failed to marshal JSON bytes: %v", err)
	}
	return bytes
}

func removeDevicesWithModifyFunc(res http.ResponseWriter, req *http.Request, modifyFunc func(*model.DtoResponseCUD)) {
	response := &model.DtoResponseCUD{
		StatusCode: 0,
		Message:    "OK",
		Data: &model.DtoTaskResponseData{
			Workflow: "Remove Devices",
			TaskUUID: []string{LocaTaskUUID},
		},
	}
	modifyFunc(response)
	WriteStructToResponse(res, req, response, http.StatusCreated)
}

func RemoveDevicesFunc(res http.ResponseWriter, req *http.Request) {
	removeDevicesWithModifyFunc(res, req, func(_ *model.DtoResponseCUD) {
		res.WriteHeader(http.StatusCreated)
	})
}

func FailedRemoveDevicesFunc(res http.ResponseWriter, req *http.Request) {
	removeDevicesWithModifyFunc(res, req, func(response *model.DtoResponseCUD) {
		zlog.Debug().Msgf("Failed to remove device")
		response.Data = nil
		response.Message = "id: " + LocaDeviceID + " is not found" // generic response message
		response.StatusCode = 3003

		res.WriteHeader(http.StatusBadRequest)
	})
}

func getTaskWithModify(res http.ResponseWriter, req *http.Request, modifyFunc func(*model.DtoTaskQryResponse)) {
	WriteFileToResponseWithModify(res, req, &model.DtoTaskQryResponse{}, taskManagementTasks, modifyFunc)
}

func SuccessfulGetTask(res http.ResponseWriter, req *http.Request) {
	getTaskWithModify(res, req, func(response *model.DtoTaskQryResponse) {
		response.Data.Status = TaskStatusSuccessful
	})
}

func RunningGetTask(res http.ResponseWriter, req *http.Request) {
	getTaskWithModify(res, req, func(_ *model.DtoTaskQryResponse) {
		// intentionally blank
	})
}

func getTemplatesWithModify(res http.ResponseWriter, req *http.Request, modifyFunc func(*model.DtoTemplatesQryResponse)) {
	WriteFileToResponseWithModify(res, req, &model.DtoTemplatesQryResponse{}, deploymentTemplateGetResponse, modifyFunc)
}

func getTemplates(res http.ResponseWriter, req *http.Request) {
	getTemplatesWithModify(res, req, func(_ *model.DtoTemplatesQryResponse) {
		// intentionally left blank
	})
}

//nolint:dupl // set crud for site.
func SitesCrudFuncs(ms *MockServer, prepopulate bool, site *locationv1.SiteResource) {
	// map that stores Sites per LOC-A, site ID is used as an inner key,
	// Site itself is a stored as a set of JSON bytes (for marshaling it to any needed structure).
	sites := &sync.Map{}
	if prepopulate {
		prepopulateSite(sites, site)
	}
	ms.Override(InventorySitesPath, func(res http.ResponseWriter, req *http.Request) {
		sitesFunc(res, req, sites)
	}, http.MethodGet, http.MethodPost)
	ms.Override(InventorySitesID, func(res http.ResponseWriter, req *http.Request) {
		sitesByIDFunc(res, req, sites)
	}, http.MethodGet)
	ms.Override(InventorySitesRemovePath, func(res http.ResponseWriter, req *http.Request) {
		deleteSite(res, req, sites)
	}, http.MethodPost)
}

func sitesFunc(res http.ResponseWriter, req *http.Request, sites *sync.Map) {
	switch req.Method {
	case http.MethodPost:
		// handle POST request

		createSite(res, req, sites)
		return
	case http.MethodGet:
		res.WriteHeader(http.StatusOK)

		// handle GET request
		getSiteWithModify(res, req, func(response *model.DtoSitesQueryResponse) {
			appendListOfSitesToTheResponse(response, sites, "")
		})
		return
	default:
		zlog.Fatal().Msgf("Unsupported method obtained: %s", req.Method)
	}
}

// sitesByIDFunc returns the Site with provided ID, if it is present in the LOC-A store.
// In the other case (i.e., if Site is not present in the LOC-A Store), it returns 'Not Found'.
//
//nolint:dupl // set site by id mock func.
func sitesByIDFunc(res http.ResponseWriter, req *http.Request, sites *sync.Map) {
	// extracting Site ID
	locaSiteID := getResourceIDFromRequest(req)
	zlog.Debug().Msgf("Requesting Site (%s) from LOC-A (%v)", locaSiteID, req.Host)

	// creating a template structure for further manipulations
	response := &model.DtoSiteQueryResponse{
		StatusCode: 0,
		Message:    "OK",
		Data:       nil,
	}

	// obtaining sites for the current LOC-A Host
	locaSrvKey := getStorageServerKeyFromRequest(req)
	if sites == nil {
		// map was not initialized, i.e., no Sites, returning empty list
		zlog.Debug().Msgf("Site store is not initialized for the LOC-A server (%v),"+
			"returning 'Not Found'", locaSrvKey)
		res.WriteHeader(http.StatusBadRequest)

		res.Write(craftSiteByIDNotFoundResponse(response, locaSiteID))
		return
	}

	// map is initialized, retrieving site (i.e., JSON bytes) from map
	siteAny, ok := sites.Load(locaSiteID)
	if !ok {
		zlog.Debug().Msgf("Site (%s) was NOT found in the LOC-A (%v)", locaSiteID, locaSrvKey)
		res.WriteHeader(http.StatusBadRequest)
		res.Write(craftSiteByIDNotFoundResponse(response, locaSiteID))
		return
	}
	zlog.Debug().Msgf("Site (%s) was found in the LOC-A (%v)", locaSiteID, locaSrvKey)
	// Site was found, casting it to the '[]byte' (now it's any')
	siteBytes, ok := siteAny.([]byte)
	if !ok {
		// failed to cast store value to bytes, skipping iteration
		zlog.Error().Msgf("Casting Site %v to []byte failed", locaSiteID)
	}
	// obtaining protobuf struct
	var site *model.DtoSite
	site, err := util.ParseJSONBytesIntoStruct(siteBytes, site)
	if err != nil {
		zlog.Fatal().Msgf("Can't parse JSON bytes: %v", err)
	}

	// adding site to the response
	response.Data = site

	// marshaling bytes into structure
	bytes, err := json.Marshal(response)
	if err != nil {
		zlog.Fatal().Msgf("Failed to marshal JSON bytes: %v", err)
	}
	res.Write(bytes)
}

// createSite logic is following:
// - take the message,
// - check that all mandatory fields are set,
// - store it,
// - return success.
func createSite(res http.ResponseWriter, req *http.Request, sites *sync.Map) {
	zlog.Debug().Msg("Create Site request is obtained")
	// extracting body from the request - it should contain IDs
	body, err := extractBodyFromTheRequest(req)
	if err != nil {
		zlog.Fatal().Msgf("Can't extract Body from the Request: %v", err)
	}
	// extract request fields
	var data []*model.DtoSites
	err = json.Unmarshal(body, &data)
	if err != nil {
		zlog.Fatal().Msgf("Can't parse JSON bytes: %v", err)
	}

	// checking that Site storage is initialized for this LOC-A
	if sites == nil {
		sites = &sync.Map{}
	}
	// iterate over sites, check the fields, and store the Site in a store
	for _, locaSite := range data {
		// if Site doesn't have all contained data, skip it
		if !checkAllSiteInputDataPresent(locaSite) {
			continue
		}
		// if Site exists, then returning a failure
		if findSiteInTheStore(locaSite, sites) {
			// return failure - mimic real LOC-A behavior
			response := &model.DtoSitesCreatedResponse{
				StatusCode: 3004, //nolint:mnd // this is a real response
				Message: "Bad request: site with name " + locaSite.Name +
					" already exists, please check your request body",
			}
			// marshaling back to JSON bytes
			bytes, err1 := json.Marshal(response)
			if err1 != nil {
				zlog.Fatal().Msgf("Failed to marshal JSON bytes: %v", err1)
			}

			res.WriteHeader(http.StatusBadRequest)
			res.Write(bytes)
			return
		}

		// all conditions are met, no duplicates found, storing site
		addSiteToTheStore(locaSite, sites)
	}

	response := &model.DtoSitesCreatedResponse{
		StatusCode: 0,
		Message:    "Created successfully",
		Data: &model.DtoSiteCreatedListData{
			Count:   int64(len(data)),
			Results: data,
		},
	}

	// marshaling back to JSON bytes
	bytes, err := json.Marshal(response)
	if err != nil {
		zlog.Fatal().Msgf("Failed to marshal JSON bytes: %v", err)
	}
	res.WriteHeader(http.StatusCreated)

	res.Write(bytes)
}

// deleteSite logic is following:
// - extract ID of the Site,
// - find the Site in the store,
// - remove the site from the Store,
// - return response.
func deleteSite(res http.ResponseWriter, req *http.Request, sites *sync.Map) {
	zlog.Debug().Msg("Delete Site request is obtained")
	// extracting body from the request - it should contain IDs
	body, err := extractBodyFromTheRequest(req)
	if err != nil {
		zlog.Fatal().Msgf("Can't extract Body from the Request: %v", err)
	}

	// craft the success response - mimics LOC-A v3.2 behavior
	response := &model.DtoResponseCUD{
		StatusCode: 0,
		Message:    "Remove sites task created",
		Data: &model.DtoTaskResponseData{
			TaskUUID: []string{uuid.NewString()}, // random UUID to represent the task has been created in LOC-A
		},
	}

	// extract response fields
	var data *model.DtoSitesRemoveRequest
	data, err = util.ParseJSONBytesIntoStruct(body, data)
	if err != nil {
		zlog.Fatal().Msgf("Can't parse JSON bytes: %v", err)
	}

	// checking that Site storage is initialized for this LOC-A
	locaSrvKey := getStorageServerKeyFromRequest(req)

	// map was initialized, check that the corresponding Site exists, and then delete it
	for _, locaSiteID := range data.Ids {
		zlog.Debug().Msgf("Deleting Site (%s) from LOC-A (%v)", locaSiteID, locaSrvKey)
		// map is initialized, retrieving site (i.e., JSON bytes) from map
		_, ok := sites.Load(locaSiteID)
		if !ok {
			zlog.Debug().Msgf("Site (%s) was NOT found in the LOC-A (%v)", locaSiteID, locaSrvKey)
			res.WriteHeader(http.StatusBadRequest)
			res.Write(craftDeleteSiteNotFoundResponse(response, locaSiteID))
			return
		}
		sites.Delete(locaSiteID)
	}
	// not depending on LOC-A having or not having sites, it reports successful creation of the task

	zlog.Debug().Msg("Returning successful response")

	// marshaling back to JSON bytes
	bytes, err := json.Marshal(response)
	if err != nil {
		zlog.Fatal().Msgf("Failed to marshal JSON bytes: %v", err)
	}
	res.WriteHeader(http.StatusCreated)
	res.Write(bytes)
}

func getSiteWithModify(res http.ResponseWriter, _ *http.Request, modifyFunc func(*model.DtoSitesQueryResponse)) {
	// creating a template structure for further manipulations
	response := &model.DtoSitesQueryResponse{
		StatusCode: 0,
		Message:    "OK",
		Data: &model.DtoSiteListData{
			Results: make([]*model.DtoSites, 0),
		},
	}

	modifyFunc(response)
	// marshaling back to JSON bytes
	bytes, err := json.Marshal(response)
	if err != nil {
		zlog.Fatal().Msgf("Failed to marshal JSON bytes: %v", err)
	}
	res.Write(bytes)
}

//nolint:dupl // set crud for CS.
func CSCrudFuncs(ms *MockServer, prepopulate bool, cs *model.DtoCloudServiceListElement) {
	// map that stores CS per LOC-A, CS name is used as an inner key,
	// CS itself is a stored as a set of JSON bytes (for marshaling it to any needed structure).
	css := &sync.Map{}
	if prepopulate {
		prepopulateCS(css, cs)
	}
	ms.Override(InventoryCloudServicesPath, func(res http.ResponseWriter, req *http.Request) {
		cssFunc(res, req, css)
	}, http.MethodGet, http.MethodPost)
	ms.Override(InventoryCloudServicesIDPath, func(res http.ResponseWriter, req *http.Request) {
		cssByIDFunc(res, req, css)
	}, http.MethodGet)
	ms.Override(InventoryCloudServicesRemovePath, func(res http.ResponseWriter, req *http.Request) {
		deleteCS(res, req, css)
	}, http.MethodPost)
}

func cssFunc(res http.ResponseWriter, req *http.Request, css *sync.Map) {
	switch req.Method {
	case http.MethodPost:
		// handle POST request
		createCS(res, req, css)
		return
	case http.MethodGet:
		res.WriteHeader(http.StatusOK)

		// handle GET request
		getCSWithModify(res, req, func(response *model.DtoCloudServiceListResponse) {
			appendListOfCSSToTheResponse(response, css)
		})
		return
	default:
		zlog.Fatal().Msgf("Unsupported method obtained: %s", req.Method)
	}
}

// cssByIDFunc returns the CS with provided ID, if it is present in the LOC-A store.
// In the other case (i.e., if CS is not present in the LOC-A Store), it returns 'Not Found'.
//
//nolint:dupl // set css by ID mock func.
func cssByIDFunc(res http.ResponseWriter, req *http.Request, css *sync.Map) {
	// extracting CS ID
	locaCSID := getResourceIDFromRequest(req)
	zlog.Debug().Msgf("Requesting CS (%s) from LOC-A (%v)", locaCSID, req.Host)

	// creating a template structure for further manipulations
	response := &model.DtoCloudServiceResponse{
		StatusCode: 0,
		Message:    "OK",
		Data:       nil,
	}

	// obtaining css for the current LOC-A Host
	locaSrvKey := getStorageServerKeyFromRequest(req)
	if css == nil {
		// map was not initialized, i.e., no CSs, returning empty list
		zlog.Debug().Msgf("CS store is not initialized for the LOC-A server (%v),"+
			"returning 'Not Found'", locaSrvKey)
		res.WriteHeader(http.StatusBadRequest)

		res.Write(craftCSNotFoundResponse(response, locaCSID))
		return
	}

	// map is initialized, retrieving cs (i.e., JSON bytes) from map
	csAny, ok := css.Load(locaCSID)
	if !ok {
		zlog.Debug().Msgf("CS (%s) was NOT found in the LOC-A (%v)", locaCSID, locaSrvKey)
		res.WriteHeader(http.StatusBadRequest)
		res.Write(craftCSNotFoundResponse(response, locaCSID))
		return
	}
	zlog.Debug().Msgf("CS (%s) was found in the LOC-A (%v)", locaCSID, locaSrvKey)
	// CS was found, casting it to the '[]byte' (now it's any')
	csBytes, ok := csAny.([]byte)
	if !ok {
		// failed to cast store value to bytes, skipping iteration
		zlog.Error().Msgf("Casting CS %v to []byte failed", locaCSID)
	}
	// obtaining protobuf struct
	var cs *model.DtoCloudServiceSingleElement
	cs, err := util.ParseJSONBytesIntoStruct(csBytes, cs)
	if err != nil {
		zlog.Fatal().Msgf("Can't parse JSON bytes: %v", err)
	}

	// adding cs to the response
	response.Data = cs

	// marshaling bytes into structure
	bytes, err := json.Marshal(response)
	if err != nil {
		zlog.Fatal().Msgf("Failed to marshal JSON bytes: %v", err)
	}
	res.Write(bytes)
}

// deleteCS logic is following:
// - extract ID of the CS,
// - find the CS in the store,
// - remove the CS from the Store,
// - return response.
func deleteCS(res http.ResponseWriter, req *http.Request, css *sync.Map) {
	res.WriteHeader(http.StatusCreated)
	zlog.Debug().Msg("Delete CS request is obtained")
	// extracting body from the request - it should contain IDs
	body, err := extractBodyFromTheRequest(req)
	if err != nil {
		zlog.Fatal().Msgf("Can't extract Body from the Request: %v", err)
	}

	// extract response fields
	var data *model.DtoServiceRemoveRequest
	data, err = util.ParseJSONBytesIntoStruct(body, data)
	if err != nil {
		zlog.Fatal().Msgf("Can't parse JSON bytes: %v", err)
	}

	// checking that CS storage is initialized for this LOC-A
	locaSrvKey := getStorageServerKeyFromRequest(req)

	// map was initialized, check that the corresponding CS exists, and then delete it
	for _, locaCSID := range data.Ids {
		zlog.Debug().Msgf("Deleting CS (%s) from LOC-A (%v)", locaCSID, locaSrvKey)
		css.Delete(locaCSID)
	}
	// not depending on LOC-A having or not having css, it reports successful creation of the task

	zlog.Debug().Msg("Returning successful response")
	// craft the success response - mimics LOC-A v3.2 behavior
	response := &model.DtoResponseCUD{
		StatusCode: 0,
		Message:    "Remove cs task created",
		Data: &model.DtoTaskResponseData{
			TaskUUID: []string{uuid.NewString()}, // random UUID to represent the task has been created in LOC-A
		},
	}

	// marshaling back to JSON bytes
	bytes, err := json.Marshal(response)
	if err != nil {
		zlog.Fatal().Msgf("Failed to marshal JSON bytes: %v", err)
	}
	res.Write(bytes)
}

// createCS logic is following:
// - take the message,
// - check that all mandatory fields are set,
// - store it,
// - return success.
func createCS(res http.ResponseWriter, req *http.Request, css *sync.Map) {
	convertToCloudServiceListElements := func(data []*model.DtoCloudServiceCreateRequest) []*model.DtoCloudServiceListElement {
		var elements []*model.DtoCloudServiceListElement
		for _, cs := range data {
			elements = append(elements, &model.DtoCloudServiceListElement{
				Name:            *cs.Name,
				PlatformType:    *cs.PlatformType,
				ServiceAddress:  *cs.ServiceAddress,
				SiteAssociation: []string{*cs.SiteAssociation},
				Status:          *cs.Status,
			})
		}
		return elements
	}
	zlog.Debug().Msg("Create CS request is obtained")
	// extracting body from the request - it should contain IDs
	body, err := extractBodyFromTheRequest(req)
	if err != nil {
		zlog.Fatal().Msgf("Can't extract Body from the Request: %v", err)
	}
	// extract request fields
	var data []*model.DtoCloudServiceCreateRequest
	err = json.Unmarshal(body, &data)
	if err != nil {
		zlog.Fatal().Msgf("Can't parse JSON bytes: %v", err)
	}

	// checking that CS storage is initialized for this LOC-A
	if css == nil {
		css = &sync.Map{}
	}
	// iterate over css, check the fields, and store the CS in a store
	for _, locaCS := range data {
		// if CS doesn't have all contained data, skip it
		if !checkAllCSInputDataPresent(locaCS) {
			continue
		}
		// if CS exists, then returning a failure
		if findCSInTheStore(locaCS, css) {
			// return failure - mimic real LOC-A behavior
			response := &model.DtoCloudServicesCreatedResponse{
				StatusCode: 3004, //nolint:mnd // this is a real response
				Message: "Bad request: cs with name " + *locaCS.Name +
					" already exists, please check your request body",
			}
			// marshaling back to JSON bytes
			bytes, err1 := json.Marshal(response)
			if err1 != nil {
				zlog.Fatal().Msgf("Failed to marshal JSON bytes: %v", err1)
			}

			res.WriteHeader(http.StatusBadRequest)
			res.Write(bytes)
			return
		}

		// all conditions are met, no duplicates found, storing cs
		addCSToTheStore(locaCS, css)
	}

	response := &model.DtoCloudServicesCreatedResponse{
		StatusCode: 0,
		Message:    "Created successfully",
		Data: &model.DtoCloudServiceCreatedListData{
			Count:   int64(len(data)),
			Results: convertToCloudServiceListElements(data),
		},
	}

	// marshaling back to JSON bytes
	bytes, err := json.Marshal(response)
	if err != nil {
		zlog.Fatal().Msgf("Failed to marshal JSON bytes: %v", err)
	}
	res.WriteHeader(http.StatusCreated)

	res.Write(bytes)
}

func getCSWithModify(res http.ResponseWriter, _ *http.Request, modifyFunc func(*model.DtoCloudServiceListResponse)) {
	// creating a template structure for further manipulations
	response := &model.DtoCloudServiceListResponse{
		StatusCode: 0,
		Message:    "OK",
		Data: &model.DtoCloudServiceListData{
			Results: make([]*model.DtoCloudServiceListElement, 0),
		},
	}

	modifyFunc(response)
	// marshaling back to JSON bytes
	bytes, err := json.Marshal(response)
	if err != nil {
		zlog.Fatal().Msgf("Failed to marshal JSON bytes: %v", err)
	}
	res.Write(bytes)
}
