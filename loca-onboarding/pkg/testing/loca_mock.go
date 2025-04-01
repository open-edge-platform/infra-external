// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package testing

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"runtime"
	"slices"
	"strings"
	"sync"

	gorilla "github.com/gorilla/mux"

	locationv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/location/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/model"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/util"
)

const (
	AuthLoginPath = "/api/v1/auth/login"
	//nolint:gosec // not a secret
	SecretsCredentialPoliciesPath = "/api/v1/secrets/credential-policies"
	//nolint:gosec // not a secret
	SecretsCredentialPoliciesIDPath  = "/api/v1/secrets/credential-policies/{id}"
	DeploymentTemplatesRemovePath    = "/api/v1/deployment/templates/remove"
	DeploymentTemplatesPath          = "/api/v1/deployment/templates"
	DeploymentInstancesCreate        = "/api/v1/deployment/instances/create"
	DeploymentInstancesDeploy        = "/api/v1/deployment/instances/deploy"
	DeploymentInstancesRemovePath    = "/api/v1/deployment/instances/remove"
	DeploymentInstancesPlanningPath  = "/api/v1/deployment/instances/planning"
	DeploymentReadinessPath          = "/api/v1/deployment/readiness"
	InventoryCloudServicesPath       = "/api/v1/inventory/cloud-services"
	InventoryCloudServicesRemovePath = "/api/v1/inventory/cloud-services/remove"
	InventoryCloudServicesIDPath     = "/api/v1/inventory/cloud-services/{id}"
	InventoryDevicesRemovePath       = "/api/v1/inventory/devices/remove"
	InventoryDevicesIDUpdatePath     = "/api/v1/inventory/devices/{id}/update"
	InventoryDeviceProfilesPath      = "/api/v1/inventory/device-profiles"
	InventoryRepositoryPath          = "/api/v1/inventory/repository"
	InventorySitesPath               = "/api/v1/inventory/sites"
	InventorySitesID                 = "/api/v1/inventory/sites/{id}"
	InventorySitesRemovePath         = "/api/v1/inventory/sites/remove"
	DeploymentInstancesIDPath        = "/api/v1/deployment/instances/{id}"
	DeploymentInstancesPath          = "/api/v1/deployment/instances"
	InventoryDevicesPath             = "/api/v1/inventory/devices"
	TaskManagementTasksIDPath        = "/api/v1/task-management/tasks/{id}"
)

const (
	pageNotFound                          = "loca_api_404.json"
	instancesResponse                     = "loca_api_deployment_instances.json"
	instancesResponsePost                 = "loca_api_deployment_instances_post.json"
	InstancesByIDResponse                 = "loca_api_deployment_instances_id.json"
	inventoryRepositoryResponse           = "loca_api_inventory_repository.json"
	devicesResponse                       = "loca_api_inventory_devices.json"
	deviceUpdateResponse                  = "loca_api_inventory_device_update.json"
	deviceProfilesResponse                = "loca_api_inventory_device_profiles.json"
	secretsCredentialPolicyRemoveResponse = "loca_api_secrets_credential_policy_remove.json"
	deploymentTemplateGetResponse         = "loca_api_deployment_templates_get.json"
	deploymentTemplateRemoveResponse      = "loca_api_deployment_template_remove.json"
	deploymentReadinessGet                = "loca_api_deployment_readiness_get.json"
	deploymentReadinessPost               = "loca_api_deployment_readiness_post.json"
	deploymentInstancesPlanningPost       = "loca_api_deployment_instances_planning_post.json"
	deploymentInstancesPlanningGet        = "loca_api_deployment_instances_planning_get.json"
	inventoryCloudServicesGet             = "loca_api_inventory_cloud_services_get.json"
	InventoryCloudServicesByIDGet         = "loca_api_inventory_cloud_services_by_id.json"
	InventoryCloudServicesPost            = "loca_api_inventory_cloud_services_post.json"
	inventoryCloudServicesRemove          = "loca_api_inventory_cloud_services_remove.json"
	taskManagementTasks                   = "loca_api_task_management_tasks_get.json"
)

const (
	ExtraVarsOSResourceID      = "os_resource_id"
	authHeader                 = "Authorization"
	StageInstalled             = "installed"
	StageActive                = "active"
	OperationDeploy            = "Deploy"
	StatusFinishedSuccessfully = "Finished successfully"
	SiteID                     = "66d5a4a57bc832e5fbf72705"
	SecondaryInstanceID        = "870c483ef445a55d541460db"
	SecondaryRawUUID           = "12BD576A2E8233DD837C3A5B5468BDE3"
	SecondarySerialNumber      = "AAAA1111"
	authHeaderLen              = 2
	ValidToken                 = "some-valid-dummy-authentication-token"
	//nolint:gosec // dummy value, not used in the production
	RefreshToken                      = "some-dummy-refresh-token"
	DefaultUsername                   = "admin"
	DefaultPassword                   = "admin"
	relativeFolderWithMockedResponses = "/../examples"
	ServerModel                       = "ThinkEdge SE360 V2"
)

var (
	Responses map[string][]byte
	zlog      = logging.GetLogger("LOC-A Mock")
)

// Credentials structure is used solely for Mock server purposes.
// It allows to perform a credentials check at authorization call.
// Default credentials are Global constants that can be exported to
// the other packages for unit testing purposes.
type Credentials struct {
	Username string `json:"name"`
	Password string `json:"password"`
}

type overriddenEndpoint struct {
	f       func(http.ResponseWriter, *http.Request)
	methods []string
}

type MockServer struct {
	TestServer *httptest.Server
	Router     *gorilla.Router
	// mutex shared with middleware that is used to prevent race conditions between request from client and mock
	// basically it means that either exactly 1 client could execute request to mock or we are overwriting one of the endpoints.
	overrideMutex    *sync.Mutex
	overriddenRoutes map[string]overriddenEndpoint
}

type notFoundHandler struct {
	ms *MockServer
}

func (h notFoundHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if requestIsOverridden(writer, request, h.ms) {
		return
	}

	writer.WriteHeader(http.StatusNotFound)
	writer.Header().Add("Content-Type", "application/json")
	bytes := Responses[pageNotFound]

	_, err := writer.Write(bytes)
	if err != nil {
		zlog.Warn().Err(err).Msgf("failed to write body to 404 response")
	}
}

type methodNotAAllowedHandler struct {
	ms *MockServer
}

func (h methodNotAAllowedHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if requestIsOverridden(writer, request, h.ms) {
		return
	}

	writer.WriteHeader(http.StatusMethodNotAllowed)
	writer.Header().Add("Content-Type", "application/json")
	bytes := Responses[pageNotFound]

	_, err := writer.Write(bytes)
	if err != nil {
		zlog.Warn().Err(err).Msgf("failed to write body to 405 response")
	}
}

func (ms *MockServer) GetURL() string {
	return ms.TestServer.URL
}

// If no configuration provided, returns an empty HTTP Server.
func StartDummyLOCAServer() (*MockServer, error) {
	Responses = make(map[string][]byte)

	// Relative on runtime DIR:
	_, fileCaller, _, _ := runtime.Caller(0) //nolint:dogsled // uses only what needed
	pkgTestingDir := path.Join(path.Dir(fileCaller))

	dir, err := os.ReadDir(pkgTestingDir + relativeFolderWithMockedResponses)
	if err != nil {
		zlog.Fatal().Err(err).Msgf("failed to read directory with mocked Responses")
	}
	for _, responseMock := range dir {
		response, err := readFileAndGetBytes(pkgTestingDir + relativeFolderWithMockedResponses + "/" + responseMock.Name())
		if err != nil {
			zlog.Fatal().Err(err).Msgf("failed to read file with mocked response")
		}
		Responses[responseMock.Name()] = response
	}

	mutex := &sync.Mutex{}
	router := gorilla.NewRouter()
	ms := &MockServer{
		Router:           router,
		overrideMutex:    mutex,
		overriddenRoutes: map[string]overriddenEndpoint{},
	}
	router.Use(func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Add("Content-Type", "application/json")
			handler.ServeHTTP(writer, request)
		})
	})

	router.Use(func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			// skip token check for auth endpoint
			if strings.HasSuffix(request.URL.String(), "auth/login") || tokenIsValid(request) {
				handler.ServeHTTP(writer, request)
				return
			}
			createUnauthenticatedResponse(writer)
		})
	})

	router.NotFoundHandler = notFoundHandler{
		ms: ms,
	}
	router.MethodNotAllowedHandler = methodNotAAllowedHandler{
		ms: ms,
	}

	router.Use(func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if requestIsOverridden(writer, request, ms) {
				return
			}
			handler.ServeHTTP(writer, request)
		})
	})
	router.HandleFunc(AuthLoginPath, authFunc).Methods("POST")
	router.HandleFunc(SecretsCredentialPoliciesIDPath, credentialPolicyRemove).Methods("DELETE")
	router.HandleFunc(DeploymentTemplatesRemovePath, templateRemove).Methods("POST")
	router.HandleFunc(DeploymentTemplatesPath, getTemplates).Methods("GET", "POST")
	router.HandleFunc(DeploymentInstancesPlanningPath, DeploymentInstancesPlanning).Methods("GET", "POST")
	router.HandleFunc(DeploymentInstancesPath, instancesFunc).Methods("GET")
	router.HandleFunc(DeploymentInstancesPath, postDeploymentInstances).Methods("POST")
	router.HandleFunc(DeploymentInstancesRemovePath, RemoveInstancesFunc).Methods("POST")
	router.HandleFunc(DeploymentInstancesIDPath, InstancesByIDFunc).Methods("GET")
	router.HandleFunc(DeploymentReadinessPath, getDeploymentReadiness).Methods("GET")
	router.HandleFunc(DeploymentReadinessPath, postDeploymentReadiness).Methods("POST")
	router.HandleFunc(TaskManagementTasksIDPath, RunningGetTask).Methods("GET")
	router.HandleFunc(InventoryCloudServicesPath, cloudServices2XX).Methods("GET", "POST")
	router.HandleFunc(InventoryCloudServicesRemovePath, cloudServicesRemove2XX).Methods("POST")
	router.HandleFunc(InventoryCloudServicesIDPath, CloudServicesByID2XX).Methods("GET")
	router.HandleFunc(InventoryDevicesPath, DevicesFunc).Methods("GET")
	router.HandleFunc(InventoryDevicesRemovePath, RemoveDevicesFunc).Methods("POST")
	router.HandleFunc(InventoryDevicesIDUpdatePath, deviceUpdate).Methods("POST")
	router.HandleFunc(InventoryDeviceProfilesPath, getDeviceProfiles).Methods("GET")
	router.HandleFunc(InventoryRepositoryPath, getInventoryRepository).Methods("GET")

	// starting test server
	testServer := httptest.NewServer(router)
	ms.TestServer = testServer

	return ms, nil
}

func requestIsOverridden(writer http.ResponseWriter, request *http.Request, ms *MockServer) bool {
	routeMatch := &gorilla.RouteMatch{}
	ms.overrideMutex.Lock()
	defer ms.overrideMutex.Unlock()
	router := gorilla.NewRouter()
	for endpoint, handler := range ms.overriddenRoutes {
		// there are some issues for endpoints like `deployment/{id}` and `deployment/remove`
		// since `remove` is treated as variable
		// so making sure that exact match working as expected
		if strings.EqualFold(request.URL.Path, endpoint) &&
			(len(handler.methods) == 0 || slices.Contains(handler.methods, request.Method)) {
			writer.Header().Add("Content-Type", "application/json")
			handler.f(writer, request)
			return true
		}

		if strings.Contains(endpoint, "{") || strings.Contains(endpoint, "}") {
			r := router.NewRoute().Path(endpoint).HandlerFunc(handler.f)
			if len(handler.methods) != 0 {
				r.Methods(handler.methods...)
			}
		}
	}

	if router.Match(request, routeMatch) {
		writer.Header().Add("Content-Type", "application/json")
		routeMatch.Handler.ServeHTTP(writer, request)
		return true
	}
	return false
}

// Gracefully shutdown LOC-A Mock Server.
func (ms *MockServer) StopDummyLOCAServer() {
	ms.TestServer.Close()
}

func (ms *MockServer) SeedOSResourceID(resourceID string) {
	ms.Override(DeploymentTemplatesPath, func(writer http.ResponseWriter, request *http.Request) {
		getTemplatesWithModify(writer, request, func(response *model.DtoTemplatesQryResponse) {
			for _, template := range response.Data.Results {
				defaultOSRes := template.ExtraVars[ExtraVarsOSResourceID].(string) //nolint:errcheck // used only in tests
				newTemplateName := strings.ReplaceAll(template.Name, defaultOSRes, resourceID)
				template.Name = newTemplateName
			}
		})
	})

	ms.Override(DeploymentInstancesIDPath, func(writer http.ResponseWriter, request *http.Request) {
		InstancesByIDWithModify(writer, request, func(_ http.ResponseWriter, _ *model.DtoInstanceQryResponse) {
			// intentionally left blank
		}, resourceID)
	})
}

func (ms *MockServer) SeedSiteResourceID(siteID string) {
	ms.Override(DeploymentReadinessPath, func(res http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet {
			getDeploymentReadinessWithModify(res, req, func(readinessSiteResponse *model.DtoReadinessesQryResponse) {
				for _, readinessSite := range readinessSiteResponse.Data.Results {
					readinessSite.Site.SiteCode = siteID
				}
			})
		} else {
			postDeploymentReadiness(res, req)
		}
	}, http.MethodGet, http.MethodPost)
	site := &locationv1.SiteResource{
		ResourceId: siteID,
	}
	SitesCrudFuncs(ms, true, site)
}

func (ms *MockServer) Override(endpoint string, f func(http.ResponseWriter, *http.Request), methods ...string) {
	ms.overrideMutex.Lock()
	defer ms.overrideMutex.Unlock()

	ms.overriddenRoutes[endpoint] = overriddenEndpoint{f: f, methods: methods}
}

func tokenIsValid(req *http.Request) bool {
	tokenStr := req.Header.Get(authHeader)
	tokens := strings.Split(tokenStr, " ")
	if len(tokens) != authHeaderLen {
		zlog.Debug().Msgf(
			"Wrong authorization header obtained. It should be in format: Bearer AUTH_TOKEN; got %s",
			tokenStr,
		)
		return false
	}
	return tokens[1] == ValidToken
}

func prepopulateSite(sites *sync.Map, site *locationv1.SiteResource) {
	// Creating LOC-A Site with randomized fields.
	// Basic values are taken form the example response.
	if site == nil {
		site = &locationv1.SiteResource{
			ResourceId: "site-1234abcd",
			Name:       "INTC-SC11",
			//nolint:mnd // fake latitude
			SiteLat: 37,
			SiteLng: -121,
			Address: "2191,Laurelwood Road",
		}
	}

	locaSite, err := util.ConvertSiteResourceToLOCASite(site)
	if err != nil {
		zlog.Err(err).Msg("Failed to convert site resource to LOC-A site")
		return
	}
	locaSite.ID = site.GetResourceId()

	// marshaling it to JSON bytes
	siteBytes, err := json.Marshal(locaSite)
	if err != nil {
		zlog.Err(err).Msg("Failed to marshal site to JSON bytes")
		return
	}

	sites.Store(site.GetResourceId(), siteBytes)
	zlog.Debug().Msg("Site template is uploaded")
}

func prepopulateCS(css *sync.Map, cs *model.DtoCloudServiceListElement) {
	// Creating LOC-A CS with randomized fields.
	// Basic values are taken form the example response.
	if cs == nil {
		cs = &model.DtoCloudServiceListElement{
			ID:              "cs-123",
			Name:            "INTC-SC11",
			SiteAssociation: []string{"INTC-SC11"},
			ServiceAddress:  "",
		}
	}

	// marshaling it to JSON bytes
	csBytes, err := json.Marshal(cs)
	if err != nil {
		zlog.Err(err).Msg("Failed to marshal cs to JSON bytes")
		return
	}

	css.Store(cs.ID, csBytes)
	zlog.Debug().Msg("CS template is uploaded")
}
