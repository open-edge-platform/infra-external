// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

//nolint:testpackage // tests private functions
package templates

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	inventoryv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	osv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/os/v1"
	providerv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/provider/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/providerconfiguration"
	inv_testing "github.com/open-edge-platform/infra-core/inventory/v2/pkg/testing"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/model"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/loca"
	loca_testing "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/testing"
	loca_util "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/util"
	"github.com/open-edge-platform/infra-external/loca-templates/pkg/config"
	"github.com/open-edge-platform/infra-external/loca-templates/pkg/testutils"
)

const (
	name1           = "abc"
	name2           = "bcd"
	name3           = "cde"
	clientName      = "TestTMTemplateHandler"
	serverModel     = "serverModel"
	deviceProfileID = "6785126d77586056d1409fc6"
)

var name = "test"

func ProviderCredentials(secrets []string) inv_testing.Opt[providerv1.ProviderResource] {
	return func(p *providerv1.ProviderResource) {
		p.ApiCredentials = secrets
	}
}

func OsProviderKind(kind osv1.OsProviderKind) inv_testing.Opt[osv1.OperatingSystemResource] {
	return func(os *osv1.OperatingSystemResource) {
		os.OsProvider = kind
	}
}

func OsType(osType osv1.OsType) inv_testing.Opt[osv1.OperatingSystemResource] {
	return func(os *osv1.OperatingSystemResource) {
		os.OsType = osType
	}
}

func OsSha256(sha256 string) inv_testing.Opt[osv1.OperatingSystemResource] {
	return func(os *osv1.OperatingSystemResource) {
		os.Sha256 = sha256
	}
}

func TestMain(t *testing.M) {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	projectRoot := filepath.Dir(filepath.Dir(wd))
	policyPath := projectRoot + "/out"
	migrationsDir := projectRoot + "/out"
	secretsDir, err := os.MkdirTemp("/tmp", "")
	if err != nil {
		panic(err)
	}
	err = os.Setenv(loca.CaCertPath, secretsDir)
	if err != nil {
		panic(err)
	}

	loca_testing.StartTestingEnvironment(policyPath, migrationsDir, clientName)
	loca_testing.StartMockSecretService()

	code := t.Run()

	err = os.RemoveAll(secretsDir)
	if err != nil {
		panic(err)
	}
	inv_testing.StopTestingEnvironment()
	os.Exit(code)
}

func Test_differenceToBeAdded_whenBothAreEqualThenNoDifferenceShouldBeDetected(t *testing.T) {
	testutils.MockTemplatesManagerConfigWithSingleRepo(t)
	templates := &model.DtoTemplatesQryResponse{
		Data: &model.DtoTemplateList{
			Results: []*model.DtoTemplate{
				{Name: loca_util.GetTemplateName(name1, serverModel)}, {Name: loca_util.GetTemplateName(name2, serverModel)},
			},
		},
	}
	operatingSystems := []*osv1.OperatingSystemResource{
		{ResourceId: name1},
		{ResourceId: name2},
	}

	diff := findTemplatesToBeAdded(operatingSystems, templates)
	assert.Len(t, diff, 0)
}

func Test_differenceToBeAdded_whenTheresExtraOperatingSystemThenSingleDiffShouldBeReturned(t *testing.T) {
	testutils.MockTemplatesManagerConfigWithSingleRepo(t)
	templates := &model.DtoTemplatesQryResponse{
		Data: &model.DtoTemplateList{
			Results: []*model.DtoTemplate{
				{Name: loca_util.GetTemplateName(name1, serverModel)},
				{Name: loca_util.GetTemplateName(name2, serverModel)},
			},
		},
	}
	operatingSystems := []*osv1.OperatingSystemResource{
		{ResourceId: name1},
		{ResourceId: name2},
		{ResourceId: name3},
	}

	diff := findTemplatesToBeAdded(operatingSystems, templates)
	assert.Len(t, diff, 1)
	assert.Equal(t, diff[0].os.GetResourceId(), name3)
}

func Test_differenceToBeAdded_whenTheresExtraTemplateThenNoDiffShouldBeDetected(t *testing.T) {
	testutils.MockTemplatesManagerConfigWithSingleRepo(t)
	templates := &model.DtoTemplatesQryResponse{Data: &model.DtoTemplateList{Results: []*model.DtoTemplate{
		{Name: loca_util.GetTemplateName(name1, serverModel)},
		{Name: loca_util.GetTemplateName(name2, serverModel)},
		{Name: loca_util.GetTemplateName(name3, serverModel)},
	}}}
	operatingSystems := []*osv1.OperatingSystemResource{
		{ResourceId: name1},
		{ResourceId: name2},
	}

	diff := findTemplatesToBeAdded(operatingSystems, templates)
	assert.Len(t, diff, 0)
}

func Test_differenceToBeAdded_whenEmptyValuesArePassedThenNoErrorAndDiffShouldBeReturned(t *testing.T) {
	testutils.MockTemplatesManagerConfigWithSingleRepo(t)
	templates := &model.DtoTemplatesQryResponse{Data: &model.DtoTemplateList{Results: []*model.DtoTemplate{}}}
	var operatingSystems []*osv1.OperatingSystemResource

	diff := findTemplatesToBeAdded(operatingSystems, templates)
	assert.Len(t, diff, 0)
}

func Test_findTemplateToBeRemoved_whenBothAreEqualThenNoDifferenceShouldBeDetected(t *testing.T) {
	testutils.MockTemplatesManagerConfigWithSingleRepo(t)
	templates := &model.DtoTemplatesQryResponse{
		Data: &model.DtoTemplateList{Results: []*model.DtoTemplate{
			{Name: loca_util.GetTemplateName(name1, serverModel)}, {Name: loca_util.GetTemplateName(name2, serverModel)},
		}},
	}
	operatingSystems := []*osv1.OperatingSystemResource{
		{ResourceId: name1},
		{ResourceId: name2},
	}

	diff := findTemplatesToBeRemoved(operatingSystems, templates)
	assert.Len(t, diff, 0)
}

func Test_differenceToBeRemoved_whenTheresExtraOperatingSystemThenThenNoDiffShouldBeDetected(t *testing.T) {
	testutils.MockTemplatesManagerConfigWithSingleRepo(t)
	templates := &model.DtoTemplatesQryResponse{
		Data: &model.DtoTemplateList{
			Results: []*model.DtoTemplate{
				{Name: loca_util.GetTemplateName(name1, serverModel)},
				{Name: loca_util.GetTemplateName(name2, serverModel)},
			},
		},
	}
	operatingSystems := []*osv1.OperatingSystemResource{
		{ResourceId: name1},
		{ResourceId: name2},
		{ResourceId: name3},
	}

	diff := findTemplatesToBeRemoved(operatingSystems, templates)
	assert.Len(t, diff, 0)
}

func Test_differenceToBeRemoved_whenTheresExtraTemplateThenSingleEntryShouldBeDetected(t *testing.T) {
	testutils.MockTemplatesManagerConfigWithSingleRepo(t)
	templates := &model.DtoTemplatesQryResponse{Data: &model.DtoTemplateList{Results: []*model.DtoTemplate{
		{Name: loca_util.GetTemplateName(name1, serverModel)},
		{Name: loca_util.GetTemplateName(name2, serverModel)},
		{
			Name: loca_util.GetTemplateName(name3, serverModel),
			ExtraVars: map[string]any{
				osResourceID: name3,
			},
			Devices: []*model.DtoTemplateDevice{
				{
					Filters: struct{ model.DtoTemplateDeviceFilters }{
						DtoTemplateDeviceFilters: model.DtoTemplateDeviceFilters{Model: []string{serverModel}},
					},
				},
			},
		},
	}}}

	operatingSystems := []*osv1.OperatingSystemResource{
		{ResourceId: name1},
		{ResourceId: name2},
	}

	diff := findTemplatesToBeRemoved(operatingSystems, templates)
	assert.Len(t, diff, 1)
	assert.Equal(t, name3, diff[0].os.GetResourceId())
}

func Test_differenceToBeRemoved_whenEmptyValuesArePassedThenNoErrorAndDiffShouldBeReturned(t *testing.T) {
	testutils.MockTemplatesManagerConfigWithSingleRepo(t)
	templates := &model.DtoTemplatesQryResponse{
		Data: &model.DtoTemplateList{Count: 0},
	}
	var operatingSystems []*osv1.OperatingSystemResource

	diff := findTemplatesToBeRemoved(operatingSystems, templates)
	assert.Len(t, diff, 0)
}

func Test_getFdeSetting_whenUsingProviderWithoutFdeThenShouldReturnFalse(t *testing.T) {
	operatingSystem := &osv1.OperatingSystemResource{SecurityFeature: osv1.SecurityFeature_SECURITY_FEATURE_NONE}

	fde := getFdeSetting(operatingSystem)
	assert.Equal(t, "false", fde)
}

func Test_getFdeSetting_whenUsingProviderWithFdeThenShouldReturnTrue(t *testing.T) {
	operatingSystem := &osv1.OperatingSystemResource{
		SecurityFeature: osv1.SecurityFeature_SECURITY_FEATURE_SECURE_BOOT_AND_FULL_DISK_ENCRYPTION,
	}

	fde := getFdeSetting(operatingSystem)
	assert.Equal(t, "true", fde)
}

func Test_prepareTemplate_ShouldSetVarsFromProvidedStructs(t *testing.T) {
	osPassword := "testPassword"
	postScriptVal := "postScript"
	dnsDomain := "dns"
	instanceTpl := "intel{{#}}"
	managerConfig := &config.TemplatesManagerConfig{
		SupportedServers: []string{name1},
		OsPassword:       osPassword,
		PostScript:       postScriptVal,
	}
	providerConfig := &providerconfiguration.LOCAProviderConfig{
		DNSDomain:   dnsDomain,
		InstanceTpl: instanceTpl,
	}

	credentialPolicyID := "671f95a73c99a3902980ff11" //nolint:gosec // not a credential

	osPrettyName := "templateName"
	imageID := "imageID"
	resID := "id"
	osResource := &osv1.OperatingSystemResource{
		Name:            osPrettyName,
		ImageId:         imageID,
		ResourceId:      resID,
		SecurityFeature: osv1.SecurityFeature_SECURITY_FEATURE_SECURE_BOOT_AND_FULL_DISK_ENCRYPTION,
	}

	template := prepareTemplate(managerConfig, providerConfig, credentialPolicyID, serverModel, deviceProfileID, osResource)

	assert.Equal(t, loca_util.GetTemplateName(resID, serverModel), template.Name)
	assert.Equal(t, osPassword, template.Devices[0].OsSettings.Credentials[0].Password)
	assert.Contains(t, template.InstanceInfo.FlavorOptions.OsVersion, imageID)
	assert.Contains(t, template.InstanceInfo.FlavorOptions.OsVersion, imageID)
	assert.Equal(t, deviceProfileID, template.DeviceProfileID)

	dns := template.Networking.DNS
	assert.Equal(t, dnsDomain, dns.Domain)
	assert.Equal(t, instanceTpl, dns.Hostname)

	extraVars, ok := template.ExtraVars.(map[string]string)
	assert.True(t, ok)

	assert.Equal(t, "true", extraVars[fdeEnabled])
	assert.Equal(t, postScriptVal, extraVars[postScript])
	assert.Equal(t, osPrettyName, extraVars[prettyName])
	assert.Equal(t, resID, extraVars[osResourceID])
}

func Test_getCredentialPolicyID_WhenUnableToGetResourceFromLocaShouldReturnError(t *testing.T) {
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer locaTS.StopDummyLOCAServer()

	locaTS.Override(loca_testing.SecretsCredentialPoliciesPath, func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusBadRequest)
	}, http.MethodGet)

	cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)

	credentialPolicyID, err := getCredentialPolicyID(context.Background(), cli, "fail", &config.TemplatesManagerConfig{})
	assert.ErrorContains(t, err, "[400]")
	assert.Zero(t, credentialPolicyID)
}

func Test_getCredentialPolicyID_WhenCredentialPolicyDoesntExistShouldCreateNewOne(t *testing.T) {
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer locaTS.StopDummyLOCAServer()
	locaTS.Override(loca_testing.SecretsCredentialPoliciesPath, mockCreateNewCredentialPolicy, http.MethodPost, http.MethodGet)
	cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)

	credentialPolicyID, err := getCredentialPolicyID(context.TODO(), cli, "notfound", &config.TemplatesManagerConfig{})
	assert.NoError(t, err)
	assert.Equal(t, "6720e3893c99a3902980ffa3", credentialPolicyID) // hardcoded value in LOC-A mock response
}

func mockCreateNewCredentialPolicy(writer http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		loca_testing.WriteStructToResponse(writer, request, &model.DtoCredentialpoliciesResponse{
			Message: "test",
			Data:    &model.DtoCredentialpolicies{Count: 0},
		}, http.StatusOK)
	} else {
		loca_testing.WriteStructToResponse(writer, request, &model.DtoCreateCredentialpoliciesResponse{
			Data: &model.DtoCreateCredentialpolicies{Count: 1, Results: []string{"6720e3893c99a3902980ffa3"}},
		}, http.StatusOK)
	}
}

func Test_templateAlreadyExists_whenTemplateExistsShouldReturnTrue(t *testing.T) {
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer locaTS.StopDummyLOCAServer()

	cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)

	exists := templateAlreadyExists(context.Background(), cli, "exists")
	assert.True(t, exists)
}

func Test_templateAlreadyExists_whenCannotConnectToLocaShouldReturnFalls(t *testing.T) {
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer locaTS.StopDummyLOCAServer()

	cli := loca.InitialiseTestLocaClient("wrongURL", loca_testing.LocaSecret)

	exists := templateAlreadyExists(context.Background(), cli, "wrongURL")
	assert.False(t, exists)
}

func Test_templateAlreadyExists_whenTemplateDoesntExistShouldReturnFalse(t *testing.T) {
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer locaTS.StopDummyLOCAServer()
	locaTS.Override(loca_testing.DeploymentTemplatesPath, loca_testing.ReturnEmptyResponse)

	cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)

	exists := templateAlreadyExists(context.Background(), cli, "doesntExist")
	assert.False(t, exists)
}

func Test_deleteCredentialPolicies_shouldNotReturnAnyErrorsOrPanic(t *testing.T) {
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer locaTS.StopDummyLOCAServer()

	resp := &model.DtoTemplate{
		Devices: []*model.DtoTemplateDevice{
			{
				OsSettings: struct{ model.DtoTemplateOsSettings }{
					model.DtoTemplateOsSettings{
						Credentials: []*model.DtoCredential{
							{
								CredentialPolicy: struct{ model.DtoCredentialPolicy }{
									model.DtoCredentialPolicy{ID: "test"},
								},
							},
						},
					},
				},
			},
		},
	}

	cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)

	deleteCredentialPolicies(context.Background(), resp, cli)
}

func Test_getProvidersAndTenantID_whenNoProvidersConfiguredShouldFailToGetTenantID(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)

	_, _, err := getProvidersAndTenantID(context.Background(), dao.GetRMClient())

	assert.ErrorContains(t, err, "No tenantID found")
}

func Test_getProvidersAndTenantID_happyPath(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	dao.CreateProviderWithArgs(t, loca_testing.Tenant1, t.Name()[0:10]+"bm", "test", []string{},
		providerv1.ProviderVendor_PROVIDER_VENDOR_LENOVO_LOCA,
		inv_testing.ProviderKind(providerv1.ProviderKind_PROVIDER_KIND_BAREMETAL))

	_, _, err := getProvidersAndTenantID(context.Background(), dao.GetRMClient())

	assert.NoError(t, err)
}

func Test_deleteTemplate_whenCannotCreateClientShouldReturnError(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)
	prov := &providerv1.ProviderResource{
		ApiEndpoint:    "zxc",
		ApiCredentials: []string{"xcv", "zxc"},
	}

	assertHook := loca_util.NewTestAssertHook("failed to create LOC-A client")
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	deleteTemplate(ctx, wg, name, prov, serverModel)
	assertHook.Assert(t)
}

func Test_deleteTemplate_whenCannotCreateLocaClientShouldLogError(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)
	prov := &providerv1.ProviderResource{
		ApiEndpoint:    "zxc",
		ApiCredentials: []string{"xcv", "zxc"},
	}

	assertHook := loca_util.NewTestAssertHook("failed to create LOC-A client")
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	deleteTemplate(ctx, wg, name, prov, serverModel)
	assertHook.Assert(t)
}

func Test_deleteTemplate_whenCannotGetTemplateShouldLogError(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer locaTS.StopDummyLOCAServer()
	locaTS.Override("/api/v1/deployment/templates", loca_testing.ReturnServerUnavailable)

	prov := &providerv1.ProviderResource{
		ApiEndpoint:    locaTS.GetURL(),
		ApiCredentials: []string{loca_testing.LocaSecret},
	}

	assertHook := loca_util.NewTestAssertHook("Failed to get template")
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	deleteTemplate(ctx, wg, name, prov, serverModel)
	assertHook.Assert(t)
}

func Test_deleteTemplate_whenGot0TemplatesShouldSkipDeleted(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer locaTS.StopDummyLOCAServer()
	locaTS.Override(loca_testing.DeploymentTemplatesPath, func(writer http.ResponseWriter, request *http.Request) {
		loca_testing.WriteStructToResponse(writer, request, &model.DtoTemplatesQryResponse{
			Data: &model.DtoTemplateList{Count: 0},
		}, http.StatusOK)
	})

	prov := &providerv1.ProviderResource{
		ApiEndpoint:    locaTS.GetURL(),
		ApiCredentials: []string{loca_testing.LocaSecret},
	}

	assertHook := loca_util.NewTestAssertHook("Failed to get template")

	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	deleteTemplate(ctx, wg, name, prov, serverModel)
	assertHook.Assert(t)
}

func Test_deleteTemplate_happyPath(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(3)

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer locaTS.StopDummyLOCAServer()
	locaTS.Override(loca_testing.DeploymentTemplatesPath, func(writer http.ResponseWriter, request *http.Request) {
		loca_testing.WriteStructToResponse(writer, request, &model.DtoTemplatesQryResponse{
			Data: &model.DtoTemplateList{
				Count:   1,
				Results: []*model.DtoTemplate{{ID: "test"}},
			},
		}, http.StatusOK)
	})
	locaTS.Override(loca_testing.DeploymentTemplatesRemovePath, func(writer http.ResponseWriter, request *http.Request) {
		loca_testing.WriteStructToResponse(writer, request, &model.DtoResponseBase{
			StatusCode: 0,
			Message:    "Template delete success",
		}, http.StatusOK)
	})

	prov := &providerv1.ProviderResource{
		ApiEndpoint:    locaTS.GetURL(),
		ApiCredentials: []string{loca_testing.LocaSecret},
	}

	assertHook := loca_util.NewTestAssertHook("template was removed")
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	// Delete template
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	deleteTemplate(ctx, wg, name, prov, serverModel)
	assertHook.Assert(t)
}

func Test_createTemplate_happyPath(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer locaTS.StopDummyLOCAServer()
	locaTS.Override(loca_testing.SecretsCredentialPoliciesPath, mockCreateNewCredentialPolicy, http.MethodPost, http.MethodGet)
	locaTS.Override(loca_testing.DeploymentTemplatesPath, mockCreateNewTemplate, http.MethodGet, http.MethodPost)
	providerConfig := providerconfiguration.LOCAProviderConfig{
		InstanceTpl: name1,
		DNSDomain:   name2,
	}
	provConfigBytes, err := json.Marshal(providerConfig)
	assert.NoError(t, err)
	osResource := &osv1.OperatingSystemResource{
		Name: "name", ResourceId: "resourceID",
		OsType: osv1.OsType_OS_TYPE_MUTABLE, OsProvider: osv1.OsProviderKind_OS_PROVIDER_KIND_LENOVO,
	}

	prov := &providerv1.ProviderResource{
		ApiEndpoint:    locaTS.GetURL(),
		ApiCredentials: []string{loca_testing.LocaSecret},
		Config:         string(provConfigBytes),
	}

	testutils.MockTemplatesManagerConfigWithSingleRepo(t)

	assertHook := loca_util.NewTestAssertHook("Template was created")
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	// Create template
	createTemplate(wg, osResource, prov, serverModel)
	assertHook.Assert(t)
}

func mockCreateNewTemplate(writer http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		loca_testing.WriteStructToResponse(writer, request, &model.DtoTemplatesQryResponse{
			Data: &model.DtoTemplateList{Count: 0},
		}, http.StatusOK)
	} else {
		loca_testing.WriteStructToResponse(writer, request, &model.DtoCreatedWorkflowResponse{
			Data: &model.DtoCreatedWorkflowDetails{TaskUUID: []string{"task-uuid-" + uuid.NewString()}},
		}, http.StatusCreated)
	}
}

func Test_createTemplate_whenCannotCreateLocaClientShouldLogError(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)

	osResource := &osv1.OperatingSystemResource{
		Name: "name", ResourceId: "resourceID",
		OsProvider: osv1.OsProviderKind_OS_PROVIDER_KIND_LENOVO, OsType: osv1.OsType_OS_TYPE_MUTABLE,
	}

	prov := &providerv1.ProviderResource{
		ApiEndpoint:    "",
		ApiCredentials: []string{loca_testing.LocaSecret},
	}

	assertHook := loca_util.NewTestAssertHook("failed to create LOC-A client")
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	testutils.MockTemplatesManagerConfig(t)

	createTemplate(wg, osResource, prov, serverModel)
	assertHook.Assert(t)
}

func Test_createTemplate_whenProvidedWithNonMutableOsShouldLogError(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer locaTS.StopDummyLOCAServer()

	osResource := &osv1.OperatingSystemResource{Name: "name", ResourceId: "resourceID"}

	prov := &providerv1.ProviderResource{
		ApiEndpoint:    locaTS.GetURL(),
		ApiCredentials: []string{loca_testing.LocaSecret},
	}

	assertHook := loca_util.NewTestAssertHook(`only 'OS_TYPE_MUTABLE' OSes are supported.`)
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}
	zGlobalLevel := zerolog.GlobalLevel()
	defer zerolog.SetGlobalLevel(zGlobalLevel)
	zerolog.SetGlobalLevel(zerolog.DebugLevel)

	testutils.MockTemplatesManagerConfig(t)

	createTemplate(wg, osResource, prov, serverModel)
	assertHook.Assert(t)
}

func Test_createTemplate_whenProvidedWithOsWithUnsupportedProviderKindShouldLogError(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer locaTS.StopDummyLOCAServer()

	osResource := &osv1.OperatingSystemResource{
		Name: "name", ResourceId: "resourceID",
		OsType: osv1.OsType_OS_TYPE_MUTABLE, OsProvider: osv1.OsProviderKind_OS_PROVIDER_KIND_INFRA,
	}

	prov := &providerv1.ProviderResource{
		ApiEndpoint:    locaTS.GetURL(),
		ApiCredentials: []string{loca_testing.LocaSecret},
	}

	assertHook := loca_util.NewTestAssertHook(`but only 'OS_PROVIDER_KIND_LENOVO' OSes are supported`)
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}
	zGlobalLevel := zerolog.GlobalLevel()
	defer zerolog.SetGlobalLevel(zGlobalLevel)
	zerolog.SetGlobalLevel(zerolog.DebugLevel)

	testutils.MockTemplatesManagerConfig(t)

	createTemplate(wg, osResource, prov, serverModel)
	assertHook.Assert(t)
}

func Test_createTemplate_whenTemplateAlreadyExistsShouldDoNothing(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer locaTS.StopDummyLOCAServer()
	locaTS.Override(loca_testing.DeploymentTemplatesPath, func(writer http.ResponseWriter, request *http.Request) {
		loca_testing.WriteStructToResponse(writer, request, &model.DtoTemplatesQryResponse{
			Data: &model.DtoTemplateList{Count: 1},
		}, http.StatusOK)
	}, http.MethodGet)

	osResource := &osv1.OperatingSystemResource{
		Name:       "name",
		ResourceId: "resourceID" + uuid.NewString(),
		OsType:     osv1.OsType_OS_TYPE_MUTABLE,
		OsProvider: osv1.OsProviderKind_OS_PROVIDER_KIND_LENOVO,
	}

	prov := &providerv1.ProviderResource{
		ApiEndpoint:    locaTS.GetURL(),
		ApiCredentials: []string{loca_testing.LocaSecret},
	}

	assertHook := loca_util.NewTestAssertHook(`template as it is already exists`)
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}
	zGlobalLevel := zerolog.GlobalLevel()
	defer zerolog.SetGlobalLevel(zGlobalLevel)
	zerolog.SetGlobalLevel(zerolog.DebugLevel)

	testutils.MockTemplatesManagerConfig(t)

	createTemplate(wg, osResource, prov, serverModel)
	assertHook.Assert(t)
}

func Test_processEvent_whenSendingCreateEventShouldTryAndCreateTemplate(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer locaTS.StopDummyLOCAServer()
	locaTS.Override(loca_testing.SecretsCredentialPoliciesPath, mockCreateNewCredentialPolicy, http.MethodPost, http.MethodGet)
	locaTS.Override(loca_testing.DeploymentTemplatesPath, mockCreateNewTemplate, http.MethodGet, http.MethodPost)

	dao := inv_testing.NewInvResourceDAOOrFail(t)

	event := &inventoryv1.SubscribeEventsResponse{
		EventKind: inventoryv1.SubscribeEventsResponse_EVENT_KIND_CREATED,
		Resource: &inventoryv1.Resource{
			Resource: &inventoryv1.Resource_Os{
				Os: &osv1.OperatingSystemResource{
					ResourceId: "resourceID" + uuid.NewString(),
					OsType:     osv1.OsType_OS_TYPE_MUTABLE,
					OsProvider: osv1.OsProviderKind_OS_PROVIDER_KIND_LENOVO,
				},
			},
		},
	}

	testutils.MockTemplatesManagerConfigWithSingleRepo(t)
	assert.NoError(t, err)
	providerConfig := providerconfiguration.LOCAProviderConfig{
		InstanceTpl: name1,
		DNSDomain:   name2,
	}
	provConfigBytes, err := json.Marshal(providerConfig)
	assert.NoError(t, err)
	dao.CreateProviderWithArgs(t, loca_testing.Tenant1, t.Name()[0:10]+"bm", locaTS.GetURL(), []string{},
		providerv1.ProviderVendor_PROVIDER_VENDOR_LENOVO_LOCA,
		inv_testing.ProviderKind(providerv1.ProviderKind_PROVIDER_KIND_BAREMETAL),
		ProviderCredentials([]string{loca_testing.LocaSecret}),
		inv_testing.ProviderConfig(string(provConfigBytes)))

	assertEventHook := loca_util.NewTestAssertHook(`Got created event`)
	assertTemplateHook := loca_util.NewTestAssertHook(`Template was created`)
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertEventHook, assertTemplateHook)}

	processEvent(wg, dao.GetAPIClient(), event)
	// template creation is running in separate goroutine, so we have to sleep to allow LOC-A mock to respond goroutine
	time.Sleep(time.Second)
	assertTemplateHook.Assert(t)
	assertEventHook.Assert(t)

	// Finish create template task and rerun createTemplate to clean up the task in TaskTracker
	processEvent(wg, dao.GetAPIClient(), event)
	time.Sleep(100 * time.Millisecond)
}

func Test_processEvent_whenSendingDeleteEventShouldTryAndDeleteTemplate(t *testing.T) {
	wg := &sync.WaitGroup{}

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer locaTS.StopDummyLOCAServer()
	locaTS.Override(loca_testing.DeploymentTemplatesPath, func(writer http.ResponseWriter, request *http.Request) {
		loca_testing.WriteStructToResponse(writer, request, &model.DtoTemplatesQryResponse{
			Data: &model.DtoTemplateList{
				Count: 1,
				Results: []*model.DtoTemplate{
					{
						Devices: []*model.DtoTemplateDevice{{
							OsSettings: struct{ model.DtoTemplateOsSettings }{
								model.DtoTemplateOsSettings{
									Credentials: []*model.DtoCredential{
										{
											CredentialPolicy: struct{ model.DtoCredentialPolicy }{
												model.DtoCredentialPolicy{ID: "test"},
											},
										},
									},
								},
							},
						}},
					},
				},
			},
		}, http.StatusOK)
	}, http.MethodGet)

	dao := inv_testing.NewInvResourceDAOOrFail(t)

	event := &inventoryv1.SubscribeEventsResponse{
		EventKind: inventoryv1.SubscribeEventsResponse_EVENT_KIND_DELETED,
		Resource: &inventoryv1.Resource{
			Resource: &inventoryv1.Resource_Os{
				Os: &osv1.OperatingSystemResource{
					ResourceId: "resourceID" + uuid.NewString(),
					OsType:     osv1.OsType_OS_TYPE_MUTABLE,
				},
			},
		},
	}

	testutils.MockTemplatesManagerConfigWithSingleRepo(t)
	assert.NoError(t, err)
	dao.CreateProviderWithArgs(t, loca_testing.Tenant1, t.Name()[0:10]+"bm", locaTS.GetURL(), []string{},
		providerv1.ProviderVendor_PROVIDER_VENDOR_LENOVO_LOCA,
		inv_testing.ProviderKind(providerv1.ProviderKind_PROVIDER_KIND_BAREMETAL),
		ProviderCredentials([]string{loca_testing.LocaSecret}))

	assertEventHook := loca_util.NewTestAssertHook(`Got deleted event`)
	assertTemplateHook := loca_util.NewTestAssertHook(`template was removed`)
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertEventHook, assertTemplateHook)}

	processEvent(wg, dao.GetAPIClient(), event)
	// template creation is running in separate goroutine, so we have to sleep to allow LOC-A mock to respond goroutine
	time.Sleep(time.Second)
	assertTemplateHook.Assert(t)
	assertEventHook.Assert(t)
}

func Test_processEvent_whenProvidersAreNotConfiguredShouldLogError(t *testing.T) {
	wg := &sync.WaitGroup{}
	wg.Add(1)

	dao := inv_testing.NewInvResourceDAOOrFail(t)

	event := &inventoryv1.SubscribeEventsResponse{
		EventKind: inventoryv1.SubscribeEventsResponse_EVENT_KIND_DELETED,
		Resource: &inventoryv1.Resource{
			Resource: &inventoryv1.Resource_Os{
				Os: &osv1.OperatingSystemResource{
					ResourceId: "resourceID" + uuid.NewString(),
					OsType:     osv1.OsType_OS_TYPE_MUTABLE,
				},
			},
		},
	}

	assertHook := loca_util.NewTestAssertHook(`failed to get tenantID`)
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	processEvent(wg, dao.GetAPIClient(), event)
	assertHook.Assert(t)
}

func Test_processProvider_whenOperatingSystemExistsWithoutTemplateShouldCreateTemplateForIt(t *testing.T) {
	testutils.MockTemplatesManagerConfigWithSingleRepo(t)
	wg := &sync.WaitGroup{}
	wg.Add(1)

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer locaTS.StopDummyLOCAServer()
	locaTS.Override(loca_testing.DeploymentTemplatesPath, loca_testing.ReturnEmptyResponse)
	locaTS.Override(loca_testing.SecretsCredentialPoliciesPath, mockCreateNewCredentialPolicy, http.MethodPost, http.MethodGet)
	locaTS.Override(loca_testing.DeploymentTemplatesPath, mockCreateNewTemplate, http.MethodGet, http.MethodPost)
	cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)

	dao := inv_testing.NewInvResourceDAOOrFail(t)
	dao.CreateOsWithOpts(t, loca_testing.Tenant1, true, OsProviderKind(osv1.OsProviderKind_OS_PROVIDER_KIND_LENOVO),
		OsType(osv1.OsType_OS_TYPE_MUTABLE), OsSha256(inv_testing.GenerateRandomSha256()))

	providerConfig := providerconfiguration.LOCAProviderConfig{
		InstanceTpl: name1,
		DNSDomain:   name2,
	}
	provConfigBytes, err := json.Marshal(providerConfig)
	assert.NoError(t, err)
	prov := &providerv1.ProviderResource{
		ApiEndpoint:    locaTS.GetURL(),
		ApiCredentials: []string{loca_testing.LocaSecret},
		Config:         string(provConfigBytes),
	}

	assertHook := loca_util.NewTestAssertHook(`Template was created`)
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	processProvider(ctx, wg, dao.GetAPIClient(), loca_testing.Tenant1, cli, prov)
	// template creation is running in separate goroutine, so we have to sleep to allow LOC-A mock to respond goroutine
	time.Sleep(time.Second)
	assertHook.Assert(t)
}

func Test_processProvider_whenTemplateExistsWithoutCorrespondingOsResourceShouldDeleteIt(t *testing.T) {
	testutils.MockTemplatesManagerConfigWithSingleRepo(t)
	wg := &sync.WaitGroup{}
	wg.Add(1)

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer locaTS.StopDummyLOCAServer()
	cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)

	dao := inv_testing.NewInvResourceDAOOrFail(t)

	prov := &providerv1.ProviderResource{
		ApiEndpoint:    locaTS.GetURL(),
		ApiCredentials: []string{loca_testing.LocaSecret},
	}

	assertHook := loca_util.NewTestAssertHook(`template was removed`)
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	processProvider(ctx, wg, dao.GetAPIClient(), loca_testing.Tenant1, cli, prov)
	// template creation is running in separate goroutine, so we have to sleep to allow LOC-A mock to respond goroutine
	time.Sleep(time.Second)
	assertHook.Assert(t)
}

func Test_processAllOsResources_happyPath(t *testing.T) {
	testutils.MockTemplatesManagerConfigWithSingleRepo(t)
	wg := &sync.WaitGroup{}

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer locaTS.StopDummyLOCAServer()
	locaTS.Override(loca_testing.DeploymentTemplatesPath, loca_testing.ReturnEmptyResponse)
	locaTS.Override(loca_testing.SecretsCredentialPoliciesPath, mockCreateNewCredentialPolicy, http.MethodPost, http.MethodGet)
	locaTS.Override(loca_testing.DeploymentTemplatesPath, mockCreateNewTemplate, http.MethodGet, http.MethodPost)

	dao := inv_testing.NewInvResourceDAOOrFail(t)
	assert.NoError(t, err)
	providerConfig := providerconfiguration.LOCAProviderConfig{
		InstanceTpl: name1,
		DNSDomain:   name2,
	}
	provConfigBytes, err := json.Marshal(providerConfig)
	assert.NoError(t, err)
	dao.CreateProviderWithArgs(t, loca_testing.Tenant1, t.Name()[0:10]+"bm", locaTS.GetURL(), []string{},
		providerv1.ProviderVendor_PROVIDER_VENDOR_LENOVO_LOCA,
		inv_testing.ProviderKind(providerv1.ProviderKind_PROVIDER_KIND_BAREMETAL),
		ProviderCredentials([]string{loca_testing.LocaSecret}),
		inv_testing.ProviderConfig(string(provConfigBytes)))
	dao.CreateOsWithOpts(t, loca_testing.Tenant1, true,
		OsProviderKind(osv1.OsProviderKind_OS_PROVIDER_KIND_LENOVO),
		OsType(osv1.OsType_OS_TYPE_MUTABLE), OsSha256(inv_testing.GenerateRandomSha256()))

	assertHook := loca_util.NewTestAssertHook(`Template was created`)
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	processAllOsResources(wg, dao.GetAPIClient())
	// template creation is running in separate goroutine, so we have to sleep to allow LOC-A mock to respond goroutine
	time.Sleep(time.Second)
	assertHook.Assert(t)
}

func Test_processAllOsResources_whenCannotGetProvidersShouldReturnError(t *testing.T) {
	testutils.MockTemplatesManagerConfigWithSingleRepo(t)
	wg := &sync.WaitGroup{}
	wg.Add(1)
	dao := inv_testing.NewInvResourceDAOOrFail(t)

	assertHook := loca_util.NewTestAssertHook(`failed to get tenantID`)
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	processAllOsResources(wg, dao.GetAPIClient())
	// template creation is running in separate goroutine, so we have to sleep to allow LOC-A mock to respond goroutine
	time.Sleep(time.Second)
	assertHook.Assert(t)
}
