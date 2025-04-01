// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package templates

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"

	inventoryv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	osv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/os/v1"
	providerv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/provider/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	inv_errors "github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/providerconfiguration"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/client/deployment"
	loca_inventory "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/client/inventory"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/client/secrets"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/model"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/inventory"
	locarm "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/loca"
	loca_util "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/util"
	"github.com/open-edge-platform/infra-external/loca-templates/pkg/config"
	"github.com/open-edge-platform/infra-external/loca-templates/pkg/images"
)

const (
	ubuntuName = "Ubuntu "

	fdeEnabled   = "fde_enabled"
	postScript   = "post_script"
	prettyName   = "pretty_name"
	osResourceID = "os_resource_id"

	// There are two concurrent routines: event handling and periodic reconciliation. We set each operation to last at
	// least 95% of the reconciliation period. The idea is to save some time for the next reconciliation cycle and prevent
	// overruns (which means wait again a full reconciliation period). TM operations are in general slow so the following
	// assumptions are made when there is no work to be done or just removal. In that case the operations should not exceed
	// the 95% of the reconciliation period.
	reconciliationPeriodWeight = 95  // %
	totalWeight                = 100 // %
)

var (
	log      = logging.GetLogger("templates")
	termChan = make(chan bool, 1)
)

type osAndModelPair struct {
	model string
	os    *osv1.OperatingSystemResource
}

func Start(wg *sync.WaitGroup, mainLoopStartedChan chan bool,
	eventWatcher chan *client.WatchEvents, invClient client.TenantAwareInventoryClient,
) {
	defer wg.Done()
	if mainLoopStartedChan != nil {
		mainLoopStartedChan <- true
	}

	managerConfig := config.GetConfig()
	ticker := time.NewTicker(managerConfig.TemplateReconcilePeriod)
	processAllOsResources(wg, invClient)

	for {
		select {
		case event, ok := <-eventWatcher:
			if !ok {
				ticker.Stop()
				log.InfraSec().Fatal().Msg("gRPC stream with Inventory closed")
			}
			processEvent(wg, invClient, event.Event)
		case <-ticker.C:
			processAllOsResources(wg, invClient)
		case <-termChan:
			log.Info().Msgf("Received SIGTERM signal. Stopping template manager.")
			return
		}
	}
}

func Stop(invClient client.TenantAwareInventoryClient) {
	termChan <- true
	close(termChan)
	err := invClient.Close()
	if err != nil {
		log.InfraErr(err).Msgf("failed to close inventory client")
	}
	inventory.StopTenantGetter()
}

func processAllOsResources(wg *sync.WaitGroup,
	invClient client.TenantAwareInventoryClient,
) {
	synchronizationTimeout := config.GetConfig().TemplateReconcilePeriod * reconciliationPeriodWeight / totalWeight
	ctx, cancel := context.WithTimeout(context.Background(), synchronizationTimeout)
	defer cancel()

	locaProviders, tenantID, err := getProvidersAndTenantID(ctx, invClient)
	if err != nil {
		return
	}
	for _, locaProvider := range locaProviders {
		locaClient, err := locarm.InitialiseLOCAClient(locaProvider.GetApiEndpoint(), locaProvider.GetApiCredentials())
		if err != nil {
			log.Warn().Msgf("failed to create LOC-A client for %v - %v", locaProvider.GetApiEndpoint(), err)
			continue
		}

		wg.Add(1)
		go processProvider(context.WithoutCancel(ctx), wg, invClient, tenantID, locaClient, locaProvider)
	}
}

func processProvider(ctx context.Context, wg *sync.WaitGroup, invClient client.TenantAwareInventoryClient,
	tenantID string, locaClient *locarm.LocaCli, locaProvider *providerv1.ProviderResource,
) {
	defer wg.Done()

	operatingSystems, err := inventory.ListAllMutableOperatingSystems(ctx, invClient, tenantID)
	if err != nil {
		log.InfraErr(err).Msgf("failed to list OS resources")
		return
	}

	templates, err := locaClient.LocaAPI.Deployment.GetAPIV1DeploymentTemplates(
		&deployment.GetAPIV1DeploymentTemplatesParams{Context: ctx}, locaClient.AuthWriter)
	if err != nil {
		log.InfraErr(err).Msgf("couldn't list templates")
		return
	}

	toBeAdded := findTemplatesToBeAdded(operatingSystems, templates.Payload)

	for _, toAdd := range toBeAdded {
		// intentionally uploading in main goroutine to make sure that only 1 thread will upload it
		err = images.HandleImage(locaClient, toAdd.os)
		if err != nil {
			log.InfraErr(err).Msg("failed to handle image")
			return
		}
		wg.Add(1)
		go createTemplate(wg, toAdd.os, locaProvider, toAdd.model)
	}

	toBeDeleted := findTemplatesToBeRemoved(operatingSystems, templates.Payload)
	for _, toDelete := range toBeDeleted {
		wg.Add(1)
		go deleteTemplate(ctx, wg, toDelete.os.GetResourceId(), locaProvider, toDelete.model)
	}
}

func getProvidersAndTenantID(ctx context.Context,
	invClient client.TenantAwareInventoryClient,
) ([]*providerv1.ProviderResource, string, error) {
	locaProviders, err := inventory.ListLOCAProviderResources(ctx, invClient)
	if err != nil {
		return nil, "", err
	}

	tenantID, err := inventory.GetSingularTenantIDFromProviders(locaProviders)
	if err != nil {
		log.Err(err).Msgf("failed to get tenantID")
		return nil, "", err
	}

	return locaProviders, tenantID, nil
}

func findTemplatesToBeAdded(operatingSystems []*osv1.OperatingSystemResource,
	existingTemplates *model.DtoTemplatesQryResponse,
) []*osAndModelPair {
	exists := make(map[string]bool, len(existingTemplates.Data.Results))
	for _, template := range existingTemplates.Data.Results {
		exists[template.Name] = true
	}

	var diff []*osAndModelPair
	for _, serverModel := range config.GetConfig().SupportedServers {
		for _, os := range operatingSystems {
			if _, found := exists[loca_util.GetTemplateName(os.GetResourceId(), serverModel)]; !found {
				diff = append(diff, &osAndModelPair{model: serverModel, os: os})
			}
		}
	}

	return diff
}

func findTemplatesToBeRemoved(operatingSystems []*osv1.OperatingSystemResource,
	existingTemplates *model.DtoTemplatesQryResponse,
) []*osAndModelPair {
	exists := make(map[string]bool, len(operatingSystems))
	for _, serverModel := range config.GetConfig().SupportedServers {
		for _, os := range operatingSystems {
			exists[loca_util.GetTemplateName(os.GetResourceId(), serverModel)] = true
		}
	}

	var diff []*osAndModelPair
	for _, template := range existingTemplates.Data.Results {
		if _, found := exists[template.Name]; !found {
			// LOC-A templates support only 1 device, so this indexing should safe
			diff = append(diff, &osAndModelPair{
				model: template.Devices[0].Filters.Model[0],
				os: &osv1.OperatingSystemResource{
					ResourceId: fmt.Sprintf("%v", template.ExtraVars[osResourceID]),
				},
			})
		}
	}
	return diff
}

func processEvent(wg *sync.WaitGroup, invClient client.TenantAwareInventoryClient, event *inventoryv1.SubscribeEventsResponse) {
	synchronizationTimeout := config.GetConfig().TemplateReconcilePeriod * reconciliationPeriodWeight / totalWeight
	ctx, cancel := context.WithTimeout(context.Background(), synchronizationTimeout)
	defer cancel()

	os := event.GetResource().GetOs()
	locaProviders, _, err := getProvidersAndTenantID(ctx, invClient)
	if err != nil {
		return
	}

	for _, locaProvider := range locaProviders {
		if event.EventKind == inventoryv1.SubscribeEventsResponse_EVENT_KIND_CREATED {
			log.Info().Msgf("Got created event for %v", os.GetResourceId())
			locaClient, err := locarm.InitialiseLOCAClient(locaProvider.GetApiEndpoint(), locaProvider.GetApiCredentials())
			if err != nil {
				log.Err(err).Msgf("failed to create LOC-A client")
				return
			}

			for _, serverModel := range config.GetConfig().SupportedServers {
				// intentionally uploading in main goroutine to make sure that only 1 thread will upload it
				err = images.HandleImage(locaClient, os)
				if err != nil {
					log.InfraErr(err).Msg("failed to handle image")
					return
				}

				wg.Add(1)
				go createTemplate(wg, os, locaProvider, serverModel)
			}
		}
		if event.EventKind == inventoryv1.SubscribeEventsResponse_EVENT_KIND_DELETED {
			log.Info().Msgf("Got deleted event for %v", os.GetResourceId())
			for _, serverModel := range config.GetConfig().SupportedServers {
				wg.Add(1)
				go deleteTemplate(context.WithoutCancel(ctx), wg, os.GetResourceId(), locaProvider, serverModel)
			}
		}
	}
}

func deleteTemplate(ctx context.Context, wg *sync.WaitGroup, osResourceID string,
	locaProvider *providerv1.ProviderResource, serverModel string,
) {
	defer wg.Done()

	templateName := loca_util.GetTemplateName(osResourceID, serverModel)

	locaClient, err := locarm.InitialiseLOCAClient(locaProvider.GetApiEndpoint(), locaProvider.GetApiCredentials())
	if err != nil {
		log.Err(err).Msgf("failed to create LOC-A client")
		return
	}

	// get template before deletion to get credential policy ID
	template, err := locaClient.GetTemplateByTemplateName(ctx, templateName)
	if err != nil {
		log.Err(err).Msgf("Failed to get template (%s) from LOC-A", templateName)
		return
	}

	log.Info().Msgf("Deleting %v template", templateName)
	//nolint:errcheck // no need to check output
	_, err = locaClient.LocaAPI.Deployment.PostAPIV1DeploymentTemplatesRemove(
		&deployment.PostAPIV1DeploymentTemplatesRemoveParams{
			Context: ctx,
			Body:    &model.DtoRemoveTemplateRequest{TemplateName: []string{templateName}},
		},
		locaClient.AuthWriter)
	if err != nil {
		log.InfraErr(err).Msgf("failed to DELETE %v template", templateName)
		return
	}
	log.Info().Msgf("%v template was removed", templateName)

	deleteCredentialPolicies(ctx, template, locaClient)
}

// loops through all credentialPolicies for deleted template and tries to remove them
// since TM manager only manages templates that were created by TM
// extremely inefficient loop should delete only 1 credentialPolicy.
func deleteCredentialPolicies(ctx context.Context, template *model.DtoTemplate, locaClient *locarm.LocaCli) {
	for _, device := range template.Devices {
		for _, credential := range device.OsSettings.Credentials {
			credentialPolicyID := credential.CredentialPolicy.ID

			//nolint:errcheck // no need to check output
			_, err := locaClient.LocaAPI.Secrets.DeleteAPIV1SecretsCredentialPoliciesID(
				&secrets.DeleteAPIV1SecretsCredentialPoliciesIDParams{ID: credentialPolicyID, Context: ctx},
				locaClient.AuthWriter)
			if err != nil {
				if strings.Contains(err.Error(), "status 404") {
					log.Debug().Err(err).Msgf("Credential policy %v (%v) not found. It might be already deleted.",
						credential.CredentialPolicy.Name, credentialPolicyID)
				} else {
					log.Error().Err(err).Msgf("Unexpected error occurred while deleting credential policy %v (%v).",
						credential.CredentialPolicy.Name, credentialPolicyID)
				}
			}
		}
	}
}

func createTemplate(wg *sync.WaitGroup, osResource *osv1.OperatingSystemResource,
	locaProvider *providerv1.ProviderResource, serverModel string,
) {
	defer wg.Done()
	if osResource.OsType != osv1.OsType_OS_TYPE_MUTABLE {
		log.Debug().Msgf("%v OS is '%v', but only '%v' OSes are supported.",
			osResource.GetResourceId(), osResource.GetOsType().String(), osv1.OsType_OS_TYPE_MUTABLE.String())
		return
	}
	if osResource.GetOsProvider() != osv1.OsProviderKind_OS_PROVIDER_KIND_LENOVO {
		log.Debug().Msgf("%v OS is '%v', but only '%v' OSes are supported.",
			osResource.GetResourceId(), osResource.GetOsProvider(), osv1.OsProviderKind_OS_PROVIDER_KIND_LENOVO)
		return
	}

	managerConfig := config.GetConfig()
	templateName := loca_util.GetTemplateName(osResource.GetResourceId(), serverModel)

	locaClient, err := locarm.InitialiseLOCAClient(locaProvider.GetApiEndpoint(), locaProvider.GetApiCredentials())
	if err != nil {
		log.Err(err).Msgf("failed to create LOC-A client")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), managerConfig.TemplateCreationTimeout)
	defer cancel()

	if templateAlreadyExists(ctx, locaClient, templateName) {
		return
	}

	log.Info().Msgf("Processing creation of template for %v(%v) OS", osResource.GetName(), templateName)

	credentialPolicyID, err := getCredentialPolicyID(ctx, locaClient, templateName, managerConfig)
	if err != nil {
		log.InfraErr(err).Msg("failed to get credential policy ID")
		return
	}

	providerConfig, err := config.GetProviderConfig(locaProvider)
	if err != nil {
		log.InfraErr(err).Msg("provider config misconfiguration")
		return
	}

	deviceProfileID, err := getDeviceProfileID(ctx, locaClient, serverModel)
	if err != nil {
		log.InfraErr(err).Msgf("failed to get device profile ID for %v", serverModel)
		return
	}

	template := prepareTemplate(managerConfig, providerConfig,
		credentialPolicyID, serverModel, deviceProfileID, osResource)
	//nolint:errcheck // no need to check output
	_, err = locaClient.LocaAPI.Deployment.PostAPIV1DeploymentTemplates(
		&deployment.PostAPIV1DeploymentTemplatesParams{
			Context: ctx,
			Body:    &template,
		}, locaClient.AuthWriter)
	if err != nil {
		log.InfraErr(err).Msgf("failed to create %v template", templateName)
		return
	}

	log.Info().Msgf("Template was created %v(%v)", osResource.GetName(), templateName)
}

func templateAlreadyExists(ctx context.Context, locaClient *locarm.LocaCli, name string) bool {
	getResponse, err := locaClient.LocaAPI.Deployment.GetAPIV1DeploymentTemplates(
		&deployment.GetAPIV1DeploymentTemplatesParams{Context: ctx, Name: &name},
		locaClient.AuthWriter)
	if err != nil {
		log.InfraErr(err).Msgf("failed to GET %v template, assuming that it doesn't exists", name)
		return false
	}

	if getResponse.Payload.Data.Count != 0 {
		log.Debug().Msgf("Skipping creation of %v template as it is already exists.", name)
		return true
	}
	return false
}

func prepareTemplate(managerConfig *config.TemplatesManagerConfig,
	providerConfig *providerconfiguration.LOCAProviderConfig, credentialPolicyID, serverModel, deviceProfileID string,
	osResource *osv1.OperatingSystemResource,
) model.DtoCreateTemplateRequest {
	return model.DtoCreateTemplateRequest{
		DeviceProfileID: deviceProfileID,
		Devices: []*model.DtoCreateUpdateTemplateDevice{
			{
				CloudRole: []string{"auto"},
				Filters: struct {
					model.DtoTemplateDeviceFilters
				}{
					DtoTemplateDeviceFilters: model.DtoTemplateDeviceFilters{
						Model: []string{serverModel},
					},
				},
				FirmwarePackageID: "none",
				NumberOfDevices:   1,
				OsSettings: struct {
					model.DtoCreateUpdateTemplateOsSettings
				}{DtoCreateUpdateTemplateOsSettings: model.DtoCreateUpdateTemplateOsSettings{
					Credentials: []*model.DtoCreateUpdateTemplateCredential{
						{
							CredentialPolicyID: credentialPolicyID,
							Kind:               "OS",
							Password:           managerConfig.OsPassword,
						},
					},
				}},
			},
		},
		ExtraVars: map[string]string{
			fdeEnabled:   getFdeSetting(osResource),
			postScript:   managerConfig.PostScript,
			prettyName:   osResource.GetName(),
			osResourceID: osResource.GetResourceId(),
		},
		InstanceInfo: struct {
			model.DtoTemplateInstanceInfo
		}{DtoTemplateInstanceInfo: model.DtoTemplateInstanceInfo{
			Flavor: "Edge Manageability Framework",
			FlavorOptions: struct {
				model.DtoTemplateFlavorOptions
			}{
				DtoTemplateFlavorOptions: model.DtoTemplateFlavorOptions{
					OsVersion: ubuntuName + osResource.GetImageId(),
					Version:   ubuntuName + osResource.GetImageId(),
				},
			},
		}},

		Kind: "os",
		Name: loca_util.GetTemplateName(osResource.GetResourceId(), serverModel),
		Networking: struct {
			model.DtoCreateUpdateTemplateNetworking
		}{
			DtoCreateUpdateTemplateNetworking: model.DtoCreateUpdateTemplateNetworking{
				DNS: struct {
					model.DtoCreateUpdateTemplateNetwork
				}{
					DtoCreateUpdateTemplateNetwork: model.DtoCreateUpdateTemplateNetwork{
						Domain:   providerConfig.DNSDomain,
						Hostname: providerConfig.InstanceTpl,
					},
				},
			},
		},
	}
}

// intentionally returning string, as LOC-A configuration doesn't supports boolean.
func getFdeSetting(os *osv1.OperatingSystemResource) string {
	return strconv.FormatBool(os.GetSecurityFeature() ==
		osv1.SecurityFeature_SECURITY_FEATURE_SECURE_BOOT_AND_FULL_DISK_ENCRYPTION)
}

func getCredentialPolicyID(ctx context.Context, locaClient *locarm.LocaCli,
	name string, managerConfig *config.TemplatesManagerConfig,
) (string, error) {
	secretResp, err := locaClient.LocaAPI.Secrets.GetAPIV1SecretsCredentialPolicies(
		&secrets.GetAPIV1SecretsCredentialPoliciesParams{Context: ctx, Name: &name},
		locaClient.AuthWriter)
	if err != nil {
		return "", err
	}

	credentialPolicyID := ""
	if secretResp.Payload.Data.Count != 0 {
		credentialPolicyID = secretResp.Payload.Data.Results[0].ID
		log.Info().Msgf("Skipping creation of %v credential policy as it is already exists", name)
	} else {
		postResp, newErr := locaClient.LocaAPI.Secrets.PostAPIV1SecretsCredentialPolicies(
			&secrets.PostAPIV1SecretsCredentialPoliciesParams{
				Context: ctx, Body: &model.ModelsCredentialPolicyCreateParams{Data: []*model.ModelsCreateCredentialPolicyParam{{
					Approach:         "static",
					Kind:             "OS",
					Name:             name,
					PasswordTemplate: managerConfig.OsPassword,
				}}},
			}, locaClient.AuthWriter)
		if newErr != nil {
			return "", newErr
		}
		credentialPolicyID = postResp.Payload.Data.Results[0]
		log.Info().Msgf("Created %v (%v) credential policy", name, credentialPolicyID)
	}
	log.Info().Msgf("Using credential policy %v for %v template", credentialPolicyID, name)
	return credentialPolicyID, nil
}

func getDeviceProfileID(ctx context.Context, locaClient *locarm.LocaCli, serverModel string) (string, error) {
	filter := fmt.Sprintf(`[{"attributes":"deviceModel","values":%q}]`, serverModel)

	deviceProfiles, err := locaClient.LocaAPI.Inventory.GetAPIV1InventoryDeviceProfiles(
		&loca_inventory.GetAPIV1InventoryDeviceProfilesParams{Context: ctx, FilterContains: &filter},
		locaClient.AuthWriter)
	if err != nil {
		return "", err
	}

	if len(deviceProfiles.GetPayload().Data.Results) != 1 {
		err = inv_errors.Errorfc(codes.InvalidArgument, "Obtained %v device profiles for server model %v, but expected one",
			len(deviceProfiles.GetPayload().Data.Results), serverModel)
		log.InfraErr(err).Msgf("")
		return "", err
	}

	return deviceProfiles.GetPayload().Data.Results[0].ID, nil
}
