// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"

	computev1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/compute/v1"
	inv_v1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	locationv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/location/v1"
	providerv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/provider/v1"
	statusv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/status/v1"
	kk_auth "github.com/open-edge-platform/infra-core/inventory/v2/pkg/auth"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	inv_util "github.com/open-edge-platform/infra-core/inventory/v2/pkg/util"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/client/deployment"
	loca_inventory "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/client/inventory"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/model"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/inventory"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/loca"
	loca_status "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/status"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/util"
)

const (
	hostStatusActive                   = "active"
	instanceStageInstalled             = "installed"
	instanceStatusFinishedSuccessfully = "Finished successfully"
	AllowHostDiscovery                 = "allowHostDiscovery"
	AllowHostDiscoveryDescription      = "Flag to allow Host discovery automatically when it does not exist in the Inventory"
)

var HostDiscovery = true // default value in flag

func (lrm *LOCARM) UpdateHosts(
	ctx context.Context, locaClient *loca.LocaCli, tenantID string, locaProvider *providerv1.ProviderResource,
) error {
	// read list of the devices from LOC-A
	locaHosts, err := locaClient.LocaAPI.Inventory.GetAPIV1InventoryDevices(
		&loca_inventory.GetAPIV1InventoryDevicesParams{Context: ctx}, locaClient.AuthWriter)
	if err != nil {
		return err
	}

	invHosts, err := inventory.ListAllHostsByLOCAProvider(ctx, lrm.invClient, tenantID, locaClient.GetURL())
	if err != nil {
		return err
	}

	invHosts = lrm.synchronizeLOCADevices(ctx, locaClient, tenantID, locaProvider, invHosts, locaHosts.GetPayload().Data.Results)
	lrm.synchronizeInventoryHosts(ctx, locaClient, tenantID, invHosts, locaHosts.GetPayload().Data.Results)
	return nil
}

//nolint:cyclop // PoC logic
func (lrm *LOCARM) synchronizeLOCADevices(
	ctx context.Context,
	locaClient *loca.LocaCli,
	tenantID string,
	locaProvider *providerv1.ProviderResource,
	invHosts []*computev1.HostResource,
	locaHosts []*model.DtoDeviceListElement,
) []*computev1.HostResource {
	// handle Host discovery and Host update
	for _, host := range locaHosts {
		tmpHost, err := lrm.processDeviceEntry(host)
		if err != nil {
			continue
		}

		// look for a provided Host
		foundHost, exists, err := util.FindHostInList(tmpHost, invHosts)
		if err != nil {
			// Data inconsistency case.
			// Error is already logged in the inner function.
			// Skipping the rest of the iteration.
			continue
		}

		// Host handling logic
		if !HostDiscovery && !exists {
			// Host discovery is not allowed and Host was not found -> log an error
			zlog.InfraError("Host registration failed").Msgf("Host (%s) registration has failed: Host discovery is disabled",
				tmpHost.GetUuid())
			// skipping the rest of iteration
			continue
		}
		if HostDiscovery && !exists {
			// create a new Host
			tmpHost, err = lrm.handleCreateHost(ctx, locaClient, tenantID,
				tmpHost.GetUuid(), tmpHost.GetSerialNumber(), host.ID, host.DeviceType.Name, locaProvider)
			if err != nil {
				continue
			}
			// append new host to the Host list obtained from Inventory
			invHosts = append(invHosts, tmpHost)
		}

		if exists {
			if foundHost.GetDesiredState() == computev1.HostState_HOST_STATE_DELETED {
				zlog.Debug().Msgf("Host (%s) is going to be deleted during reconciliation",
					foundHost.GetUuid())
				// no need to update Host's status, it must be removed from the system
				// skipping the rest of the iteration
				continue
			} else if foundHost.GetDesiredState() == computev1.HostState_HOST_STATE_UNTRUSTED {
				zlog.Warn().Msgf("Host (%s) is going to be invalidated during reconciliation",
					foundHost.GetUuid())
				// no need to update Host's status, it must be removed from the system
				// skipping the rest of the iteration
				continue
			}

			// if Host was found, getting its information to perform an update
			tmpHost = foundHost
		}

		// associate Host with Site if it is not associated yet
		if tmpHost.GetSite() == nil {
			zlog.Info().Msgf("Site is not associated with Host (%s), updating it", tmpHost.GetUuid())
			err = lrm.associateSiteWithHost(ctx, locaClient, tmpHost, tenantID, host.Site)
			if err != nil {
				zlog.InfraErr(err).Msgf("Failed to associate Site with Host")
				continue
			}
		}

		if host.Status == hostStatusActive &&
			foundHost.GetCurrentState() == computev1.HostState_HOST_STATE_ONBOARDED &&
			foundHost.GetOnboardingStatus() == loca_status.DeviceStatusActive.Status &&
			foundHost.GetOnboardingStatusIndicator() == loca_status.DeviceStatusActive.StatusIndicator {
			// we do not report final state
			continue
		}
		zlog.Debug().Msgf("Host (%s) is found, updating its status", tmpHost.GetUuid())
		// Host exists (i.e., either was found or was just created), updating its status
		currentState, onboardingStatus, statusIndication, err := util.ConvertLOCADeviceStatusToFMStateAndStatus(host.Status)
		if err != nil {
			zlog.InfraErr(err).Msgf("Failed to craft state and status information for Device obtained from LOC-A. "+
				"Hostname: %s; UUID: %s; Serial Number: %s.",
				host.Hostname, host.UUID, host.SerialNumber)
		}
		// updating Host's state and Status
		lrm.updateHostStateAndStatus(ctx, tenantID, tmpHost, currentState, onboardingStatus, statusIndication)
	}
	return invHosts
}

// processes Device entry and determines whether corresponding Host should be updated (or discovered).
func (lrm *LOCARM) processDeviceEntry(host *model.DtoDeviceListElement) (*computev1.HostResource, error) {
	// convert LOC-A UUID to the Inventory UUID representation
	tmpHostUUID, err := util.ConvertUUIDToFMInventoryUUID(host.UUID)
	if err != nil {
		zlog.InfraErr(err).Msgf("Failed to convert UUID from LOC-A format to Inventory format")
		return nil, err
	}
	sn := host.SerialNumber

	if tmpHostUUID == "" || sn == "" {
		newErr := errors.Errorfc(codes.InvalidArgument, "Empty Host UUID or Serial Number obtained")
		zlog.InfraErr(newErr).Msgf("")
		return nil, newErr
	}

	// create a dummy Host for comparison
	tmpHost := util.BuildNewHost(tmpHostUUID, sn)

	return tmpHost, nil
}

func (lrm *LOCARM) synchronizeInventoryHosts(
	ctx context.Context,
	locaClient *loca.LocaCli,
	tenantID string,
	invHosts []*computev1.HostResource,
	locaHosts []*model.DtoDeviceListElement,
) {
	// iterating over the Hosts reported by Inventory and checking if the Host is present in LOC-A
	// if not, setting its current state to be Deleted - it would be further reconciled and removed from the Inventory
	for _, invHost := range invHosts {
		// reconciling Host
		locaHost, exist := util.FindDeviceInLOCAHostList(invHost, locaHosts)
		switch invHost.GetDesiredState() {
		case computev1.HostState_HOST_STATE_DELETED:
			// treating the case when desired state is Deleted and Host is gone
			// deleting the Host
			lrm.deleteInventoryHost(ctx, locaClient, tenantID, invHost, exist, locaHost)
		case computev1.HostState_HOST_STATE_UNTRUSTED:
			lrm.invalidateInventoryHost(ctx, invHost, tenantID)
		default:
			lrm.updateTickInventoryHost(ctx, exist, invHost, tenantID)
		}
	}
}

func (lrm *LOCARM) updateTickInventoryHost(ctx context.Context, exist bool, invHost *computev1.HostResource, tenantID string) {
	var err error
	if exist {
		return
	}
	// treating the case when desired state is not Deleted, but Host is gone
	if invHost.GetCurrentState() == computev1.HostState_HOST_STATE_UNSPECIFIED {
		// skipping iteration, Host was just onboarded, no need to do anything
		return
	}
	// Inventory assumes that this Host is operational, which is wrong.
	// We need to update Host status to be error.
	invHost.OnboardingStatus = loca_status.DeviceStatusDoesNotExist.Status
	invHost.OnboardingStatusIndicator = loca_status.DeviceStatusDoesNotExist.StatusIndicator
	invHost.OnboardingStatusTimestamp, err = inv_util.Int64ToUint64(time.Now().Unix())
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to parse current time")
		// this error is unlikely, but in such case, set timestamp = 0
		invHost.OnboardingStatusTimestamp = 0
	}
	//nolint:errcheck // error is logged in the inner function, no need to report it
	_ = inventory.UpdateHostOnboardingStatus(ctx, lrm.invClient, tenantID, invHost)
}

func (lrm *LOCARM) invalidateInventoryHost(ctx context.Context, invHost *computev1.HostResource, tenantID string) {
	var err error
	if invHost.GetCurrentState() == computev1.HostState_HOST_STATE_UNTRUSTED {
		// Current state of the Host is already untrusted, no need in further processing
		return
	}
	// The Current state will be updated to UNTRUSTED anyway, even if the Keycloak/Vault communication is disabled
	zlog.InfraSec().Debug().Msgf("Invalidating Host (%s)", invHost.GetResourceId())
	// invalidating Device
	err = kk_auth.RevokeHostCredentials(ctx, tenantID, invHost.GetUuid())
	if err != nil {
		// error is logged in the inner function
		// skipping the rest of the iteration
		return
	}
	// setting current state of the Host to be UNTRUSTED
	invHost.CurrentState = computev1.HostState_HOST_STATE_UNTRUSTED
	invHost.HostStatus = loca_status.HostStatusInvalidated.Status
	invHost.HostStatusIndicator = loca_status.HostStatusInvalidated.StatusIndicator
	invHost.HostStatusTimestamp, err = inv_util.Int64ToUint64(time.Now().Unix())
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to parse current time")
		// this error is unlikely, but in such case, set timestamp = 0
		invHost.HostStatusTimestamp = 0
	}
	//nolint:errcheck // error is logged in the inner function, no need to report it
	_ = inventory.UpdateHostStatus(ctx, lrm.invClient, tenantID, invHost)
}

func (lrm *LOCARM) deleteInventoryHost(
	ctx context.Context, locaClient *loca.LocaCli, tenantID string,
	invHost *computev1.HostResource, exist bool, locaHost *model.DtoDeviceListElement,
) {
	err := util.CheckIfInstanceIsAssociated(ctx, lrm.invClient, tenantID, invHost)
	if err != nil {
		return
	}

	// Verify if a removal task for the Host is already running in LOC-A
	taskRunning, errTracker := loca.DefaultTaskTracker.TaskIsRunningFor(locaClient, invHost.GetResourceId())
	if errTracker != nil {
		zlog.InfraSec().InfraErr(errTracker).Msgf("Failed to check if a task is running for Host (%s)",
			invHost.GetResourceId())
		return
	}
	if taskRunning {
		// Device remove task is created, waiting on its delete
		zlog.Info().Msgf("Remove LOC-A device (%s) task is already running, waiting on its completion",
			invHost.GetResourceId())
		return
	}

	// check if Host exists in LOC-A, it needs to be removed first
	if exist {
		// Host is found, removing it from LOC-A
		zlog.Info().Msgf("Removing Host (%s) from LOC-A (%s/%s)", invHost.GetUuid(),
			invHost.GetProvider().GetName(), invHost.GetProvider().GetApiEndpoint())
		resp, err := locaClient.LocaAPI.Inventory.PostAPIV1InventoryDevicesRemove(
			&loca_inventory.PostAPIV1InventoryDevicesRemoveParams{Context: ctx, Body: []string{locaHost.ID}},
			locaClient.AuthWriter)
		if err != nil {
			// Failed to remove Host from LOC-A
			zlog.InfraSec().InfraErr(err).Msgf("Host (%s) cannot be reconciled", invHost.GetResourceId())
			// Updating onboarding status to reflect the failure in the UI
			invHost.OnboardingStatus = util.StatusFailedToRemoveHostFromLOCA
			invHost.OnboardingStatusIndicator = statusv1.StatusIndication_STATUS_INDICATION_ERROR
			invHost.OnboardingStatusTimestamp, err = inv_util.Int64ToUint64(time.Now().Unix())
			if err != nil {
				zlog.InfraSec().InfraErr(err).Msgf("Failed to parse current time")
				// this error is unlikely, but in such case, set timestamp = 0
				invHost.OnboardingStatusTimestamp = 0
			}
			// update host status
			err = inventory.UpdateHostOnboardingStatus(ctx, lrm.invClient, tenantID, invHost)
			if err != nil {
				zlog.InfraSec().InfraErr(err).Msgf("Failed to update Host Onboarding Status")
			}
			return
		}

		// Tracking the remove device task
		errTracker = loca.DefaultTaskTracker.TrackTask(invHost.GetResourceId(), resp.Payload.Data.TaskUUID)
		if errTracker != nil {
			zlog.InfraSec().InfraErr(errTracker).Msgf("Failed to track task (%s) for Host (%s)",
				resp.Payload.Data.TaskUUID, invHost.GetResourceId())
			return
		}

		// Device remove task is created, skipping the rest of iteration
		zlog.Debug().Msgf("Remove Device task (%s) is created, waiting on its completion",
			resp.Payload.Data.TaskUUID)
		return
	}
	//nolint:errcheck // error is logged in the inner function, no need to report it
	_ = inventory.RemoveHost(ctx, lrm.invClient, tenantID, invHost)
}

//nolint:lll // PoC logic, decompose this function for future
func (lrm *LOCARM) handleCreateHost(
	ctx context.Context,
	locaClient *loca.LocaCli,
	tenantID, tmpHostUUID, sn, locaHostID, serverModel string,
	provider *providerv1.ProviderResource,
) (*computev1.HostResource, error) {
	newHost := util.BuildNewHost(tmpHostUUID, sn)
	newHost.Provider = provider
	newHost.ProductName = serverModel

	// In discovery mode, a newly created host immediately starts with the Onboarded Current State.
	// Therefore, new credentials must be generated after the host is created in Inventory, as we don't have a Desired State.
	clientID, clientSecret, err := util.CreateENCredentials(ctx, tenantID, newHost.GetUuid())
	if err != nil {
		zlog.InfraErr(err).Msgf("Failed to create EN credentials")
		return nil, err
	}

	enCredentials := map[string]interface{}{
		"edgeNodeCredentials": map[string]interface{}{
			"oid":          locaHostID,
			"clientID":     clientID,
			"clientSecret": clientSecret,
		},
	}
	// Store created EN credentials in LOC-A
	//nolint:errcheck // error is checked, we don't care about response
	_, err = locaClient.LocaAPI.Inventory.PostAPIV1InventoryDevicesIDUpdate(&loca_inventory.PostAPIV1InventoryDevicesIDUpdateParams{Context: ctx, ID: locaHostID, Body: &model.DtoDeviceUpdateParams{
		Settings: enCredentials,
	}}, locaClient.AuthWriter)
	if err != nil {
		zlog.InfraErr(err).Msgf("Failed to store EN credentials")
		return nil, err
	}

	resourceID, err := inventory.CreateHostResource(ctx, lrm.invClient, tenantID, tmpHostUUID, newHost)
	if err != nil {
		zlog.InfraErr(err).Msgf("Failed to create new Host")
		return nil, err
	}

	enCredentials = map[string]interface{}{
		"edgeNodeCredentials": map[string]interface{}{
			"oid":          locaHostID,
			"clientID":     clientID,
			"clientSecret": clientSecret,
			"hostname":     resourceID,
		},
	}

	//nolint:errcheck // error is checked, we don't care about response
	_, err = locaClient.LocaAPI.Inventory.PostAPIV1InventoryDevicesIDUpdate(&loca_inventory.PostAPIV1InventoryDevicesIDUpdateParams{Context: ctx, ID: locaHostID, Body: &model.DtoDeviceUpdateParams{
		Settings: enCredentials,
	}}, locaClient.AuthWriter)
	if err != nil {
		zlog.InfraErr(err).Msgf("Failed to store EN credentials with hostname")
		return nil, err
	}

	newHost.ResourceId = resourceID
	zlog.Debug().Msgf("New Host (%s) is discovered, resource ID is %s", tmpHostUUID, resourceID)
	return newHost, nil
}

func (lrm *LOCARM) updateHostStateAndStatus(
	ctx context.Context,
	tenantID string,
	host *computev1.HostResource,
	currentState *computev1.HostState,
	onboardingStatus string,
	statusIndication statusv1.StatusIndication,
) {
	var err error
	zlog.Debug().Msgf("Updating Host state and status: tenantID=%s, uuid=%s", tenantID, host.GetUuid())

	// currentState == nil meaning there is no need to change state
	if currentState != nil {
		host.CurrentState = *currentState
	}
	host.OnboardingStatus = onboardingStatus
	host.OnboardingStatusIndicator = statusIndication
	host.OnboardingStatusTimestamp, err = inv_util.Int64ToUint64(time.Now().Unix())
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to parse current time")
		// this error is unlikely, but in such case, set timestamp = 0
		host.OnboardingStatusTimestamp = 0
	}
	// update host status
	err = inventory.UpdateHostOnboardingStatus(ctx, lrm.invClient, tenantID, host)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to update Host Status")
		return
	}
}

func (lrm *LOCARM) associateSiteWithHost(
	ctx context.Context,
	locaClient *loca.LocaCli,
	host *computev1.HostResource,
	tenantID, siteName string,
) error {
	resp, err := locaClient.LocaAPI.Inventory.GetAPIV1InventorySites(
		&loca_inventory.GetAPIV1InventorySitesParams{Context: ctx, Name: &siteName}, locaClient.AuthWriter)
	if err != nil {
		zlog.InfraErr(err).Msgf("Failed to get Site (%s) by name", siteName)
		return err
	}

	if len(resp.Payload.Data.Results) != 1 {
		err = errors.Errorfc(codes.InvalidArgument,
			"Obtained non-singular Site resource")
		zlog.InfraErr(err).Msg("")
		return err
	}

	// retrieve Site ID and create a Site Resource
	siteID := resp.Payload.Data.Results[0].SiteCode
	siteRes := &inv_v1.Resource{
		Resource: &inv_v1.Resource_Site{
			Site: &locationv1.SiteResource{
				ResourceId: siteID,
			},
		},
	}

	// associate Host with the Site
	host.Site = siteRes.GetSite()
	err = inventory.UpdateHostSite(ctx, lrm.invClient, tenantID, host)
	if err != nil {
		zlog.InfraErr(err).Msgf("Failed to update Host Site")
		return err
	}
	return nil
}

func (lrm *LOCARM) UpdateInstances(
	ctx context.Context, locaClient *loca.LocaCli, tenantID string, provider *providerv1.ProviderResource,
) error {
	// retrieve a list of instances from the LOC-A
	locaInstances, err := locaClient.LocaAPI.Deployment.GetAPIV1DeploymentInstances(
		&deployment.GetAPIV1DeploymentInstancesParams{Context: ctx}, locaClient.AuthWriter)
	if err != nil {
		return err
	}

	// list all Instances from Inventory attached to the LOC-A provider
	invInstances, err := inventory.ListAllInstancesByLOCAProvider(ctx, lrm.invClient, tenantID, locaClient.GetURL())
	if err != nil {
		return err
	}

	locaInstancesFullList, invInstances := lrm.synchronizeLOCAInstances(
		ctx,
		tenantID,
		provider,
		locaInstances.GetPayload().Data.Results,
		locaClient,
		invInstances,
	)
	lrm.synchronizeInventoryInstances(ctx, locaClient, tenantID, locaInstancesFullList, invInstances)
	return nil
}

//nolint:cyclop // this is synchronization logic
func (lrm *LOCARM) synchronizeLOCAInstances(
	ctx context.Context,
	tenantID string,
	provider *providerv1.ProviderResource,
	locaInstances []*model.DtoInstanceInList,
	locaClient *loca.LocaCli,
	invInstances []*computev1.InstanceResource,
) ([]*model.DtoInstance, []*computev1.InstanceResource) {
	locaInstancesFullList := make([]*model.DtoInstance, 0)
	for _, locaInstance := range locaInstances {
		locaInstanceID := locaInstance.ID

		// retrieve full information about instance from LOC-A
		locaInstanceFull, err := locaClient.LocaAPI.Deployment.GetAPIV1DeploymentInstancesID(
			&deployment.GetAPIV1DeploymentInstancesIDParams{Context: ctx, ID: locaInstanceID},
			locaClient.AuthWriter)
		if err != nil {
			zlog.InfraSec().InfraErr(err).Msgf("Failed to retrieve instance (%s) from LOC-A %s/%s",
				locaInstanceID, provider.GetName(), provider.GetApiEndpoint())
			// obtained an error, skipping the rest of iteration
			// error is logged in the inner function
			continue
		}
		locaInstancesFullList = append(locaInstancesFullList, locaInstanceFull.Payload.Data)
		tmpInstance, err := util.BuildNewInstance(locaInstanceFull.Payload.Data)
		if err != nil {
			// no need to report error, it is logged in the inner function
			continue
		}

		// find instance in Inventory list
		foundInstance, exists := util.FindInstanceInList(tmpInstance, invInstances)
		if !exists {
			var instance *computev1.InstanceResource
			zlog.Debug().Msgf("Instance was NOT found, creating one")
			instance, err = lrm.handleInstanceCreate(ctx, tenantID, tmpInstance, locaInstanceFull.Payload.Data)
			if err != nil {
				// obtained an error, skipping the rest of the iteration
				// error is logged in the inner function
				continue
			}

			// add it to the invInstancesList
			invInstances = append(invInstances, instance)

			// fake a found instance to be a newly created Instance for a consequent State and Status update
			foundInstance = instance
			// we are ready at that point to update the Instance State and Status straight away
		}
		if locaInstanceFull.Payload.Data.Stage == instanceStageInstalled &&
			locaInstanceFull.Payload.Data.Status == instanceStatusFinishedSuccessfully &&
			foundInstance.GetCurrentState() == computev1.InstanceState_INSTANCE_STATE_RUNNING &&
			foundInstance.GetProvisioningStatus() == loca_status.InstanceStatusInstalled.Status &&
			foundInstance.GetProvisioningStatusIndicator() == loca_status.InstanceStatusInstalled.StatusIndicator {
			// we do not overwrite final state
			continue
		} else if foundInstance.GetCurrentState() == computev1.InstanceState_INSTANCE_STATE_RUNNING {
			// updating only Provisioning status. Do NOT update the current state
			// craft a new status of instance
			_, provisioningStatus, statusIndicator, err := util.ConvertLOCAInstanceStateAndStatusToFMStateAndStatus(
				locaInstance.Operation,
				locaInstance.Stage,
				locaInstance.Status,
			)
			if err != nil {
				zlog.InfraErr(err).Msgf("Failed to craft state and status for Instance obtained from LOC-A. "+
					"Instance: %s; Name: %s;", locaInstance.Name, locaInstance.ID)
				continue
			}
			foundInstance.ProvisioningStatus = provisioningStatus
			foundInstance.ProvisioningStatusIndicator = statusIndicator
			foundInstance.ProvisioningStatusTimestamp, err = inv_util.Int64ToUint64(time.Now().Unix())
			if err != nil {
				zlog.InfraSec().InfraErr(err).Msgf("Failed to parse current time")
				// this error is unlikely, but in such case, set timestamp = 0
				foundInstance.ProvisioningStatusTimestamp = 0
			}
			// update host status
			err = inventory.UpdateInstanceProvisioningStatus(ctx, lrm.invClient, tenantID, foundInstance)
			if err != nil {
				zlog.InfraSec().InfraErr(err).Msgf("Failed to update Instance State and Status")
				continue
			}
		}
		if foundInstance.GetDesiredState() == computev1.InstanceState_INSTANCE_STATE_DELETED {
			zlog.Debug().Msgf("Instance (%s; %s) is going to be deleted during reconciliation",
				foundInstance.GetResourceId(), foundInstance.GetName())
			// skipping the rest of iteration
			continue
		}
		if foundInstance.GetDesiredState() == computev1.InstanceState_INSTANCE_STATE_UNTRUSTED {
			zlog.Warn().Msgf("Instance (%s; %s) is going to be invalidated during reconciliation",
				foundInstance.GetResourceId(), foundInstance.GetName())
			// skipping the rest of iteration
			continue
		}

		// resource is found, updating its status
		lrm.handleUpdateInstanceStateAndStatus(ctx, tenantID, foundInstance, locaInstanceFull.Payload.Data)
	}
	return locaInstancesFullList, invInstances
}

//nolint:cyclop,funlen // cyclomatic complexity is high due to business logic
func (lrm *LOCARM) synchronizeInventoryInstances(
	ctx context.Context,
	locaClient *loca.LocaCli,
	tenantID string,
	locaInstances []*model.DtoInstance,
	invInstances []*computev1.InstanceResource,
) {
	// iterating over the Instances reported by Inventory and checking if the Instance is present in LOC-A
	// if not, setting its current state to be Deleted - it would be further reconciled and removed from the Inventory
	for _, invInstance := range invInstances {
		locaInstance, exist := util.FindLOCAInstanceInLOCAInstanceList(invInstance, locaInstances)
		// Instance is not reported by LOC-A, reconciling it
		// treating the case when desired state is Deleted and Host is gone
		// deleting the Host
		//nolint:gocritic // leaving if-else statement in favor of switch statement
		if invInstance.GetDesiredState() == computev1.InstanceState_INSTANCE_STATE_DELETED {
			// Verify if a removal task for the Instance is already in progress in LOC-A
			taskRunning, errTracker := loca.DefaultTaskTracker.TaskIsRunningFor(locaClient, invInstance.GetResourceId())
			if errTracker != nil {
				zlog.InfraSec().InfraErr(errTracker).Msgf("Failed to check if a task is running for Instance (%s)",
					invInstance.GetResourceId())
				continue
			}
			if taskRunning {
				// Instance remove task is created, waiting on its delete
				zlog.Info().Msgf("Remove Instance (%s) task is already running, waiting on its completion",
					invInstance.GetResourceId())
				continue
			}

			// Check if instance still exists
			if exist {
				zlog.Info().Msgf("Attempting to remove Instance (%s) from LOC-A", invInstance.GetResourceId())
				// Attempting to remove Instance
				resp, err := locaClient.LocaAPI.Deployment.PostAPIV1DeploymentInstancesRemove(
					&deployment.PostAPIV1DeploymentInstancesRemoveParams{
						Context: ctx, Body: &model.ModelsRemoveInstancesRequest{Ids: []string{locaInstance.ID}},
					}, locaClient.AuthWriter)
				if err != nil {
					// Failed to remove Instance
					zlog.InfraErr(err).Msgf("Failed to remove Instance (%s) from LOC-A (%s/%s)",
						invInstance.GetResourceId(), invInstance.GetHost().GetProvider().GetName(),
						invInstance.GetHost().GetProvider().GetApiEndpoint())
					// Updating Provisioning status to reflect changes in the UI
					invInstance.ProvisioningStatus = util.StatusFailedToRemoveInstance
					invInstance.ProvisioningStatusIndicator = statusv1.StatusIndication_STATUS_INDICATION_ERROR
					invInstance.ProvisioningStatusTimestamp, err = inv_util.Int64ToUint64(time.Now().Unix())
					if err != nil {
						zlog.InfraSec().InfraErr(err).Msgf("Failed to parse current time")
						// this error is unlikely, but in such case, set timestamp = 0
						invInstance.ProvisioningStatusTimestamp = 0
					}
					// Update Instance status
					err = inventory.UpdateInstanceProvisioningStatus(ctx, lrm.invClient, tenantID, invInstance)
					if err != nil {
						zlog.InfraSec().InfraErr(err).Msgf("Failed to update Instance Provisioning Status")
					}
					continue
				}

				// Tracking the remove instance task
				errTracker = loca.DefaultTaskTracker.TrackTask(invInstance.GetResourceId(), resp.Payload.Data.TaskUUID)
				if errTracker != nil {
					zlog.InfraSec().InfraErr(errTracker).Msgf("Failed to track task (%s) for Instance (%s)",
						resp.Payload.Data.TaskUUID, invInstance.GetResourceId())
					continue
				}

				// Instance remove task is created, waiting on its delete.
				// Logic is the following:
				// - skipping the rest of the iteration to check in the next cycle if Instance is still present in LOC-A;
				// - if not, proceeding and setting current state to be DELETED;
				// - if yes, attempting to delete it again and checking next cycle, if it's present in LOC-A.
				zlog.Debug().Msgf("Delete Instance task (%s) is created in LOC-A", resp.Payload.Data.TaskUUID)
				continue
			}
			// we don't need to delete the Instance object itself.
			// Inventory will remove it when current_state = DELETED.
			//nolint:errcheck // no need to report error, it is logged in the inner function
			_ = inventory.UpdateInstanceCurrentState(
				ctx,
				lrm.invClient,
				tenantID,
				invInstance,
				computev1.InstanceState_INSTANCE_STATE_DELETED,
			)
		} else if invInstance.GetDesiredState() == computev1.InstanceState_INSTANCE_STATE_UNTRUSTED {
			var err error
			if invInstance.GetCurrentState() == computev1.InstanceState_INSTANCE_STATE_UNTRUSTED {
				// Current state of the Instance is already UNTRUSTED, no need in further processing
				continue
			}
			zlog.InfraSec().Debug().Msgf("Invalidating Instance (%s)", invInstance.GetResourceId())
			invInstance.CurrentState = computev1.InstanceState_INSTANCE_STATE_UNTRUSTED
			invInstance.InstanceStatus = loca_status.InstanceStatusInvalidated.Status
			invInstance.InstanceStatusIndicator = loca_status.InstanceStatusInvalidated.StatusIndicator
			invInstance.InstanceStatusTimestamp, err = inv_util.Int64ToUint64(time.Now().Unix())
			if err != nil {
				zlog.InfraSec().InfraErr(err).Msgf("Failed to parse current time")
				// this error is unlikely, but in such case, set timestamp = 0
				invInstance.InstanceStatusTimestamp = 0
			}
			err = inventory.UpdateInstanceStatus(ctx, lrm.invClient, tenantID, invInstance)
			if err != nil {
				zlog.InfraSec().InfraErr(err).Msgf("Failed to update Instance State and Status")
			}
			invInstance.GetHost().GetResourceId()
		} else if invInstance.GetDesiredState() == computev1.InstanceState_INSTANCE_STATE_RUNNING &&
			invInstance.GetCurrentState() == computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED && !exist {
			// handle nTouch provisioning for instances with a RUNNING desired state in Inventory but not found in LOC-A
			zlog.InfraSec().Info().Msgf("Starting instance (%s) execution", invInstance.GetResourceId())

			// get OS Resource ID and Server Model from Instance
			osResID := invInstance.GetDesiredOs().GetResourceId()
			serverModel := invInstance.GetHost().GetProductName()

			// get template name based on the OS Resource ID and Server Model
			templateName := util.GetTemplateName(osResID, serverModel)

			// get host serial number, host UUID and site ID
			hostSN := invInstance.GetHost().GetSerialNumber()
			hostUUID := invInstance.GetHost().GetUuid()
			siteID := invInstance.GetHost().GetSite().GetResourceId()

			// provision Instance in LOC-A
			locaInstanceID, err := locaClient.ProvisionInstance(ctx, templateName, hostSN, hostUUID, siteID)
			if err != nil {
				zlog.InfraSec().InfraErr(err).Msgf("Failed to provision Instance (%s) in LOC-A", invInstance.GetResourceId())
				continue
			}

			// update instance name in the inventory
			//nolint:errcheck // no need to report error, it is logged in the inner function
			_ = inventory.UpdateInstanceName(ctx, lrm.invClient, tenantID, invInstance, locaInstanceID)

			zlog.InfraSec().Info().Msgf("Created Instance (%s) in LOC-A", locaInstanceID)
		} else {
			var err error
			if exist {
				// we do not care
				continue
			}
			// treating the case when desired state is not Deleted, but Instance is gone
			if invInstance.GetCurrentState() == computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED {
				// skipping iteration, Instance was just onboarded, no need to do anything
				continue
			}
			// Inventory assumes that this Instance is operational, which is wrong.
			// We need to update Instance status to be error.
			invInstance.ProvisioningStatus = loca_status.InstanceStatusDoesNotExist.Status
			invInstance.ProvisioningStatusIndicator = loca_status.InstanceStatusDoesNotExist.StatusIndicator
			invInstance.ProvisioningStatusTimestamp, err = inv_util.Int64ToUint64(time.Now().Unix())
			if err != nil {
				zlog.InfraSec().InfraErr(err).Msgf("Failed to parse current time")
				// this error is unlikely, but in such case, set timestamp = 0
				invInstance.ProvisioningStatusTimestamp = 0
			}
			//nolint:errcheck // no need to report error, it is logged in the inner function
			_ = inventory.UpdateInstanceProvisioningStatus(ctx, lrm.invClient, tenantID, invInstance)
		}
	}
}

func (lrm *LOCARM) handleInstanceCreate(
	ctx context.Context,
	tenantID string,
	tmpInstance *computev1.InstanceResource,
	locaInstance *model.DtoInstance,
) (*computev1.InstanceResource, error) {
	// obtain a Host on which Instance should be deployed
	// checking on how many Hosts Instance is being deployed - it should be precisely one
	if len(locaInstance.Nodes) != 1 {
		zlog.InfraError("Obtained unexpected number of Hosts to create an Instance: %d",
			len(locaInstance.Nodes)).Msgf("Failed to create an Instance - incorrect Host information")
	}
	// get the Host Serial Number
	hostSN := locaInstance.Nodes[0].SerialNumber
	host, err := inventory.GetHostResourceBySerialNumber(ctx, lrm.invClient, tenantID, hostSN)
	if err != nil {
		// error is logged in the inner function
		return nil, err
	}

	// get OS resource ID from template
	resourceID, err := util.ExtractOSResourceIDFromTemplate(locaInstance.Template)
	if err != nil {
		return nil, err
	}
	// retrieve OS Resource from Inventory
	osRes, err := inventory.GetOSResourceByResourceID(ctx, lrm.invClient, tenantID, resourceID)
	if err != nil {
		// error is logged in the inner function
		return nil, err
	}

	// create new Instance Resource
	instance, err := inventory.CreateInstanceResource(ctx, lrm.invClient, tenantID, tmpInstance, osRes, host)
	if err != nil {
		// error is logged in the inner function
		return nil, err
	}

	// set a Resource ID on the dummy instance (needed for consequent status update)
	tmpInstance.ResourceId = instance.GetResourceId()
	return tmpInstance, nil
}

func (lrm *LOCARM) handleUpdateInstanceStateAndStatus(
	ctx context.Context,
	tenantID string,
	foundInstance *computev1.InstanceResource,
	locaInstance *model.DtoInstance,
) {
	// craft a new status of instance
	state, provisioningStatus, statusIndicator, err := util.ConvertLOCAInstanceStateAndStatusToFMStateAndStatus(
		locaInstance.Operation,
		locaInstance.Stage,
		locaInstance.Status,
	)
	if err != nil {
		zlog.InfraErr(err).Msgf("Failed to craft state and status for Instance obtained from LOC-A. "+
			"Instance: %s; Name: %s;", locaInstance.Name, locaInstance.ID)
		return
	}
	lrm.updateInstanceStateAndStatus(ctx, tenantID, foundInstance, state, provisioningStatus, statusIndicator)
}

func (lrm *LOCARM) updateInstanceStateAndStatus(
	ctx context.Context,
	tenantID string,
	instance *computev1.InstanceResource,
	state *computev1.InstanceState,
	provisioningStatus string,
	statusIndicator statusv1.StatusIndication,
) {
	var err error
	zlog.Debug().Msgf("Updating Instance (%s) state and status", instance.GetResourceId())
	// state == nil meaning there is no need to change state
	if state != nil {
		instance.CurrentState = *state
	}
	instance.ProvisioningStatus = provisioningStatus
	instance.ProvisioningStatusIndicator = statusIndicator
	instance.ProvisioningStatusTimestamp, err = inv_util.Int64ToUint64(time.Now().Unix())
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to parse current time")
		// this error is unlikely, but in such case, set timestamp = 0
		instance.ProvisioningStatusTimestamp = 0
	}
	// update host status
	err = inventory.UpdateInstanceProvisioningStatus(ctx, lrm.invClient, tenantID, instance)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to update Instance State and Status")
		return
	}
}
