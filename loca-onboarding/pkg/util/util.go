// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"

	computev1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/compute/v1"
	locationv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/location/v1"
	osv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/os/v1"
	statusv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/status/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/auth"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	inv_util "github.com/open-edge-platform/infra-core/inventory/v2/pkg/util"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/model"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/inventory"
)

var zlog = logging.GetLogger("util")

const (
	httpsProtocol                          = "HTTPS"
	httpsPort                              = 443
	defaultTinkCAPath                      = "/etc/ssl/boots-ca-cert"
	defaultTinkCAName                      = "boots-ca-cert"
	TinkCAPath                             = "TINK_CA_PATH"
	TinkCAName                             = "TINK_CA_NAME"
	cloudServiceRole                       = "Edge Orchestrator"
	cloudServicePlatformType               = "Edge Manageability Framework"
	ClusterDomain                          = "CLUSTER_DOMAIN"
	certExtension                          = ".crt"
	TinkerbellCAKey                        = "TinkerbellCA"
	extraVarsOSResourceIDKey               = "os_resource_id"
	StatusInstanceOnboarded                = "Instance is onboarded"
	StatusInstanceProvisioned              = "Instance is provisioned"
	StatusWaitingOnHostRemoval             = "Waiting on Host removal"
	StatusFailedToRemoveHostFromLOCA       = "Failed to remove Host from LOC-A"
	StatusWaitingOnInstanceRemoval         = "Waiting on Instance removal"
	StatusFailedToRemoveInstance           = "Failed to Remove Instance"
	operationDeploy                        = "Deploy"
	operationExpand                        = "Expand"
	statusOnboarded                        = "Onboarded"
	statusFinishedSuccessfully             = "Finished successfully"
	StatusFailed                           = "Failed"
	statusInProgress                       = "In progress"
	stageOnboarded                         = "onboarded"
	stageDeviceProfileApplying             = "device profile applying"
	stageOsInstalling                      = "os installing"
	StageInstancePreconfiguring            = "instance pre-configuring"
	stageInstanceInstalling                = "instance installing"
	StageInstancePostconfiguring           = "instance post-configuring"
	stageConfiguring                       = "configuring"
	stageInstanceConfiguring               = "instance configuring"
	stageInstalled                         = "installed"
	statusActive                           = "active"
	DeviceStatusActiveDescription          = "Host is active"
	deviceStatusStaged                     = "staged"
	DeviceStatusStagedDescription          = "Host is being provisioned"
	deviceStatusInventory                  = "inventory"
	DeviceStatusInventoryDescription       = "Host is ready to be provisioned"
	StageOnboardedDescription              = "Automation tasks have saved allocated data to the LOC-A DB"
	StageDeviceProfileApplyingDescription  = "Automation task is applying device profile with XCC/UEFI settings"
	StageConfiguringDescription            = "Automation task is configuring UEFI and upgrading firmware"
	StageOsInstallingDescription           = "Operation task is deploying an operating system"
	StageInstanceInstallingDescription     = "Automation task is deploying cloud instance"
	StageInstancePostconfiguredDescription = "Automation task is executing the post script after instance installed"
	StageInstanceConfiguringDescription    = "Automation task is performing instance configuration after deployment"
	StageInstalledDescription              = "All installation tasks have been completed"
	e7Multiplier                           = 10000000
	lenGPS                                 = 2
)

func ConvertUUIDToFMInventoryUUID(incorrectUUID string) (string, error) {
	correctUUID, err := uuid.Parse(incorrectUUID)
	if err != nil {
		newErr := errors.Errorfc(codes.Internal, "Failed to parse UUID from LOC-A: %v", err)
		zlog.InfraErr(newErr).Msgf("")
		return "", newErr
	}
	return correctUUID.String(), nil
}

func ConvertUUIDToLOCAUUID(uuidStr string) string {
	return strings.ToUpper(strings.ReplaceAll(uuidStr, "-", ""))
}

func ParseJSONBytesIntoStruct[T any](jsonBytes []byte, structure *T) (*T, error) {
	if len(jsonBytes) == 0 {
		zlog.Debug().Msgf("Empty JSON body is received, returning an empty structure")
		return structure, nil
	}

	err := json.Unmarshal(jsonBytes, &structure)
	if err != nil {
		zlog.InfraErr(err).Msgf("Failed to unmarshal JSON bytes into structure %T", structure)
		return structure, err
	}

	return structure, nil
}

func craftStatusDetail(operation, stage, status string) string {
	if status == statusOnboarded && stage == stageOnboarded {
		return StatusInstanceOnboarded
	}
	if status == statusFinishedSuccessfully && stage == stageInstalled {
		return StatusInstanceProvisioned
	}
	return fmt.Sprintf("%s operation at stage %s is %s", operation, stage, status)
}

//nolint:cyclop,funlen // cyclomatic complexity & function length are due to matrix nature of the operation-stage-status relation
func ConvertLOCAInstanceStateAndStatusToFMStateAndStatus(operation, stage, status string) (
	*computev1.InstanceState,
	string,
	statusv1.StatusIndication,
	error,
) {
	if operation == operationDeploy { // This operation creates an instance deployment workflow
		// treating stage and status per `state_and_status_mapping.md` document
		if status == statusOnboarded {
			if stage == stageOnboarded {
				state := computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED
				return &state, craftStatusDetail(operation, stage, status),
					statusv1.StatusIndication_STATUS_INDICATION_IDLE, nil
			}
			// unhandled error state, log error
			statusDetails, statusIndicator, err := handleInstanceStatusAndLogError(operation, stage, status)
			return nil, statusDetails, statusIndicator, err
		}

		if status == statusInProgress {
			if stage == stageOnboarded {
				state := computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED
				return &state, StageOnboardedDescription,
					statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS, nil
			}
			if stage == stageConfiguring {
				state := computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED
				return &state, StageConfiguringDescription,
					statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS, nil
			}
			if stage == stageDeviceProfileApplying {
				state := computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED
				return &state, StageDeviceProfileApplyingDescription,
					statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS, nil
			}
			if stage == stageOsInstalling {
				state := computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED
				return &state, StageOsInstallingDescription,
					statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS, nil
			}
			if stage == stageInstanceInstalling {
				state := computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED
				return &state, StageInstanceInstallingDescription,
					statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS, nil
			}
			if stage == StageInstancePostconfiguring {
				state := computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED
				return &state, StageInstancePostconfiguredDescription,
					statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS, nil
			}
			if stage == stageInstanceConfiguring {
				state := computev1.InstanceState_INSTANCE_STATE_UNSPECIFIED
				return &state, StageInstanceConfiguringDescription,
					statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS, nil
			}
			// unhandled error state, log error
			statusDetails, statusIndicator, err := handleInstanceStatusAndLogError(operation, stage, status)
			return nil, statusDetails, statusIndicator, err
		}

		if status == statusFinishedSuccessfully {
			if stage == stageInstalled {
				state := computev1.InstanceState_INSTANCE_STATE_RUNNING
				return &state, craftStatusDetail(operation, stage, status),
					statusv1.StatusIndication_STATUS_INDICATION_IDLE, nil
			}
			// unhandled error state, log error
			statusDetails, statusIndicator, err := handleInstanceStatusAndLogError(operation, stage, status)
			return nil, statusDetails, statusIndicator, err
		}

		if status == StatusFailed {
			// All the handled states are valid, no need to return an error
			details := craftStatusDetail(operation, stage, status)
			if stage == stageOnboarded {
				zlog.InfraSec().InfraError("Instance onboarding has failed: %s", details).Msgf("")
				return nil, StageOnboardedDescription,
					statusv1.StatusIndication_STATUS_INDICATION_ERROR, nil
			}
			if stage == stageConfiguring {
				zlog.InfraSec().InfraError("UEFI/XCC update has failed: %s", details).Msgf("")
				return nil, StageConfiguringDescription,
					statusv1.StatusIndication_STATUS_INDICATION_ERROR, nil
			}
			if stage == stageDeviceProfileApplying {
				zlog.InfraSec().InfraError("UEFI/XCC profile applying has failed: %s", details).Msgf("")
				return nil, StageDeviceProfileApplyingDescription,
					statusv1.StatusIndication_STATUS_INDICATION_ERROR, nil
			}
			zlog.InfraSec().InfraError("Instance provisioning has failed: %s", details).Msgf("")
			if stage == stageOsInstalling {
				// this is a valid state, no need to return an error - it is logged
				return nil, StageOsInstallingDescription,
					statusv1.StatusIndication_STATUS_INDICATION_ERROR, nil
			}
			if stage == stageInstanceInstalling {
				// this is a valid state, no need to return an error - it is logged
				return nil, StageInstanceInstallingDescription,
					statusv1.StatusIndication_STATUS_INDICATION_ERROR, nil
			}
			if stage == StageInstancePostconfiguring {
				// this is a valid state, no need to return an error - it is logged
				return nil, StageInstancePostconfiguredDescription,
					statusv1.StatusIndication_STATUS_INDICATION_ERROR, nil
			}
			if stage == stageInstanceConfiguring {
				// this is a valid state, no need to return an error - it is logged
				return nil, StageInstanceConfiguringDescription,
					statusv1.StatusIndication_STATUS_INDICATION_ERROR, nil
			}
			// unhandled invalid state, log an error
			statusDetails, statusIndicator, err := handleInstanceStatusAndLogError(operation, stage, status)
			return nil, statusDetails, statusIndicator, err
		}
		// unhandled error state, log error
		statusDetails, statusIndicator, err := handleInstanceStatusAndLogError(operation, stage, status)
		return nil, statusDetails, statusIndicator, err
	}
	if operation == operationExpand {
		// This operation create a cluster extension workflow ( N/A for baremetal and Intel flavor types)
		// not a case for us => does not support gathering multiple instances into a single cluster
		err := errors.Errorfc(codes.Internal, "Creating a cluster extension workflow is not supported")
		zlog.InfraSec().InfraErr(err).Msgf("%s", craftStatusDetail(operation, stage, status))
		return nil, "Operation " + operationExpand + " is not supported",
			statusv1.StatusIndication_STATUS_INDICATION_ERROR, err
	}

	// unhandled error state, log error
	statusDetails, statusIndicator, err := handleInstanceStatusAndLogError(operation, stage, status)
	return nil, statusDetails, statusIndicator, err
}

// Log error with InfraSec() and InfraErr() and return errored Instance state, status, and details.
func handleInstanceStatusAndLogError(operation, stage, status string) (
	string,
	statusv1.StatusIndication,
	error,
) {
	details := craftStatusDetail(operation, stage, status)
	err := errors.Errorfc(codes.Internal, "Unexpected state has occurred: %s", details)
	zlog.InfraSec().InfraErr(err).Msgf("%s", details)
	return craftStatusDetail(operation, stage, status),
		statusv1.StatusIndication_STATUS_INDICATION_ERROR, err
}

func ConvertLOCADeviceStatusToFMStateAndStatus(status string) (
	*computev1.HostState,
	string,
	statusv1.StatusIndication,
	error,
) {
	switch status {
	case deviceStatusInventory:
		// The device is initialized and can be deployed,
		// i.e., The device is planned for an instance deployment,
		// but has not yet completed deployment
		state := computev1.HostState_HOST_STATE_ONBOARDED
		return &state, DeviceStatusInventoryDescription,
			statusv1.StatusIndication_STATUS_INDICATION_IDLE, nil
	case deviceStatusStaged:
		state := computev1.HostState_HOST_STATE_ONBOARDED
		return &state, DeviceStatusStagedDescription,
			statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS, nil
	case statusActive:
		// The device has become a node in the cluster
		state := computev1.HostState_HOST_STATE_ONBOARDED
		return &state, DeviceStatusActiveDescription,
			statusv1.StatusIndication_STATUS_INDICATION_IDLE, nil
	default:
		err := errors.Errorfc(codes.InvalidArgument, "Obtained unexpected Device status: %s", status)
		zlog.InfraSec().InfraErr(err).Msgf("")
		hostStatus := "Host is " + status
		if status == "" {
			hostStatus = "Host status is unknown"
		}
		return nil, hostStatus, statusv1.StatusIndication_STATUS_INDICATION_ERROR, err
	}
}

// Logic is the following: find Host by UUID and find Host by SN separately. Compare if Host
// found by UUID have the same Serial Number, and Host found by Serial Number has the same UUID.
// After that, return matched the Host.
func FindHostInList(hostToFind *computev1.HostResource, listOfHosts []*computev1.HostResource) (
	*computev1.HostResource, bool, error,
) {
	// searching for Host by UUID
	hostByUUID, hostByUUIDexist := FindHostInListByUUID(hostToFind.GetUuid(), listOfHosts)

	// searching for Host by Serial Number
	hostBySN, hostBySNexist := FindHostInListBySerialNumber(hostToFind.GetSerialNumber(), listOfHosts)

	// possible cases:
	// 1. Did not find any Host => return (nil, false, nil).
	// 2. Found Host by UUID, but not found Host by SN => Inconsistent Host SN, return (nil, false, error).
	// 3. Found Host by SN, but not found Host by UUID => Inconsistent Host UUID, return (nil, false, error).
	// 4. Found both Hosts => Perform consistency check:
	// - Resource ID should be the same, return (Host, true, nil);
	// - otherwise Host data are inconsistent, return (nil, false, error).

	// no Hosts found
	if !hostByUUIDexist && !hostBySNexist {
		zlog.Debug().Msgf("Host is not found")
		return nil, false, nil
	}

	// found only Host by UUID, but not by SN.
	// It automatically means that Host found by UUID has different SN than the provided one => data inconsistency.
	if hostByUUIDexist && !hostBySNexist {
		err := errors.Errorfc(codes.InvalidArgument, "Inconsistent Host Serial Number (%s)", hostToFind.GetSerialNumber())
		zlog.InfraSec().InfraErr(err).Msgf("Host Serial Number from Inventory does NOT match reported Serial Number (%s)",
			hostToFind.GetSerialNumber())
		return nil, false, err
	}

	// found only host by SN, but not by UUID.
	// It automatically means that Host found by SN has different UUID than the provided one => data inconsistency.
	if hostBySNexist && !hostByUUIDexist {
		err := errors.Errorfc(codes.InvalidArgument, "Inconsistent Host UUID (%s)", hostToFind.GetUuid())
		zlog.InfraSec().InfraErr(err).Msgf("Host UUID from Inventory does NOT match reported UUID (%s)",
			hostToFind.GetUuid())
		return nil, false, err
	}

	// found both Hosts, performing consistency check
	if hostByUUID.GetResourceId() != hostBySN.GetResourceId() {
		err := errors.Errorfc(codes.Internal, "Host data are inconsistent")
		zlog.InfraSec().InfraErr(err).Msgf("Failed to find Host by Serial Number (%s) and UUID (%s), "+
			"found two different Hosts. Host data are inconsistent!",
			hostToFind.GetSerialNumber(), hostToFind.GetUuid())
		return nil, false, err
	}

	// all checks have passed, Host is found
	zlog.Debug().Msgf("Found Host (%s) with UUID (%s) and Serial Number (%s)",
		hostBySN.GetResourceId(), hostBySN.GetUuid(), hostBySN.GetSerialNumber())
	return hostBySN, true, nil
}

func FindHostInListByUUID(uuID string, listOfHosts []*computev1.HostResource) (
	*computev1.HostResource, bool,
) {
	uuidList := make([]*computev1.HostResource, 0)
	for _, host := range listOfHosts {
		if uuID == host.GetUuid() {
			uuidList = append(uuidList, host)
		}
	}
	err := inv_util.CheckListOutputIsSingular(uuidList)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Couldn't find Host by UUID (%s)", uuID)
		return nil, false
	}
	return uuidList[0], true
}

func FindHostInListBySerialNumber(sn string, listOfHosts []*computev1.HostResource) (
	*computev1.HostResource, bool,
) {
	snList := make([]*computev1.HostResource, 0)
	for _, host := range listOfHosts {
		if sn == host.GetSerialNumber() {
			snList = append(snList, host)
		}
	}
	err := inv_util.CheckListOutputIsSingular(snList)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Couldn't find Host by Serial Number (%s)", sn)
		return nil, false
	}
	return snList[0], true
}

func FindHostInLOCAHostList(hostToFind *computev1.HostResource, locaHostList []*model.DtoDeviceListElement) (
	*computev1.HostResource, bool,
) {
	for _, locaHost := range locaHostList {
		hostRawUUID := inv_util.ConvertInventoryUUIDToLenovoUUID(hostToFind.GetUuid())
		if hostRawUUID == locaHost.UUID &&
			hostToFind.GetSerialNumber() == locaHost.SerialNumber {
			zlog.Debug().Msgf("Host (%s) is found", hostToFind.GetUuid())
			return hostToFind, true
		}
	}
	return nil, false
}

func FindDeviceInLOCAHostList(hostToFind *computev1.HostResource, locaHostList []*model.DtoDeviceListElement) (
	*model.DtoDeviceListElement, bool,
) {
	for _, locaHost := range locaHostList {
		hostRawUUID := inv_util.ConvertInventoryUUIDToLenovoUUID(hostToFind.GetUuid())
		if hostRawUUID == locaHost.UUID &&
			hostToFind.GetSerialNumber() == locaHost.SerialNumber {
			zlog.Debug().Msgf("Host (%s) is found", hostToFind.GetUuid())
			return locaHost, true
		}
	}
	return nil, false
}

func BuildNewHost(uuID, sn string) *computev1.HostResource {
	return &computev1.HostResource{
		Uuid:         uuID,
		SerialNumber: sn,
	}
}

func BuildNewInstance(locaInstance *model.DtoInstance) (*computev1.InstanceResource, error) {
	osResourceID, err := ExtractOSResourceIDFromTemplate(locaInstance.Template)
	if err != nil {
		return nil, err
	}
	return &computev1.InstanceResource{
		Name: locaInstance.ID,
		Os: &osv1.OperatingSystemResource{
			ResourceId: osResourceID, // this is safe, because OS is overwritten in the upper layers
		},
	}, nil
}

func FindInstanceInList(instanceToFind *computev1.InstanceResource, listOfInstances []*computev1.InstanceResource) (
	*computev1.InstanceResource, bool,
) {
	for _, instance := range listOfInstances {
		if instanceToFind.GetName() == instance.GetName() &&
			instanceToFind.GetOs().GetResourceId() == instance.GetOs().GetResourceId() {
			zlog.Debug().Msgf("Instance (%s) is found", instanceToFind.GetName())
			return instance, true
		}
	}
	return nil, false
}

func FindInstanceInLOCAInstanceList(instanceToFind *computev1.InstanceResource, locaInstanceList []*model.DtoInstance) (
	*computev1.InstanceResource, bool,
) {
	for _, locaInstance := range locaInstanceList {
		osResourceID, err := ExtractOSResourceIDFromTemplate(locaInstance.Template)
		if err != nil {
			continue
		}
		if instanceToFind.GetName() == locaInstance.ID &&
			instanceToFind.GetOs().GetResourceId() == osResourceID {
			zlog.Debug().Msgf("Instance (%s) is found", instanceToFind.GetName())
			return instanceToFind, true
		}
	}
	return nil, false
}

func FindLOCAInstanceInLOCAInstanceList(instanceToFind *computev1.InstanceResource, locaInstanceList []*model.DtoInstance) (
	*model.DtoInstance, bool,
) {
	for _, locaInstance := range locaInstanceList {
		osResourceID, err := ExtractOSResourceIDFromTemplate(locaInstance.Template)
		if err != nil {
			continue
		}
		if instanceToFind.GetName() == locaInstance.ID &&
			instanceToFind.GetOs().GetResourceId() == osResourceID {
			zlog.Debug().Msgf("Instance (%s) is found", instanceToFind.GetName())
			return locaInstance, true
		}
	}
	return nil, false
}

func GetOSSHA256FromOsNameAndOsVersion(osName, osVersion string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(osName+osVersion)))
}

func CheckIfInstanceIsAssociated(
	ctx context.Context, c client.TenantAwareInventoryClient, tenantID string, host *computev1.HostResource,
) error {
	var err error
	if host.GetInstance() != nil {
		reconcErr := errors.Errorf("Instance %s is still assigned to Host %s, waiting for Instance to be deleted first",
			host.GetInstance().GetResourceId(), host.GetResourceId())
		zlog.Warn().Err(reconcErr).Msg("")

		host.OnboardingStatus = StatusWaitingOnInstanceRemoval
		host.OnboardingStatusIndicator = statusv1.StatusIndication_STATUS_INDICATION_ERROR
		host.OnboardingStatusTimestamp, err = inv_util.Int64ToUint64(time.Now().Unix())
		if err != nil {
			zlog.Debug().Err(err).Msgf("Failed to parse current time")
		}
		err := inventory.UpdateHostOnboardingStatus(ctx, c, tenantID, host)
		if err != nil {
			// log debug message only in the case of failure
			zlog.Debug().Err(err).Msgf("Failed update status detail for host %s", host.GetResourceId())
		}

		return reconcErr
	}

	return nil
}

// DecodeBase64 function decodes base64-encoded string back into a human-readable string.
// ToDo (Ivan) - move to the shared utility functions package.
func DecodeBase64(str string) (string, bool) {
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return "", false
	}
	return string(data), true
}

func CreateENCredentials(ctx context.Context, tenantID, hostUUID string) (string, string, error) {
	authService, err := auth.AuthServiceFactory(ctx)
	if err != nil {
		return "", "", err
	}
	defer authService.Logout(ctx)

	clientID, clientSecret, err := authService.CreateCredentialsWithUUID(ctx, tenantID, hostUUID)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("")
		return "", "", err
	}
	return clientID, clientSecret, nil
}

// ConvertGPSStringToLatLng converts GPS coordinates according to the convention:
// The geolocation (i.e., latitude and longtitude) of the Site is represented with int32 in Inventory.
// Points are represented as latitude-longitude pairs in the E7 representation
// (i.e., degrees multiplied by 10**7 and rounded to the nearest integer).
// siteLat should be in the range +/- 90 degrees.
// siteLng should be in the range +/- 180 degrees (inclusive).
func ConvertGPSStringToLatLng(gpsCoordinates string) (int32, int32, error) {
	gps := strings.Split(gpsCoordinates, ",")
	if len(gps) != lenGPS {
		return 0, 0, errors.Errorfc(codes.InvalidArgument, "Invalid format for GOS coordinates")
	}

	lat, err := strconv.ParseFloat(gps[0], 64)
	if err != nil {
		err = errors.Errorfc(codes.InvalidArgument, "Failed to convert latitude")
		zlog.InfraErr(err).Send()
		return 0, 0, err
	}

	lng, err := strconv.ParseFloat(gps[1], 64)
	if err != nil {
		err = errors.Errorfc(codes.InvalidArgument, "Failed to convert longtitude")
		zlog.InfraErr(err).Send()
		return 0, 0, err
	}

	int32Lat := int32(lat * e7Multiplier)
	if int32Lat > 90*e7Multiplier || int32Lat < -90*e7Multiplier {
		// exceeded boundaries, throwing an error
		err = errors.Errorfc(codes.InvalidArgument, "Latitude exceeds boundaries")
		return 0, 0, err
	}

	int32Lng := int32(lng * e7Multiplier)
	if int32Lng > 180*e7Multiplier || int32Lng < -180*e7Multiplier {
		// exceeded boundaries, throwing an error
		err = errors.Errorfc(codes.InvalidArgument, "Latitude exceeds boundaries")
		return 0, 0, err
	}

	return int32Lat, int32Lng, nil
}

// ConvertLatLngToGPSString function does the backward conversion of ConvertGPSStringToLatLng function.
func ConvertLatLngToGPSString(lat, lng int32) (string, error) {
	if lat > 90*e7Multiplier || lat < -90*e7Multiplier {
		// exceeded boundaries, throwing an error
		err := errors.Errorfc(codes.InvalidArgument, "Latitude exceeds boundaries")
		return "", err
	}

	if lng > 180*e7Multiplier || lng < -180*e7Multiplier {
		// exceeded boundaries, throwing an error
		err := errors.Errorfc(codes.InvalidArgument, "Latitude exceeds boundaries")
		return "", err
	}
	return fmt.Sprintf("%.7f,%.7f", float64(lat)/e7Multiplier, float64(lng)/e7Multiplier), nil
}

func ConvertLOCASiteToSiteResource(site *model.DtoSite) (*locationv1.SiteResource, error) {
	siteLat, siteLng, err := ConvertGPSStringToLatLng(site.GpsCoordinates)
	if err != nil {
		zlog.InfraErr(err).Msgf("Failed to convert Site to Site Resource")
		return nil, err
	}
	return &locationv1.SiteResource{
		ResourceId: site.SiteCode,
		Name:       site.Name,
		Address:    site.Address,
		SiteLat:    siteLat,
		SiteLng:    siteLng,
	}, nil
}

func ConvertSiteResourceToLOCASite(site *locationv1.SiteResource) (*model.DtoSites, error) {
	gpsCoordinates, err := ConvertLatLngToGPSString(site.GetSiteLat(), site.GetSiteLng())
	if err != nil {
		zlog.InfraErr(err).Msgf("Failed to convert Site Resource to Site")
		return nil, err
	}
	return &model.DtoSites{
		Name: site.GetName(),
		// ToDo (ITEP-15398): remove hardcoding and parse these values from the corresponding Region resources
		Geo:      "managed-by-inframanager",
		Country:  "managed-by-inframanager",
		Province: "managed-by-inframanager",
		City:     "managed-by-inframanager",
		// ToDo (ITEP-15398): avoid hardcoding this value
		CloudType:      "Edge Manageability Framework",
		Address:        site.GetAddress(),
		GpsCoordinates: gpsCoordinates,
		SiteCode:       site.GetResourceId(),
	}, nil
}

func FindInventorySiteInInventorySiteListByName(name string, listOfSites []*locationv1.SiteResource) (
	*locationv1.SiteResource, bool,
) {
	siteList := make([]*locationv1.SiteResource, 0)
	for _, site := range listOfSites {
		if name == site.GetName() {
			siteList = append(siteList, site)
		}
	}
	err := inv_util.CheckListOutputIsSingular(siteList)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Couldn't find Site %s in Inventory", name)
		return nil, false
	}
	return siteList[0], true
}

func FindLOCASiteInLOCASiteListByName(name string, listOfSites []*model.DtoSites) (
	*model.DtoSites, bool,
) {
	siteList := make([]*model.DtoSites, 0)
	for _, site := range listOfSites {
		if name == site.Name {
			siteList = append(siteList, site)
		}
	}
	err := inv_util.CheckListOutputIsSingular(siteList)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Couldn't find Site %s in LOC-A", name)
		return nil, false
	}
	return siteList[0], true
}

func ExtractOSResourceIDFromTemplate(template *model.DtoTemplate) (string, error) {
	var resourceID string
	fields := template.ExtraVars
	osResourceID, ok := fields[extraVarsOSResourceIDKey]
	if !ok {
		// log an error
		err := errors.Errorfc(codes.NotFound, "ExtraVars does not contain field 'os_resource_id'")
		zlog.InfraSec().InfraErr(err).Send()
		return "", err
	}
	// extracting resource ID
	resourceID, ok = osResourceID.(string)
	if !ok {
		err := errors.Errorfc(codes.NotFound, "Not able to get OS resource ID for template %s", template.Name)
		zlog.InfraErr(err).Send()
		return "", err
	}
	if resourceID == "" {
		// throw a not found error
		err := errors.Errorfc(codes.NotFound, "OS resource ID was not found for template %s", template.Name)
		zlog.InfraErr(err).Send()
		return "", err
	}
	return resourceID, nil
}

func GetTemplateName(osResourceID, serverModel string) string {
	// removes ThinkEdge prefix to avoid character limit in LOC-A and removes unsupported whitespace
	// ThinkEdge SE360 V2 -> SE360V2.
	serverName := strings.ReplaceAll(strings.TrimPrefix(serverModel, "ThinkEdge "), " ", "")
	return osResourceID + "-" + serverName
}

func FindWhichCloudServiceAttachedToSite(
	siteName string,
	csList []*model.DtoCloudServiceListElement,
) (
	*model.DtoCloudServiceListElement,
	bool,
) {
	for _, cs := range csList {
		// checking if Cloud Service is attached to Site
		if len(cs.SiteAssociation) == 0 {
			// no sites attached, skipping the rest of the iteration
			continue
		}
		// Site is attached, checking if it matches the one we need
		for _, site := range cs.SiteAssociation {
			if site == siteName && cs.Name == siteName {
				return cs, true
			}
		}
	}
	return nil, false
}

func ReadTinkerbellCA() (string, error) {
	caPath := os.Getenv(TinkCAPath)
	if caPath == "" {
		// using default CA path
		caPath = defaultTinkCAPath
	}

	entries, err := os.ReadDir(caPath)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to read directory %s", caPath)
		return "", err
	}
	caCerts := make([][]byte, 0)
	for _, e := range entries {
		if !strings.Contains(e.Name(), certExtension) {
			continue
		}

		zlog.Debug().Msgf("Passing certificate %s to the Cloud Service template", e.Name())
		caFullPath := caPath + "/" + e.Name()
		caCert, readErr := os.ReadFile(caFullPath)
		if readErr != nil {
			zlog.InfraSec().InfraErr(readErr).Msgf("Failed to read CA certificate %s", caFullPath)
			return "", readErr
		}
		caCerts = append(caCerts, caCert)
	}

	// ToDo (ITEP-15397): adjust the code and all dependencies (e.g., LOC-A plugin) to support multiple CAs
	if len(caCerts) != 1 {
		err = errors.Errorfc(codes.FailedPrecondition, "Expected 1 CA certificate, found %d", len(caCerts))
		zlog.InfraSec().InfraErr(err).Send()
		return "", err
	}
	// swapping all new lines with whitespaces to be compliant with LOC-A
	tinkCA := strings.ReplaceAll(string(caCerts[0]), "\n", " ")
	return tinkCA, nil
}

func CreateCloudServiceTemplate(siteName string) (*model.DtoCloudServiceCreateRequest, error) {
	fqdn := os.Getenv(ClusterDomain)
	if fqdn == "" {
		err := errors.Errorfc(codes.NotFound, "Environment variable '%v' is not set", ClusterDomain)
		zlog.InfraSec().InfraErr(err).Send()
		return nil, err
	}
	caCert, err := ReadTinkerbellCA()
	if err != nil {
		return nil, err
	}

	serviceSettings := map[string]any{
		TinkerbellCAKey: caCert,
	}
	return &model.DtoCloudServiceCreateRequest{
		Name:            StrPtr(siteName),
		Role:            StrPtr(cloudServiceRole),
		ConnectionCheck: BoolPtr(false),
		Protocol:        httpsProtocol,
		Port:            httpsPort,
		SiteAssociation: StrPtr(siteName),
		PlatformType:    StrPtr(cloudServicePlatformType),
		Status:          StrPtr(statusActive),
		ServiceAddress:  StrPtr(fqdn),
		ServiceSettings: serviceSettings,
	}, nil
}

func StrPtr(s string) *string {
	return &s
}

func BoolPtr(b bool) *bool {
	return &b
}
