// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	computev1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/compute/v1"
	inv_v1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	locationv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/location/v1"
	network_v1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/network/v1"
	os_v1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/os/v1"
	providerv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/provider/v1"
	kk_auth "github.com/open-edge-platform/infra-core/inventory/v2/pkg/auth"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	inv_errors "github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/util"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/util/filters"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/validator"
)

const (
	DefaultInventoryTimeout = 5 * time.Second
)

var (
	zlog = logging.GetLogger("InvClient")

	inventoryTimeout = flag.Duration("invTimeout", DefaultInventoryTimeout, "Inventory API calls timeout")
)

// List resources by the provided filter. Filter is done only on fields that are set (not default values of the
// resources). Note that this function will NOT return an error if an object is not found.
func listAllResources(
	ctx context.Context,
	c client.TenantAwareInventoryClient,
	filter *inv_v1.ResourceFilter,
) ([]*inv_v1.Resource, error) {
	ctx, cancel := context.WithTimeout(ctx, *inventoryTimeout)
	defer cancel()
	// we agreed to not return a NotFound error to avoid too many 'Not Found'
	// responses to the consumer of our external APIs.
	objs, err := c.ListAll(ctx, filter)
	if err != nil && !inv_errors.IsNotFound(err) {
		zlog.InfraSec().InfraErr(err).Msgf("Unable to listAll %v", filter)
		return nil, err
	}
	for _, v := range objs {
		if err = validator.ValidateMessage(v); err != nil {
			zlog.InfraSec().InfraErr(err).Msgf("Invalid input, validation has failed: %v", v)
			return nil, inv_errors.Wrap(err)
		}
	}
	return objs, nil
}

func listAndReturnHost(
	ctx context.Context,
	c client.TenantAwareInventoryClient,
	filter *inv_v1.ResourceFilter,
) (*computev1.HostResource, error) {
	resources, err := listAllResources(ctx, c, filter)
	if err != nil {
		return nil, err
	}
	err = util.CheckListOutputIsSingular(resources)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msg("Obtained non-singular Host resource")
		return nil, err
	}
	hostres := resources[0].GetHost()
	if hostres == nil {
		err = inv_errors.Errorfc(codes.Internal, "Empty Host resource")
		zlog.InfraSec().InfraErr(err).Msg("Inventory returned an empty Host resource")
		return nil, err
	}

	return hostres, nil
}

//nolint:dupl // this call retrieves different resource
func ListAllHostsByLOCAProvider(
	ctx context.Context,
	c client.TenantAwareInventoryClient,
	tenantID string,
	apiEndpoint string,
) ([]*computev1.HostResource, error) {
	zlog.Debug().Msgf("Obtaining all Hosts resource for LOC-A Provider with endpoint: tenantID=%s, endpoint=%s",
		tenantID, apiEndpoint)

	craftedFilter := fmt.Sprintf("%s = %q AND %s.%s=%s AND %s.%s=%s AND %s.%s=%q",
		computev1.HostResourceFieldTenantId, tenantID,
		computev1.HostResourceEdgeProvider, providerv1.ProviderResourceFieldProviderKind,
		providerv1.ProviderKind_PROVIDER_KIND_BAREMETAL, computev1.HostResourceEdgeProvider,
		providerv1.ProviderResourceFieldProviderVendor, providerv1.ProviderVendor_PROVIDER_VENDOR_LENOVO_LOCA,
		computev1.HostResourceEdgeProvider, providerv1.ProviderResourceFieldApiEndpoint, apiEndpoint)
	filter := &inv_v1.ResourceFilter{
		Resource: &inv_v1.Resource{
			Resource: &inv_v1.Resource_Host{},
		},
		Filter: craftedFilter,
	}
	hostsInv, err := listAllResources(ctx, c, filter)
	if err != nil {
		return nil, err
	}

	hosts, err := util.GetSpecificResourceList[*computev1.HostResource](hostsInv)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msg("Failed to get a Host resource list")
		return nil, err
	}

	return hosts, nil
}

func ListAllInstancesByLOCAProvider(
	ctx context.Context,
	c client.TenantAwareInventoryClient,
	tenantID string,
	apiEndpoint string,
) ([]*computev1.InstanceResource, error) {
	zlog.Debug().Msgf("Obtaining all Instance resource for LOC-A Provider with endpoint: tenantID=%s, endpoint=%s",
		tenantID, apiEndpoint)

	craftedFilter := fmt.Sprintf("%s = %q AND %s.%s.%s=%s AND %s.%s.%s=%s AND %s.%s.%s=%q",
		computev1.InstanceResourceFieldTenantId, tenantID,
		computev1.InstanceResourceEdgeHost, computev1.InstanceResourceEdgeProvider,
		providerv1.ProviderResourceFieldProviderKind, providerv1.ProviderKind_PROVIDER_KIND_BAREMETAL,
		computev1.InstanceResourceEdgeHost, computev1.InstanceResourceEdgeProvider,
		providerv1.ProviderResourceFieldProviderVendor, providerv1.ProviderVendor_PROVIDER_VENDOR_LENOVO_LOCA,
		computev1.InstanceResourceEdgeHost, computev1.InstanceResourceEdgeProvider,
		providerv1.ProviderResourceFieldApiEndpoint, apiEndpoint)
	filter := &inv_v1.ResourceFilter{
		Resource: &inv_v1.Resource{
			Resource: &inv_v1.Resource_Instance{},
		},
		Filter: craftedFilter,
	}
	instancesInv, err := listAllResources(ctx, c, filter)
	if err != nil {
		return nil, err
	}

	instances, err := util.GetSpecificResourceList[*computev1.InstanceResource](instancesInv)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msg("Failed to get an Instance resource list")
		return nil, err
	}

	return instances, nil
}

func ListAllSitesByTenantID(
	ctx context.Context,
	c client.TenantAwareInventoryClient,
	tenantID string,
) ([]*locationv1.SiteResource, error) {
	zlog.Debug().Msgf("Obtaining all Site resources for Tenant with ID=%s", tenantID)

	craftedFilter := fmt.Sprintf("%s = %q",
		locationv1.SiteResourceFieldTenantId, tenantID)
	filter := &inv_v1.ResourceFilter{
		Resource: &inv_v1.Resource{
			Resource: &inv_v1.Resource_Site{},
		},
		Filter: craftedFilter,
	}
	sitesInv, err := listAllResources(ctx, c, filter)
	if err != nil {
		return nil, err
	}

	sites, err := util.GetSpecificResourceList[*locationv1.SiteResource](sitesInv)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msg("Failed to get an Site resource list")
		return nil, err
	}

	return sites, nil
}

//nolint:dupl // this call retrieves different resource
func ListAllSitesByLOCAProvider(
	ctx context.Context,
	c client.TenantAwareInventoryClient,
	tenantID string,
	apiEndpoint string,
) ([]*locationv1.SiteResource, error) {
	zlog.Debug().Msgf("Obtaining all Site resources for LOC-A Provider with ID: tenantID=%s, endpoint=%s",
		tenantID, apiEndpoint)

	craftedFilter := fmt.Sprintf("%s = %q AND %s.%s=%s AND %s.%s=%s AND %s.%s=%q",
		locationv1.SiteResourceFieldTenantId, tenantID,
		locationv1.SiteResourceEdgeProvider, providerv1.ProviderResourceFieldProviderKind,
		providerv1.ProviderKind_PROVIDER_KIND_BAREMETAL, locationv1.SiteResourceEdgeProvider,
		providerv1.ProviderResourceFieldProviderVendor, providerv1.ProviderVendor_PROVIDER_VENDOR_LENOVO_LOCA,
		locationv1.SiteResourceEdgeProvider, providerv1.ProviderResourceFieldApiEndpoint, apiEndpoint)
	filter := &inv_v1.ResourceFilter{
		Resource: &inv_v1.Resource{
			Resource: &inv_v1.Resource_Site{},
		},
		Filter: craftedFilter,
	}
	sitesInv, err := listAllResources(ctx, c, filter)
	if err != nil {
		return nil, err
	}

	sites, err := util.GetSpecificResourceList[*locationv1.SiteResource](sitesInv)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msg("Failed to get an Site resource list")
		return nil, err
	}

	return sites, nil
}

func GetHostResourceByUUID(
	ctx context.Context,
	c client.TenantAwareInventoryClient,
	tenantID string,
	uuID string,
) (*computev1.HostResource, error) {
	ctx, cancel := context.WithTimeout(ctx, *inventoryTimeout)
	defer cancel()

	zlog.Debug().Msgf("Obtaining Host resource by its UUID: tenantID=%s, UUID=%s", tenantID, uuID)
	// validating if a correct UUID passed
	if _, err := uuid.Parse(uuID); err != nil {
		newErr := inv_errors.Errorfc(codes.InvalidArgument, "Invalid UUID")
		zlog.InfraSec().InfraErr(err).Msg("Invalid UUID obtained at the input of the function")
		return nil, newErr
	}
	return c.GetHostByUUID(ctx, tenantID, uuID)
}

func GetHostResourceBySerialNumber(
	ctx context.Context,
	c client.TenantAwareInventoryClient,
	tenantID string,
	sn string,
) (*computev1.HostResource, error) {
	zlog.Debug().Msgf("Obtaining Host resource by its Serial Number: tenantID=%s, serialNumber=%s", tenantID, sn)
	if sn == "" {
		err := inv_errors.Errorfc(codes.InvalidArgument, "Empty Serial Number")
		zlog.InfraSec().InfraErr(err).Msg("Empty Serial Number obtained at the input of the function")
		return nil, err
	}

	craftedFilter := fmt.Sprintf("%s = %q AND %s = %q",
		computev1.HostResourceFieldTenantId, tenantID,
		computev1.HostResourceFieldSerialNumber, sn)
	filter := &inv_v1.ResourceFilter{
		Resource: &inv_v1.Resource{
			Resource: &inv_v1.Resource_Host{},
		},
		Filter: craftedFilter,
	}
	return listAndReturnHost(ctx, c, filter)
}

// GetOSResourceByResourceID returns the OS Resource filtered by the Resource ID.
func GetOSResourceByResourceID(
	ctx context.Context,
	c client.TenantAwareInventoryClient,
	tenantID, resourceID string,
) (
	*os_v1.OperatingSystemResource, error,
) {
	zlog.Debug().Msgf("Obtaining Operating System (%s) for tenant (%s)", resourceID, tenantID)

	craftedFilter := fmt.Sprintf("%s = %q AND %s = %q",
		os_v1.OperatingSystemResourceFieldTenantId, tenantID,
		os_v1.OperatingSystemResourceFieldResourceId, resourceID)
	filter := &inv_v1.ResourceFilter{
		Resource: &inv_v1.Resource{
			Resource: &inv_v1.Resource_Os{},
		},
		Filter: craftedFilter,
	}

	resources, err := listAllResources(ctx, c, filter)
	if err != nil {
		return nil, err
	}
	err = util.CheckListOutputIsSingular(resources)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Obtained non-singular Operating System resource")
		return nil, err
	}
	osRes := resources[0].GetOs()
	if osRes == nil {
		err = inv_errors.Errorfc(codes.Internal, "Empty Operating System resource")
		zlog.InfraSec().InfraErr(err).Msg("Inventory returned an empty Operating System resource")
		return nil, err
	}

	return osRes, nil
}

// GetInstanceResourceByName is used solely for obtaining an Instance by its Name from the Inventory.
func GetInstanceResourceByName(
	ctx context.Context,
	c client.TenantAwareInventoryClient,
	tenantID string,
	instanceName string,
) (*computev1.InstanceResource, error) {
	logDetails := fmt.Sprintf("tenantID=%s, name=%s", tenantID, instanceName)
	zlog.Debug().Msgf("Obtaining Instance resource with name: %s", logDetails)

	craftedFilter := fmt.Sprintf("%s = %q AND %s = %q",
		computev1.InstanceResourceFieldTenantId, tenantID,
		computev1.InstanceResourceFieldName, instanceName)
	filter := &inv_v1.ResourceFilter{
		Resource: &inv_v1.Resource{
			Resource: &inv_v1.Resource_Instance{},
		},
		Filter: craftedFilter,
	}

	resources, err := listAllResources(ctx, c, filter)
	if err != nil {
		return nil, err
	}

	err = util.CheckListOutputIsSingular(resources)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Obtained non-singular Instance resource")
		return nil, err
	}
	// checking if obtained Instance is not nil
	retInst := resources[0].GetInstance()
	if retInst == nil {
		// obtained instance is nil, returning an error
		err = inv_errors.Errorfc(codes.Internal, "Obtained empty Instance")
		zlog.InfraSec().InfraErr(err).Msgf("Obtained from Inventory Instance is nil: %s", logDetails)
		return nil, err
	}

	return retInst, nil
}

// ListLOCAProviderResources is used to obtaining all LOC-A Providers from the Inventory.
func ListLOCAProviderResources(
	ctx context.Context, c client.TenantAwareInventoryClient,
) ([]*providerv1.ProviderResource, error) {
	zlog.Debug().Msgf("Obtaining all LOC-A Provider resources from Inventory")

	craftedFilter := fmt.Sprintf("%s=%s AND %s=%s",
		providerv1.ProviderResourceFieldProviderKind, providerv1.ProviderKind_PROVIDER_KIND_BAREMETAL.String(),
		providerv1.ProviderResourceFieldProviderVendor, providerv1.ProviderVendor_PROVIDER_VENDOR_LENOVO_LOCA.String())
	filter := &inv_v1.ResourceFilter{
		Resource: &inv_v1.Resource{
			Resource: &inv_v1.Resource_Provider{},
		},
		Filter: craftedFilter,
	}

	resources, err := listAllResources(ctx, c, filter)
	if err != nil {
		return nil, err
	}

	providers, err := util.GetSpecificResourceList[*providerv1.ProviderResource](resources)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msg("Failed to list LOC-A Provider resources")
		return nil, err
	}
	return providers, nil
}

// GetLOCAProviderResource is used solely for obtaining a LOC-A Provider resource from the Inventory.
func GetLOCAProviderResource(
	ctx context.Context,
	c client.TenantAwareInventoryClient,
	tenantID string,
	apiEndpoint string,
) (*providerv1.ProviderResource, error) {
	logDetails := fmt.Sprintf("tenantID=%s, endpoint=%s", tenantID, apiEndpoint)
	zlog.Debug().Msgf("Obtaining LOC-A Provider resource with following endpoint: %s", logDetails)

	craftedFilter := fmt.Sprintf("%s = %q AND %s=%s AND %s=%s AND %s=%q",
		providerv1.ProviderResourceFieldTenantId, tenantID,
		providerv1.ProviderResourceFieldProviderKind, providerv1.ProviderKind_PROVIDER_KIND_BAREMETAL,
		providerv1.ProviderResourceFieldProviderVendor, providerv1.ProviderVendor_PROVIDER_VENDOR_LENOVO_LOCA,
		providerv1.ProviderResourceFieldApiEndpoint, apiEndpoint)
	filter := &inv_v1.ResourceFilter{
		Resource: &inv_v1.Resource{
			Resource: &inv_v1.Resource_Provider{},
		},
		Filter: craftedFilter,
	}

	resources, err := listAllResources(ctx, c, filter)
	if err != nil {
		return nil, err
	}

	err = util.CheckListOutputIsSingular(resources)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Obtained non-singular LOC-A Provider resource")
		return nil, err
	}
	// checking if obtained Provider is not nil
	retProvider := resources[0].GetProvider()
	if retProvider == nil {
		// obtained Provider is nil, returning an error
		err = inv_errors.Errorfc(codes.Internal, "Obtained empty LOC-A Provider")
		zlog.InfraSec().InfraErr(err).Msgf("Obtained from Inventory Provider is nil: %s", logDetails)
		return nil, err
	}

	return retProvider, nil
}

func CreateHostResource(
	ctx context.Context, c client.TenantAwareInventoryClient, tenantID, uuID string, hostres *computev1.HostResource,
) (
	string,
	error,
) {
	ctx, cancel := context.WithTimeout(ctx, *inventoryTimeout)
	defer cancel()

	hostres.Uuid = uuID
	hostres.TenantId = tenantID

	zlog.Debug().Msgf("Create Host Resource: %v", hostres)
	createresreq := &inv_v1.Resource{
		Resource: &inv_v1.Resource_Host{
			Host: hostres,
		},
	}

	res, err := c.Create(ctx, tenantID, createresreq)
	if err != nil {
		zlog.Err(err).Msgf("Failed to create Host Resource with %v", hostres)
		return "", err
	}
	resID, err := util.GetResourceIDFromResource(res)
	if err != nil {
		zlog.Err(err).Msgf("Failed to get resourceID: resource=%v", res)
	}
	zlog.Debug().Msgf("New Host: %s", FormatTenantResourceID(tenantID, resID))
	return resID, nil
}

//nolint:dupl // used for testing purposes
func CreateOSResource(
	ctx context.Context, c client.TenantAwareInventoryClient, tenantID string, osres *os_v1.OperatingSystemResource,
) (
	string,
	error,
) {
	ctx, cancel := context.WithTimeout(ctx, *inventoryTimeout)
	defer cancel()

	zlog.Debug().Msgf("Create OS Resource: %v", osres)
	createresreq := &inv_v1.Resource{
		Resource: &inv_v1.Resource_Os{
			Os: osres,
		},
	}

	res, err := c.Create(ctx, tenantID, createresreq)
	if err != nil {
		zlog.Err(err).Msgf("Failed to create OS Resource with %v", osres)
		return "", err
	}
	resID, err := util.GetResourceIDFromResource(res)
	if err != nil {
		zlog.Err(err).Msgf("Failed to get resourceID: resource=%v", res)
	}
	zlog.Debug().Msgf("New OS: %s", FormatTenantResourceID(tenantID, resID))
	return resID, nil
}

//nolint:dupl // used for testing purposes
func CreateSiteResource(
	ctx context.Context, c client.TenantAwareInventoryClient, tenantID string, siteRes *locationv1.SiteResource,
) (
	string,
	error,
) {
	ctx, cancel := context.WithTimeout(ctx, *inventoryTimeout)
	defer cancel()

	zlog.Debug().Msgf("Create Site Resource: %v", siteRes)
	createresreq := &inv_v1.Resource{
		Resource: &inv_v1.Resource_Site{
			Site: siteRes,
		},
	}

	res, err := c.Create(ctx, tenantID, createresreq)
	if err != nil {
		zlog.Err(err).Msgf("Failed to create Site Resource with %v", siteRes)
		return "", err
	}
	resID, err := util.GetResourceIDFromResource(res)
	if err != nil {
		zlog.Err(err).Msgf("Failed to get resourceID: resource=%v", res)
	}
	zlog.Debug().Msgf("New Site: %s", FormatTenantResourceID(tenantID, resID))
	return resID, nil
}

func CreateInstanceResource(
	ctx context.Context,
	c client.TenantAwareInventoryClient,
	tenantID string,
	instRes *computev1.InstanceResource,
	osRes *os_v1.OperatingSystemResource,
	hostres *computev1.HostResource,
) (*computev1.InstanceResource, error) {
	ctx, cancel := context.WithTimeout(ctx, *inventoryTimeout)
	defer cancel()

	// attaching OS and Host resources to the Instance
	instRes.Os = osRes
	instRes.Host = hostres
	instRes.TenantId = tenantID

	zlog.Debug().Msgf("Creating an Instance resource: tenantID=%s, uuid=%s, osProfileName=%s, providerName=%s.",
		tenantID, instRes.GetHost().GetUuid(), instRes.GetOs().GetProfileName(), instRes.GetHost().GetProvider().GetName())
	createresreq := &inv_v1.Resource{
		Resource: &inv_v1.Resource_Instance{
			Instance: instRes,
		},
	}

	res, err := c.Create(ctx, tenantID, createresreq)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed create Instance resource with %v", instRes)
		return nil, err
	}

	return res.GetInstance(), nil
}

// RegisterHost updates UUID and serial number to the Host Resource in Inventory.
// It takes computev1.HostResource as an argument, but ignores all fields other than uuid and serial_number.
// It overwrites uuid and serial_number with provided values in computev1.HostResource.
// The function requires ResourceId to be set in computev1.HostResource.
func RegisterHost(
	ctx context.Context, c client.TenantAwareInventoryClient, tenantID string, host *computev1.HostResource,
) error {
	return UpdateInvResourceFields(ctx, c, tenantID, host, []string{
		computev1.HostResourceFieldSerialNumber,
	})
}

// UpdateHostStatus updates only the host-related statuses, keeping other fields of
// HostResource unchanged. It takes computev1.HostResource as an argument, but ignores all fields other
// than current_state, onboarding_status, onboarding_status_indicator and onboarding_status_timestamp.
// It overwrites current_state, onboarding_status, onboarding_status_indicator and onboarding_status_timestamp
// with provided values in computev1.HostResource. The function requires ResourceId to be set in computev1.HostResource.
func UpdateHostStatus(
	ctx context.Context,
	c client.TenantAwareInventoryClient,
	tenantID string,
	host *computev1.HostResource,
) error {
	return UpdateInvResourceFields(ctx, c, tenantID, host, []string{
		computev1.HostResourceFieldCurrentState, computev1.HostResourceFieldHostStatus,
		computev1.HostResourceFieldHostStatusIndicator, computev1.HostResourceFieldHostStatusTimestamp,
	})
}

// UpdateHostOnboardingStatus updates only the host-related statuses, keeping other fields of HostResource unchanged.
// It takes computev1.HostResource as an argument, but ignores all fields other than host_status. It overwrites host_status
// with provided values in computev1.HostResource. The function requires ResourceId to be set in computev1.HostResource.
func UpdateHostOnboardingStatus(
	ctx context.Context, c client.TenantAwareInventoryClient, tenantID string, host *computev1.HostResource,
) error {
	return UpdateInvResourceFields(ctx, c, tenantID, host, []string{
		computev1.HostResourceFieldCurrentState, computev1.HostResourceFieldOnboardingStatus,
		computev1.HostResourceFieldOnboardingStatusIndicator, computev1.HostResourceFieldOnboardingStatusTimestamp,
	})
}

// UpdateHostSite updates Site to the Host Resource in Inventory.
// It takes computev1.HostResource as an argument, but ignores all fields other than site.
// It overwrites site with provided values in computev1.HostResource.
// The function requires ResourceId to be set in computev1.HostResource.
func UpdateHostSite(
	ctx context.Context, c client.TenantAwareInventoryClient, tenantID string, host *computev1.HostResource,
) error {
	return UpdateInvResourceFields(ctx, c, tenantID, host, []string{
		computev1.HostResourceEdgeSite,
	})
}

// UpdateInstanceProvisioningStatus updates only the instance-related status, keeping other fields of InstanceResource unchanged.
// It takes computev1.InstanceResource as an argument, but ignores all fields other than status and status_detail
// It overwrites status and status_detail with provided values in computev1.InstanceResource. The function requires
// ResourceId to be set in computev1.InstanceResource.
func UpdateInstanceProvisioningStatus(
	ctx context.Context, c client.TenantAwareInventoryClient, tenantID string, instance *computev1.InstanceResource,
) error {
	return UpdateInvResourceFields(ctx, c, tenantID, instance, []string{
		computev1.InstanceResourceFieldCurrentState, computev1.InstanceResourceFieldProvisioningStatus,
		computev1.InstanceResourceFieldProvisioningStatusIndicator, computev1.InstanceResourceFieldProvisioningStatusTimestamp,
	})
}

// UpdateInstanceStatus updates only the instance-related status, keeping other fields of InstanceResource unchanged.
// It takes computev1.InstanceResource as an argument, but ignores all fields other than status and status_detail
// It overwrites status and status_detail with provided values in computev1.InstanceResource. The function requires
// ResourceId to be set in computev1.InstanceResource.
func UpdateInstanceStatus(
	ctx context.Context, c client.TenantAwareInventoryClient, tenantID string, instance *computev1.InstanceResource,
) error {
	return UpdateInvResourceFields(ctx, c, tenantID, instance, []string{
		computev1.InstanceResourceFieldCurrentState, computev1.InstanceResourceFieldInstanceStatus,
		computev1.InstanceResourceFieldInstanceStatusIndicator, computev1.InstanceResourceFieldInstanceStatusTimestamp,
	})
}

// UpdateInvResourceFields updates selected fields of a resource in Inventory.
// The resource object can contain any fields, but only the selected fields will be overwritten in Inventory
// (also if they are empty), so take care to always fill expected values for fields that will be updated.
// This function doesn't modify the resource object (instead creates a deep copy that is further modified).
func UpdateInvResourceFields(
	ctx context.Context, c client.TenantAwareInventoryClient, tenantID string, resource proto.Message, fields []string,
) error {
	if resource == nil {
		err := inv_errors.Errorfc(codes.InvalidArgument, "no resource provided")
		zlog.InfraSec().InfraErr(err).Msg("Empty resource is provided")
		return err
	}

	if len(fields) == 0 {
		zlog.InfraSec().Debug().Msgf("Skipping, no fields selected to update for an inventory resource: tenantID=%s, resource=%v",
			tenantID, resource)
		return nil
	}

	resCopy := proto.Clone(resource)

	invResource, invResourceID, err := getInventoryResourceAndID(resCopy)
	if err != nil {
		return err
	}

	fieldMask, err := fieldmaskpb.New(resCopy, fields...)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msg("Failed to construct a fieldmask")
		return inv_errors.Wrap(err)
	}

	err = util.ValidateMaskAndFilterMessage(resCopy, fieldMask, true)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msg("Failed to validate a fieldmask and filter message")
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, *inventoryTimeout)
	defer cancel()

	_, err = c.Update(ctx, tenantID, invResourceID, fieldMask, invResource)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to update resource: %s", FormatTenantResourceID(tenantID, invResourceID))
		return err
	}
	return nil
}

func getInventoryResourceAndID(resource proto.Message) (*inv_v1.Resource, string, error) {
	invResource := &inv_v1.Resource{}
	var invResourceID string

	if resource == nil {
		err := inv_errors.Errorfc(codes.InvalidArgument, "no resource provided")
		zlog.InfraSec().InfraErr(err).Msgf("getInventoryResourceAndID")
		return nil, invResourceID, err
	}

	switch res := resource.(type) {
	case *computev1.HostResource:
		invResource.Resource = &inv_v1.Resource_Host{
			Host: res,
		}
		invResourceID = res.GetResourceId()
	case *computev1.HoststorageResource:
		invResource.Resource = &inv_v1.Resource_Hoststorage{
			Hoststorage: res,
		}
		invResourceID = res.GetResourceId()
	case *computev1.HostnicResource:
		invResource.Resource = &inv_v1.Resource_Hostnic{
			Hostnic: res,
		}
		invResourceID = res.GetResourceId()
	case *computev1.HostusbResource:
		invResource.Resource = &inv_v1.Resource_Hostusb{
			Hostusb: res,
		}
		invResourceID = res.GetResourceId()
	case *computev1.HostgpuResource:
		invResource.Resource = &inv_v1.Resource_Hostgpu{
			Hostgpu: res,
		}
		invResourceID = res.GetResourceId()
	case *network_v1.IPAddressResource:
		invResource.Resource = &inv_v1.Resource_Ipaddress{
			Ipaddress: res,
		}
		invResourceID = res.GetResourceId()
	case *computev1.InstanceResource:
		invResource.Resource = &inv_v1.Resource_Instance{
			Instance: res,
		}
		invResourceID = res.GetResourceId()
	default:
		err := inv_errors.Errorfc(codes.InvalidArgument, "unsupported resource type: %t", resource)
		zlog.InfraSec().InfraErr(err).Msg("getInventoryResourceAndID")
		return nil, invResourceID, err
	}

	return invResource, invResourceID, nil
}

// DeleteHostnic deletes an existing Hostnic resource in Inventory. If it gets a not found error while deleting the given
// resource, it doesn't return an error.
//
//nolint:dupl // refactor later
func DeleteHostnic(ctx context.Context, c client.TenantAwareInventoryClient, tenantID, resourceID string) error {
	zlog.Debug().Msgf("Update Host NIC: %s", FormatTenantResourceID(tenantID, resourceID))

	ctx, cancel := context.WithTimeout(ctx, *inventoryTimeout)
	defer cancel()
	_, err := c.Delete(ctx, tenantID, resourceID)
	if inv_errors.IsNotFound(err) {
		zlog.Debug().Msgf("Not found while Host NIC delete, dropping err: %s", FormatTenantResourceID(tenantID, resourceID))
		return nil
	}
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed delete Host NIC resource: %s", FormatTenantResourceID(tenantID, resourceID))
		return err
	}
	return err
}

// ListIPAddresses returns the list of IP addresses associated to the nic.
func ListIPAddresses(
	ctx context.Context, c client.TenantAwareInventoryClient, tenantID string, hostNic *computev1.HostnicResource,
) ([]*network_v1.IPAddressResource, error) {
	zlog.Debug().Msgf("List IPAddress associated to: tenantID=%s, hostNic=%v", tenantID, hostNic)

	filter := &inv_v1.ResourceFilter{
		Resource: &inv_v1.Resource{
			Resource: &inv_v1.Resource_Ipaddress{},
		},
		Filter: fmt.Sprintf("%s = %q AND has(%s) AND %s.%s=%q",
			network_v1.IPAddressResourceFieldTenantId, tenantID,
			network_v1.IPAddressResourceEdgeNic,
			network_v1.IPAddressResourceEdgeNic, computev1.HostnicResourceFieldResourceId, hostNic.GetResourceId()),
	}
	resources, err := listAllResources(ctx, c, filter)
	if err != nil {
		return nil, err
	}
	return util.GetSpecificResourceList[*network_v1.IPAddressResource](resources)
}

func RemoveHost(
	ctx context.Context, c client.TenantAwareInventoryClient, tenantID string, invHost *computev1.HostResource,
) error {
	// deleting all the components of the Host, then deleting the Host itself
	zlog.Info().Msgf("Deleting Host (set current status to be Deleted): %s",
		FormatTenantResourceID(tenantID, invHost.GetResourceId()))

	// Before deleting the Host, we should move it to the UNTRUSTED state
	if invHost.GetCurrentState() != computev1.HostState_HOST_STATE_UNTRUSTED {
		if err := kk_auth.RevokeHostCredentials(ctx, tenantID, invHost.GetUuid()); err != nil {
			return err
		}
	}

	// following functions are only modifying current state
	// we continue to delete other host objects in case of not found errors
	if err := deleteHostNicByHost(ctx, c, tenantID, invHost); err != nil {
		zlog.InfraSec().InfraError("Failed to delete Host NIC resource of Host: %s",
			FormatTenantResourceID(tenantID, invHost.GetResourceId())).Msg("deleteHost")
		return err
	}

	if err := deleteHostStorageByHost(ctx, c, tenantID, invHost); err != nil {
		zlog.InfraSec().InfraError("Failed to delete Host Storage resource of Host: %s",
			FormatTenantResourceID(tenantID, invHost.GetResourceId())).Msg("deleteHost")
		return err
	}

	if err := deleteHostUsbByHost(ctx, c, tenantID, invHost); err != nil {
		zlog.InfraSec().InfraError("Failed to delete Host USB resource of Host: %s",
			FormatTenantResourceID(tenantID, invHost.GetResourceId())).Msg("deleteHost")
		return err
	}

	if err := deleteHostGpuByHost(ctx, c, tenantID, invHost); err != nil {
		zlog.InfraSec().InfraError("Failed to delete Host GPU resource of Host: %s",
			FormatTenantResourceID(tenantID, invHost.GetResourceId())).Msg("deleteHost")
		return err
	}

	// we don't need to delete the Host object itself.
	// Inventory will remove it when current_state = DELETED.
	if err := UpdateHostCurrentState(ctx, c, tenantID, invHost, computev1.HostState_HOST_STATE_DELETED); err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to update Host Current State to be DELETED: %s",
			FormatTenantResourceID(tenantID, invHost.GetResourceId()))
		return err
	}

	return nil
}

// DeleteIPAddress deletes an existing IP address resource in Inventory
// by setting to DELETED the current state of the resource.
func DeleteIPAddress(ctx context.Context, c client.TenantAwareInventoryClient, tenantID, resourceID string) error {
	zlog.Debug().Msgf("Delete IP Address: %s", FormatTenantResourceID(tenantID, resourceID))

	ctx, cancel := context.WithTimeout(ctx, *inventoryTimeout)
	defer cancel()
	ipAddress := &network_v1.IPAddressResource{
		ResourceId:   resourceID,
		CurrentState: network_v1.IPAddressState_IP_ADDRESS_STATE_DELETED,
	}

	err := UpdateInvResourceFields(ctx, c, tenantID, ipAddress, []string{network_v1.IPAddressResourceFieldCurrentState})
	if inv_errors.IsNotFound(err) {
		zlog.Debug().Msgf("Not found while IP Address delete, dropping err: %s",
			FormatTenantResourceID(tenantID, resourceID))
		return nil
	}
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed delete IP Address resource: %s",
			FormatTenantResourceID(tenantID, resourceID))
		return err
	}

	return err
}

// DeleteHoststorage deletes an existing Hoststorage resource in Inventory. If it gets a not found error while deleting the given
// resource, it doesn't return an error.
//
//nolint:dupl // refactor later
func DeleteHoststorage(ctx context.Context, c client.TenantAwareInventoryClient, tenantID, resourceID string) error {
	zlog.Debug().Msgf("Delete Host Storage: %s", FormatTenantResourceID(tenantID, resourceID))

	ctx, cancel := context.WithTimeout(ctx, *inventoryTimeout)
	defer cancel()

	_, err := c.Delete(ctx, tenantID, resourceID)
	if inv_errors.IsNotFound(err) {
		zlog.Debug().Msgf("Not found while Host Storage delete, dropping err: %s",
			FormatTenantResourceID(tenantID, resourceID))
		return nil
	}
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed delete Host Storage resource: %s",
			FormatTenantResourceID(tenantID, resourceID))
		return err
	}

	return err
}

// DeleteHostusb deletes an existing Hostusb resource in Inventory. If it gets a not found error while deleting the given
// resource, it doesn't return an error.
//
//nolint:dupl // refactor later
func DeleteHostusb(ctx context.Context, c client.TenantAwareInventoryClient, tenantID, resourceID string) error {
	zlog.Debug().Msgf("Delete Host USB: %s", FormatTenantResourceID(tenantID, resourceID))

	ctx, cancel := context.WithTimeout(ctx, *inventoryTimeout)
	defer cancel()

	_, err := c.Delete(ctx, tenantID, resourceID)
	if inv_errors.IsNotFound(err) {
		zlog.Debug().Msgf("Not found while Host USB delete, dropping err: %s",
			FormatTenantResourceID(tenantID, resourceID))
		return nil
	}
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed delete Host USB resource: %s",
			FormatTenantResourceID(tenantID, resourceID))
		return err
	}

	return err
}

//nolint:dupl // refactor later
func DeleteHostgpu(ctx context.Context, c client.TenantAwareInventoryClient, tenantID, resourceID string) error {
	zlog.Debug().Msgf("Delete Host GPU: %s", FormatTenantResourceID(tenantID, resourceID))

	ctx, cancel := context.WithTimeout(ctx, *inventoryTimeout)
	defer cancel()
	_, err := c.Delete(ctx, tenantID, resourceID)
	if inv_errors.IsNotFound(err) {
		zlog.Debug().Msgf("Not found while Host GPU delete, dropping err: %s",
			FormatTenantResourceID(tenantID, resourceID))
		return nil
	}
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed delete Host GPU resource: %s",
			FormatTenantResourceID(tenantID, resourceID))
		return err
	}
	return err
}

func UpdateHostCurrentState(
	ctx context.Context,
	c client.TenantAwareInventoryClient,
	tenantID string,
	host *computev1.HostResource,
	state computev1.HostState,
) error {
	zlog.Debug().Msgf("Updating Host current state: tenantID=%s, UUID=%s", tenantID, host.GetUuid())
	host.CurrentState = state
	// update host current state
	err := UpdateInvResourceFields(ctx, c, tenantID, host, []string{
		computev1.HostResourceFieldCurrentState,
	})
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to update Host Status")
		return err
	}
	return nil
}

func UpdateInstanceCurrentState(
	ctx context.Context,
	c client.TenantAwareInventoryClient,
	tenantID string,
	instance *computev1.InstanceResource,
	state computev1.InstanceState,
) error {
	zlog.Debug().Msgf("Updating Instance current state: %s", FormatTenantResourceID(tenantID, instance.GetResourceId()))
	instance.CurrentState = state
	// update instance current state
	err := UpdateInvResourceFields(ctx, c, tenantID, instance, []string{
		computev1.InstanceResourceFieldCurrentState,
	})
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to update Instance State and Status")
		return err
	}
	return nil
}

func UpdateInstanceName(
	ctx context.Context,
	c client.TenantAwareInventoryClient,
	tenantID string,
	instance *computev1.InstanceResource,
	instanceName string,
) error {
	zlog.Debug().Msgf("Updating Instance Name: %s", instanceName)
	instance.Name = instanceName

	err := UpdateInvResourceFields(ctx, c, tenantID, instance, []string{
		computev1.InstanceResourceFieldName,
	})
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to update Instance Name")
		return err
	}
	return nil
}

func deleteHostNicByHost(
	ctx context.Context, c client.TenantAwareInventoryClient, tenantID string, hostres *computev1.HostResource,
) error {
	// eager loaded from Host
	nics := hostres.GetHostNics()

	for _, nic := range nics {
		// Firstly the IPAddresses due to the strong relation with nic
		if err := deleteIPsByHostNic(ctx, c, tenantID, nic); err != nil {
			return err
		}

		zlog.Debug().Msgf("Deleting host NIC with: %s", FormatTenantResourceID(tenantID, nic.GetResourceId()))
		err := DeleteHostnic(ctx, c, tenantID, nic.GetResourceId())
		if err != nil {
			return err
		}
	}

	return nil
}

func deleteIPsByHostNic(
	ctx context.Context, c client.TenantAwareInventoryClient, tenantID string, hostNic *computev1.HostnicResource,
) error {
	// IPs are not eager loaded
	nicIPs, err := ListIPAddresses(ctx, c, tenantID, hostNic)
	if err != nil {
		return err
	}

	for _, ip := range nicIPs {
		zlog.Debug().Msgf("Deleting IP address: %s", FormatTenantResourceID(tenantID, ip.GetResourceId()))
		err := DeleteIPAddress(ctx, c, tenantID, ip.GetResourceId())
		if err != nil {
			return err
		}
	}

	return nil
}

func deleteHostStorageByHost(
	ctx context.Context, c client.TenantAwareInventoryClient, tenantID string, hostres *computev1.HostResource,
) error {
	// eager loaded from Host
	disks := hostres.GetHostStorages()

	for _, disk := range disks {
		zlog.Debug().Msgf("Deleting host storage: %s", FormatTenantResourceID(tenantID, disk.GetResourceId()))
		err := DeleteHoststorage(ctx, c, tenantID, disk.GetResourceId())
		if err != nil {
			return err
		}
	}

	return nil
}

func deleteHostUsbByHost(
	ctx context.Context, c client.TenantAwareInventoryClient, tenantID string, host *computev1.HostResource,
) error {
	usbs := host.GetHostUsbs()

	for _, usb := range usbs {
		zlog.Debug().Msgf("Deleting host USB: %s", FormatTenantResourceID(tenantID, usb.GetResourceId()))
		err := DeleteHostusb(ctx, c, tenantID, usb.GetResourceId())
		if err != nil {
			return err
		}
	}

	return nil
}

func deleteHostGpuByHost(
	ctx context.Context, c client.TenantAwareInventoryClient, tenantID string, hostres *computev1.HostResource,
) error {
	// eager loaded from Host
	gpus := hostres.GetHostGpus()

	for _, gpu := range gpus {
		zlog.Debug().Msgf("Deleting host GPU: %s", FormatTenantResourceID(tenantID, gpu.GetResourceId()))
		err := DeleteHostgpu(ctx, c, tenantID, gpu.GetResourceId())
		if err != nil {
			return err
		}
	}

	return nil
}

//nolint:dupl // this call retrieves different resource
func GetHostResourceByResourceID(
	ctx context.Context,
	c client.TenantAwareInventoryClient,
	tenantID string,
	resourceID string,
) (*computev1.HostResource, error) {
	ctx, cancel := context.WithTimeout(ctx, *inventoryTimeout)
	defer cancel()

	zlog.Debug().Msgf("Obtaining Host resource by its Resource ID: %s", FormatTenantResourceID(tenantID, resourceID))

	err := checkResourceIDAndTenantID(resourceID, tenantID)
	if err != nil {
		return nil, err
	}

	resp, err := c.Get(ctx, tenantID, resourceID)
	if err != nil {
		return nil, err
	}

	hostRes := resp.GetResource().GetHost()

	if validateErr := validator.ValidateMessage(hostRes); validateErr != nil {
		zlog.InfraSec().Err(validateErr).Msgf("Failed to validate Host resource: %v", hostRes)
		return nil, inv_errors.Wrap(validateErr)
	}
	if hostRes == nil {
		newErr := inv_errors.Errorfc(codes.Internal, "Obtained Host from Inventory is 'nil': %s",
			FormatTenantResourceID(tenantID, resourceID))
		zlog.InfraSec().InfraErr(newErr).Msgf("Obtained Host from Inventory is 'nil': %s",
			FormatTenantResourceID(tenantID, resourceID))
		return nil, newErr
	}

	return hostRes, nil
}

//nolint:dupl // this call retrieves different resource
func GetInstanceResourceByResourceID(
	ctx context.Context,
	c client.TenantAwareInventoryClient,
	tenantID string,
	resourceID string,
) (*computev1.InstanceResource, error) {
	ctx, cancel := context.WithTimeout(ctx, *inventoryTimeout)
	defer cancel()

	zlog.Debug().Msgf("Obtaining Instance resource by its Resource ID: %s", FormatTenantResourceID(tenantID, resourceID))

	err := checkResourceIDAndTenantID(resourceID, tenantID)
	if err != nil {
		return nil, err
	}

	resp, err := c.Get(ctx, tenantID, resourceID)
	if err != nil {
		return nil, err
	}

	instRes := resp.GetResource().GetInstance()

	if validateErr := validator.ValidateMessage(instRes); validateErr != nil {
		zlog.InfraSec().Err(validateErr).Msgf("Failed to validate Instance resource: %v", instRes)
		return nil, inv_errors.Wrap(validateErr)
	}
	if instRes == nil {
		newErr := inv_errors.Errorfc(codes.Internal, "Obtained Instance from Inventory is 'nil': %s",
			FormatTenantResourceID(tenantID, resourceID))
		zlog.InfraSec().InfraErr(newErr).Msgf("Obtained Instance from Inventory is 'nil': %s",
			FormatTenantResourceID(tenantID, resourceID))
		return nil, newErr
	}

	return instRes, nil
}

func FormatTenantResourceID(tenantID, resourceID string) string {
	return fmt.Sprintf("[tenantID=%s, resourceID=%s]", tenantID, resourceID)
}

// GetSingularTenantIDFromProviders gets the singular tenant ID if all given providers belong to a single tenant.
// Returns Internal error otherwise. Returns NotFound if no providers are provided.
func GetSingularTenantIDFromProviders(providers []*providerv1.ProviderResource) (string, error) {
	if len(providers) == 0 {
		return "", inv_errors.Errorfc(codes.NotFound, "No tenantID found")
	}
	tenantID := ""
	for _, provider := range providers {
		if tenantID == "" {
			tenantID = provider.GetTenantId()
		}
		if tenantID != provider.GetTenantId() {
			return "", inv_errors.Errorfc(codes.Internal, "Found multiple providers!")
		}
	}
	return tenantID, nil
}

func ListAllMutableOperatingSystems(
	ctx context.Context,
	c client.TenantAwareInventoryClient,
	tenantID string,
) ([]*os_v1.OperatingSystemResource, error) {
	zlog.Debug().Msgf("Obtaining all OperatingSystem resource: %s=%s, %s=%s",
		os_v1.OperatingSystemResourceFieldTenantId, tenantID,
		os_v1.OperatingSystemResourceFieldOsType, os_v1.OsType_OS_TYPE_MUTABLE)

	queryFilter := filters.NewBuilderWith(
		filters.ValEq(os_v1.OperatingSystemResourceFieldTenantId, tenantID)).
		And(
			filters.ValEq(os_v1.OperatingSystemResourceFieldOsType, os_v1.OsType_OS_TYPE_MUTABLE)).
		Build()

	filter := &inv_v1.ResourceFilter{
		Resource: &inv_v1.Resource{
			Resource: &inv_v1.Resource_Os{},
		},
		Filter: queryFilter,
	}
	osInv, err := listAllResources(ctx, c, filter)
	if err != nil {
		return nil, err
	}

	osResList, err := util.GetSpecificResourceList[*os_v1.OperatingSystemResource](osInv)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msg("Failed to get an Operating System resource list")
		return nil, err
	}

	return osResList, nil
}

//nolint:dupl // this call retrieves different resource
func GetSiteResourceByResourceID(
	ctx context.Context,
	c client.TenantAwareInventoryClient,
	tenantID string,
	resourceID string,
) (*locationv1.SiteResource, error) {
	ctx, cancel := context.WithTimeout(ctx, *inventoryTimeout)
	defer cancel()

	zlog.Debug().Msgf("Obtaining Site resource by its Resource ID: %s", FormatTenantResourceID(tenantID, resourceID))

	err := checkResourceIDAndTenantID(resourceID, tenantID)
	if err != nil {
		return nil, err
	}

	resp, err := c.Get(ctx, tenantID, resourceID)
	if err != nil {
		return nil, err
	}

	siteRes := resp.GetResource().GetSite()

	if err := validator.ValidateMessage(siteRes); err != nil {
		zlog.InfraSec().Err(err).Msgf("Failed to validate Site resource: %v", siteRes)
		return nil, inv_errors.Wrap(err)
	}
	if siteRes == nil {
		newErr := inv_errors.Errorfc(codes.Internal, "Obtained Site from Inventory is 'nil': %s",
			FormatTenantResourceID(tenantID, resourceID))
		zlog.InfraSec().InfraErr(newErr).Msgf("Obtained Site from Inventory is 'nil': %s",
			FormatTenantResourceID(tenantID, resourceID))
		return nil, newErr
	}

	return siteRes, nil
}

func checkResourceIDAndTenantID(resourceID, tenantID string) error {
	if resourceID == "" || tenantID == "" {
		err := inv_errors.Errorfc(codes.InvalidArgument, "Empty Resource ID or Tenant ID")
		zlog.InfraSec().InfraErr(err).Msg("Empty Resource ID or Tenant ID obtained at the input of the function")
		return err
	}
	return nil
}
