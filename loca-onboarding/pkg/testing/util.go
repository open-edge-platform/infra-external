// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package testing

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	computev1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/compute/v1"
	inv_v1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	location_v1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/location/v1"
	network_v1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/network/v1"
	osv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/os/v1"
	providerv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/provider/v1"
	statusv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/status/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	inv_errors "github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	inv_testing "github.com/open-edge-platform/infra-core/inventory/v2/pkg/testing"
	inv_util "github.com/open-edge-platform/infra-core/inventory/v2/pkg/util"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/inventory"
	loca_status "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/status"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/util"
)

const (
	TestTimeout2S            = 2 * time.Second
	TestTimeout5S            = 5 * time.Second
	TestReconciliationPeriod = 1 * time.Second
	ProvisioningWeight       = 45  // %
	TotalWeight              = 100 // %
	timeout                  = 1 * time.Second
	LocaSecret               = "loca-secret"
	LocaDeviceSN             = "J900VN44"
	LocaDeviceRawUUID        = "57ED598C4B9411EE806C3A7C7693AAC3"
	LocaDeviceID             = "658c3b86f445a55d541460cf"
	LocaInstanceFlavor       = "Ubuntu 22.04.3"
	LocaInstanceID           = "658c483ef445a55d541460db"
	LocaSiteID               = "66d5a4a57bc832e5fbf72705"
	LocaSiteName             = "SANTA-CLARA"
	LocaTaskUUID             = "b3b36443-aac1-4847-aed1-80dea17226ea"
	CloudServiceTaskUUID     = "e83c81ab-415a-4377-ae47-e7355702764e"
	DefaultProviderName      = "LOC-A"
	HostStatusRunning        = "Running"
	InstanceStatusRunning    = "Running"
	TaskStatusRunning        = "running"
	TaskStatusSuccessful     = "successful"

	Tenant1 = "11111111-1111-1111-1111-111111111111"
	Tenant2 = "22222222-2222-2222-2222-222222222222"
)

var (
	LocaRMClient       client.TenantAwareInventoryClient
	LocaRMEventsClient chan *client.WatchEvents
)

func InitializeInventoryClient(clientName string) {
	resourceKinds := []inv_v1.ResourceKind{
		inv_v1.ResourceKind_RESOURCE_KIND_INSTANCE,
		inv_v1.ResourceKind_RESOURCE_KIND_HOST,
		inv_v1.ResourceKind_RESOURCE_KIND_HOSTNIC,
		inv_v1.ResourceKind_RESOURCE_KIND_HOSTSTORAGE,
		inv_v1.ResourceKind_RESOURCE_KIND_HOSTUSB,
	}
	clType := inv_testing.ClientType(clientName)
	err := inv_testing.CreateClient(clType, inv_v1.ClientKind_CLIENT_KIND_RESOURCE_MANAGER, resourceKinds, "")
	if err != nil {
		panic(err)
	}

	// assigning created client to global variable
	LocaRMClient = inv_testing.TestClients[clType].GetTenantAwareInventoryClient()
	LocaRMEventsClient = inv_testing.TestClientsEvents[clType]
}

func initializeLOCAServer() *MockServer {
	var err error
	locaTS, err := StartDummyLOCAServer()
	SitesCrudFuncs(locaTS, true, nil)
	if err != nil {
		panic(err)
	}
	return locaTS
}

func CloseInventoryClientChannel(clientName string) {
	if err := LocaRMClient.Close(); err != nil {
		fmt.Printf("Error occurred while closing the Inventory channel: %v\n", err)
	}
	delete(inv_testing.TestClients, inv_testing.ClientType(clientName))
	delete(inv_testing.TestClientsEvents, inv_testing.ClientType(clientName))
}

func StartTestingEnvironment(policyPath, migrationsDir, clientName string) *MockServer {
	inv_testing.StartTestingEnvironment(policyPath, "", migrationsDir)
	// initializing Inventory channels
	InitializeInventoryClient(clientName)
	return initializeLOCAServer()
}

func StopTestingEnvironment(locaTS *MockServer, clientName string) {
	CloseInventoryClientChannel(clientName)
	locaTS.StopDummyLOCAServer()
	inv_testing.StopTestingEnvironment()
}

func ParseUUID(t *testing.T, rawUUID string) string {
	t.Helper()

	uuID, err := uuid.Parse(rawUUID)
	require.NoError(t, err)

	return uuID.String()
}

func UpdateInstanceCurrentStateStatusAndStatusIndicator(
	t *testing.T,
	instInv *computev1.InstanceResource,
	state computev1.InstanceState,
	provisioningStatus string,
	statusIndicator statusv1.StatusIndication,
) (
	*computev1.InstanceResource, error,
) {
	t.Helper()
	var err error

	instInv.CurrentState = state
	instInv.ProvisioningStatus = provisioningStatus
	instInv.ProvisioningStatusIndicator = statusIndicator
	instInv.ProvisioningStatusTimestamp, err = inv_util.Int64ToUint64(time.Now().Unix())
	require.NoError(t, err)

	// creating fieldmask
	fieldmask, err := fieldmaskpb.New(
		instInv,
		computev1.InstanceResourceFieldCurrentState,
		computev1.InstanceResourceFieldProvisioningStatus,
		computev1.InstanceResourceFieldProvisioningStatusIndicator,
		computev1.InstanceResourceFieldProvisioningStatusTimestamp,
	)
	if err != nil {
		return nil, err
	}

	// creating context
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// updating Instance's state, status, and status details
	_, err = inv_testing.TestClients[inv_testing.RMClient].Update(
		ctx, instInv.GetResourceId(), fieldmask, &inv_v1.Resource{
			Resource: &inv_v1.Resource_Instance{
				Instance: instInv,
			},
		})
	if err != nil {
		return nil, err
	}

	return instInv, nil
}

func UpdateOnboardingStatusAndStatusIndicator(
	t *testing.T,
	hostInv *computev1.HostResource,
	onboardingStatus string,
	statusIndicator statusv1.StatusIndication,
) (
	*computev1.HostResource, error,
) {
	t.Helper()
	var err error

	hostInv.OnboardingStatus = onboardingStatus
	hostInv.OnboardingStatusIndicator = statusIndicator
	hostInv.OnboardingStatusTimestamp, err = inv_util.Int64ToUint64(time.Now().Unix())
	require.NoError(t, err)

	// creating fieldmask
	fieldmask, err := fieldmaskpb.New(
		hostInv, computev1.HostResourceFieldOnboardingStatus,
		computev1.HostResourceFieldOnboardingStatusIndicator,
		computev1.HostResourceFieldOnboardingStatusTimestamp,
	)
	if err != nil {
		return nil, err
	}

	// creating context
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// updating Host's status and status details
	_, err = inv_testing.TestClients[inv_testing.RMClient].Update(
		ctx, hostInv.GetResourceId(), fieldmask, &inv_v1.Resource{
			Resource: &inv_v1.Resource_Host{
				Host: hostInv,
			},
		})
	if err != nil {
		return nil, err
	}

	return hostInv, nil
}

//nolint:dupl // almost the same as UpdateHostProductName, but setting different field
func UpdateHostSerialNumber(t *testing.T, tenantID, resourceID, sn string) error {
	t.Helper()

	// adjusting the Serial Number
	host := &computev1.HostResource{
		SerialNumber: sn,
	}

	// creating fieldmask
	fieldmask, err := fieldmaskpb.New(host, "serial_number")
	if err != nil {
		return err
	}

	// creating context
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// updating Instance's name
	_, err = inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient().Update(
		ctx, tenantID, resourceID, fieldmask, &inv_v1.Resource{
			Resource: &inv_v1.Resource_Host{
				Host: host,
			},
		})
	if err != nil {
		return err
	}

	return nil
}

//nolint:dupl // almost the same as UpdateHostSite, but setting different field
func UpdateHostProductName(t *testing.T, tenantID, resourceID, productName string) error {
	t.Helper()

	// adjusting the Product Name
	host := &computev1.HostResource{
		ProductName: productName,
	}

	// creating fieldmask
	fieldmask, err := fieldmaskpb.New(host, "product_name")
	if err != nil {
		return err
	}

	// creating context
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// updating Product Name
	_, err = inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient().Update(
		ctx, tenantID, resourceID, fieldmask, &inv_v1.Resource{
			Resource: &inv_v1.Resource_Host{
				Host: host,
			},
		})
	if err != nil {
		return err
	}

	return nil
}

func UpdateHostSite(t *testing.T, tenantID, resourceID string, site *location_v1.SiteResource) error {
	t.Helper()

	// adjusting the Site
	host := &computev1.HostResource{
		Site: site,
	}

	// creating fieldmask
	fieldmask, err := fieldmaskpb.New(host, "site")
	if err != nil {
		return err
	}

	// creating context
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// updating Site
	_, err = inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient().Update(
		ctx, tenantID, resourceID, fieldmask, &inv_v1.Resource{
			Resource: &inv_v1.Resource_Host{
				Host: host,
			},
		})
	if err != nil {
		return err
	}

	return nil
}

func HostCleanupByUUID(t *testing.T, c client.TenantAwareInventoryClient, tenantID, uuID string) {
	t.Helper()
	dao := inv_testing.NewInvResourceDAOOrFail(t)

	// Host cleanup at the end of this function
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	host, err := inventory.GetHostResourceByUUID(ctx, c, tenantID, uuID)
	if err != nil {
		// host not found (i.e., was not created), ending the function.
		return
	}

	// deleting host
	dao.HardDeleteHost(t, tenantID, host.GetResourceId())
}

func InstanceCleanupByName(t *testing.T, c client.TenantAwareInventoryClient, tenantID, name string) {
	t.Helper()
	dao := inv_testing.NewInvResourceDAOOrFail(t)

	// Instance cleanup at the end of this TC
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	instance, errGet := inventory.GetInstanceResourceByName(ctx, c, tenantID, name)
	if errGet != nil {
		// Instance not found (i.e., was not created), ending the function.
		return
	}

	// deleting Instance
	dao.HardDeleteInstance(t, tenantID, instance.GetResourceId())
}

func PopulateInventoryWithLOCAProvider(t *testing.T, tenantID, providerName, locaTSURL string) *providerv1.ProviderResource {
	t.Helper()
	dao := inv_testing.NewInvResourceDAOOrFail(t)

	// creating LOC-A Provider
	lenovo := dao.CreateProviderWithArgs(t,
		tenantID,
		providerName, locaTSURL,
		[]string{LocaSecret},
		providerv1.ProviderVendor_PROVIDER_VENDOR_LENOVO_LOCA,
		inv_testing.ProviderKind(providerv1.ProviderKind_PROVIDER_KIND_BAREMETAL),
	)
	return lenovo
}

//nolint:gocritic // this function populates Host components to Inventory
func PopulateInventoryWithHostResources(t *testing.T, tenantID string, lenovo *providerv1.ProviderResource, cleanup bool) (
	*computev1.HostResource,
	*computev1.HostnicResource,
	*network_v1.IPAddressResource,
	*computev1.HoststorageResource,
	*computev1.HostusbResource,
	*computev1.HostgpuResource,
) {
	t.Helper()
	dao := inv_testing.NewInvResourceDAOOrFail(t)

	hostUUID, err := uuid.Parse(LocaDeviceRawUUID)
	require.NoError(t, err)
	// creating Host and Host component Resources from NB to get Inventory ready for Instance onboarding
	host := dao.CreateHostWithOpts(
		t, tenantID, cleanup,
		inv_testing.HostUUID(hostUUID.String()), inv_testing.HostSerialNumber(LocaDeviceSN), inv_testing.HostProvider(lenovo))
	host.Provider = lenovo
	// create Host components on the same Host
	//nolint:ineffassign // workaround for cleanup feature
	hostNic := &computev1.HostnicResource{}         // ToDo(Ivan): Make createHostnic (and the rest below) function exportable
	hostStorage := &computev1.HoststorageResource{} //nolint:ineffassign // workaround for cleanup feature
	hostUsb := &computev1.HostusbResource{}         //nolint:ineffassign // workaround for cleanup feature
	hostGpu := &computev1.HostgpuResource{}         //nolint:ineffassign // workaround for cleanup feature
	if cleanup {
		hostNic = dao.CreateHostNic(t, tenantID, host)
		hostStorage = dao.CreateHostStorage(t, tenantID, host)
		hostUsb = dao.CreateHostUsb(t, tenantID, host)
		hostGpu = dao.CreateHostGPU(t, tenantID, host)
	} else {
		hostNic = dao.CreateHostNicNoCleanup(t, tenantID, host)
		hostStorage = dao.CreateHostStorageNoCleanup(t, tenantID, host)
		hostUsb = dao.CreateHostUsbNoCleanup(t, tenantID, host)
		hostGpu = dao.CreateHostGPUNoCleanup(t, tenantID, host)
	}
	nicIP := dao.CreateIPAddress(t, Tenant1, hostNic, cleanup)

	return host, hostNic, nicIP, hostStorage, hostUsb, hostGpu
}

func PopulateInventoryWithOSResource(t *testing.T, locaMocks []*MockServer, tenantID string) *osv1.OperatingSystemResource {
	t.Helper()
	dao := inv_testing.NewInvResourceDAOOrFail(t)

	// faking SHA256 checksum
	// OS name and OS version are similar in dummy LOC-A server
	checksum := util.GetOSSHA256FromOsNameAndOsVersion(LocaInstanceFlavor, LocaInstanceFlavor)
	osRes := dao.CreateOsWithOpts(t, tenantID, true, func(osr *osv1.OperatingSystemResource) {
		osr.Sha256 = checksum
		osr.ProfileName = LocaInstanceFlavor
		osr.SecurityFeature = osv1.SecurityFeature_SECURITY_FEATURE_NONE
		osr.OsType = osv1.OsType_OS_TYPE_MUTABLE
	})

	// seeding the same OS Resource ID to be a part of the Instance Template for all Mocks
	for _, mock := range locaMocks {
		mock.SeedOSResourceID(osRes.GetResourceId())
	}

	return osRes
}

func PopulateInventoryWithInstanceAndOSResource(
	t *testing.T,
	locaMocks []*MockServer,
	tenantID string,
	host *computev1.HostResource,
	cleanup bool,
) (
	*computev1.InstanceResource,
	*osv1.OperatingSystemResource,
) {
	t.Helper()
	dao := inv_testing.NewInvResourceDAOOrFail(t)

	osRes := PopulateInventoryWithOSResource(t, locaMocks, tenantID)

	// creating Instance
	//nolint:staticcheck // use deprecated function for now.
	instance := dao.CreateInstanceWithArgs(t, tenantID, LocaInstanceID, osv1.SecurityFeature_SECURITY_FEATURE_NONE,
		host, osRes, nil, nil, cleanup)

	return instance, osRes
}

func PopulateInventoryWithSite(t *testing.T, tenantID, siteName string) *location_v1.SiteResource {
	t.Helper()
	dao := inv_testing.NewInvResourceDAOOrFail(t)

	site := dao.CreateSite(t, tenantID, func(site *location_v1.SiteResource) {
		site.Name = siteName
		site.Address = "Very long street name"
		site.SiteLat = 373541070
		site.SiteLng = 121955238
	})

	return site
}

func InvalidateHost(t *testing.T, tenantID, hostID string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// setting desired state of the Host to be UNTRUSTED
	_, err := inv_testing.TestClients[inv_testing.APIClient].GetTenantAwareInventoryClient().Update(
		ctx,
		tenantID,
		hostID,
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.HostResourceFieldDesiredState,
		}},
		&inv_v1.Resource{
			Resource: &inv_v1.Resource_Host{
				Host: &computev1.HostResource{
					DesiredState: computev1.HostState_HOST_STATE_UNTRUSTED,
				},
			},
		},
	)
	require.NoError(t, err)
}

func InvalidateInstance(t *testing.T, tenantID, instanceID string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// setting desired state of the Instance to be UNTRUSTED
	_, err := inv_testing.TestClients[inv_testing.APIClient].GetTenantAwareInventoryClient().Update(
		ctx,
		tenantID,
		instanceID,
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.InstanceResourceFieldDesiredState,
		}},
		&inv_v1.Resource{
			Resource: &inv_v1.Resource_Instance{
				Instance: &computev1.InstanceResource{
					DesiredState: computev1.InstanceState_INSTANCE_STATE_UNTRUSTED,
				},
			},
		},
	)
	require.NoError(t, err)
}

func AssertHost(
	t *testing.T,
	tenantID string,
	providerAPI, hostSN, hostUUID string,
	desiredState computev1.HostState,
	currentState computev1.HostState,
	onboardingStatus string,
	statusIndicator statusv1.StatusIndication,
	hostStatus string,
	hostStatusIndicator statusv1.StatusIndication,
) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// reading Host from Inventory back
	host, err := inventory.GetHostResourceByUUID(ctx, LocaRMClient, tenantID, hostUUID)
	require.NoError(t, err)
	assert.Equalf(t, hostSN, host.GetSerialNumber(),
		"Wrong serial number: expected %s, got %s", hostSN, host.GetSerialNumber())
	assert.Equalf(t, hostUUID, host.GetUuid(),
		"Wrong Host UUID: expected %s, got %s", hostUUID, host.GetUuid())
	assert.Equalf(t, providerAPI, host.GetProvider().GetApiEndpoint(),
		"Wrong provider API: expected %s, got %s", providerAPI, host.GetProvider().GetApiEndpoint())

	// checking if the Host Status, and Provider Status are updated and correspond to 'staged'
	assert.Equalf(t, desiredState, host.GetDesiredState(),
		"Wrong desired state: expected=%v, actual=%v", desiredState, host.GetDesiredState())
	assert.Equalf(t, currentState, host.GetCurrentState(),
		"Wrong cured state: expected=%v, actual=%v", currentState, host.GetCurrentState())
	assert.Equalf(t, onboardingStatus, host.GetOnboardingStatus(),
		"Wrong onboarding status: expected=%v, actual=%v", onboardingStatus, host.GetOnboardingStatus())
	assert.Equalf(t, statusIndicator, host.GetOnboardingStatusIndicator(),
		"Wrong status indicator: expected=%v, actual=%v", statusIndicator, host.GetOnboardingStatusIndicator())
	assert.Equalf(t, hostStatus, host.GetHostStatus(),
		"Wrong host status: expected=%v, actual=%v", hostStatus, host.GetHostStatus())
	assert.Equalf(t, hostStatusIndicator, host.GetHostStatusIndicator(),
		"Wrong host status indicator: expected=%v, actual=%v", hostStatus, host.GetHostStatusIndicator())
}

func AssertInstance(
	t *testing.T,
	tenantID string,
	providerAPI, locaInstanceName string,
	desiredState computev1.InstanceState,
	currentState computev1.InstanceState,
	provisioningStatus string,
	statusIndicator statusv1.StatusIndication,
	instanceStatus string,
	instanceStatusIndicator statusv1.StatusIndication,
) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// reading Instance from Inventory back
	instance, err := inventory.GetInstanceResourceByName(ctx, LocaRMClient, tenantID, locaInstanceName)
	require.NoError(t, err)
	assert.Equalf(t, locaInstanceName, instance.GetName(),
		"Wrong instance name: expected %s, got %s", locaInstanceName, instance.GetName())

	// instance was de-provisioned, error state is expected
	assert.Equalf(t, providerAPI, instance.GetHost().GetProvider().GetApiEndpoint(),
		"Wrong provider API: expected %s, got %s", providerAPI, instance.GetHost().GetProvider().GetApiEndpoint())
	assert.Equalf(t, desiredState, instance.GetDesiredState(),
		"Wrong desired state: expected=%v, actual=%v", desiredState, instance.GetDesiredState())
	assert.Equalf(t, currentState, instance.GetCurrentState(),
		"Wrong current state: expected=%v, actual=%v", currentState, instance.GetCurrentState())
	assert.Equalf(t, provisioningStatus, instance.GetProvisioningStatus(),
		"Wrong provisioning status: expected=%v, actual=%v", provisioningStatus, instance.GetProvisioningStatus())
	assert.Equalf(t, statusIndicator, instance.GetProvisioningStatusIndicator(),
		"Wrong status indicator: expected=%v, actual=%v", statusIndicator, instance.GetProvisioningStatusIndicator())
	assert.Equalf(t, instanceStatus, instance.GetInstanceStatus(),
		"Wrong instance status: expected=%v, actual=%v", instanceStatus, instance.GetInstanceStatus())
	assert.Equalf(t, instanceStatusIndicator, instance.GetInstanceStatusIndicator(),
		"Wrong instance status indicator: expected=%v, actual=%v", instanceStatusIndicator, instance.GetInstanceStatusIndicator())
}

func RequireIsNotFound(t *testing.T, tenantID, resourceID string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	_, err := inv_testing.TestClients[inv_testing.APIClient].GetTenantAwareInventoryClient().Get(ctx, tenantID, resourceID)
	require.True(t, inv_errors.IsNotFound(err))
}

func AssertNumberHostsForProvider(t *testing.T, tenantID, apiEndpoint string, numHosts int) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	hostsInv, err := inventory.ListAllHostsByLOCAProvider(ctx, LocaRMClient, tenantID, apiEndpoint)
	require.NoError(t, err)
	assert.Equal(t, numHosts, len(hostsInv))
}

func AssertNumberInstancesForProvider(t *testing.T, tenantID, apiEndpoint string, numInstances int) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	instancesInv, err := inventory.ListAllInstancesByLOCAProvider(ctx, LocaRMClient, tenantID, apiEndpoint)
	require.NoError(t, err)
	assert.Equal(t, numInstances, len(instancesInv))
}

// SimulateNodeAgentAction simulates the Node Agent action which happens after the Host was successfully provisioned
// and Instance was deployed on the Host. This function emulates the update that HRM does to the Inventory
// when the Node Agent kicks in and interfaces with SBI (through HRM).
func SimulateNodeAgentAction(t *testing.T, tenantID, hostID, instanceID string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	currentTimestamp, err := inv_util.Int64ToUint64(time.Now().Unix())
	require.NoError(t, err)

	// Setting Host Status and Host Status Indicator to be 'Running'/IDLE.
	_, err = inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient().Update(
		ctx,
		tenantID,
		hostID,
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.HostResourceFieldHostStatus,
			computev1.HostResourceFieldHostStatusIndicator,
			computev1.HostResourceFieldHostStatusTimestamp,
		}},
		&inv_v1.Resource{
			Resource: &inv_v1.Resource_Host{
				Host: &computev1.HostResource{
					HostStatus:          HostStatusRunning,
					HostStatusIndicator: statusv1.StatusIndication_STATUS_INDICATION_IDLE,
					HostStatusTimestamp: currentTimestamp,
				},
			},
		},
	)
	require.NoError(t, err)

	// Setting Instance Status and Instance Status Indicator to be 'Running'/IDLE.
	_, err = inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient().Update(
		ctx,
		tenantID,
		instanceID,
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.InstanceResourceFieldInstanceStatus,
			computev1.InstanceResourceFieldInstanceStatusIndicator,
			computev1.InstanceResourceFieldInstanceStatusTimestamp,
		}},
		&inv_v1.Resource{
			Resource: &inv_v1.Resource_Instance{
				Instance: &computev1.InstanceResource{
					InstanceStatus:          InstanceStatusRunning,
					InstanceStatusIndicator: statusv1.StatusIndication_STATUS_INDICATION_IDLE,
					InstanceStatusTimestamp: currentTimestamp,
				},
			},
		},
	)
	require.NoError(t, err)
	// Also, setting Instance's Current State to be RUNNING (as HRM does when Node Agent reports 'Running' status)
	InstanceRunning(t, tenantID, instanceID)
}

// HostProvisioned sets the Current state of the Host to be PROVISIONED and Onboarding Status
// and its Indicator to correspond to the Device status 'active' reported by LOC-A.
// This function should be solely used only for bootstrapping unit test environment
// to production state, i.e., when Host is provisioned. A use case is to prepare unit
// test environment to the scenario:
// - Host was removed from LOC-A or had any other failure;
// - LOC-A server outage.
//
//nolint:dupl // almost the same as HostProvisioned, but setting different fields of the different resource
func HostProvisioned(t *testing.T, tenantID, hostID string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	currentTimestamp, err := inv_util.Int64ToUint64(time.Now().Unix())
	require.NoError(t, err)

	_, err = inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient().Update(
		ctx,
		tenantID,
		hostID,
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.HostResourceFieldCurrentState,
			computev1.HostResourceFieldOnboardingStatus,
			computev1.HostResourceFieldOnboardingStatusIndicator,
			computev1.HostResourceFieldOnboardingStatusTimestamp,
		}},
		&inv_v1.Resource{
			Resource: &inv_v1.Resource_Host{
				Host: &computev1.HostResource{
					CurrentState:              computev1.HostState_HOST_STATE_ONBOARDED,
					OnboardingStatus:          loca_status.DeviceStatusActive.Status,
					OnboardingStatusIndicator: loca_status.DeviceStatusActive.StatusIndicator,
					OnboardingStatusTimestamp: currentTimestamp,
				},
			},
		},
	)
	require.NoError(t, err)
}

// InstanceRunning sets the Current state of the Instance to be RUNNING and Provisioning Status
// and its Indicator to correspond to the 'Finished successfully' status at stage 'installed' in operation 'Deploy'.
// This function should be solely used only for bootstrapping unit test environment
// to production state, i.e., when Instance is onboarded and running. A use case is to prepare unit
// test environment to the scenario:
// - Instance was removed from LOC-A or had any other failure;
// - LOC-A server outage.
//
//nolint:dupl // almost the same as HostProvisioned, but setting different fields of the different resource
func InstanceRunning(t *testing.T, tenantID, instanceID string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	currentTimestamp, err := inv_util.Int64ToUint64(time.Now().Unix())
	require.NoError(t, err)

	_, err = inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient().Update(
		ctx,
		tenantID,
		instanceID,
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.InstanceResourceFieldCurrentState,
			computev1.InstanceResourceFieldProvisioningStatus,
			computev1.InstanceResourceFieldProvisioningStatusIndicator,
			computev1.InstanceResourceFieldProvisioningStatusTimestamp,
		}},
		&inv_v1.Resource{
			Resource: &inv_v1.Resource_Instance{
				Instance: &computev1.InstanceResource{
					CurrentState:                computev1.InstanceState_INSTANCE_STATE_RUNNING,
					ProvisioningStatus:          loca_status.InstanceStatusInstalled.Status,
					ProvisioningStatusIndicator: loca_status.InstanceStatusInstalled.StatusIndicator,
					ProvisioningStatusTimestamp: currentTimestamp,
				},
			},
		},
	)
	require.NoError(t, err)
}

// BootstrapProductionEnvironment function bootstraps unit test environment to match production environment.
// It updates Current states of the Host and Instance to be PROVISIONED and RUNNING correspondingly and simulates
// the Node Agent action, i.e., setting the Host Status and the Instance Status to be both 'Running'.
// It also updates Onboarding and Provisioning statuses of Host and Instance to be 'active' and 'installed successfully'
// in order to match real situation in the running production.
func BootstrapProductionEnvironment(t *testing.T, tenantID, hostID, instanceID string) {
	t.Helper()

	HostProvisioned(t, tenantID, hostID)
	InstanceRunning(t, tenantID, instanceID)

	SimulateNodeAgentAction(t, tenantID, hostID, instanceID)
}
