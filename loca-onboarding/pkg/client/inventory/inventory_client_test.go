// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package inventory_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpc_status "google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	computev1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/compute/v1"
	invv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	location_v1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/location/v1"
	network_v1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/network/v1"
	os_v1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/os/v1"
	providerv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/provider/v1"
	statusv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/status/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/auth"
	inv_client "github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	inv_testing "github.com/open-edge-platform/infra-core/inventory/v2/pkg/testing"
	inv_util "github.com/open-edge-platform/infra-core/inventory/v2/pkg/util"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/inventory"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/loca"
	loca_testing "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/testing"
)

const (
	apiEndpoint            = "https://192.168.201.100/"
	tenantGetterClientKind = inv_testing.ClientType("TenantGetterTestClient")
)

func TestMain(m *testing.M) {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	projectRoot := filepath.Dir(filepath.Dir(filepath.Dir(wd)))

	policyPath := projectRoot + "/out"
	migrationsDir := projectRoot + "/out"
	err = os.Setenv(loca.CaCertPath, projectRoot+"/secrets")
	if err != nil {
		panic(err)
	}

	inv_testing.StartTestingEnvironment(policyPath, "", migrationsDir)
	// client used in tenant getter tests.
	err = inv_testing.CreateClient(
		tenantGetterClientKind,
		invv1.ClientKind_CLIENT_KIND_RESOURCE_MANAGER,
		[]invv1.ResourceKind{invv1.ResourceKind_RESOURCE_KIND_PROVIDER},
		"")
	if err != nil {
		panic(err)
	}
	loca_testing.StartMockSecretService()
	run := m.Run() // run all tests
	inv_testing.StopTestingEnvironment()

	os.Exit(run)
}

//nolint:dupl // tests different call with the same scenario
func TestInvClient_GetHostResourceByUUID(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()

	// Error - no host
	noHost, err := inventory.GetHostResourceByUUID(ctx, client, loca_testing.Tenant1, "foobar")
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, grpc_status.Code(err))
	assert.Nil(t, noHost)

	// OK - gets host
	host := dao.CreateHost(t, loca_testing.Tenant1)
	getHost, err := inventory.GetHostResourceByUUID(ctx, client, loca_testing.Tenant1, host.GetUuid())
	require.NoError(t, err)
	require.NotNil(t, getHost)
	assert.Equal(t, host.GetUuid(), getHost.GetUuid())

	// Error - not found host
	emptyHost, err2 := inventory.GetHostResourceByUUID(ctx, client, loca_testing.Tenant1, "30b7deca-72c9-4cab-93d7-69956064ea15")
	require.Error(t, err2)
	assert.Equal(t, codes.NotFound, grpc_status.Code(err2))
	require.Nil(t, emptyHost)

	// Error - empty UUID
	emptyHost2, err3 := inventory.GetHostResourceByUUID(ctx, client, loca_testing.Tenant1, "")
	require.Error(t, err3)
	assert.Equal(t, codes.InvalidArgument, grpc_status.Code(err3))
	require.Nil(t, emptyHost2)
}

//nolint:dupl // tests different call with the same scenario
func TestInvClient_GetHostResourceBySerialNumber(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()

	// Error - no host
	noHost, err := inventory.GetHostResourceBySerialNumber(ctx, client, loca_testing.Tenant1, "foobar")
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, grpc_status.Code(err))
	assert.Nil(t, noHost)

	// OK - gets host
	host := dao.CreateHost(t, loca_testing.Tenant1)
	getHost, err := inventory.GetHostResourceBySerialNumber(ctx, client, loca_testing.Tenant1, host.GetSerialNumber())
	require.NoError(t, err)
	require.NotNil(t, getHost)
	assert.Equal(t, host.GetSerialNumber(), getHost.GetSerialNumber())

	// Error - not found host
	emptyHost, err2 := inventory.GetHostResourceBySerialNumber(ctx, client, loca_testing.Tenant1, "123456789")
	require.Error(t, err2)
	assert.Equal(t, codes.NotFound, grpc_status.Code(err2))
	require.Nil(t, emptyHost)

	// Error - empty Serial Number
	emptyHost2, err3 := inventory.GetHostResourceBySerialNumber(ctx, client, loca_testing.Tenant1, "")
	require.Error(t, err3)
	assert.Equal(t, codes.InvalidArgument, grpc_status.Code(err3))
	require.Nil(t, emptyHost2)
}

func TestInvClient_GetOSResourceByProfileNameAndVersion(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	// creating OS
	os1 := dao.CreateOs(t, loca_testing.Tenant1)
	os2 := inv_testing.CreateOs(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()

	testCases := map[string]struct {
		resourceID string
		want       *os_v1.OperatingSystemResource
		valid      bool
		expError   codes.Code
	}{
		"RequiredOsRes1": {
			resourceID: os1.GetResourceId(),
			want:       os1,
			valid:      true,
		},
		"NotRequiredOsRes2": { // retrieving with wrong tenant ID
			resourceID: os2.GetResourceId(),
			valid:      false,
			expError:   codes.NotFound,
		},
	}
	for tName, tc := range testCases {
		t.Run(tName, func(t *testing.T) {
			res, err := inventory.GetOSResourceByResourceID(ctx, client,
				loca_testing.Tenant1, tc.resourceID)
			if !tc.valid {
				require.Error(t, err)
				assert.Equal(t, tc.expError, grpc_status.Code(err))
			} else {
				require.NoError(t, err, errors.ErrorToStringWithDetails(err))
				require.NotNil(t, res)
				if eq, diff := inv_testing.ProtoEqualOrDiff(tc.want, res); !eq {
					t.Errorf("GetOSResourceByResourceID() data not equal: %v", diff)
				}
			}
		})
	}
}

func TestInvClient_GetInstanceResourceByName(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()

	hostInv := dao.CreateHost(t, loca_testing.Tenant1)
	hostInv2 := dao.CreateHost(t, loca_testing.Tenant1)
	osInv := dao.CreateOs(t, loca_testing.Tenant1)
	providerInv := dao.CreateProvider(t, loca_testing.Tenant1, "Lenovo",
		inv_testing.ProviderKind(providerv1.ProviderKind_PROVIDER_KIND_BAREMETAL),
	)
	instanceInv := dao.CreateInstanceWithProvider(t, loca_testing.Tenant1, hostInv, osInv, providerInv)
	// this is needed because returned instance would contain eager-loaded OS and Host resources
	instanceInv.Host = hostInv
	instanceInv.DesiredOs = osInv
	instanceInv.CurrentOs = osInv
	instanceInv.Provider = providerInv

	// retrieving instance back
	instanceBack, err := inventory.GetInstanceResourceByName(
		context.Background(), client, loca_testing.Tenant1, instanceInv.GetName())
	require.NoError(t, err)
	res, diff := inv_testing.ProtoEqualOrDiff(instanceInv, instanceBack)
	assert.True(t, res, "Obtained Instances are not equal %v", diff)

	// creating second instance with the same name
	_ = dao.CreateInstance(t, loca_testing.Tenant1, hostInv2, osInv)

	// call should fail because we retrieve two instances with the same name, but attached to the other hosts
	_, err = inventory.GetInstanceResourceByName(context.Background(), client, loca_testing.Tenant1, instanceInv.GetName())
	require.Error(t, err)
}

func TestInvClient_CreateHostResource(t *testing.T) {
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	resourceID, err := inventory.CreateHostResource(
		ctx, client, uuid.NewString(), loca_testing.Tenant1, &computev1.HostResource{})
	require.NoError(t, err)
	assert.NotNil(t, resourceID)
}

func TestRegisterHost(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()

	hostInv := dao.CreateHost(t, loca_testing.Tenant1)

	type args struct {
		ctx              context.Context
		c                inv_client.TenantAwareInventoryClient
		host             *computev1.HostResource
		hostUUID         string
		hostSerialNumber string
		tenantID         string
	}
	tests := []struct {
		name  string
		args  args
		valid bool
	}{
		{
			name: "Success",
			args: args{
				ctx:              context.TODO(),
				c:                client,
				host:             hostInv,
				hostUUID:         hostInv.GetUuid(),
				hostSerialNumber: "11223344",
				tenantID:         loca_testing.Tenant1,
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.args.host.Uuid = tt.args.hostUUID
			tt.args.host.SerialNumber = tt.args.hostSerialNumber

			err := inventory.RegisterHost(tt.args.ctx, tt.args.c, tt.args.tenantID, tt.args.host)
			if err != nil {
				if tt.valid {
					t.Errorf("RegisterHost() failed: %s", err)
					t.FailNow()
				}
			} else {
				if !tt.valid {
					t.Errorf("RegisterHost() succeeded but should have failed")
					t.FailNow()
				}
			}

			if !t.Failed() && tt.valid {
				h, err := inventory.GetHostResourceByUUID(tt.args.ctx, tt.args.c, tt.args.tenantID, hostInv.GetUuid())
				require.NoError(t, err)
				require.NotNil(t, h)

				require.Equal(t, tt.args.hostUUID, h.GetUuid())
				require.Equal(t, tt.args.hostSerialNumber, h.GetSerialNumber())

				// other fields are not modified
				require.Equal(t, hostInv.GetCurrentState(), h.GetCurrentState())
			}
		})
	}
}

func TestUpdateInvResourceFields(t *testing.T) {
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	ctx := context.TODO()

	type args struct {
		resource proto.Message
		fields   []string
	}
	tests := []struct {
		name  string
		args  args
		valid bool
	}{
		{
			name: "Fail when no resource provided",
			args: args{
				resource: nil,
				fields:   []string{network_v1.IPAddressResourceFieldCurrentState},
			},
			valid: false,
		},
		{
			name: "Skip updating resource when no fields provided",
			args: args{
				resource: &computev1.HostResource{},
				fields:   []string{},
			},
			valid: true,
		},
		{
			name: "Update Host Storage resource",
			args: args{
				resource: dao.CreateHostStorage(t, loca_testing.Tenant1, dao.CreateHost(t, loca_testing.Tenant1)),
				fields:   []string{computev1.HoststorageResourceFieldDeviceName},
			},
			valid: true,
		},
		{
			name: "Update Host NIC resource",
			args: args{
				resource: dao.CreateHostNic(t, loca_testing.Tenant1, dao.CreateHost(t, loca_testing.Tenant1)),
				fields:   []string{computev1.HoststorageResourceFieldDeviceName},
			},
			valid: true,
		},
		{
			name: "Update Host USB resource",
			args: args{
				resource: dao.CreateHostUsb(t, loca_testing.Tenant1, dao.CreateHost(t, loca_testing.Tenant1)),
				fields:   []string{computev1.HoststorageResourceFieldDeviceName},
			},
			valid: true,
		},
		{
			name: "Update Host GPU resource",
			args: args{
				resource: dao.CreateHostGPU(t, loca_testing.Tenant1, dao.CreateHost(t, loca_testing.Tenant1)),
				fields:   []string{computev1.HoststorageResourceFieldDeviceName},
			},
			valid: true,
		},
		{
			name: "Fail when unsupported resource type",
			args: args{
				resource: &location_v1.SiteResource{},
				fields:   []string{location_v1.SiteResourceFieldName},
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := inventory.UpdateInvResourceFields(ctx, client, loca_testing.Tenant1, tt.args.resource, tt.args.fields)
			if err != nil {
				if tt.valid {
					t.Errorf("UpdateInvResourceFields() failed: %s", err)
					t.FailNow()
				}
			} else {
				if !tt.valid {
					t.Errorf("UpdateInvResourceFields() succeeded but should have failed")
					t.FailNow()
				}
			}
		})
	}
}

//nolint:dupl // this TC tests different functionality
func TestUpdateHostStateAndOnboardingStatus(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()

	hostInv := dao.CreateHost(t, loca_testing.Tenant1)

	currentTimeStamp, err := inv_util.Int64ToUint64(time.Now().Unix())
	assert.NoError(t, err)

	type args struct {
		ctx                       context.Context
		c                         inv_client.TenantAwareInventoryClient
		host                      *computev1.HostResource
		currentState              computev1.HostState
		onboardingStatus          string
		statusIndication          statusv1.StatusIndication
		statusIndicationTimestamp uint64
		tenantID                  string
	}
	tests := []struct {
		name  string
		args  args
		valid bool
	}{
		{
			name: "Success",
			args: args{
				ctx:                       context.TODO(),
				c:                         client,
				host:                      hostInv,
				currentState:              computev1.HostState_HOST_STATE_ONBOARDED,
				onboardingStatus:          "Host is active",
				statusIndication:          statusv1.StatusIndication_STATUS_INDICATION_IDLE,
				statusIndicationTimestamp: currentTimeStamp,
				tenantID:                  loca_testing.Tenant1,
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.args.host.CurrentState = tt.args.currentState
			tt.args.host.OnboardingStatus = tt.args.onboardingStatus
			tt.args.host.OnboardingStatusIndicator = tt.args.statusIndication
			tt.args.host.OnboardingStatusTimestamp = tt.args.statusIndicationTimestamp

			err := inventory.UpdateHostOnboardingStatus(tt.args.ctx, tt.args.c, tt.args.tenantID, tt.args.host)
			if err != nil {
				if tt.valid {
					t.Errorf("UpdateHostOnboardingStatus() failed: %s", err)
					t.FailNow()
				}
			} else {
				if !tt.valid {
					t.Errorf("UpdateHostOnboardingStatus() succeeded but should have failed")
					t.FailNow()
				}
			}

			//nolint:dupl // TC which have the same structure, but different resource
			if !t.Failed() && tt.valid {
				h, err := inventory.GetHostResourceByUUID(tt.args.ctx, tt.args.c, tt.args.tenantID, hostInv.GetUuid())
				require.NoError(t, err)
				require.NotNil(t, h)

				assert.Equal(t, tt.args.currentState, h.GetCurrentState())
				assert.Equal(t, tt.args.onboardingStatus, h.GetOnboardingStatus())
				assert.Equal(t, tt.args.statusIndication, h.GetOnboardingStatusIndicator())
				assert.Equal(t, tt.args.statusIndicationTimestamp, h.GetOnboardingStatusTimestamp())
			}
		})
	}
}

//nolint:dupl // this TC tests different functionality
func TestUpdateHostStateAndStatus(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()

	hostInv := dao.CreateHost(t, loca_testing.Tenant1)

	currentTimeStamp, err := inv_util.Int64ToUint64(time.Now().Unix())
	assert.NoError(t, err)

	type args struct {
		ctx                       context.Context
		c                         inv_client.TenantAwareInventoryClient
		host                      *computev1.HostResource
		currentState              computev1.HostState
		hostStatus                string
		statusIndication          statusv1.StatusIndication
		statusIndicationTimestamp uint64
		tenantID                  string
	}
	tests := []struct {
		name  string
		args  args
		valid bool
	}{
		{
			name: "Success",
			args: args{
				ctx:                       context.TODO(),
				c:                         client,
				host:                      hostInv,
				currentState:              computev1.HostState_HOST_STATE_UNTRUSTED,
				hostStatus:                "Host is NOT trusted",
				statusIndication:          statusv1.StatusIndication_STATUS_INDICATION_IDLE,
				statusIndicationTimestamp: currentTimeStamp,
				tenantID:                  loca_testing.Tenant1,
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.args.host.CurrentState = tt.args.currentState
			tt.args.host.HostStatus = tt.args.hostStatus
			tt.args.host.HostStatusIndicator = tt.args.statusIndication
			tt.args.host.HostStatusTimestamp = tt.args.statusIndicationTimestamp

			err := inventory.UpdateHostStatus(tt.args.ctx, tt.args.c, tt.args.tenantID, tt.args.host)
			if err != nil {
				if tt.valid {
					t.Errorf("UpdateHostStatus() failed: %s", err)
					t.FailNow()
				}
			} else {
				if !tt.valid {
					t.Errorf("UpdateHostStatus() succeeded but should have failed")
					t.FailNow()
				}
			}

			//nolint:dupl // TC which have the same structure, but different resource
			if !t.Failed() && tt.valid {
				h, err := inventory.GetHostResourceByUUID(tt.args.ctx, tt.args.c, tt.args.tenantID, hostInv.GetUuid())
				require.NoError(t, err)
				require.NotNil(t, h)

				assert.Equal(t, tt.args.currentState, h.GetCurrentState())
				assert.Equal(t, tt.args.hostStatus, h.GetHostStatus())
				assert.Equal(t, tt.args.statusIndication, h.GetHostStatusIndicator())
				assert.Equal(t, tt.args.statusIndicationTimestamp, h.GetHostStatusTimestamp())
			}
		})
	}
}

func TestUpdateInstanceStatus(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()

	locaProvider := dao.CreateProviderWithArgs(t,
		loca_testing.Tenant1,
		"Lenovo", "192.168.0.3",
		[]string{
			"username:" + loca_testing.DefaultUsername,
			"password:" + loca_testing.DefaultPassword,
		},
		providerv1.ProviderVendor_PROVIDER_VENDOR_LENOVO_LOCA,
		inv_testing.ProviderKind(providerv1.ProviderKind_PROVIDER_KIND_BAREMETAL),
	)
	hostInv := dao.CreateHost(t, loca_testing.Tenant1, inv_testing.HostProvider(locaProvider))
	osInv := dao.CreateOs(t, loca_testing.Tenant1)
	instInv := dao.CreateInstanceWithProvider(t, loca_testing.Tenant1, hostInv, osInv, locaProvider)

	currentTimeStamp, err := inv_util.Int64ToUint64(time.Now().Unix())
	assert.NoError(t, err)

	type args struct {
		ctx                context.Context
		c                  inv_client.TenantAwareInventoryClient
		currentState       computev1.InstanceState
		provisioningStatus string
		statusIndicator    statusv1.StatusIndication
		timestamp          uint64
		tenantID           string
	}
	tests := []struct {
		name  string
		args  args
		valid bool
	}{
		{
			name: "Success",
			args: args{
				ctx:                context.TODO(),
				c:                  client,
				currentState:       computev1.InstanceState_INSTANCE_STATE_DELETED,
				provisioningStatus: "some status detail",
				statusIndicator:    statusv1.StatusIndication_STATUS_INDICATION_IDLE,
				timestamp:          currentTimeStamp,
				tenantID:           loca_testing.Tenant1,
			},
			valid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := inventory.UpdateInstanceProvisioningStatus(tt.args.ctx, tt.args.c, tt.args.tenantID,
				&computev1.InstanceResource{
					ResourceId:                  instInv.GetResourceId(),
					CurrentState:                tt.args.currentState,
					ProvisioningStatus:          tt.args.provisioningStatus,
					ProvisioningStatusIndicator: tt.args.statusIndicator,
					ProvisioningStatusTimestamp: tt.args.timestamp,
				})
			if err != nil {
				if tt.valid {
					t.Errorf("UpdateInstanceStatus() failed: %s", err)
					t.FailNow()
				}
			} else {
				if !tt.valid {
					t.Errorf("UpdateInstanceStatus() succeeded but should have failed")
					t.FailNow()
				}
			}

			//nolint:dupl // TC which have the same structure, but different resource
			if !t.Failed() && tt.valid {
				retInst, err := inventory.GetInstanceResourceByName(tt.args.ctx, tt.args.c, tt.args.tenantID, instInv.GetName())
				require.NoError(t, err)
				require.NotNil(t, retInst)

				assert.Equal(t, tt.args.currentState, retInst.GetCurrentState())
				assert.Equal(t, tt.args.provisioningStatus, retInst.GetProvisioningStatus())
				assert.Equal(t, tt.args.statusIndicator, retInst.GetProvisioningStatusIndicator())
				assert.Equal(t, tt.args.timestamp, retInst.GetProvisioningStatusTimestamp())
			}
		})
	}
}

//nolint:dupl // This TC verifies the same scenario with different resource
func Test_ListAllHostsByProviderName(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// no Hosts - an empty list should be returned
	hostList, err := inventory.ListAllHostsByLOCAProvider(ctx, client, loca_testing.Tenant1, apiEndpoint)
	require.NoError(t, err)
	assert.Equal(t, len(hostList), 0)

	// create two Hosts with empty provider
	_ = dao.CreateHost(t, loca_testing.Tenant1)
	_ = dao.CreateHost(t, loca_testing.Tenant1)

	// still an empty list should be returned
	hostList, err = inventory.ListAllHostsByLOCAProvider(ctx, client, loca_testing.Tenant1, apiEndpoint)
	require.NoError(t, err)
	assert.Equal(t, len(hostList), 0)

	// create Lenovo provider
	lenovoProvider := dao.CreateProviderWithArgs(t,
		loca_testing.Tenant1,
		"LOC-A#1", apiEndpoint,
		[]string{
			"username:" + loca_testing.DefaultUsername,
			"password:" + loca_testing.DefaultPassword,
		},
		providerv1.ProviderVendor_PROVIDER_VENDOR_LENOVO_LOCA,
		inv_testing.ProviderKind(providerv1.ProviderKind_PROVIDER_KIND_BAREMETAL),
	)

	// create a Host Lenovo provider
	hostInv := dao.CreateHost(t, loca_testing.Tenant1, inv_testing.HostProvider(lenovoProvider))

	// still an empty list should be returned
	hostList, err = inventory.ListAllHostsByLOCAProvider(ctx, client, loca_testing.Tenant1, apiEndpoint)
	require.NoError(t, err)
	require.Equal(t, len(hostList), 1)
	assert.Equal(t, hostInv.GetResourceId(), hostList[0].GetResourceId())
	assert.Equal(t, hostInv.GetUuid(), hostList[0].GetUuid())
	assert.Equal(t, hostInv.GetSerialNumber(), hostList[0].GetSerialNumber())
}

func Test_GetLOCAProviderResource(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	providerName := "not LOC-A"
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// no Providers - an error should be returned
	provider, err := inventory.GetLOCAProviderResource(ctx, client, loca_testing.Tenant1, apiEndpoint)
	require.Error(t, err)
	assert.Nil(t, provider)

	// creating provider
	_ = dao.CreateProvider(t, loca_testing.Tenant1,
		providerName, inv_testing.ProviderKind(providerv1.ProviderKind_PROVIDER_KIND_BAREMETAL),
	)

	// a single Provider, but not LOC-A, is present in Inventory, an error should still occur
	provider, err = inventory.GetLOCAProviderResource(ctx, client, loca_testing.Tenant1, apiEndpoint)
	require.Error(t, err)
	assert.Nil(t, provider)

	// creating LOC-A provider
	locaProvider := dao.CreateProviderWithArgs(t,
		loca_testing.Tenant1,
		"LOC-A#1", apiEndpoint,
		[]string{
			"username:" + loca_testing.DefaultUsername,
			"password:" + loca_testing.DefaultPassword,
		},
		providerv1.ProviderVendor_PROVIDER_VENDOR_LENOVO_LOCA,
		inv_testing.ProviderKind(providerv1.ProviderKind_PROVIDER_KIND_BAREMETAL),
	)

	// a single Provider, but not LOC-A, is present in Inventory, an error should still occur
	provider, err = inventory.GetLOCAProviderResource(ctx, client, loca_testing.Tenant1, apiEndpoint)
	require.NoError(t, err)
	assert.NotNil(t, provider)
	assert.Equal(t, provider.GetResourceId(), locaProvider.GetResourceId())
}

func Test_ListLOCAProviderResources(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// No LOC-A providers are present in Inventory
	providers, err := inventory.ListLOCAProviderResources(ctx, client)
	require.NoError(t, err)
	assert.NotNil(t, providers)
	assert.Equal(t, 0, len(providers))

	// creating two LOC-A providers
	_ = dao.CreateProviderWithArgs(t,
		loca_testing.Tenant1,
		"LOC-A#1", apiEndpoint,
		[]string{
			"username:" + loca_testing.DefaultUsername,
			"password:" + loca_testing.DefaultPassword,
		},
		providerv1.ProviderVendor_PROVIDER_VENDOR_LENOVO_LOCA,
		inv_testing.ProviderKind(providerv1.ProviderKind_PROVIDER_KIND_BAREMETAL),
	)
	_ = dao.CreateProviderWithArgs(t,
		loca_testing.Tenant2,
		"LOC-A#2", "192.172.1.1",
		[]string{
			"username:" + loca_testing.DefaultUsername,
			"password:" + loca_testing.DefaultPassword,
		},
		providerv1.ProviderVendor_PROVIDER_VENDOR_LENOVO_LOCA,
		inv_testing.ProviderKind(providerv1.ProviderKind_PROVIDER_KIND_BAREMETAL),
	)

	// two LOC-A providers are present in Inventory from different tenants
	providers, err = inventory.ListLOCAProviderResources(ctx, client)
	require.NoError(t, err)
	assert.NotNil(t, providers)
	assert.Equal(t, 2, len(providers))

	// creating other than LOC-A provider
	_ = dao.CreateProvider(t, uuid.NewString(), loca_testing.Tenant1,
		inv_testing.ProviderKind(providerv1.ProviderKind_PROVIDER_KIND_BAREMETAL),
	)

	// three Providers in total, but two LOC-A providers are present in Inventory
	providers, err = inventory.ListLOCAProviderResources(ctx, client)
	require.NoError(t, err)
	assert.NotNil(t, providers)
	assert.Equal(t, 2, len(providers))
}

func Test_CreateInstanceResource(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// creating provider
	locaProvider := dao.CreateProvider(t, loca_testing.Tenant1, "Lenovo",
		inv_testing.ProviderKind(providerv1.ProviderKind_PROVIDER_KIND_BAREMETAL),
	)

	// creating Host Resource
	host := dao.CreateHost(t, loca_testing.Tenant1, inv_testing.HostProvider(locaProvider))

	// Creating OS profile
	osRes := dao.CreateOs(t, loca_testing.Tenant1)

	// Creating Instance itself
	instance, err := inventory.CreateInstanceResource(ctx, client, loca_testing.Tenant1, &computev1.InstanceResource{},
		osRes, host)
	require.NoError(t, err)
	require.NotNil(t, instance)

	// cleaning up DB
	dao.HardDeleteInstance(t, loca_testing.Tenant1, instance.GetResourceId())
}

func TestInvClient_DeleteHostnic(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()

	// Not found, does not return error
	err := inventory.DeleteHostnic(ctx, client, loca_testing.Tenant1, "hostnic-12345678")
	require.NoError(t, err)

	// creating Host NIC
	host := dao.CreateHost(t, loca_testing.Tenant1)
	nic := dao.CreateHostNicNoCleanup(t, loca_testing.Tenant1, host)
	assert.NotNil(t, nic)

	err = inventory.DeleteHostnic(ctx, client, loca_testing.Tenant1, nic.GetResourceId())
	require.NoError(t, err)
}

func TestInvClient_DeleteIPAddress(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()

	// Not found, does not return error
	err := inventory.DeleteIPAddress(ctx, client, loca_testing.Tenant1, "ipaddr-12345678")
	require.NoError(t, err)

	// Creating IP address resource
	host := dao.CreateHost(t, loca_testing.Tenant1)
	nic := dao.CreateHostNic(t, loca_testing.Tenant1, host)
	ipAddr := dao.CreateIPAddress(t, loca_testing.Tenant1, nic, false)

	// OK
	err = inventory.DeleteIPAddress(ctx, client, loca_testing.Tenant1, ipAddr.GetResourceId())
	require.NoError(t, err)
}

//nolint:dupl // refactor later
func TestInvClient_DeleteHoststorage(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()

	// Not found, does not return error
	err := inventory.DeleteHoststorage(ctx, client, loca_testing.Tenant1, "hoststorage-12345678")
	require.NoError(t, err)

	// Creating Host Storage resource
	host := dao.CreateHost(t, loca_testing.Tenant1)
	storage := dao.CreateHostStorageNoCleanup(t, loca_testing.Tenant1, host)

	// OK
	err = inventory.DeleteHoststorage(ctx, client, loca_testing.Tenant1, storage.GetResourceId())
	require.NoError(t, err)
}

//nolint:dupl // refactor later
func TestInvClient_DeleteHostUsbResource(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()

	// Not found, does not return error
	err := inventory.DeleteHostusb(ctx, client, loca_testing.Tenant1, "hostusb-12345678")
	require.NoError(t, err)

	// create usb
	host := dao.CreateHost(t, loca_testing.Tenant1)
	usb := dao.CreateHostUsbNoCleanup(t, loca_testing.Tenant1, host)

	// OK
	err = inventory.DeleteHostusb(ctx, client, loca_testing.Tenant1, usb.GetResourceId())
	require.NoError(t, err)
}

func TestInvClient_DeleteHostgpu(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()

	// Not found, does not return error
	err := inventory.DeleteHostgpu(ctx, client, loca_testing.Tenant1, "hostgpu-12345678")
	require.NoError(t, err)

	// OK
	host := dao.CreateHost(t, loca_testing.Tenant1)
	gpu := dao.CreateHostGPUNoCleanup(t, loca_testing.Tenant1, host)

	err = inventory.DeleteHostgpu(ctx, client, loca_testing.Tenant1, gpu.ResourceId)
	require.NoError(t, err)
}

func TestInvClient_UpdateHostCurrentState(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()

	host := &computev1.HostResource{}

	// Not found, returns error
	err := inventory.UpdateHostCurrentState(ctx, client, loca_testing.Tenant1, host, computev1.HostState_HOST_STATE_DELETED)
	require.Error(t, err)

	// OK
	host = dao.CreateHost(t, loca_testing.Tenant1)
	err = inventory.UpdateHostCurrentState(ctx, client, loca_testing.Tenant1, host, computev1.HostState_HOST_STATE_DELETED)
	require.NoError(t, err)

	// retrieving Host back to check that the current state has been changed
	retHost, err := inventory.GetHostResourceByUUID(ctx, client, loca_testing.Tenant1, host.GetUuid())
	require.NoError(t, err)
	require.NotNil(t, retHost)
	assert.Equal(t, retHost.GetCurrentState(), computev1.HostState_HOST_STATE_DELETED)
}

func TestInvClient_UpdateInstanceCurrentState(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()

	instance := &computev1.InstanceResource{}

	// Not found, returns error
	err := inventory.UpdateInstanceCurrentState(
		ctx, client, loca_testing.Tenant1, instance, computev1.InstanceState_INSTANCE_STATE_DELETED)
	require.Error(t, err)

	// OK
	host := dao.CreateHost(t, loca_testing.Tenant1)
	osRes := dao.CreateOs(t, loca_testing.Tenant1)
	instance = dao.CreateInstance(t, loca_testing.Tenant1, host, osRes)
	err = inventory.UpdateInstanceCurrentState(
		ctx, client, loca_testing.Tenant1, instance, computev1.InstanceState_INSTANCE_STATE_DELETED)
	require.NoError(t, err)

	// retrieving Instance back to check that the current state has been changed
	retInstance, err := inventory.GetInstanceResourceByName(ctx, client, loca_testing.Tenant1, instance.GetName())
	require.NoError(t, err)
	require.NotNil(t, retInstance)
	assert.Equal(t, retInstance.GetCurrentState(), computev1.InstanceState_INSTANCE_STATE_DELETED)
}

func TestInvClient_UpdateInstanceName(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()

	instance := &computev1.InstanceResource{}

	testInstName := "testName"

	// Not found, returns error
	err := inventory.UpdateInstanceName(ctx, client, loca_testing.Tenant1, instance, testInstName)
	require.Error(t, err)

	// OK
	host := dao.CreateHost(t, loca_testing.Tenant1)
	osRes := dao.CreateOs(t, loca_testing.Tenant1)
	instance = dao.CreateInstance(t, loca_testing.Tenant1, host, osRes)

	// ensuring that the Init Instance Name is different from the test instance name
	require.NotEqualf(t, testInstName, instance.GetName(), "Init instance name should be different")

	// updating the instance name
	err = inventory.UpdateInstanceName(ctx, client, loca_testing.Tenant1, instance, testInstName)
	require.NoError(t, err)

	// retrieving Instance back to check that the Instance Name has been changed
	retInstance, err := inventory.GetInstanceResourceByResourceID(ctx, client, loca_testing.Tenant1, instance.GetResourceId())
	require.NoError(t, err)
	require.NotNil(t, retInstance)
	assert.Equal(t, testInstName, retInstance.GetName())
}

func TestInvClient_GetHostResourceByResourceId(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()

	// Error - empty Resource ID
	noHost, err := inventory.GetHostResourceByResourceID(ctx, client, loca_testing.Tenant1, "")
	require.Error(t, err)
	assert.Equal(t, grpc_status.Code(err).String(), codes.InvalidArgument.String())
	require.Nil(t, noHost)

	// Error - not existing Host resource ID
	noHost, err = inventory.GetHostResourceByResourceID(ctx, client, loca_testing.Tenant1, "host-12345678")
	require.Error(t, err)
	assert.Equal(t, grpc_status.Code(err).String(), codes.NotFound.String())
	require.Nil(t, noHost)

	// Error - instance resource ID instead of host
	instance := dao.CreateInstance(t, loca_testing.Tenant1, dao.CreateHost(t, loca_testing.Tenant1),
		dao.CreateOs(t, loca_testing.Tenant1))
	noHost, err = inventory.GetHostResourceByResourceID(ctx, client, loca_testing.Tenant1, instance.GetResourceId())
	require.Error(t, err)
	assert.Equal(t, grpc_status.Code(err).String(), codes.Internal.String())
	assert.ErrorContains(t, err, "Obtained Host from Inventory is 'nil'")
	require.Nil(t, noHost)

	// OK - gets instance
	host := dao.CreateHost(t, loca_testing.Tenant1)
	getHost, err := inventory.GetHostResourceByResourceID(ctx, client, loca_testing.Tenant1, host.GetResourceId())
	require.NoError(t, err)
	require.NotNil(t, getHost)
	assert.Equal(t, host.GetResourceId(), getHost.GetResourceId())
}

func TestInvClient_GetInstanceResourceByResourceId(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()

	// Error - empty Resource ID
	noInstance, err := inventory.GetInstanceResourceByResourceID(ctx, client, loca_testing.Tenant1, "")
	require.Error(t, err)
	assert.Equal(t, grpc_status.Code(err).String(), codes.InvalidArgument.String())
	require.Nil(t, noInstance)

	// Error - not existing Instance resource ID
	noInstance, err = inventory.GetInstanceResourceByResourceID(ctx, client, loca_testing.Tenant1, "inst-12345678")
	require.Error(t, err)
	assert.Equal(t, grpc_status.Code(err).String(), codes.NotFound.String())
	require.Nil(t, noInstance)

	// Error - host resource ID instead of instance
	host := dao.CreateHost(t, loca_testing.Tenant1)
	noInstance, err = inventory.GetInstanceResourceByResourceID(ctx, client, loca_testing.Tenant1, host.GetResourceId())
	require.Error(t, err)
	assert.Equal(t, grpc_status.Code(err).String(), codes.Internal.String())
	assert.ErrorContains(t, err, "Obtained Instance from Inventory is 'nil'")
	require.Nil(t, noInstance)

	// OK - gets Instance
	host = dao.CreateHost(t, loca_testing.Tenant1)
	osRes := dao.CreateOs(t, loca_testing.Tenant1)
	instance := dao.CreateInstance(t, loca_testing.Tenant1, host, osRes)
	getInst, err := inventory.GetInstanceResourceByResourceID(ctx, client, loca_testing.Tenant1, instance.GetResourceId())
	require.NoError(t, err)
	require.NotNil(t, getInst)
	assert.Equal(t, instance.GetResourceId(), getInst.GetResourceId())
}

func TestInvClient_GetSingularTenantIDFromProviders(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	providers, err := inventory.ListLOCAProviderResources(ctx, client)
	require.NoError(t, err)
	// No providers
	tID, err := inventory.GetSingularTenantIDFromProviders(providers)
	require.Error(t, err)
	assert.Empty(t, tID)
	assert.Equal(t, codes.NotFound, grpc_status.Code(err))

	_ = dao.CreateProviderWithArgs(t,
		loca_testing.Tenant1,
		"LOC-A#1", apiEndpoint,
		[]string{
			"username:" + loca_testing.DefaultUsername,
			"password:" + loca_testing.DefaultPassword,
		},
		providerv1.ProviderVendor_PROVIDER_VENDOR_LENOVO_LOCA,
		inv_testing.ProviderKind(providerv1.ProviderKind_PROVIDER_KIND_BAREMETAL),
	)
	_ = dao.CreateProviderWithArgs(t,
		loca_testing.Tenant1,
		"LOC-A#2", apiEndpoint,
		[]string{
			"username:" + loca_testing.DefaultUsername,
			"password:" + loca_testing.DefaultPassword,
		},
		providerv1.ProviderVendor_PROVIDER_VENDOR_LENOVO_LOCA,
		inv_testing.ProviderKind(providerv1.ProviderKind_PROVIDER_KIND_BAREMETAL),
	)

	providers, err = inventory.ListLOCAProviderResources(ctx, client)
	require.NoError(t, err)
	// 2 providers single tenant
	tID, err = inventory.GetSingularTenantIDFromProviders(providers)
	require.NoError(t, err)
	assert.Equal(t, loca_testing.Tenant1, tID)

	// creating other than LOC-A provider
	_ = dao.CreateProvider(t, uuid.NewString(), loca_testing.Tenant2,
		inv_testing.ProviderKind(providerv1.ProviderKind_PROVIDER_KIND_BAREMETAL),
	)

	providers, err = inventory.ListLOCAProviderResources(ctx, client)
	require.NoError(t, err)
	// 3 providers multiple tenants, but only 2 LOCA providers!
	tID, err = inventory.GetSingularTenantIDFromProviders(providers)
	require.NoError(t, err)
	assert.Equal(t, loca_testing.Tenant1, tID)

	_ = dao.CreateProviderWithArgs(t,
		loca_testing.Tenant2,
		"LOC-A#2", "192.172.1.1",
		[]string{
			"username:" + loca_testing.DefaultUsername,
			"password:" + loca_testing.DefaultPassword,
		},
		providerv1.ProviderVendor_PROVIDER_VENDOR_LENOVO_LOCA,
		inv_testing.ProviderKind(providerv1.ProviderKind_PROVIDER_KIND_BAREMETAL),
	)

	providers, err = inventory.ListLOCAProviderResources(ctx, client)
	require.NoError(t, err)
	// 4 providers multiple tenants, multiple tenants for LOCA providers!
	tID, err = inventory.GetSingularTenantIDFromProviders(providers)
	require.Error(t, err)
	assert.Empty(t, tID)
	assert.Equal(t, codes.Internal, grpc_status.Code(err))
}

//nolint:dupl // This TC verifies the same scenario with different resource
func Test_ListAllSitesByProviderName(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// no Sites - an empty list should be returned
	siteList, err := inventory.ListAllSitesByLOCAProvider(ctx, client, loca_testing.Tenant1, apiEndpoint)
	require.NoError(t, err)
	assert.Equal(t, len(siteList), 0)

	// create two Sites with empty provider
	_ = dao.CreateSite(t, loca_testing.Tenant1)
	_ = dao.CreateSite(t, loca_testing.Tenant1)

	// still an empty list should be returned
	siteList, err = inventory.ListAllSitesByLOCAProvider(ctx, client, loca_testing.Tenant1, apiEndpoint)
	require.NoError(t, err)
	assert.Equal(t, len(siteList), 0)

	// create Lenovo provider
	lenovoProvider := dao.CreateProviderWithArgs(t,
		loca_testing.Tenant1,
		"LOC-A#1", apiEndpoint,
		[]string{
			"username:" + loca_testing.DefaultUsername,
			"password:" + loca_testing.DefaultPassword,
		},
		providerv1.ProviderVendor_PROVIDER_VENDOR_LENOVO_LOCA,
		inv_testing.ProviderKind(providerv1.ProviderKind_PROVIDER_KIND_BAREMETAL),
	)

	// create a Site with Lenovo provider
	siteInv := dao.CreateSite(t, loca_testing.Tenant1, inv_testing.SiteProvider(lenovoProvider))

	// returned list should contain precisely one Site Resource
	siteList, err = inventory.ListAllSitesByLOCAProvider(ctx, client, loca_testing.Tenant1, apiEndpoint)
	require.NoError(t, err)
	require.Equal(t, len(siteList), 1)
	assert.Equal(t, siteInv.GetResourceId(), siteList[0].GetResourceId())
	assert.Equal(t, siteInv.GetName(), siteList[0].GetName())
	assert.Equal(t, siteInv.GetTenantId(), siteList[0].GetTenantId())
}

func Test_ListAllSitesByTenantID(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// no Sites - an empty list should be returned
	siteList, err := inventory.ListAllSitesByTenantID(ctx, client, loca_testing.Tenant1)
	require.NoError(t, err)
	assert.Equal(t, len(siteList), 0)

	// create two Sites
	_ = dao.CreateSite(t, loca_testing.Tenant1)
	_ = dao.CreateSite(t, loca_testing.Tenant1)

	// still an empty list should be returned
	siteList, err = inventory.ListAllSitesByTenantID(ctx, client, loca_testing.Tenant1)
	require.NoError(t, err)
	assert.Equal(t, len(siteList), 2)

	// create Site with other Tenant
	_ = dao.CreateSite(t, loca_testing.Tenant2)

	// returned list should contain precisely one Site Resource
	siteList, err = inventory.ListAllSitesByTenantID(ctx, client, loca_testing.Tenant1)
	require.NoError(t, err)
	require.Equal(t, len(siteList), 2)
}

func TestListAllMutableOperatingSystems_whenRequestingOsForSameTenantShouldReturnOs(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	dao.CreateOs(t, loca_testing.Tenant1)

	operatingSystems, err := inventory.ListAllMutableOperatingSystems(ctx, client, loca_testing.Tenant1)
	assert.NoError(t, err)
	assert.Len(t, operatingSystems, 1)
	assert.Equal(t, os_v1.OsType_OS_TYPE_MUTABLE, operatingSystems[0].OsType)
}

func TestListAllMutableOperatingSystems_whenTenantDoesntHasMutableOsThenEmptyListShouldBeReturned(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	dao.CreateOsWithOpts(t, loca_testing.Tenant1, true, func(osr *os_v1.OperatingSystemResource) {
		osr.Sha256 = inv_testing.GenerateRandomSha256()
		osr.ProfileName = inv_testing.GenerateRandomProfileName()
		osr.SecurityFeature = os_v1.SecurityFeature_SECURITY_FEATURE_UNSPECIFIED
		osr.OsType = os_v1.OsType_OS_TYPE_IMMUTABLE
	})

	operatingSystems, err := inventory.ListAllMutableOperatingSystems(ctx, client, loca_testing.Tenant1)
	assert.NoError(t, err)
	assert.Len(t, operatingSystems, 0)
}

func TestListAllMutableOperatingSystems_whenRequestingOsOwnedByDifferentTenantShouldReturnEmptyResponse(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	dao.CreateOs(t, loca_testing.Tenant1)

	operatingSystems, err := inventory.ListAllMutableOperatingSystems(ctx, client, loca_testing.Tenant2)
	assert.NoError(t, err)
	assert.Len(t, operatingSystems, 0)
}

func TestCreateOSResource(t *testing.T) {
	client := inv_testing.TestClients[inv_testing.APIClient].GetTenantAwareInventoryClient()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	osRes := &os_v1.OperatingSystemResource{
		Name:            "Ubuntu 22.04.3",
		OsType:          os_v1.OsType_OS_TYPE_MUTABLE,
		ProfileName:     "ubuntu-lenovo",
		ImageUrl:        "https://old-releases.ubuntu.com/releases/22.04/ubuntu-22.04.3-live-server-amd64.iso.",
		ImageId:         "22.04.3",
		Sha256:          "a4acfda10b18da50e2ec50ccaf860d7f20b389df8765611142305c0e911d16fd",
		SecurityFeature: os_v1.SecurityFeature_SECURITY_FEATURE_SECURE_BOOT_AND_FULL_DISK_ENCRYPTION,
		OsProvider:      os_v1.OsProviderKind_OS_PROVIDER_KIND_LENOVO,
		TenantId:        loca_testing.Tenant1,
	}

	resourceID, err := inventory.CreateOSResource(ctx, client, loca_testing.Tenant1, osRes)
	assert.NoError(t, err)

	// check if resource exist in Inventory - no error is enough
	_, err = client.Get(ctx, loca_testing.Tenant1, resourceID)
	assert.NoError(t, err)

	// attempt to create duplicated resource with different tenant - should fail
	osRes.TenantId = loca_testing.Tenant2
	_, err = inventory.CreateOSResource(ctx, client, loca_testing.Tenant1, osRes)
	assert.Error(t, err)

	// cleaning up resource from Inventory
	_, err = client.Delete(ctx, loca_testing.Tenant1, resourceID)
	require.NoError(t, err)
}

func TestCreateSiteResource(t *testing.T) {
	client := inv_testing.TestClients[inv_testing.APIClient].GetTenantAwareInventoryClient()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	provider := loca_testing.PopulateInventoryWithLOCAProvider(t, loca_testing.Tenant1,
		"LOC-A #1", "https://provider.com/api/v1")

	siteRes := &location_v1.SiteResource{
		Name:     "Test_Site",
		Address:  "Very long street name",
		SiteLat:  373541070,
		SiteLng:  -1219552380,
		Provider: provider,
		TenantId: loca_testing.Tenant1,
	}

	resourceID, err := inventory.CreateSiteResource(ctx, client, loca_testing.Tenant1, siteRes)
	assert.NoError(t, err)

	// check if resource exist in Inventory - no error is enough
	_, err = client.Get(ctx, loca_testing.Tenant1, resourceID)
	assert.NoError(t, err)

	// attempt to create duplicated resource with different tenant - should fail
	siteRes.TenantId = loca_testing.Tenant2
	_, err = inventory.CreateSiteResource(ctx, client, loca_testing.Tenant1, siteRes)
	assert.Error(t, err)

	// cleaning up resource from Inventory
	_, err = client.Delete(ctx, loca_testing.Tenant1, resourceID)
	require.NoError(t, err)
}

// TestRemoveHost_failsOnCredentialsRevocationError verifies that the removal of a host fails when the revocation
// of credentials fails.
func TestRemoveHost_failsOnCredentialsRevocationError(t *testing.T) {
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// revoking of credentials should fail
	auth.AuthServiceFactory = auth.AuthServiceMockFactory(t, false, false, true)

	host := dao.CreateHost(t, loca_testing.Tenant1)

	// removing Host should fail due to failed credentials revocation
	err := inventory.RemoveHost(ctx, client, loca_testing.Tenant1, host)
	require.Error(t, err)
	assert.Equal(t, grpc_status.Code(err).String(), codes.Internal.String())
}

func TestUpdateHostSite(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// create site
	siteName := "Test_Site"
	site := loca_testing.PopulateInventoryWithSite(t, loca_testing.Tenant1, siteName)

	// create host without site
	host := dao.CreateHost(t, loca_testing.Tenant1)
	assert.Nil(t, host.GetSite())

	// update host with site
	host.Site = site
	err := inventory.UpdateHostSite(ctx, client, loca_testing.Tenant1, host)
	assert.NoError(t, err)

	// check if host is updated
	getHost, err := inventory.GetHostResourceByUUID(ctx, client, loca_testing.Tenant1, host.GetUuid())
	assert.NoError(t, err)
	assert.Equal(t, site.GetName(), getHost.GetSite().GetName())
}

func Test_GetSiteResourceByResourceID(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	client := inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// no Sites - an empty list should be returned
	siteList, err := inventory.GetSiteResourceByResourceID(ctx, client, loca_testing.Tenant1, "")
	require.Error(t, err)
	require.Nil(t, siteList)

	siteRes := &location_v1.SiteResource{
		Name:     "Test_Site",
		Address:  "Very long street name",
		SiteLat:  373541070,
		SiteLng:  -1219552380,
		TenantId: loca_testing.Tenant1,
	}

	// create a new site
	resourceID, err := inventory.CreateSiteResource(ctx, client, loca_testing.Tenant1, siteRes)
	assert.NoError(t, err)

	_ = dao.CreateSite(t, loca_testing.Tenant1)

	// list size should be 1
	siteList, err = inventory.GetSiteResourceByResourceID(ctx, client, loca_testing.Tenant1, resourceID)
	require.NoError(t, err)
	require.NotNil(t, siteList)
}
