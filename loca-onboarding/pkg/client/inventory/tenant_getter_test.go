// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0
package inventory_test

import (
	"flag"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	invv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	providerv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/provider/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	inv_testing "github.com/open-edge-platform/infra-core/inventory/v2/pkg/testing"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/inventory"
	loca_testing "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/testing"
)

func TestTenantGetter_Init(t *testing.T) {
	var wg sync.WaitGroup

	// Expected to fail in test
	err := inventory.InitTenantGetter(&wg, "bufconn", false)
	require.Error(t, err)

	inventory.TestInitTenantGetter(
		inv_testing.TestClients[inv_testing.RMClient].GetTenantAwareInventoryClient(), make(chan *client.WatchEvents))

	getSingularTenantID, gotErr := inventory.GetSingularProviderTenantID()
	assert.Empty(t, getSingularTenantID)
	assert.Error(t, gotErr)
	assert.Equal(t, codes.Unavailable, status.Code(gotErr))
}

func TestTenantGetter_TenantGetterNotInitialized(t *testing.T) {
	inventory.TestResetTenantGetter()
	err := inventory.StartTenantGetter()
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.ErrorContains(t, err, "tenant getter not initialized")

	tID, err := inventory.GetSingularProviderTenantID()
	require.Error(t, err)
	assert.Empty(t, tID)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.ErrorContains(t, err, "tenant getter not initialized")
}

func TestTenantGetter_StartStop(t *testing.T) {
	inventory.TestInitTenantGetter(
		inv_testing.TestClients[tenantGetterClientKind].GetTenantAwareInventoryClient(),
		inv_testing.TestClientsEvents[tenantGetterClientKind],
	)
	err := inventory.StartTenantGetter()
	require.NoError(t, err)

	tID, err := inventory.GetSingularProviderTenantID()
	assert.Empty(t, tID)
	assert.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))

	inventory.StopTenantGetter()
	time.Sleep(100 * time.Millisecond)

	CreateProviderForTenantGetterTest(t, loca_testing.Tenant1, true)

	// No updates to the tenant ID because tenant getter was already stopped
	tID, err = inventory.GetSingularProviderTenantID()
	assert.Empty(t, tID)
	assert.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestTenantGetter_StartStopMultiple(t *testing.T) {
	// Validate if any races between start and stop.
	inventory.TestInitTenantGetter(
		inv_testing.TestClients[tenantGetterClientKind].GetTenantAwareInventoryClient(),
		inv_testing.TestClientsEvents[tenantGetterClientKind],
	)
	inventory.StopTenantGetter()

	err := inventory.StartTenantGetter()
	require.NoError(t, err)

	CreateProviderForTenantGetterTest(t, loca_testing.Tenant1, true)

	time.Sleep(10 * time.Millisecond)

	tID, err := inventory.GetSingularProviderTenantID()
	assert.Empty(t, tID)
	assert.ErrorContains(t, err, "inventory client is not registered")

	inventory.StopTenantGetter()
}

func TestTenantGetter_GetSingularTenantID(t *testing.T) {
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	provider1 := CreateProviderForTenantGetterTest(t, loca_testing.Tenant1, false)
	// User helper function for test to setup tenant getter.
	loca_testing.SetupTenantGetterTest()
	defer inventory.StopTenantGetter()

	tID, err := inventory.GetSingularProviderTenantID()
	assert.NoError(t, err)
	assert.Equal(t, loca_testing.Tenant1, tID)

	dao.DeleteResource(t, loca_testing.Tenant1, provider1.GetResourceId())

	// Give some time to manage the event.
	time.Sleep(100 * time.Millisecond)

	tID, err = inventory.GetSingularProviderTenantID()
	assert.Empty(t, tID)
	assert.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))

	CreateProviderForTenantGetterTest(t, loca_testing.Tenant2, true)

	// Give some time to manage the event.
	time.Sleep(100 * time.Millisecond)

	tID, err = inventory.GetSingularProviderTenantID()
	assert.NoError(t, err)
	assert.Equal(t, loca_testing.Tenant2, tID)

	CreateProviderForTenantGetterTest(t, loca_testing.Tenant1, true)

	// Give some time to manage the event.
	time.Sleep(100 * time.Millisecond)

	tID, err = inventory.GetSingularProviderTenantID()
	assert.Empty(t, tID)
	assert.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
	assert.ErrorContains(t, err, "Found multiple providers!")
}

func TestTenantGetter_TestForcedRefresh(t *testing.T) {
	err := flag.Set("tenantGetterRefresh", "2s")
	require.NoError(t, err)

	err = recreateClient(tenantGetterClientKind)
	require.NoError(t, err)

	inventory.TestInitTenantGetter(
		inv_testing.TestClients[tenantGetterClientKind].GetTenantAwareInventoryClient(),
		make(chan *client.WatchEvents), // pass fake watch channel, we want to update status with tenant refresher.
	)
	err = inventory.StartTenantGetter()
	require.NoError(t, err)
	defer inventory.StopTenantGetter()

	tID, err := inventory.GetSingularProviderTenantID()
	assert.Empty(t, tID)
	assert.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))

	CreateProviderForTenantGetterTest(t, loca_testing.Tenant1, true)
	// Wait a little bit more than tenantGetterRefresh interval, to ensure update is done.
	time.Sleep(2*time.Second + 200*time.Millisecond)
	tID, err = inventory.GetSingularProviderTenantID()
	assert.NoError(t, err)
	assert.Equal(t, loca_testing.Tenant1, tID)
}

// recreates client if it was closed by test previously.
func recreateClient(ct inv_testing.ClientType) error {
	delete(inv_testing.TestClients, ct)
	delete(inv_testing.TestClientsEvents, ct)

	return inv_testing.CreateClient(
		tenantGetterClientKind,
		invv1.ClientKind_CLIENT_KIND_RESOURCE_MANAGER,
		[]invv1.ResourceKind{invv1.ResourceKind_RESOURCE_KIND_PROVIDER},
		"")
}

func CreateProviderForTenantGetterTest(t *testing.T, tenantID string, cleanup bool) *providerv1.ProviderResource {
	t.Helper()
	dao := inv_testing.NewInvResourceDAOOrFail(t)
	if cleanup {
		return dao.CreateProviderWithArgs(t,
			tenantID,
			"LOC-A#2", "192.172.1.1",
			[]string{
				"username:" + loca_testing.DefaultUsername,
				"password:" + loca_testing.DefaultPassword,
			},
			providerv1.ProviderVendor_PROVIDER_VENDOR_LENOVO_LOCA,
			inv_testing.ProviderKind(providerv1.ProviderKind_PROVIDER_KIND_BAREMETAL),
		)
	}
	return dao.CreateProviderWithArgsNoCleanup(t,
		tenantID,
		"LOC-A#2", "192.172.1.1",
		[]string{
			"username:" + loca_testing.DefaultUsername,
			"password:" + loca_testing.DefaultPassword,
		},
		providerv1.ProviderVendor_PROVIDER_VENDOR_LENOVO_LOCA,
		inv_testing.ProviderKind(providerv1.ProviderKind_PROVIDER_KIND_BAREMETAL),
	)
}
