// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	inv_v1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	os_v1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/os/v1"
	provider_v1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/provider/v1"
	grpcclient "github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/inventory"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/util"
)

const defaultTimeout = 3

var (
	zlog      = logging.GetLogger("Provider Creator")
	apiClient grpcclient.TenantAwareInventoryClient
	servaddr  = flag.String(
		"servaddr",
		"localhost:50051",
		"Inventory Service address to connect to",
	)
)

func DeleteResource(tenantID, resourceID string) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout*time.Second)
	defer cancel()
	_, err := apiClient.Delete(ctx,
		tenantID,
		resourceID,
	)
	if err != nil {
		zlog.Info().Msgf("Error while soft removing: %s", inventory.FormatTenantResourceID(tenantID, resourceID))
	}
}

func OnboardPrerequisites(sigChan chan os.Signal) error {
	var err error

	tenantID, err := inventory.GetSingularProviderTenantID()
	if err != nil {
		return err
	}
	zlog.Info().Msgf("TenantID=%s\n", tenantID)

	// We create first the provider
	pres := &provider_v1.ProviderResource{
		ProviderKind:   provider_v1.ProviderKind_PROVIDER_KIND_BAREMETAL,
		ProviderVendor: provider_v1.ProviderVendor_PROVIDER_VENDOR_LENOVO_LOCA,
		Name:           "LOC-A #1",
		ApiEndpoint:    "https://192.168.202.4/api/v1",
		ApiCredentials: []string{"username:admin", "password:Edgeinfra12"},
		TenantId:       tenantID,
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout*time.Second)
	defer cancel()

	createresreq := &inv_v1.Resource{Resource: &inv_v1.Resource_Provider{Provider: pres}}
	createresresp, err := apiClient.Create(ctx, tenantID, createresreq)
	if err != nil {
		return err
	}
	providerID := createresresp.GetProvider().GetResourceId()
	defer DeleteResource(tenantID, providerID)
	zlog.Info().Msgf("New Provider ID: %s", inventory.FormatTenantResourceID(tenantID, providerID))

	// we create OS resource
	locaInstanceFlavor := "Ubuntu 22.04.3"
	checksum := util.GetOSSHA256FromOsNameAndOsVersion(locaInstanceFlavor, locaInstanceFlavor)
	osRes := &os_v1.OperatingSystemResource{
		Name:         locaInstanceFlavor,
		Architecture: "x86",
		Sha256:       checksum,
		ProfileName:  locaInstanceFlavor,
		ImageUrl:     "some repo URL",
		TenantId:     tenantID,
	}

	createOsResReq := &inv_v1.Resource{Resource: &inv_v1.Resource_Os{Os: osRes}}
	createOsResResp, err := apiClient.Create(ctx, tenantID, createOsResReq)
	if err != nil {
		return err
	}
	osID := createOsResResp.GetOs().GetResourceId()
	defer DeleteResource(tenantID, osID)
	zlog.Info().Msgf("New Operating System ID: %s", inventory.FormatTenantResourceID(tenantID, osID))

	<-sigChan

	return nil
}

func main() {
	flag.Parse()

	// Context and signal to handle termination and capture signals
	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	// waitgroup for gRPC connection
	wg := sync.WaitGroup{}

	// don't stream any resource types
	kinds := []inv_v1.ResourceKind{}

	clientCfg := grpcclient.InventoryClientConfig{
		Name:    "api",
		Address: *servaddr,
		SecurityCfg: &grpcclient.SecurityConfig{
			Insecure: true,
			CaPath:   "",
			CertPath: "",
			KeyPath:  "",
		},
		Events:        make(chan *grpcclient.WatchEvents, 1),
		ClientKind:    inv_v1.ClientKind_CLIENT_KIND_API,
		ResourceKinds: kinds,
		Wg:            &wg,
		EnableTracing: false,
	}

	var err error
	// create gRPC API client (global)
	apiClient, err = grpcclient.NewTenantAwareInventoryClient(ctx, clientCfg)
	if err != nil {
		zlog.Fatal().Msgf("Couldn't create a NewInventoryClient: %v", err)
	}
	defer func() {
		// Exit cleanly.
		if err = apiClient.Close(); err != nil {
			zlog.Fatal().Err(err).Msg("Exit Failed")
		}
	}()

	err = inventory.InitTenantGetter(&wg, *servaddr, false)
	if err != nil {
		zlog.Error().Msgf("Could not initialize TenantGetter: %v", err)
		panic(err)
	}
	err = inventory.StartTenantGetter()
	if err != nil {
		zlog.Error().Msgf("Could not start TenantGetter: %v", err)
		panic(err)
	}

	// Create a new host via API
	err = OnboardPrerequisites(sigChan)
	if err != nil {
		zlog.Fatal().Err(err).Msg("CreateProvider Failed")
	}

	cancel()
	inventory.StopTenantGetter()
	// wait for waitgroup
	wg.Wait()
}
