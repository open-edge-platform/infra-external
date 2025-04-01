// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	computev1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/compute/v1"
	inv_v1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	locationv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/location/v1"
	osv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/os/v1"
	grpcclient "github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/inventory"
)

const defaultTimeout = 3

var (
	apiClient grpcclient.TenantAwareInventoryClient
	servaddr  = flag.String(
		"servaddr",
		"localhost:50051",
		"Inventory Service address to connect to",
	)

	listSites         = flag.Bool("listSites", false, "List all Sites per provider")
	createSite        = flag.Bool("createSite", false, "Create Site for testing purposes")
	deleteSites       = flag.Bool("deleteSites", false, "Delete all sites for all providers")
	onboardOSResource = flag.Bool("onboardOSResource", false, "Onboards OS resource for testing purposes")
	listAllResources  = flag.Bool("listAllResources", false, "List all Hosts and Instances per Provider")
	listHosts         = flag.Bool("listHosts", false, "List all Hosts per Provider")
	listInstances     = flag.Bool("listInstances", false, "List all Instances per Provider")
	removeHost        = flag.Bool("removeHost", false, "Remove Host for every Provider")
	removeInstance    = flag.Bool("removeInstance", false, "Remove Instance for every Provider")
)

func onboardOperatingSystemResource() error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout*time.Second)
	defer cancel()

	tenantID, err := inventory.GetSingularProviderTenantID()
	if err != nil {
		return err
	}

	osRes := &osv1.OperatingSystemResource{
		Name:            "Ubuntu 22.04.3",
		OsType:          osv1.OsType_OS_TYPE_MUTABLE,
		ProfileName:     "ubuntu-lenovo",
		ImageUrl:        "https://old-releases.ubuntu.com/releases/22.04/ubuntu-22.04.3-live-server-amd64.iso.",
		ImageId:         "22.04.3",
		Sha256:          "a4acfda10b18da50e2ec50ccaf860d7f20b389df8765611142305c0e911d16fd",
		SecurityFeature: osv1.SecurityFeature_SECURITY_FEATURE_SECURE_BOOT_AND_FULL_DISK_ENCRYPTION,
		TenantId:        tenantID,
		OsProvider:      osv1.OsProviderKind_OS_PROVIDER_KIND_LENOVO,
	}

	resourceID, err := inventory.CreateOSResource(ctx, apiClient, tenantID, osRes)
	if err != nil {
		fmt.Printf("Failed to create OS resource: %v\n", err)
		return err
	}
	fmt.Printf("OS Resource (%s) is created\n", resourceID)

	return nil
}

func createSiteResource() error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout*time.Second)
	defer cancel()

	tenantID, err := inventory.GetSingularProviderTenantID()
	if err != nil {
		return err
	}

	providers, err := inventory.ListLOCAProviderResources(ctx, apiClient)
	if err != nil {
		return err
	}

	// expecting to have only one provider
	if len(providers) != 1 {
		err = fmt.Errorf("expecting to have only one provider, got %v", len(providers))
		fmt.Printf("%v", err)
		return err
	}

	siteRes := &locationv1.SiteResource{
		Name:    "Test_Site",
		Address: "Very long street name",
		//nolint:mnd // this is a dummy value for testing purposes, not going to production
		SiteLat:  373541070,
		SiteLng:  -1219552380,
		Provider: providers[0],
		TenantId: tenantID,
	}

	resourceID, err := inventory.CreateSiteResource(ctx, apiClient, tenantID, siteRes)
	if err != nil {
		fmt.Printf("Failed to create OS resource: %v\n", err)
		return err
	}
	fmt.Printf("Site resource (%s) is created\n", resourceID)

	return nil
}

func listSiteResources() error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout*time.Second)
	defer cancel()

	tenantID, err := inventory.GetSingularProviderTenantID()
	if err != nil {
		return err
	}

	providers, err := inventory.ListLOCAProviderResources(ctx, apiClient)
	if err != nil {
		return err
	}

	for _, provider := range providers {
		// listing sites for each provider
		sites, err := inventory.ListAllSitesByTenantID(ctx, apiClient, tenantID)
		if err != nil {
			fmt.Printf("Failed to list all sites for provider %v: %v\n", provider.GetApiEndpoint(), err)
			continue
		}
		fmt.Printf("\n--------------------------------------------------------\n")
		fmt.Printf("Found %d sites\n", len(sites))
		for _, site := range sites {
			fmt.Printf("Site (%s): %v\n", site.GetResourceId(), site)
		}
		fmt.Printf("\n--------------------------------------------------------\n")
	}

	return nil
}

func deleteSiteResources() error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout*time.Second)
	defer cancel()

	tenantID, err := inventory.GetSingularProviderTenantID()
	if err != nil {
		return err
	}

	providers, err := inventory.ListLOCAProviderResources(ctx, apiClient)
	if err != nil {
		return err
	}

	for _, provider := range providers {
		sites, err := inventory.ListAllSitesByTenantID(ctx, apiClient, tenantID)
		if err != nil {
			fmt.Printf("Failed to retrieve Sites for the provider (%s/%s)\n", provider.GetName(), provider.GetApiEndpoint())
			return err
		}
		for _, site := range sites {
			// removing site
			_, err := apiClient.Delete(ctx, tenantID, site.GetResourceId())
			if err != nil {
				fmt.Printf("Failed to delete Site (%v)\n", site.GetResourceId())
				continue
			}
		}
	}

	return nil
}

// lists all Hosts and Instances by Provider.
func listAll() error {
	var err error

	// listing all Hosts
	err = listHostsByProvider()
	if err != nil {
		return err
	}

	// listing all Instances
	err = listInstancesByProvider()
	if err != nil {
		return err
	}

	return nil
}

// lists all Hosts by Provider.
func listHostsByProvider() error {
	var err error
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout*time.Second)
	defer cancel()
	tenantID, err := inventory.GetSingularProviderTenantID()
	if err != nil {
		return err
	}
	fmt.Printf("TenantID=%s\n", tenantID)
	// The assumption is that all LOCA provider resources belongs to a single tenant.
	providers, err := inventory.ListLOCAProviderResources(ctx, apiClient)
	if err != nil {
		return err
	}

	for _, provider := range providers {
		// listing all Hosts for current Provider
		hosts, err := inventory.ListAllHostsByLOCAProvider(ctx, apiClient, tenantID, provider.GetApiEndpoint())
		if err != nil {
			fmt.Printf("Failed to list Hosts for Provider %s/%s\n",
				provider.GetName(), provider.GetApiEndpoint())
			continue
		}

		if len(hosts) == 0 {
			fmt.Printf("Provider %s/%s has no associations with Hosts",
				provider.GetName(), provider.GetApiEndpoint())
			continue
		}
		fmt.Printf("\n--------------------------------------------------------\n")
		fmt.Printf("Following %d Hosts are associated with the Provider %s/%s:\n",
			len(hosts), provider.GetName(), provider.GetApiEndpoint())
		for _, host := range hosts {
			fmt.Printf("Host (%s) with UUID (%s), Serial Number (%s)\n",
				host.GetResourceId(), host.GetUuid(), host.GetSerialNumber())
			fmt.Printf("Host (%s) is currently in %v State and have %v Status which is %s at %v\n",
				host.GetResourceId(), host.GetCurrentState(), host.GetOnboardingStatus(),
				host.GetOnboardingStatusIndicator(), host.GetOnboardingStatusTimestamp())
			fmt.Printf("Full Host information is: %v\n", host)
		}
		fmt.Printf("--------------------------------------------------------\n\n")
	}

	return nil
}

// lists all Instances by Provider.
func listInstancesByProvider() error {
	var err error
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout*time.Second)
	defer cancel()

	tenantID, err := inventory.GetSingularProviderTenantID()
	if err != nil {
		return err
	}
	fmt.Printf("TenantID=%s\n", tenantID)

	// The assumption is that all LOCA provider resources belongs to a single tenant.
	providers, err := inventory.ListLOCAProviderResources(ctx, apiClient)
	if err != nil {
		return err
	}

	for _, provider := range providers {
		// listing all Hosts for current Provider
		instances, err := inventory.ListAllInstancesByLOCAProvider(ctx, apiClient, tenantID, provider.GetApiEndpoint())
		if err != nil {
			fmt.Printf("Failed to list Instances for Provider %s/%s\n",
				provider.GetName(), provider.GetApiEndpoint())
			continue
		}

		if len(instances) == 0 {
			fmt.Printf("Provider %s/%s has no associations with Instances",
				provider.GetName(), provider.GetApiEndpoint())
			continue
		}
		fmt.Printf("\n--------------------------------------------------------\n")
		fmt.Printf("Following %d Instances are associated with the Provider %s/%s:\n",
			len(instances), provider.GetName(), provider.GetApiEndpoint())
		for _, instance := range instances {
			fmt.Printf("Instance (%s; %s) associated to Host (%s) with UUID (%s), Serial Number (%s)\n",
				instance.GetResourceId(), instance.GetName(), instance.GetHost().GetResourceId(), instance.GetHost().GetUuid(),
				instance.GetHost().GetSerialNumber())
			fmt.Printf("Instance (%s; %s) is currently in %v State and have %v Status which is %s at %v\n",
				instance.GetResourceId(), instance.GetName(), instance.GetCurrentState(), instance.GetProvisioningStatus(),
				instance.GetProvisioningStatusIndicator(), instance.GetProvisioningStatusTimestamp())
		}
		fmt.Printf("--------------------------------------------------------\n\n")
	}

	return nil
}

// Removes Host for every Provider.
//
//nolint:dupl // implements remove operation for different resource
func removeHostWithID() error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout*time.Second)
	defer cancel()

	tenantID, err := inventory.GetSingularProviderTenantID()
	if err != nil {
		return err
	}
	fmt.Printf("TenantID=%s\n", tenantID)

	// The assumption is that all LOCA provider resources belongs to a single tenant.
	providers, err := inventory.ListLOCAProviderResources(ctx, apiClient)
	if err != nil {
		return err
	}

	for _, provider := range providers {
		// listing all Hosts for current Provider
		hosts, err := inventory.ListAllHostsByLOCAProvider(ctx, apiClient, tenantID, provider.GetApiEndpoint())
		if err != nil {
			fmt.Printf("Failed to list Hosts for Provider %s/%s\n",
				provider.GetName(), provider.GetApiEndpoint())
			continue
		}

		if len(hosts) != 1 {
			fmt.Printf("Provider %s/%s has no associations with Hosts",
				provider.GetName(), provider.GetApiEndpoint())
			continue
		}

		hosts[0].DesiredState = computev1.HostState_HOST_STATE_DELETED
		// updating Desired state of a Host
		err = inventory.UpdateInvResourceFields(ctx, apiClient, tenantID, hosts[0], []string{
			computev1.HostResourceFieldDesiredState,
		})
		if err != nil {
			fmt.Printf("Failed to remove Host (%s): %v\n", hosts[0].GetResourceId(), err)
			continue
		}
	}

	return nil
}

// Removes Instance for every Provider.
//
//nolint:dupl // implements remove operation for different resource
func removeInstanceWithID() error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout*time.Second)
	defer cancel()

	tenantID, err := inventory.GetSingularProviderTenantID()
	if err != nil {
		return err
	}
	fmt.Printf("TenantID=%s\n", tenantID)

	providers, err := inventory.ListLOCAProviderResources(ctx, apiClient)
	if err != nil {
		return err
	}

	for _, provider := range providers {
		// listing all Hosts for current Provider
		instances, err := inventory.ListAllInstancesByLOCAProvider(ctx, apiClient, tenantID, provider.GetApiEndpoint())
		if err != nil {
			fmt.Printf("Failed to list Instances for Provider %s/%s\n",
				provider.GetName(), provider.GetApiEndpoint())
			continue
		}

		if len(instances) != 1 {
			fmt.Printf("Provider %s/%s has no associations with Instances",
				provider.GetName(), provider.GetApiEndpoint())
			continue
		}
		instances[0].DesiredState = computev1.InstanceState_INSTANCE_STATE_DELETED
		// updating Desired state of an Instance
		err = inventory.UpdateInvResourceFields(ctx, apiClient, tenantID, instances[0], []string{
			computev1.InstanceResourceFieldDesiredState,
		})
		if err != nil {
			fmt.Printf("Failed to remove Instance (%s): %v\n", instances[0].GetResourceId(), err)
			continue
		}
	}

	return nil
}

//nolint:cyclop,funlen // this is a sample CLI, not going to the production
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
		fmt.Printf("Couldn't create a NewInventoryClient: %v", err)
		panic(err)
	}
	defer func() {
		// Exit cleanly.
		if err = apiClient.Close(); err != nil {
			fmt.Printf("Exit Failed")
			panic(err)
		}
	}()

	err = inventory.InitTenantGetter(&wg, *servaddr, false)
	if err != nil {
		fmt.Printf("Could not initialize TenantGetter: %v", err)
		panic(err)
	}
	err = inventory.StartTenantGetter()
	if err != nil {
		fmt.Printf("Could not start TenantGetter: %v", err)
		panic(err)
	}

	if *listAllResources {
		err = listAll()
		if err != nil {
			fmt.Printf("Failed to list all Hosts and Instances: %v\n", err)
		}
	}

	if *listHosts {
		err = listHostsByProvider()
		if err != nil {
			fmt.Printf("Failed to list all Hosts by Provider: %v\n", err)
		}
	}

	if *listInstances {
		err = listInstancesByProvider()
		if err != nil {
			fmt.Printf("Failed to list all Instances by Provider: %v\n", err)
		}
	}

	if *removeHost {
		err = removeHostWithID()
		if err != nil {
			fmt.Printf("Failed to remove Hosts: %v\n", err)
		}
	}

	if *removeInstance {
		err = removeInstanceWithID()
		if err != nil {
			fmt.Printf("Failed to remove Instances: %v\n", err)
		}
	}

	if *onboardOSResource {
		err = onboardOperatingSystemResource()
		if err != nil {
			fmt.Printf("Failed to onboard OS resource: %v\n", err)
		}
	}

	if *createSite {
		err = createSiteResource()
		if err != nil {
			fmt.Printf("Failed to create Site resource for testing purposes: %v\n", err)
		}
	}

	if *deleteSites {
		err = deleteSiteResources()
		if err != nil {
			fmt.Printf("Failed to delete Site resources: %v\n", err)
		}
	}

	if *listSites {
		err = listSiteResources()
		if err != nil {
			fmt.Printf("Failed to list Site resources: %v\n", err)
		}
	}

	cancel()
	inventory.StopTenantGetter()
	// wait for waitgroup
	wg.Wait()
}
