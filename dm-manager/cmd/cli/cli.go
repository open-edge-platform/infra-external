// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"fmt"
	"sync"

	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	computev1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/compute/v1"
	inventoryv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	invClient "github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
)

const powerOn = 2

var (
	desiredState = flag.Int("desiredState", powerOn, "Desired state of the host for update command")
	tenantID     = flag.String("tenantID", "91000763-23a2-4a2b-984a-37f69989b7e0",
		"Tenant ID to use for the inventory client")
	hostUUID       = flag.String("hostUUID", "874873cd-d715-d223-66fa-88aedd715d23", "Host UUID to use for the inventory client")
	amtSku         = flag.String("amtSku", "AMT Pro Corporate", "AMT SKU to use for the host")
	listHostsFlag  = flag.Bool("listHosts", false, "List hosts")
	createHostFlag = flag.Bool("createHost", false, "Create a host")
	deleteHostFlag = flag.Bool("deleteHost", false, "Delete a host")
	updateHostFlag = flag.Bool("updateHost", false, "Update a host")
)

func main() {
	flag.Parse()
	apiClient, err := invClient.NewTenantAwareInventoryClient(context.Background(), invClient.InventoryClientConfig{
		Name:    "api",
		Address: "localhost:50051",
		SecurityCfg: &invClient.SecurityConfig{
			Insecure: true,
		},
		Events:     make(chan *invClient.WatchEvents),
		ClientKind: inventoryv1.ClientKind_CLIENT_KIND_API,
		Wg:         &sync.WaitGroup{},
	})
	if err != nil {
		log.Fatal().Err(err).Msgf("cannot create client")
	}

	rmClient, err := invClient.NewTenantAwareInventoryClient(context.Background(), invClient.InventoryClientConfig{
		Name:    "RM",
		Address: "localhost:50051",
		SecurityCfg: &invClient.SecurityConfig{
			Insecure: true,
		},
		Events:     make(chan *invClient.WatchEvents),
		ClientKind: inventoryv1.ClientKind_CLIENT_KIND_RESOURCE_MANAGER,
		Wg:         &sync.WaitGroup{},
	})
	if err != nil {
		log.Fatal().Err(err).Msgf("cannot create client")
	}

	if *listHostsFlag {
		listHosts(apiClient)
	}
	if *updateHostFlag {
		updateHost(apiClient)
	}
	if *createHostFlag {
		createHost(apiClient, rmClient)
	}
	if *deleteHostFlag {
		deleteHost(apiClient, *hostUUID)
	}
}

func listHosts(invTenantClient invClient.TenantAwareInventoryClient) []*inventoryv1.Resource {
	hosts, err := invTenantClient.ListAll(context.Background(), &inventoryv1.ResourceFilter{
		Resource: &inventoryv1.Resource{Resource: &inventoryv1.Resource_Host{}},
	})
	if err != nil {
		log.Error().Err(err).Msgf("Failed to list hosts")
	}
	fmt.Println("")
	log.Info().Msgf("hosts - %v, len - %v", hosts, len(hosts))
	fmt.Println("")

	return hosts
}

func createHost(apiClient, rmClient invClient.TenantAwareInventoryClient) {
	host, err := apiClient.Create(context.Background(), *tenantID,
		&inventoryv1.Resource{
			Resource: &inventoryv1.Resource_Host{
				Host: &computev1.HostResource{
					PowerCommandPolicy: computev1.PowerCommandPolicy_POWER_COMMAND_POLICY_ORDERED,
					DesiredPowerState:  computev1.PowerState_POWER_STATE_SLEEP,
					DesiredAmtState:    computev1.AmtState_AMT_STATE_PROVISIONED,
					TenantId:           *tenantID,
					Uuid:               *hostUUID,
					AmtSku:             *amtSku,
				},
			},
		})
	if err != nil {
		log.Error().Err(err).Msgf("Failed to create host")
	}

	_, err = rmClient.Update(context.Background(), *tenantID, host.GetHost().GetResourceId(),
		&fieldmaskpb.FieldMask{
			Paths: []string{
				computev1.HostResourceFieldCurrentPowerState,
				computev1.HostResourceFieldCurrentAmtState,
			},
		},
		&inventoryv1.Resource{
			Resource: &inventoryv1.Resource_Host{
				Host: &computev1.HostResource{
					CurrentPowerState: computev1.PowerState_POWER_STATE_ON,
					CurrentAmtState:   computev1.AmtState_AMT_STATE_PROVISIONED,
				},
			},
		})
	if err != nil {
		log.Error().Err(err).Msgf("Failed to update host")
	}
}

func updateHost(apiClient invClient.TenantAwareInventoryClient) {
	_, err := apiClient.Update(context.Background(), *tenantID, *hostUUID,
		&fieldmaskpb.FieldMask{
			Paths: []string{
				computev1.HostResourceFieldDesiredPowerState,
				computev1.HostResourceFieldDesiredAmtState,
			},
		},
		&inventoryv1.Resource{
			Resource: &inventoryv1.Resource_Host{
				Host: &computev1.HostResource{
					DesiredPowerState: computev1.PowerState(*desiredState), //nolint:gosec // supported command <10
					DesiredAmtState:   computev1.AmtState_AMT_STATE_PROVISIONED,
				},
			},
		})
	if err != nil {
		log.Err(err).Msgf("failed to update host")
	}
}

func deleteHost(invTenantClient invClient.TenantAwareInventoryClient, hostID string) {
	_, err := invTenantClient.Delete(context.Background(), *tenantID, hostID)
	if err != nil {
		log.Err(err).Msgf("failed delete")
	}
}
