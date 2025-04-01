// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/client/inventory"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/loca"
	loca_testing "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/testing"
)

var locaAPI = flag.String(
	"locaAPI",
	"https://sc.loca.lab/api/v1",
	"LOC-A instance API",
)

func main() {
	flag.Parse()

	// diabling TLS communication
	*loca.FlagDisableTLSCommunication = true

	fmt.Printf("Listing LOC-A (%s) Sites\n", *locaAPI)
	// initialize LOC-A client first - this is done to refresh authorization token only ones,
	// at first call, but not each time, at UpdateHosts and UpdateInstances functions beginning
	locaClient := loca.InitialiseTestLocaClient(*locaAPI, loca_testing.LocaSecret)

	sites, err := locaClient.LocaAPI.Inventory.GetAPIV1InventorySites(nil, locaClient.AuthWriter)
	if err != nil {
		fmt.Printf("Failed to retrieve Sites from LOC-A (%s): %v\n", *locaAPI, err)
		os.Exit(1)
	}
	fmt.Printf("\n--------------------------------------------------------\n")
	fmt.Printf("Obtained from LOC-A (%s) Sites is:\n%v\n", *locaAPI, sites)
	fmt.Printf("\n--------------------------------------------------------\n")

	if len(sites.Payload.Data.Results) != 0 {
		fmt.Printf("Obtaining first Site by ID (%s)", sites.Payload.Data.Results[0].ID)
		site, err := locaClient.LocaAPI.Inventory.GetAPIV1InventorySitesID(
			&inventory.GetAPIV1InventorySitesIDParams{ID: sites.Payload.Data.Results[0].ID}, locaClient.AuthWriter)
		if err != nil {
			fmt.Printf("Failed to retrieve Site (%s) from LOC-A (%s): %v\n",
				sites.Payload.Data.Results[0].ID, *locaAPI, err)
			os.Exit(1)
		}
		fmt.Printf("\n--------------------------------------------------------\n")
		fmt.Printf("Obtained from LOC-A (%s) Site (%s) is:\n%v\n", *locaAPI, site.Payload.Data.ID, site)
		fmt.Printf("\n--------------------------------------------------------\n")
	}
}
