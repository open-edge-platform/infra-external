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

	"github.com/prometheus/client_golang/prometheus"

	inventoryv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/metrics"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/oam"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/tracing"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/inventory"
	"github.com/open-edge-platform/infra-external/loca-templates/pkg/templates"
)

var (
	log                 = logging.GetLogger("LocaTemplatesManager")
	wg                  = &sync.WaitGroup{}
	sigChan             = make(chan os.Signal, 1)
	termChan            = make(chan bool, 1)
	readyChan           = make(chan bool, 1)
	mainLoopStartedChan = make(chan bool, 1)
	inventoryAddress    = flag.String(client.InventoryAddress,
		"inventory.orch-infra.svc:50051", client.InventoryAddressDescription)
	oamservaddr   = flag.String(oam.OamServerAddress, "", oam.OamServerAddressDescription)
	enableTracing = flag.Bool(tracing.EnableTracing, false, tracing.EnableTracingDescription)
	traceURL      = flag.String(tracing.TraceURL, "", tracing.TraceURLDescription)

	enableMetrics  = flag.Bool(metrics.EnableMetrics, false, metrics.EnableMetricsDescription)
	metricsAddress = flag.String(metrics.MetricsAddress, metrics.MetricsAddressDefault, metrics.MetricsAddressDescription)
)

const (
	tmName = "loca-templates-manager"
)

// Project related variables. Overwritten by build process.
var (
	RepoURL   = "https://github.com/open-edge-platform/infra-external/loca-templates.git"
	Version   = "<unset>"
	Revision  = "<unset>"
	BuildDate = "<unset>"
)

func startupSummary() {
	log.Info().Msg("Starting " + tmName)
	log.Info().Msgf("RepoURL: %s, Version: %s, Revision: %s, BuildDate: %s\n", RepoURL, Version, Revision, BuildDate)
}

func main() {
	startupSummary()

	flag.Parse()

	if *enableTracing {
		cleanup := setupTracing(*traceURL)
		if cleanup != nil {
			defer func() {
				err := cleanup(context.Background())
				if err != nil {
					log.InfraErr(err).Msg("Error in tracing cleanup")
				}
			}()
		}
	}

	if *enableMetrics {
		startMetricsServer()
	}

	eventsWatcher := make(chan *client.WatchEvents)

	err := inventory.InitTenantGetter(wg, *inventoryAddress, *enableTracing)
	if err != nil {
		log.InfraSec().Fatal().Err(err).Msgf("Unable to initialize Tenant Getter")
	}
	err = inventory.StartTenantGetter()
	if err != nil {
		log.InfraSec().Fatal().Err(err).Msgf("Unable to start Tenant Getter")
	}
	invClient, err := client.NewTenantAwareInventoryClient(context.Background(), client.InventoryClientConfig{
		Name:                      "LOC-A templates manager",
		Address:                   *inventoryAddress,
		EnableRegisterRetry:       false,
		AbortOnUnknownClientError: true,
		SecurityCfg: &client.SecurityConfig{
			Insecure: true,
			CaPath:   "",
			CertPath: "",
			KeyPath:  "",
		},
		Events:     eventsWatcher,
		ClientKind: inventoryv1.ClientKind_CLIENT_KIND_RESOURCE_MANAGER,
		ResourceKinds: []inventoryv1.ResourceKind{
			inventoryv1.ResourceKind_RESOURCE_KIND_OS,
		},
		Wg:            wg,
		EnableTracing: *enableTracing,
		EnableMetrics: *enableMetrics,
	})
	if err != nil {
		log.InfraSec().Fatal().Err(err).Msgf("failed to create inventory client")
		return
	}

	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
	wg.Add(1)
	go templates.Start(wg, mainLoopStartedChan, eventsWatcher, invClient)

	setupOamServer(*enableTracing, *oamservaddr)

	<-sigChan

	close(sigChan)
	close(termChan)
	templates.Stop(invClient)

	wg.Wait()
	log.Info().Msgf("Template manager successfully stopped")
}

func setupOamServer(enableTracing bool, oamservaddr string) {
	if oamservaddr != "" {
		// Add oam grpc server
		wg.Add(1)
		go func() {
			if err := oam.StartOamGrpcServer(termChan, readyChan, wg, oamservaddr, enableTracing); err != nil {
				log.InfraSec().Fatal().Err(err).Msg("Cannot start Inventory OAM gRPC server")
			}
		}()

		<-mainLoopStartedChan
		readyChan <- true
	}
}

func setupTracing(traceURL string) func(context.Context) error {
	cleanup, exportErr := tracing.NewTraceExporterHTTP(traceURL, tmName, nil)
	if exportErr != nil {
		log.InfraErr(exportErr).Msg("Error creating trace exporter")
	}
	if cleanup != nil {
		log.Info().Msgf("Tracing enabled %s", traceURL)
	} else {
		log.Info().Msg("Tracing disabled")
	}
	return cleanup
}

func startMetricsServer() {
	metrics.StartMetricsExporter([]prometheus.Collector{metrics.GetClientMetricsWithLatency()},
		metrics.WithListenAddress(*metricsAddress))
}
