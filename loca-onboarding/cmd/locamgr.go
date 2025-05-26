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

	inv_v1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/auth"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	inv_errors "github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/metrics"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/oam"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/tracing"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/internal/manager"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/inventory"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/flags"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/secrets"
)

const (
	clientName                             = "LOCARMInventoryClient"
	envNameOnboardingCredentialsSecretName = "ONBOARDING_CREDENTIALS_SECRET_NAME"
)

var (
	name      = "LOCARM"
	zlog      = logging.GetLogger(name + "Main")
	sigChan   = make(chan os.Signal, 1)
	wg        = sync.WaitGroup{}
	readyChan = make(chan bool, 1)
	termChan  = make(chan bool, 1)
)

var (
	inventoryAddress = flag.String(client.InventoryAddress, "localhost:50051", client.InventoryAddressDescription)
	oamservaddr      = flag.String(oam.OamServerAddress, "", oam.OamServerAddressDescription)
	enableTracing    = flag.Bool(tracing.EnableTracing, false, tracing.EnableTracingDescription)
	traceURL         = flag.String(tracing.TraceURL, "", tracing.TraceURLDescription)
	hostDiscovery    = flag.Bool(manager.AllowHostDiscovery, manager.HostDiscovery, manager.AllowHostDiscoveryDescription)

	enableMetrics  = flag.Bool(metrics.EnableMetrics, false, metrics.EnableMetricsDescription)
	metricsAddress = flag.String(metrics.MetricsAddress, metrics.MetricsAddressDefault, metrics.MetricsAddressDescription)

	// eventsWatcherBufSize is the buffer size for the events channel.
	eventsWatcherBufSize = 10
)

var (
	RepoURL   = "https://github.com/open-edge-platform/infra-external/loca-onboarding.git"
	Version   = "<unset>"
	Revision  = "<unset>"
	BuildDate = "<unset>"
)

func printSummary() {
	zlog.Info().Msg("Starting LOCA Manager")
	zlog.Info().Msgf("RepoURL: %s, Version: %s, Revision: %s, BuildDate: %s\n", RepoURL, Version, Revision, BuildDate)
}

func setupTracing(traceURL string) func(context.Context) error {
	cleanup, exportErr := tracing.NewTraceExporterHTTP(traceURL, name, nil)
	if exportErr != nil {
		zlog.InfraErr(exportErr).Msg("Error creating trace exporter")
	}
	if cleanup != nil {
		zlog.Info().Msgf("Tracing enabled %s", traceURL)
	} else {
		zlog.Info().Msg("Tracing disabled")
	}
	return cleanup
}

func setupOamServer(enableTracing bool, oamservaddr string) {
	if oamservaddr != "" {
		// Add oam grpc server
		wg.Add(1)
		go func() {
			if err := oam.StartOamGrpcServer(termChan, readyChan, &wg, oamservaddr, enableTracing); err != nil {
				zlog.InfraSec().Fatal().Err(err).Msg("Cannot start Inventory OAM gRPC server")
			}
		}()
		readyChan <- true
	}
}

func startMetricsServer() {
	metrics.StartMetricsExporter([]prometheus.Collector{metrics.GetClientMetricsWithLatency()},
		metrics.WithListenAddress(*metricsAddress))
}

//nolint:cyclop // TODO: too many statements, should be refactored
func main() {
	// Print a summary of the build
	printSummary()
	flag.Parse()
	// Startup process, respecting deps
	// 1. Setup tracing
	// 2. Start LOC-A RM Inventory client
	// 3. Start Provisioning Manager
	// 4. Start the OAM server
	if *enableTracing {
		cleanup := setupTracing(*traceURL)
		if cleanup != nil {
			defer func() {
				err := cleanup(context.Background())
				if err != nil {
					zlog.InfraErr(err).Msg("Error in tracing cleanup")
				}
			}()
		}
	}
	if *enableMetrics {
		startMetricsServer()
	}
	// set up OAM (health check) server
	setupOamServer(*enableTracing, *oamservaddr)
	eventsWatcher := make(chan *client.WatchEvents, eventsWatcherBufSize)
	invClient, err := client.NewTenantAwareInventoryClient(context.Background(),
		client.InventoryClientConfig{
			Name:                      clientName,
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
			ClientKind: inv_v1.ClientKind_CLIENT_KIND_RESOURCE_MANAGER,
			ResourceKinds: []inv_v1.ResourceKind{
				inv_v1.ResourceKind_RESOURCE_KIND_HOST,
				inv_v1.ResourceKind_RESOURCE_KIND_INSTANCE,
			},
			Wg:            &wg,
			EnableTracing: *enableTracing,
			EnableMetrics: *enableMetrics,
		})
	if err != nil {
		zlog.InfraSec().Fatal().Err(err).Msgf("Unable to start Inventory client")
	}

	err = inventory.InitTenantGetter(&wg, *inventoryAddress, *enableTracing)
	if err != nil {
		zlog.InfraSec().Fatal().Err(err).Msgf("Unable to initialize Tenant Getter")
	}
	err = inventory.StartTenantGetter()
	if err != nil {
		zlog.InfraSec().Fatal().Err(err).Msgf("Unable to start Tenant Getter")
	}

	onboardingCredentialsSecretName := os.Getenv(envNameOnboardingCredentialsSecretName)
	if onboardingCredentialsSecretName == "" {
		invErr := inv_errors.Errorf("%s env variable is not set, using default value", envNameOnboardingCredentialsSecretName)
		zlog.InfraSec().Fatal().Err(invErr).Msgf("")
		onboardingCredentialsSecretName = "3rd-party-host-manager-m2m-client-secret" //nolint:gosec // not a credential
	}

	if initErr := secrets.Init(context.Background(), []string{onboardingCredentialsSecretName}); initErr != nil {
		zlog.InfraSec().Fatal().Err(initErr).Msgf("Unable to initialize required secrets")
	}

	if authInitErr := auth.Init(); authInitErr != nil {
		zlog.InfraSec().Fatal().Err(authInitErr).Msgf("Unable to initialize auth service")
	}

	if *hostDiscovery {
		zlog.Info().Msgf("Host discovery is enabled")
	} else {
		zlog.Info().Msgf("Host discovery is disabled")
	}
	locarm, err := manager.NewLOCAManager(invClient, eventsWatcher, flags.ParseReconciliationPeriod(), &wg)
	if err != nil {
		zlog.InfraSec().Fatal().Err(err).Msgf("Unable to start LOC-A RM Manager")
	}
	locarm.Start(readyChan)

	// After the initialization blocks waiting for term signal.
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	// After the initialization blocks on sigChan
	// waiting on the term channel.
	// 1. Stop the OAM server
	// 2. Stop the Provisioning Manager
	// 3. Stop the LOC-A RM Inventory client
	<-sigChan
	close(termChan)
	locarm.Stop()
	inventory.StopTenantGetter()

	wg.Wait()
}
