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
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/metrics"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/oam"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/tracing"
	"github.com/open-edge-platform/infra-external/loca-metadata/internal/manager"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/inventory"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/flags"
)

const (
	clientName                           = "LOCAMetadataRMInventoryClient"
	envNameMetadataCredentialsSecretName = "METADATA_CREDENTIALS_SECRET_NAME" //nolint:gosec // not a hardcoded credential
)

// Configuration variables, mostly set by flags.
var (
	rmName = "LOCAMetadataRM"
	zlog   = logging.GetLogger(rmName + "Main")

	inventoryAddress = flag.String(client.InventoryAddress, "localhost:50051", client.InventoryAddressDescription)
	oamServerAddress = flag.String(oam.OamServerAddress, "", oam.OamServerAddressDescription)

	enableTracing = flag.Bool(tracing.EnableTracing, false, tracing.EnableTracingDescription)
	traceURL      = flag.String(tracing.TraceURL, "", tracing.TraceURLDescription)

	insecureGrpc = flag.Bool(client.InsecureGrpc, true, client.InsecureGrpcDescription)
	caCertPath   = flag.String(client.CaCertPath, "", client.CaCertPathDescription)
	tlsCertPath  = flag.String(client.TLSCertPath, "", client.TLSCertPathDescription)
	tlsKeyPath   = flag.String(client.TLSKeyPath, "", client.TLSKeyPathDescription)

	enableMetrics  = flag.Bool(metrics.EnableMetrics, false, metrics.EnableMetricsDescription)
	metricsAddress = flag.String(metrics.MetricsAddress, metrics.MetricsAddressDefault, metrics.MetricsAddressDescription)

	// eventsWatcherBufSize is the buffer size for the events channel.
	eventsWatcherBufSize = 10
)

// Project related variables. Overwritten by build process.
var (
	RepoURL   = "https://github.com/open-edge-platform/infra-external/loca-metadata.git"
	Version   = "<unset>"
	Revision  = "<unset>"
	BuildDate = "<unset>"
)

// Waitgroups and channels used for readiness and program exit.
var (
	wg           = sync.WaitGroup{} // all goroutines added to this, blocks program exit
	invReadyChan = make(chan bool, 1)
	sbReadyChan  = make(chan bool, 1)
	oamReadyChan = make(chan bool, 1) // used for readiness indicators to OAM
	termChan     = make(chan bool, 1) // used to pass on termination signals
	sigChan      = make(chan os.Signal, 1)
)

func printSummary() {
	zlog.Info().Msg("Starting " + rmName)
	zlog.Info().Msgf("RepoURL: %s, Version: %s, Revision: %s, BuildDate: %s\n", RepoURL, Version, Revision, BuildDate)
}

func setupTracing(traceURL string) func(context.Context) error {
	cleanup, exportErr := tracing.NewTraceExporterHTTP(traceURL, rmName, nil)
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

func startMetricsServer() {
	metrics.StartMetricsExporter([]prometheus.Collector{metrics.GetClientMetricsWithLatency()},
		metrics.WithListenAddress(*metricsAddress))
}

func getSecurityConfig() *client.SecurityConfig {
	secCfg := &client.SecurityConfig{
		CaPath:   *caCertPath,
		CertPath: *tlsCertPath,
		KeyPath:  *tlsKeyPath,
		Insecure: *insecureGrpc,
	}
	return secCfg
}

func setupOamServerAndSetReady(enableTracing bool, oamServerAddress string) {
	if oamServerAddress != "" {
		wg.Add(1) // Add oam grpc server to waitgroup

		go func() {
			if err := oam.StartOamGrpcServer(termChan, oamReadyChan, &wg, oamServerAddress, enableTracing); err != nil {
				zlog.InfraSec().Fatal().Err(err).Msg("Cannot start " + rmName + " gRPC server")
			}
		}()
	}
}

func main() {
	// Print a summary of build information
	printSummary()

	// Parse flags
	flag.Parse()

	// Tracing, if enabled
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
	setupOamServerAndSetReady(*enableTracing, *oamServerAddress)

	// connect to Inventory
	eventsWatcher := make(chan *client.WatchEvents, eventsWatcherBufSize)
	invClient, err := client.NewTenantAwareInventoryClient(context.Background(),
		client.InventoryClientConfig{
			Name:                      clientName,
			Address:                   *inventoryAddress,
			EnableRegisterRetry:       false,
			AbortOnUnknownClientError: true,
			SecurityCfg:               getSecurityConfig(),
			Events:                    eventsWatcher,
			ClientKind:                inv_v1.ClientKind_CLIENT_KIND_RESOURCE_MANAGER,
			ResourceKinds: []inv_v1.ResourceKind{
				inv_v1.ResourceKind_RESOURCE_KIND_SITE,
				inv_v1.ResourceKind_RESOURCE_KIND_REGION,
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

	locamm, err := manager.NewLOCAMetadataManager(invClient, eventsWatcher, flags.ParseReconciliationPeriod(), &wg)
	if err != nil {
		zlog.InfraSec().Fatal().Err(err).Msgf("Unable to start LOC-A MM Manager")
	}
	locamm.Start(oamReadyChan)

	// Handle OS signals (ctrl-c, etc.)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-sigChan // block until signals received

		close(termChan) // closes the SBgRPC server, OAM Server
		locamm.Stop()
		inventory.StopTenantGetter()
	}()

	// wait for Inventory API and SB gRPC API to be ready, then set OAM ready
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-invReadyChan
		<-sbReadyChan
		oamReadyChan <- true
	}()

	wg.Wait()
}
