// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	inventoryv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	invClient "github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/metrics"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/oam"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/tracing"
	"github.com/open-edge-platform/infra-external/sol-manager/pkg/api/mps"
	"github.com/open-edge-platform/infra-external/sol-manager/pkg/flags"
	"github.com/open-edge-platform/infra-external/sol-manager/pkg/sol"
	rec_v2 "github.com/open-edge-platform/orch-library/go/pkg/controller/v2"
)

const (
	solManagerName            = "sol-manager"
	eventsWatcherBufSize      = 10
	defaultRequestTimeout     = 30 * time.Second
	defaultParallelGoroutines = 10

	numberOfControllers = 1
)

var (
	log = logging.GetLogger("sol-manager")
	wg  = &sync.WaitGroup{}

	osChan    = make(chan os.Signal, 1)
	termChan  = make(chan bool, 1)
	readyChan = make(chan bool, numberOfControllers)

	inventoryAddress = flag.String(invClient.InventoryAddress,
		"inventory.orch-infra.svc:50051", invClient.InventoryAddressDescription)
	reconcilePeriod = flag.Duration(flags.ReconcilePeriodFlag, time.Minute, flags.ReconcilePeriodDescription)
	requestTimeout  = flag.Duration(flags.RequestTimeoutFlag, defaultRequestTimeout,
		flags.RequestTimeoutDescription)
	oamservaddr    = flag.String(oam.OamServerAddress, "", oam.OamServerAddressDescription)
	enableTracing  = flag.Bool(tracing.EnableTracing, false, tracing.EnableTracingDescription)
	enableMetrics  = flag.Bool(metrics.EnableMetrics, false, metrics.EnableMetricsDescription)
	traceURL       = flag.String(tracing.TraceURL, "", tracing.TraceURLDescription)
	metricsAddress = flag.String(metrics.MetricsAddress, metrics.MetricsAddressDefault,
		metrics.MetricsAddressDescription)
	mpsAddress = flag.String(flags.MpsAddressFlag, "http://mps.orch-infra.svc:3000",
		flags.MpsAddressDescription)
	insecure     = flag.Bool("InsecureSkipVerify", false, flags.InsecureDescription)
	insecureGrpc = flag.Bool(invClient.InsecureGrpc, true, invClient.InsecureGrpcDescription)
	caCertPath   = flag.String(invClient.CaCertPath, "", invClient.CaCertPathDescription)
	tlsCertPath  = flag.String(invClient.TLSCertPath, "", invClient.TLSCertPathDescription)
	tlsKeyPath   = flag.String(invClient.TLSKeyPath, "", invClient.TLSKeyPathDescription)
)

func main() {
	flag.Parse()

	if *enableMetrics {
		startMetricsServer()
	}
	if *enableTracing {
		setupTracing(*traceURL)
	}
	setupOamServer(*enableTracing, *oamservaddr)

	signal.Notify(osChan, syscall.SIGTERM, syscall.SIGINT)

	// Create MPS API client
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
	}
	if *insecure {
		log.Warn().Msgf("Insecure TLS verification for MPS is enabled. This should only be used for development.")
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec //insecure for development purposes
		}
	}
	mpsClient, err := mps.NewClientWithResponses(*mpsAddress, func(apiClient *mps.Client) error {
		apiClient.Client = &http.Client{Transport: transport}
		return nil
	})
	if err != nil {
		log.Fatal().Err(err).Msgf("cannot create MPS client")
	}

	// Create SOL session reconciler.
	solReconciler := getSOLController(mpsClient)

	wg.Add(1)
	go solReconciler.Start()

	<-osChan
	termChan <- true

	close(osChan)
	close(termChan)
	solReconciler.Stop()
	wg.Wait()
	log.Info().Msg("SOL Manager successfully stopped")
}

func getSOLController(mpsClient mps.ClientWithResponsesInterface,
) *sol.Controller {
	rmClient, eventsWatcher := prepareInventoryClients()

	solReconciler := &sol.Controller{
		MpsClient:         mpsClient,
		InventoryRmClient: rmClient,
		TermChan:          termChan,
		ReadyChan:         readyChan,
		EventsWatcher:     eventsWatcher,
		WaitGroup:         wg,
		ReconcilePeriod:   *reconcilePeriod,
		RequestTimeout:    *requestTimeout,
		Insecure:          *insecure,
	}

	solController := rec_v2.NewController(
		solReconciler.Reconcile,
		rec_v2.WithParallelism(defaultParallelGoroutines),
		rec_v2.WithTimeout(*requestTimeout))
	solReconciler.SOLController = solController
	return solReconciler
}

func prepareInventoryClients() (
	rmClient invClient.TenantAwareInventoryClient,
	eventsWatcher chan *invClient.WatchEvents,
) {
	eventsWatcher = make(chan *invClient.WatchEvents, eventsWatcherBufSize)
	rmClient, err := invClient.NewTenantAwareInventoryClient(context.Background(), invClient.InventoryClientConfig{
		Name:                      "SOL RM manager",
		Address:                   *inventoryAddress,
		EnableRegisterRetry:       false,
		AbortOnUnknownClientError: true,
		SecurityCfg: &invClient.SecurityConfig{
			CaPath:   *caCertPath,
			CertPath: *tlsCertPath,
			KeyPath:  *tlsKeyPath,
			Insecure: *insecureGrpc,
		},
		Events:     eventsWatcher,
		ClientKind: inventoryv1.ClientKind_CLIENT_KIND_RESOURCE_MANAGER,
		ResourceKinds: []inventoryv1.ResourceKind{
			inventoryv1.ResourceKind_RESOURCE_KIND_HOST,
		},
		Wg:            wg,
		EnableTracing: *enableTracing,
		EnableMetrics: *enableMetrics,
	})
	if err != nil {
		log.Fatal().Err(err).Msgf("cannot create inventory client")
	}

	return rmClient, eventsWatcher
}

func setupOamServer(enableTracing bool, oamservaddr string) {
	if oamservaddr != "" {
		wg.Add(1)
		go func() {
			if err := oam.StartOamGrpcServer(termChan, readyChan, wg, oamservaddr, enableTracing); err != nil {
				log.InfraSec().Fatal().Err(err).Msg("Cannot start OAM gRPC server")
			}
		}()

		readyChan <- true
	}
}

func setupTracing(traceURL string) func(context.Context) error {
	cleanup, exportErr := tracing.NewTraceExporterHTTP(traceURL, solManagerName, nil)
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
