// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

// Package main is the entrypoint for the kvm-manager service.
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
	"github.com/open-edge-platform/infra-external/dm-manager/pkg/api/mps"
	"github.com/open-edge-platform/infra-external/kvm-manager/pkg/flags"
	"github.com/open-edge-platform/infra-external/kvm-manager/pkg/kvm"
	rec_v2 "github.com/open-edge-platform/orch-library/go/pkg/controller/v2"
)

const (
	kvmManagerName            = "kvm-manager"
	eventsWatcherBufSize      = 10
	defaultParallelGoroutines = 10
	numberOfControllers       = 1
)

var (
	log = logging.GetLogger("KvmManager")
	wg  = &sync.WaitGroup{}

	osChan    = make(chan os.Signal, 1)
	termChan  = make(chan bool, 1)
	readyChan = make(chan bool, numberOfControllers)

	inventoryAddress = flag.String(invClient.InventoryAddress,
		"inventory.orch-infra.svc:50051", invClient.InventoryAddressDescription)
	mpsAddress = flag.String(flags.MpsAddressFlag, "http://mps.orch-infra.svc:3000",
		flags.MpsAddressDescription)
	mpsDomain = flag.String(flags.MpsDomainFlag, "mps-wss.kind.internal",
		flags.MpsDomainDescription)
	reconcilePeriod = flag.Duration(flags.ReconcilePeriod, time.Minute,
		flags.ReconcilePeriodDescription)
	requestTimeout = flag.Duration(flags.RequestTimeout, 30*time.Second,
		flags.RequestTimeoutDescription)
	insecure = flag.Bool("InsecureSkipVerify", false, flags.InsecureDescription)

	insecureGrpc   = flag.Bool(invClient.InsecureGrpc, true, invClient.InsecureGrpcDescription)
	caCertPath     = flag.String(invClient.CaCertPath, "", invClient.CaCertPathDescription)
	tlsCertPath    = flag.String(invClient.TLSCertPath, "", invClient.TLSCertPathDescription)
	tlsKeyPath     = flag.String(invClient.TLSKeyPath, "", invClient.TLSKeyPathDescription)
	oamservaddr    = flag.String(oam.OamServerAddress, "", oam.OamServerAddressDescription)
	enableTracing  = flag.Bool(tracing.EnableTracing, false, tracing.EnableTracingDescription)
	enableMetrics  = flag.Bool(metrics.EnableMetrics, false, metrics.EnableMetricsDescription)
	traceURL       = flag.String(tracing.TraceURL, "", tracing.TraceURLDescription)
	metricsAddress = flag.String(metrics.MetricsAddress, metrics.MetricsAddressDefault, metrics.MetricsAddressDescription)
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

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
	}
	if *insecure {
		log.Warn().Msg("Insecure TLS verification for MPS is enabled. Use only for development.")
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // insecure for development purposes only
		}
	}

	mpsClient, err := mps.NewClientWithResponses(*mpsAddress, func(apiClient *mps.Client) error {
		apiClient.Client = &http.Client{Transport: transport}
		return nil
	})
	if err != nil {
		log.Fatal().Err(err).Msg("cannot create MPS client")
	}

	kvmReconciler := getKvmController(mpsClient)

	wg.Add(1)
	go kvmReconciler.Start()

	<-osChan
	termChan <- true
	close(osChan)
	close(termChan)
	kvmReconciler.Stop()
	wg.Wait()
	log.Info().Msg("kvm-manager stopped")
}

func getKvmController(mpsClient *mps.ClientWithResponses) *kvm.Controller {
	rmClient, eventsWatcher := prepareInventoryClients()

	reconciler := &kvm.Controller{
		MpsClient:         mpsClient,
		InventoryRmClient: rmClient,
		TermChan:          termChan,
		ReadyChan:         readyChan,
		EventsWatcher:     eventsWatcher,
		WaitGroup:         wg,
		MpsDomain:         *mpsDomain,
		ReconcilePeriod:   *reconcilePeriod,
		RequestTimeout:    *requestTimeout,
	}

	kvmController := rec_v2.NewController[kvm.ID](
		reconciler.Reconcile,
		rec_v2.WithParallelism(defaultParallelGoroutines),
		rec_v2.WithTimeout(*requestTimeout),
	)
	reconciler.KvmController = kvmController
	return reconciler
}

func prepareInventoryClients() (invClient.TenantAwareInventoryClient, chan *invClient.WatchEvents) {
	eventsWatcher := make(chan *invClient.WatchEvents, eventsWatcherBufSize)
	rmClient, err := invClient.NewTenantAwareInventoryClient(context.Background(),
		invClient.InventoryClientConfig{
			Name:                      "kvm-manager RM",
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
		log.Fatal().Err(err).Msg("cannot create inventory RM client")
	}
	return rmClient, eventsWatcher
}

func setupOamServer(enableTracingVal bool, oamservaddrVal string) {
	if oamservaddrVal != "" {
		wg.Add(1)
		go func() {
			if err := oam.StartOamGrpcServer(
				termChan, readyChan, wg, oamservaddrVal, enableTracingVal); err != nil {
				log.InfraSec().Fatal().Err(err).Msg("cannot start OAM gRPC server")
			}
		}()
		readyChan <- true
	}
}

func setupTracing(traceURLVal string) func(context.Context) error {
	cleanup, exportErr := tracing.NewTraceExporterHTTP(traceURLVal, kvmManagerName, nil)
	if exportErr != nil {
		log.InfraErr(exportErr).Msg("error creating trace exporter")
	}
	if cleanup != nil {
		log.Info().Msgf("tracing enabled: %s", traceURLVal)
	}
	return cleanup
}

func startMetricsServer() {
	metrics.StartMetricsExporter(
		[]prometheus.Collector{metrics.GetClientMetricsWithLatency()},
		metrics.WithListenAddress(*metricsAddress),
	)
}
