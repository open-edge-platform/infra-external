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

	"github.com/prometheus/client_golang/prometheus"

	inventoryv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	invClient "github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/metrics"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/oam"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/tracing"
	"github.com/open-edge-platform/infra-external/dm-manager/pkg/api/mps"
	"github.com/open-edge-platform/infra-external/dm-manager/pkg/api/rps"
	"github.com/open-edge-platform/infra-external/dm-manager/pkg/dm"
)

const (
	mpsAddressFlag       = "mpsAddress"
	rpsAddressFlag       = "rpsAddress"
	dmName               = "dm-manager"
	eventsWatcherBufSize = 10
)

var (
	log = logging.GetLogger("DMManager")
	wg  = &sync.WaitGroup{}

	osChan    = make(chan os.Signal, 1)
	termChan  = make(chan bool, 1)
	readyChan = make(chan bool, 1)

	inventoryAddress = flag.String(invClient.InventoryAddress,
		"inventory.orch-infra.svc:50051", invClient.InventoryAddressDescription)
	oamservaddr    = flag.String(oam.OamServerAddress, "", oam.OamServerAddressDescription)
	enableTracing  = flag.Bool(tracing.EnableTracing, false, tracing.EnableTracingDescription)
	enableMetrics  = flag.Bool(metrics.EnableMetrics, false, metrics.EnableMetricsDescription)
	traceURL       = flag.String(tracing.TraceURL, "", tracing.TraceURLDescription)
	metricsAddress = flag.String(metrics.MetricsAddress, metrics.MetricsAddressDefault, metrics.MetricsAddressDescription)
	mpsAddress     = flag.String(mpsAddressFlag, "mps-webport-node",
		"Address of Management Presence Service (MPS)")
	rpsAddress = flag.String(rpsAddressFlag, "rps-webport-node",
		"Address of Remote Provisioning Service (RPS)")
	insecure = flag.Bool("InsecureSkipVerify", false,
		"Skip TLS verification for MPS/RPS. Does not recommended for production and should be used only for development.")
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

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
	}
	if *insecure {
		log.Warn().Msgf("Insecure TLS verification for MPS is enabled. This should only be used for development.")
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec //insecure for development purposes
		}
	}

	mpsClient, rpsClient, invTenantClient, eventsWatcher := prepareClients(transport)
	dmReconciler := &dm.Reconciler{
		MpsClient:       mpsClient,
		RpsClient:       rpsClient,
		InventoryClient: invTenantClient,
		EventsWatcher:   eventsWatcher,
		TermChan:        termChan,
		ReadyChan:       readyChan,
		WaitGroup:       wg,
	}
	wg.Add(1)
	go dmReconciler.Start()

	<-osChan
	termChan <- true

	close(osChan)
	close(termChan)
	dmReconciler.Stop()
	wg.Wait()
	log.Info().Msgf("Device Management Manager successfully stopped")
}

func prepareClients(transport *http.Transport) (
	*mps.ClientWithResponses, *rps.ClientWithResponses, invClient.TenantAwareInventoryClient, chan *invClient.WatchEvents) {
	authHandlerClient, err := mps.NewClientWithResponses(*mpsAddress, func(apiClient *mps.Client) error {
		apiClient.Client = &http.Client{Transport: transport}
		return nil
	})
	if err != nil {
		log.Fatal().Err(err).Msgf("cannot create client")
	}
	authHandler := dm.DmtAuthHandler{MpsClient: authHandlerClient}

	mpsClient, err := mps.NewClientWithResponses(*mpsAddress, func(apiClient *mps.Client) error {
		apiClient.Client = &http.Client{Transport: transport}
		apiClient.RequestEditors = []mps.RequestEditorFn{authHandler.DmtAuth}
		return nil
	})
	if err != nil {
		log.Fatal().Err(err).Msgf("cannot create client")
	}

	rpsClient, err := rps.NewClientWithResponses(*rpsAddress, func(apiClient *rps.Client) error {
		apiClient.Client = &http.Client{Transport: transport}
		apiClient.RequestEditors = []rps.RequestEditorFn{authHandler.DmtAuth} // TODO: check if this works
		return nil
	})
	if err != nil {
		log.Fatal().Err(err).Msgf("cannot create client")
	}

	eventsWatcher := make(chan *invClient.WatchEvents, eventsWatcherBufSize)
	invTenantClient, err := invClient.NewTenantAwareInventoryClient(context.Background(), invClient.InventoryClientConfig{
		Name:                      "DM manager",
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
		ClientKind: inventoryv1.ClientKind_CLIENT_KIND_TENANT_CONTROLLER,
		ResourceKinds: []inventoryv1.ResourceKind{
			inventoryv1.ResourceKind_RESOURCE_KIND_TENANT,
		},
		Wg:            wg,
		EnableTracing: *enableTracing,
		EnableMetrics: *enableMetrics,
	})
	if err != nil {
		log.Fatal().Err(err).Msgf("cannot create inventory client")
	}
	return mpsClient, rpsClient, invTenantClient, eventsWatcher
}

func setupOamServer(enableTracing bool, oamservaddr string) {
	if oamservaddr != "" {
		wg.Add(1)
		go func() {
			if err := oam.StartOamGrpcServer(termChan, readyChan, wg, oamservaddr, enableTracing); err != nil {
				log.InfraSec().Fatal().Err(err).Msg("Cannot start Inventory OAM gRPC server")
			}
		}()

		readyChan <- true
	}
}

func setupTracing(traceURL string) func(context.Context) error {
	cleanup, exportErr := tracing.NewTraceExporterHTTP(traceURL, dmName, nil)
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
