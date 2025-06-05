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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/util/yaml"

	inventoryv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	invClient "github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/metrics"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/oam"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/tracing"
	"github.com/open-edge-platform/infra-external/dm-manager/pkg/api/mps"
	"github.com/open-edge-platform/infra-external/dm-manager/pkg/api/rps"
	"github.com/open-edge-platform/infra-external/dm-manager/pkg/devices"
	"github.com/open-edge-platform/infra-external/dm-manager/pkg/dm"
	"github.com/open-edge-platform/infra-external/dm-manager/pkg/flags"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/secrets"
	rec_v2 "github.com/open-edge-platform/orch-library/go/pkg/controller/v2"
)

const (
	orchMpsHostKey            = "orchMPSHost"
	infraConfigPath           = "/etc/infra-config/config.yaml"
	dmName                    = "dm-manager"
	eventsWatcherBufSize      = 10
	defaultRequestTimeout     = 10 * time.Second
	defaultParallelGoroutines = 10

	numberOfControllers = 2
)

var (
	log = logging.GetLogger("Manager")
	wg  = &sync.WaitGroup{}

	osChan    = make(chan os.Signal, 1)
	termChan  = make(chan bool, 1)
	readyChan = make(chan bool, numberOfControllers)

	inventoryAddress = flag.String(invClient.InventoryAddress,
		"inventory.orch-infra.svc:50051", invClient.InventoryAddressDescription)
	reconcilePeriod = flag.Duration(flags.ReconcilePeriodFlag, time.Minute, flags.ReconcilePeriodDescription)
	requestTimeout  = flag.Duration(flags.RequestTimeoutFlag, defaultRequestTimeout,
		flags.RequestTimeoutDescription)
	passwordPolicy = flag.String(flags.PasswordPolicyFlag, "static", flags.PasswordPolicyDescription)
	oamservaddr    = flag.String(oam.OamServerAddress, "", oam.OamServerAddressDescription)
	enableTracing  = flag.Bool(tracing.EnableTracing, false, tracing.EnableTracingDescription)
	enableMetrics  = flag.Bool(metrics.EnableMetrics, false, metrics.EnableMetricsDescription)
	traceURL       = flag.String(tracing.TraceURL, "", tracing.TraceURLDescription)
	metricsAddress = flag.String(metrics.MetricsAddress, metrics.MetricsAddressDefault, metrics.MetricsAddressDescription)
	mpsAddress     = flag.String(flags.MpsAddressFlag, "http://mps.orch-infra.svc:3000",
		flags.MpsAddressDescription)
	rpsAddress = flag.String(flags.RpsAddressFlag, "http://rps.orch-infra.svc:8081",
		flags.RpsAddressDescription)
	insecure     = flag.Bool("InsecureSkipVerify", false, flags.InsecureDescription)
	insecureGrpc = flag.Bool(invClient.InsecureGrpc, true, invClient.InsecureGrpcDescription)
	caCertPath   = flag.String(invClient.CaCertPath, "", invClient.CaCertPathDescription)
	tlsCertPath  = flag.String(invClient.TLSCertPath, "", invClient.TLSCertPathDescription)
	tlsKeyPath   = flag.String(invClient.TLSKeyPath, "", invClient.TLSKeyPathDescription)
)

func main() {
	flag.Parse()
	if !(strings.EqualFold(*passwordPolicy, dm.StaticPasswordPolicy) ||
		strings.EqualFold(*passwordPolicy, dm.DynamicPasswordPolicy)) {
		log.Error().Msgf("Invalid password policy: %s. It should be either 'static' or 'dynamic'", *passwordPolicy)
		os.Exit(1)
	}

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

	mpsClient, err := mps.NewClientWithResponses(*mpsAddress, func(apiClient *mps.Client) error {
		apiClient.Client = &http.Client{Transport: transport}
		return nil
	})
	if err != nil {
		log.Fatal().Err(err).Msgf("cannot create client")
	}

	rpsClient, err := rps.NewClientWithResponses(*rpsAddress, func(apiClient *rps.Client) error {
		apiClient.Client = &http.Client{Transport: transport}
		return nil
	})
	if err != nil {
		log.Fatal().Err(err).Msgf("cannot create client")
	}

	orchMpsHost, orchMpsPort := getMpsAddress(infraConfigPath)

	vsp := secrets.VaultSecretProvider{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if initErr := vsp.Init(ctx, []string{dm.AmtPasswordSecretName}); initErr != nil {
		log.InfraSec().Fatal().Err(initErr).Msgf("Unable to initialize required secrets")
	}

	dmReconciler := getDmController(mpsClient, rpsClient, vsp, orchMpsHost, orchMpsPort)
	deviceReconciler := getDeviceController(mpsClient, rpsClient)

	wg.Add(1)
	go dmReconciler.Start()

	wg.Add(1)
	go deviceReconciler.Start()
	<-osChan
	termChan <- true

	close(osChan)
	close(termChan)
	dmReconciler.Stop()
	deviceReconciler.Stop()
	wg.Wait()
	log.Info().Msgf("Device Management Manager successfully stopped")
}

func getDmController(
	mpsClient *mps.ClientWithResponses, rpsClient *rps.ClientWithResponses, vsp secrets.VaultSecretProvider,
	orchMpsHost string, orchMpsPort int32,
) *dm.Manager {
	dmInvClient, dmEventsWatcher := prepareDmClients()
	dmReconciler := &dm.Manager{
		MpsClient:       mpsClient,
		RpsClient:       rpsClient,
		InventoryClient: dmInvClient,
		EventsWatcher:   dmEventsWatcher,
		TermChan:        termChan,
		ReadyChan:       readyChan,
		SecretProvider:  &vsp,
		WaitGroup:       wg,
		Config: &dm.ReconcilerConfig{
			MpsAddress:      orchMpsHost,
			MpsPort:         orchMpsPort,
			PasswordPolicy:  *passwordPolicy,
			ReconcilePeriod: *reconcilePeriod,
			RequestTimeout:  *requestTimeout,
		},
	}

	tenantController := rec_v2.NewController[dm.ReconcilerID](
		dmReconciler.Reconcile,
		rec_v2.WithParallelism(defaultParallelGoroutines),
		rec_v2.WithTimeout(*requestTimeout))
	dmReconciler.TenantController = tenantController
	return dmReconciler
}

func getDeviceController(mpsClient *mps.ClientWithResponses, rpsClient *rps.ClientWithResponses) devices.DeviceController {
	rmClient, apiClient, deviceEventsWatcher := prepareDevicesClients()

	deviceReconciler := devices.DeviceController{
		MpsClient:          mpsClient,
		RpsClient:          rpsClient,
		WaitGroup:          wg,
		TermChan:           termChan,
		ReadyChan:          readyChan,
		InventoryRmClient:  rmClient,
		InventoryAPIClient: apiClient,
		ReconcilePeriod:    *reconcilePeriod,
		RequestTimeout:     *requestTimeout,
		EventsWatcher:      deviceEventsWatcher,
	}
	deviceController := rec_v2.NewController[devices.DeviceID](
		deviceReconciler.Reconcile,
		rec_v2.WithParallelism(defaultParallelGoroutines),
		rec_v2.WithTimeout(*requestTimeout))
	deviceReconciler.DeviceController = deviceController
	return deviceReconciler
}

//nolint:gocritic // named results mean additional assignment/typecast.
func getMpsAddress(filepath string) (string, int32) {
	data, err := os.ReadFile(filepath)
	if err != nil {
		log.Fatal().Err(err).Msgf("Failed to read configuration file: %v", filepath)
		return "", 0
	}

	var config map[string]any
	if err = yaml.Unmarshal(data, &config); err != nil {
		log.Fatal().Err(err).Msgf("Failed to unmarshal configuration file")
		return "", 0
	}

	value, ok := config[orchMpsHostKey]
	if !ok {
		log.Fatal().Msgf("Key 'orchMPSHost' not found in configuration file")
		return "", 0
	}

	stringValue, ok := value.(string)
	if !ok {
		log.Fatal().Msgf("failed to parse '%v' as string", value)
	}

	splitted := strings.Split(stringValue, ":")
	const expectedHostAndPortLen = 2
	if len(splitted) != expectedHostAndPortLen {
		log.Fatal().Msgf("Variable 'orchMPSHost' is not set or has an invalid format."+
			" Current value: '%v'", os.Getenv(orchMpsHostKey))
		return "", 0
	}
	orchMpsHost := splitted[0]
	orchMpsPort, err := strconv.ParseInt(splitted[1], 10, 32)
	if err != nil {
		log.Fatal().Err(err).Msgf("Failed to parse port from 'orchMPSHost' environment variable: '%v'", os.Getenv(orchMpsHostKey))
		return "", 0
	}

	return orchMpsHost, int32(orchMpsPort)
}

func prepareDmClients() (
	invTenantClient invClient.TenantAwareInventoryClient, eventsWatcher chan *invClient.WatchEvents,
) {
	eventsWatcher = make(chan *invClient.WatchEvents, eventsWatcherBufSize)
	invTenantClient, err := invClient.NewTenantAwareInventoryClient(context.Background(), invClient.InventoryClientConfig{
		Name:                      "DM DMT manager",
		Address:                   *inventoryAddress,
		EnableRegisterRetry:       false,
		AbortOnUnknownClientError: true,
		SecurityCfg: &invClient.SecurityConfig{
			CaPath:   *caCertPath,
			CertPath: *tlsCertPath,
			KeyPath:  *tlsKeyPath,
			Insecure: *insecureGrpc,
		},
		Events:        eventsWatcher,
		ClientKind:    inventoryv1.ClientKind_CLIENT_KIND_API,
		ResourceKinds: []inventoryv1.ResourceKind{},
		Wg:            wg,
		EnableTracing: *enableTracing,
		EnableMetrics: *enableMetrics,
	})
	if err != nil {
		log.Fatal().Err(err).Msgf("cannot create inventory client")
	}

	return invTenantClient, eventsWatcher
}

func prepareDevicesClients() (
	rmClient invClient.TenantAwareInventoryClient, apiClient invClient.TenantAwareInventoryClient,
	eventsWatcher chan *invClient.WatchEvents,
) {
	eventsWatcher = make(chan *invClient.WatchEvents, eventsWatcherBufSize)
	rmClient, err := invClient.NewTenantAwareInventoryClient(context.Background(), invClient.InventoryClientConfig{
		Name:                      "DM RM manager",
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

	apiClient, err = invClient.NewTenantAwareInventoryClient(context.Background(), invClient.InventoryClientConfig{
		Name:                      "DM API manager",
		Address:                   *inventoryAddress,
		EnableRegisterRetry:       false,
		AbortOnUnknownClientError: true,
		SecurityCfg: &invClient.SecurityConfig{
			CaPath:   *caCertPath,
			CertPath: *tlsCertPath,
			KeyPath:  *tlsKeyPath,
			Insecure: *insecureGrpc,
		},
		Events:        eventsWatcher,
		ClientKind:    inventoryv1.ClientKind_CLIENT_KIND_API,
		Wg:            wg,
		EnableTracing: *enableTracing,
		EnableMetrics: *enableMetrics,
	})
	if err != nil {
		log.Fatal().Err(err).Msgf("cannot create inventory client")
	}

	return rmClient, apiClient, eventsWatcher
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
