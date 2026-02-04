// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"
	"net"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/metrics"
	inv_tenant "github.com/open-edge-platform/infra-core/inventory/v2/pkg/tenant"
	pb "github.com/open-edge-platform/infra-external/dm-manager/pkg/api/dm-manager"
	grpcServer "github.com/open-edge-platform/infra-external/dm-manager/pkg/grpc/grpc_server"
)

// Misc variables.
var (
	loggerName = "DeviceManagementHandler"
	zlog       = logging.GetLogger(loggerName)
)

type DMHandlerConfig struct {
	ServerAddress    string
	InventoryAddress string
	EnableTracing    bool
	EnableMetrics    bool
	MetricsAddress   string
	EnableAuth       bool
	RBAC             string
}

type DMHandler struct {
	invClient client.TenantAwareInventoryClient
	cfg       DMHandlerConfig

	lis    net.Listener
	server *grpc.Server
}

func NewDMHandler(invClient client.TenantAwareInventoryClient, config DMHandlerConfig) (*DMHandler, error) {
	lc := net.ListenConfig{}
	lis, err := lc.Listen(context.Background(), "tcp", config.ServerAddress)
	if err != nil {
		return nil, err
	}

	return NewDMHandlerWithListener(lis, invClient, config), nil
}

func NewDMHandlerWithListener(listener net.Listener,
	invClient client.TenantAwareInventoryClient,
	config DMHandlerConfig,
) *DMHandler {
	return &DMHandler{
		invClient: invClient,
		cfg:       config,
		lis:       listener,
	}
}

// Start IO server.
func (dmh *DMHandler) Start() error {
	deviceManagementService, err := grpcServer.NewDeviceManagementService(
		dmh.invClient,
		dmh.cfg.InventoryAddress, dmh.cfg.EnableTracing, dmh.cfg.EnableAuth, dmh.cfg.RBAC)
	if err != nil {
		return err
	}
	srvOpts := make([]grpc.ServerOption, 0, 1)
	var unaryInter []grpc.UnaryServerInterceptor
	unaryInter = append(unaryInter, inv_tenant.GetExtractTenantIDInterceptor(inv_tenant.GetAgentsRole()))
	srvMetrics := metrics.GetServerMetricsWithLatency()
	cliMetrics := metrics.GetClientMetricsWithLatency()
	if dmh.cfg.EnableMetrics {
		zlog.Info().Msgf("Metrics exporter Enable with address %s", dmh.cfg.MetricsAddress)
		unaryInter = append(unaryInter, srvMetrics.UnaryServerInterceptor())
	}
	srvOpts = append(srvOpts, grpc.ChainUnaryInterceptor(unaryInter...))
	dmh.server = grpc.NewServer(srvOpts...)
	pb.RegisterDeviceManagementServer(dmh.server, deviceManagementService)

	// Register reflection service on gRPC server.
	reflection.Register(dmh.server)
	if dmh.cfg.EnableMetrics {
		// Register metrics
		srvMetrics.InitializeMetrics(dmh.server)
		metrics.StartMetricsExporter([]prometheus.Collector{cliMetrics, srvMetrics},
			metrics.WithListenAddress(dmh.cfg.MetricsAddress))
	}
	// Run go routine to start the gRPC server.
	go func() {
		if err := dmh.server.Serve(dmh.lis); err != nil {
			zlog.InfraSec().Fatal().Err(err).Msgf("Error listening with TCP: %s", dmh.lis.Addr().String())
		}
	}()

	zlog.InfraSec().Info().Msgf("DM handler started")
	zlog.Debug().Msgf("DM handler started")
	return nil
}

func (dmh *DMHandler) Stop() {
	if dmh.server != nil {
		dmh.server.Stop()
		zlog.InfraSec().Info().Msgf("SB handler stopped")
	}
}
