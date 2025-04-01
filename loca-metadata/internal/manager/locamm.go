// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"sync"
	"time"

	inv_v1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	providerv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/provider/v1"
	inv_client "github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/util"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/validator"
	"github.com/open-edge-platform/infra-external/loca-metadata/internal/handlers"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/inventory"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/loca"
	rec_v2 "github.com/open-edge-platform/orch-library/go/pkg/controller/v2"
)

const (
	// There are two concurrent routines: event handling and periodic reconciliation. We set each operation to last at least 95%
	// of the reconciliation period. The idea is to save some time for the next reconciliation cycle and prevent overruns (which
	// means wait again a full reconciliation period).
	reconciliationPeriodWeight = 95  // %
	totalWeight                = 100 // %
)

var (
	zlog        = logging.GetLogger("LOCAMM")
	parallelism = 10
)

type LOCAMM struct {
	invClient            inv_client.TenantAwareInventoryClient
	invEvents            chan *inv_client.WatchEvents
	wg                   *sync.WaitGroup
	sigTerm              chan bool
	controllers          map[inv_v1.ResourceKind]*rec_v2.Controller[handlers.ReconcilerID]
	reconciliationPeriod time.Duration
}

func NewLOCAMetadataManager(
	invClient inv_client.TenantAwareInventoryClient,
	invEvents chan *inv_client.WatchEvents,
	reconciliationPeriod time.Duration,
	waitGroup *sync.WaitGroup,
) (*LOCAMM, error) {
	// initializing reconciler controllers
	controllers := initControllers(
		true,
		reconciliationPeriod*reconciliationPeriodWeight/totalWeight,
		invClient,
	)
	return &LOCAMM{
		invClient:            invClient,
		invEvents:            invEvents,
		wg:                   waitGroup,
		sigTerm:              make(chan bool),
		controllers:          controllers,
		reconciliationPeriod: reconciliationPeriod,
	}, nil
}

func (lmm *LOCAMM) Start(readyChan chan bool) {
	zlog.Info().Msgf("Starting LOC-A Metadata Manager control loop")
	lmm.wg.Add(1)

	if readyChan != nil {
		// signaling to OAM, that all routines are started
		readyChan <- true
	}

	// run full synchronization
	if err := lmm.handleSynchronizationCycle(); err != nil {
		zlog.InfraSec().Fatal().Msgf("Failed to handle metadata synchronization cycle with LOC-A: %v", err)
	}
	// start control loop
	go lmm.controlLoop()
}

func (lmm *LOCAMM) Stop() {
	close(lmm.sigTerm)
	lmm.wg.Wait()
	zlog.Info().Msg("LOC-A Metadata Manager control loop has been stopped")
}

func (lmm *LOCAMM) controlLoop() {
	ticker := time.NewTicker(lmm.reconciliationPeriod)
	for {
		select {
		case ev, ok := <-lmm.invEvents:
			if !ok {
				// Event channel is closed, stream ended. Bye!
				ticker.Stop()
				// Note this will cover the sigterm scenario as well
				zlog.InfraSec().Fatal().Msg("gRPC stream with Inventory closed")
			}
			// Either an error or unexpected event.
			if !lmm.filterEvent(ev.Event) {
				continue
			}
			// Skip if multiple tenants! LOCA providers should all belong to a single tenant!
			_, err := inventory.GetSingularProviderTenantID()
			if err != nil {
				zlog.InfraSec().Err(err).Msgf("Non singular tenant ID, skip event reconciliation!")
				continue
			}
			tID, rID, err := util.GetResourceKeyFromResource(ev.Event.Resource)
			if err != nil {
				zlog.InfraSec().Err(err).Msg("Failed to get resource tenantID and resourceID")
			}
			lmm.ReconcileResource(tID, rID, ev.Event.GetResource().GetSite().GetName())
		case <-ticker.C:
			// perform control loop activity
			if err := lmm.handleSynchronizationCycle(); err != nil {
				zlog.InfraSec().InfraErr(err).Msgf("Failed to handle metadata synchronization cycle with LOC-A")
			}
		case <-lmm.sigTerm:
			// Stop the ticker and send done signal to stop all goroutines
			// No other events will be processed
			ticker.Stop()
			lmm.wg.Done()
			return
		}
	}
}

func (lmm *LOCAMM) handleSynchronizationCycle() error {
	// in Golang it's impossible to multiply time.Duration variable with floating point number
	synchronizationTimeout := lmm.reconciliationPeriod * reconciliationPeriodWeight / totalWeight
	// Do all the operations in the same context
	ctx, cancel := context.WithTimeout(context.Background(), synchronizationTimeout)
	defer cancel()
	// fetching all LOC-A providers from Inventory
	locaProviders, err := inventory.ListLOCAProviderResources(ctx, lmm.invClient)
	if err != nil {
		return err
	}

	tenantID, err := inventory.GetSingularTenantIDFromProviders(locaProviders)
	if err != nil {
		// The expectation here is that we never get NotFound error from GetSingularTenantIDFromProviders.
		zlog.Err(err).Msg("LOCA providers belongs to different tenants! Skip reconciliation!")
		// Do not return error to avoid fatal at startup!
		return nil
	}

	// starting provisioning concurrently
	wg := sync.WaitGroup{}
	for _, locaProvider := range locaProviders {
		provider := locaProvider
		wg.Add(1)
		go func() {
			defer wg.Done()
			lmm.synchronizeProvider(ctx, tenantID, provider)
		}()
	}
	// waiting until all routines are done
	wg.Wait()
	return nil
}

func (lmm *LOCAMM) synchronizeProvider(ctx context.Context, tenantID string, provider *providerv1.ProviderResource) {
	zlog.Debug().Msgf("Synchronizing with LOC-A %s/%s", provider.GetName(), provider.GetApiEndpoint())
	// initialize LOC-A client first - this is done to refresh authorization token only ones,
	// at first call, but not each time, at UpdateSites functions beginning
	locaClient, err := loca.InitialiseLOCAClient(
		provider.GetApiEndpoint(),
		provider.GetApiCredentials(),
	)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to initialize LOC-A client for endpoint: %s",
			provider.GetApiEndpoint())
		return
	}

	// handle Metadata provisioning
	if err = lmm.updateMetadata(ctx, locaClient, tenantID); err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to synchronize metadata")
	}
}

func (lmm *LOCAMM) filterEvent(event *inv_v1.SubscribeEventsResponse) bool {
	zlog.Debug().Msgf("New Inventory event received. ResourceID=%v, Kind=%s", event.ResourceId, event.EventKind)
	if err := validator.ValidateMessage(event); err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Invalid event received: %s", event.ResourceId)
		return false
	}

	expectedKind, err := util.GetResourceKindFromResourceID(event.ResourceId)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Unknown resource kind for ID %s.", event.ResourceId)
		return false
	}

	if expectedKind == inv_v1.ResourceKind_RESOURCE_KIND_SITE {
		// We care about every Site-related event
		return true
	}
	zlog.InfraSec().Debug().Msgf("Events are not processed for %v resource kinds", expectedKind)
	return false
}

// Helper function to reconcile the resources.
func (lmm *LOCAMM) ReconcileResource(tenantID, resourceID, name string) {
	expectedKind, err := util.GetResourceKindFromResourceID(resourceID)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Unknown resource kind: %s", inventory.FormatTenantResourceID(tenantID, resourceID))
		return
	}

	zlog.Debug().Msgf("Reconciling resource of kind %s: %s",
		expectedKind, inventory.FormatTenantResourceID(tenantID, resourceID))

	controller, ok := lmm.controllers[expectedKind]
	if !ok {
		zlog.InfraSec().InfraError("").
			Msgf("Unhandled resource %s", inventory.FormatTenantResourceID(tenantID, resourceID))
		return
	}
	err = controller.Reconcile(handlers.NewReconcilerID(tenantID, resourceID, name))
	if err != nil {
		zlog.InfraSec().InfraErr(err).
			Msgf("Unable to reconcile resource: %s", inventory.FormatTenantResourceID(tenantID, resourceID))
		return
	}
}

func initControllers(
	tracingEnabled bool,
	reconcileTimeout time.Duration,
	invClient inv_client.TenantAwareInventoryClient,
) map[inv_v1.ResourceKind]*rec_v2.Controller[handlers.ReconcilerID] {
	controllers := make(map[inv_v1.ResourceKind]*rec_v2.Controller[handlers.ReconcilerID])

	// Instantiating Site reconciler
	siteReconciler := handlers.NewSiteReconciler(tracingEnabled, invClient)
	siteController := rec_v2.NewController[handlers.ReconcilerID](
		siteReconciler.Reconcile,
		rec_v2.WithParallelism(parallelism),
		rec_v2.WithTimeout(reconcileTimeout))
	controllers[inv_v1.ResourceKind_RESOURCE_KIND_SITE] = siteController

	return controllers
}
