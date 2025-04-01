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
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/internal/handlers"
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
	zlog        = logging.GetLogger("LOCARM")
	parallelism = 10
)

type LOCARM struct {
	invClient inv_client.TenantAwareInventoryClient
	invEvents chan *inv_client.WatchEvents
	wg        *sync.WaitGroup
	sigTerm   chan bool

	reconciliationPeriod time.Duration
	controllers          map[inv_v1.ResourceKind]*rec_v2.Controller[handlers.ReconcilerID]
}

func NewLOCAManager(
	invClient inv_client.TenantAwareInventoryClient,
	invEvents chan *inv_client.WatchEvents,
	reconciliationPeriod time.Duration,
	waitGroup *sync.WaitGroup,
) (*LOCARM, error) {
	// initializing reconciler controllers
	controllers := initControllers(
		true,
		reconciliationPeriod*reconciliationPeriodWeight/totalWeight,
		invClient,
	)

	return &LOCARM{
		invClient:            invClient,
		invEvents:            invEvents,
		wg:                   waitGroup,
		sigTerm:              make(chan bool),
		reconciliationPeriod: reconciliationPeriod,
		controllers:          controllers,
	}, nil
}

func (lrm *LOCARM) Start(readyChan chan bool) {
	zlog.Info().Msgf("Starting LOC-A Manager control loop")
	lrm.wg.Add(1)

	if readyChan != nil {
		// signaling to OAM, that all routines are started
		readyChan <- true
	}

	// run full synchronization
	if err := lrm.handleSynchronizationCycle(); err != nil {
		zlog.InfraSec().Fatal().Msgf("Failed to handle synchronization cycle with LOC-A: %v", err)
	}
	// start control loop
	go lrm.controlLoop()
}

func (lrm *LOCARM) Stop() {
	close(lrm.sigTerm)
	lrm.wg.Wait()
	zlog.Info().Msg("LOC-A Manager control loop has been stopped")
}

func (lrm *LOCARM) controlLoop() {
	ticker := time.NewTicker(lrm.reconciliationPeriod)
	for {
		select {
		case ev, ok := <-lrm.invEvents:
			// ToDo (Ivan): track time to avoid starvation period (i.e., check how much time we have left
			// before the next tick).
			if !ok {
				// Event channel is closed, stream ended. Bye!
				ticker.Stop()
				// Note this will cover the sigterm scenario as well
				zlog.InfraSec().Fatal().Msg("gRPC stream with Inventory closed")
			}
			// Either an error or unexpected event.
			if !lrm.filterEvent(ev.Event) {
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
			lrm.ReconcileResource(tID, rID)
		case <-ticker.C:
			// perform control loop activity
			if err := lrm.handleSynchronizationCycle(); err != nil {
				zlog.InfraSec().InfraErr(err).Msgf("Failed to handle synchronization cycle with LOC-A")
			}
		case <-lrm.sigTerm:
			// Stop the ticker and send done signal to stop all goroutines
			// No other events will be processed
			ticker.Stop()
			lrm.wg.Done()
			return
		}
	}
}

func (lrm *LOCARM) handleSynchronizationCycle() error {
	// in Golang it's impossible to multiply time.Duration variable with floating point number
	synchronizationTimeout := lrm.reconciliationPeriod * reconciliationPeriodWeight / totalWeight

	// Do all the operations in the same context
	ctx, cancel := context.WithTimeout(context.Background(), synchronizationTimeout)
	defer cancel()
	locaProviders, err := inventory.ListLOCAProviderResources(ctx, lrm.invClient)
	if err != nil {
		return err
	}
	if len(locaProviders) == 0 {
		zlog.Debug().Msgf("No LOCA providers found, skip")
		return nil
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
			lrm.synchronizeProvider(ctx, tenantID, provider)
		}()
	}
	// waiting until all routines are done
	wg.Wait()
	return nil
}

func (lrm *LOCARM) synchronizeProvider(ctx context.Context, tenantID string, provider *providerv1.ProviderResource) {
	zlog.Debug().Msgf("Synchronizing with LOC-A: tenantID=%s, %s/%s", tenantID, provider.GetName(), provider.GetApiEndpoint())
	// initialize LOC-A client first - this is done to refresh authorization token only ones,
	// at first call, but not each time, at UpdateHosts and UpdateInstances functions beginning
	locaClient, err := loca.InitialiseLOCAClient(
		provider.GetApiEndpoint(),
		provider.GetApiCredentials(),
	)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to initialize LOC-A client for endpoint: %s",
			provider.GetApiEndpoint())
		// do not conduct further provisioning
		return
	}

	// handle Host provisioning
	if err := lrm.UpdateHosts(ctx, locaClient, tenantID, provider); err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to synchronize Hosts")
	}

	// handle Instance provisioning
	if err := lrm.UpdateInstances(ctx, locaClient, tenantID, provider); err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to synchronize Instances")
	}
}

func initControllers(
	tracingEnabled bool,
	reconcileTimeout time.Duration,
	invClient inv_client.TenantAwareInventoryClient,
) map[inv_v1.ResourceKind]*rec_v2.Controller[handlers.ReconcilerID] {
	controllers := make(map[inv_v1.ResourceKind]*rec_v2.Controller[handlers.ReconcilerID])

	// Instantiating Host reconciler
	hostReconciler := handlers.NewHostReconciler(tracingEnabled, invClient)
	hostController := rec_v2.NewController[handlers.ReconcilerID](
		hostReconciler.Reconcile,
		rec_v2.WithParallelism(parallelism),
		rec_v2.WithTimeout(reconcileTimeout))
	controllers[inv_v1.ResourceKind_RESOURCE_KIND_HOST] = hostController

	// Instantiating Instance reconciler
	instanceReconciler := handlers.NewInstanceReconciler(tracingEnabled, invClient)
	instanceController := rec_v2.NewController[handlers.ReconcilerID](
		instanceReconciler.Reconcile,
		rec_v2.WithParallelism(parallelism),
	)
	controllers[inv_v1.ResourceKind_RESOURCE_KIND_INSTANCE] = instanceController

	return controllers
}

func (lrm *LOCARM) filterEvent(event *inv_v1.SubscribeEventsResponse) bool {
	zlog.Debug().Msgf("New Inventory event received. event=%v", event)
	if err := validator.ValidateMessage(event); err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Invalid event received: %s", event.ResourceId)
		return false
	}

	expectedKind, err := util.GetResourceKindFromResourceID(event.ResourceId)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Unknown resource kind for ID %s.", event.ResourceId)
		return false
	}

	if expectedKind == inv_v1.ResourceKind_RESOURCE_KIND_HOST {
		// For Hosts, we care only when the events are UPDATED
		return event.EventKind == inv_v1.SubscribeEventsResponse_EVENT_KIND_UPDATED
	}

	if expectedKind == inv_v1.ResourceKind_RESOURCE_KIND_INSTANCE {
		// For Instances, we also care about CREATED events to handle nTouch provisioning
		return event.EventKind == inv_v1.SubscribeEventsResponse_EVENT_KIND_UPDATED ||
			event.EventKind == inv_v1.SubscribeEventsResponse_EVENT_KIND_CREATED
	}

	zlog.InfraSec().Debug().Msgf("Events are not processed for %v resource kinds", expectedKind)
	return false
}

// Helper function to reconcile the resources.
func (lrm *LOCARM) ReconcileResource(tenantID, resourceID string) {
	expectedKind, err := util.GetResourceKindFromResourceID(resourceID)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Unknown resource kind: %s", inventory.FormatTenantResourceID(tenantID, resourceID))
		return
	}

	zlog.Debug().Msgf("Reconciling resource of kind %s: %s",
		expectedKind, inventory.FormatTenantResourceID(tenantID, resourceID))

	controller, ok := lrm.controllers[expectedKind]
	if !ok {
		zlog.InfraSec().InfraError("Unhandled resource %s", inventory.FormatTenantResourceID(tenantID, resourceID)).
			Msgf("Controller for resource doesn't exists")
		return
	}
	err = controller.Reconcile(handlers.NewReconcilerID(tenantID, resourceID))
	if err != nil {
		zlog.InfraSec().InfraErr(err).
			Msgf("Unable to reconcile resource: %s", inventory.FormatTenantResourceID(tenantID, resourceID))
		return
	}
}
