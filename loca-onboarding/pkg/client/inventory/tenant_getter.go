// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"flag"
	"sync"
	"time"

	"google.golang.org/grpc/codes"

	invv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
)

// Tenant Getter is a singleton implementation of a component that fetches the singular tenantID from LOCA-providers.
// The assumption for LOCA-RMs is that ALL LOCA-providers belongs to a single tenant, in order for LOCA-RMs to properly work.
// Otherwise, LOCA-RMs operations will all fail (LOCA-OM: reconciliation of Host and Instance, synchronization with LOCA).

const (
	defaultTimeoutGetTenant = 10 * time.Second
	defaultRefreshTime      = 10 * time.Minute
)

var (
	tenantRefresh = flag.Duration(
		"tenantGetterRefresh", defaultRefreshTime, "Forced refresh interval of tenant getter")
	timeoutGetTenant = flag.Duration(
		"tenantGetterInvTimeout", defaultTimeoutGetTenant, "Timeout for calls to inventory for tenant getter")
	singletonTGetter *tenantGetter
	once             sync.Once

	// eventsWatcherBufSize is the buffer size for the events channel.
	eventsWatcherBufSize = 10
)

type tenantGetter struct {
	inventoryClient client.TenantAwareInventoryClient
	eventsWatcher   chan *client.WatchEvents
	tenantID        string
	multiTenantErr  error
	lock            sync.Mutex
	stopChan        chan struct{}
}

// InitTenantGetter Init the tenant getter singleton, should be called only once.
func InitTenantGetter(wg *sync.WaitGroup, inventoryAddress string, enableTracing bool) error {
	err := error(nil)
	once.Do(func() {
		singletonTGetter, err = newTenantGetter(wg, inventoryAddress, enableTracing)
	})
	return err
}

// StartTenantGetter Starts the tenant getter if already initialized via InitTenantGetter, fails otherwise.
func StartTenantGetter() error {
	if singletonTGetter == nil {
		err := errors.Errorfc(codes.FailedPrecondition, "tenant getter not initialized")
		zlog.InfraSec().Err(err).Msg("starting tenant getter failed")
		return err
	}
	// Empty the stopChan to avoid immediate stop if StopTenantGetter is called before StartTenantGetter.
	for len(singletonTGetter.stopChan) > 0 {
		<-singletonTGetter.stopChan
	}
	singletonTGetter.startTenantGetter()
	return nil
}

// StopTenantGetter Stops the tenant getter if previously started via StartTenantGetter.
func StopTenantGetter() {
	if singletonTGetter != nil {
		singletonTGetter.stopTenantGetter()
	}
}

// GetSingularProviderTenantID Gets the singular tenant ID. If none, returns NotFound error, if multiple returns Internal error.
func GetSingularProviderTenantID() (string, error) {
	if singletonTGetter == nil {
		err := errors.Errorfc(codes.FailedPrecondition, "tenant getter not initialized")
		zlog.InfraSec().Err(err).Msg("getting singular tenantID failed")
		return "", err
	}
	return singletonTGetter.getSingularTenantID()
}

// TestInitTenantGetter for testing purposes only.
func TestInitTenantGetter(invClient client.TenantAwareInventoryClient, eventsWatcher chan *client.WatchEvents) {
	singletonTGetter = newTenantGetterWithClient(invClient, eventsWatcher)
}

// TestResetTenantGetter for testing purposes only.
func TestResetTenantGetter() {
	singletonTGetter = nil
}

func newTenantGetterWithClient(
	invClient client.TenantAwareInventoryClient, eventsWatcher chan *client.WatchEvents,
) *tenantGetter {
	return &tenantGetter{
		inventoryClient: invClient,
		eventsWatcher:   eventsWatcher,
		multiTenantErr:  errors.Errorfc(codes.Unavailable, "Not yet got a tenant"),
		tenantID:        "",
		lock:            sync.Mutex{},
		stopChan:        make(chan struct{}, 1),
	}
}

func newTenantGetter(wg *sync.WaitGroup, inventoryAddress string, enableTracing bool) (*tenantGetter, error) {
	eventsWatcher := make(chan *client.WatchEvents, eventsWatcherBufSize)
	invClient, err := client.NewTenantAwareInventoryClient(context.Background(),
		client.InventoryClientConfig{
			Name:                      "TenantGetter",
			Address:                   inventoryAddress,
			EnableRegisterRetry:       false,
			AbortOnUnknownClientError: true,
			SecurityCfg: &client.SecurityConfig{
				Insecure: true,
				CaPath:   "",
				CertPath: "",
				KeyPath:  "",
			},
			Events:     eventsWatcher,
			ClientKind: invv1.ClientKind_CLIENT_KIND_RESOURCE_MANAGER,
			ResourceKinds: []invv1.ResourceKind{
				invv1.ResourceKind_RESOURCE_KIND_PROVIDER,
			},
			Wg:            wg,
			EnableTracing: enableTracing,
		})
	if err != nil {
		zlog.InfraSec().Err(err).Msgf("Failed to create Tenant Getter inventory client")
		return nil, err
	}
	return &tenantGetter{
		inventoryClient: invClient,
		eventsWatcher:   eventsWatcher,
		multiTenantErr:  errors.Errorfc(codes.Unavailable, "Not yet got a tenant"),
		tenantID:        "",
		lock:            sync.Mutex{},
		stopChan:        make(chan struct{}, 1),
	}, nil
}

func (tg *tenantGetter) startTenantGetter() {
	tg.updateTenantIDOrSetError()
	ticker := time.NewTicker(*tenantRefresh)
	go func() {
		for {
			select {
			case <-tg.eventsWatcher:
				tg.updateTenantIDOrSetError()
			case <-ticker.C:
				tg.updateTenantIDOrSetError()
			case <-tg.stopChan:
				zlog.Debug().Msg("stopping tenant getter")
				if tg.inventoryClient != nil {
					tg.inventoryClient.Close()
				}
				return
			}
		}
	}()
}

func (tg *tenantGetter) stopTenantGetter() {
	tg.stopChan <- struct{}{}
}

func (tg *tenantGetter) updateTenantIDOrSetError() {
	ctx, cancel := context.WithTimeout(context.Background(), *timeoutGetTenant)
	defer cancel()

	providers, err := ListLOCAProviderResources(ctx, tg.inventoryClient)
	if err != nil {
		zlog.InfraSec().Err(err).Msg("Error while getting singular tenant ID")
		tg.setTenantIDAndError("", err)
		return
	}
	tenantID, err := GetSingularTenantIDFromProviders(providers)
	if err != nil {
		zlog.InfraSec().Err(err).Msg("Error while getting singular tenant ID")
		tg.setTenantIDAndError("", err)
		return
	}
	tg.setTenantIDAndError(tenantID, nil)
}

func (tg *tenantGetter) setTenantIDAndError(tenantID string, err error) {
	tg.lock.Lock()
	defer tg.lock.Unlock()
	tg.tenantID = tenantID
	tg.multiTenantErr = err
}

func (tg *tenantGetter) getSingularTenantID() (string, error) {
	tg.lock.Lock()
	defer tg.lock.Unlock()
	return tg.tenantID, tg.multiTenantErr
}
