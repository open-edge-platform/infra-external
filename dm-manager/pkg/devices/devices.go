/*
 * // SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * // SPDX-License-Identifier: Apache-2.0
 */

package devices

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/fieldmaskpb"

	computev1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/compute/v1"
	inventoryv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/inventory/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	"github.com/open-edge-platform/infra-external/dm-manager/pkg/api/mps"
	"github.com/open-edge-platform/infra-external/dm-manager/pkg/api/rps"
	rec_v2 "github.com/open-edge-platform/orch-library/go/pkg/controller/v2"
)

const (
	powerOn    = mps.PowerActionRequestActionN2
	powerOff   = mps.PowerActionRequestActionN8
	powerReset = mps.PowerActionRequestActionN10
	// In-band power actions require the presence of an agent running while the operating system
	// is up and operational like the Intel Local Manageability Service (LMS).
	powerSleep     = mps.PowerActionRequestActionN4
	powerHibernate = mps.PowerActionRequestActionN7
)

var log = logging.GetLogger("DeviceReconciler")

var powerMapping = map[computev1.PowerState]mps.PowerActionRequestAction{
	computev1.PowerState_POWER_STATE_UNSPECIFIED: powerOn, // todo: consider removing this mapping
	computev1.PowerState_POWER_STATE_ON:          powerOn,
	computev1.PowerState_POWER_STATE_OFF:         powerOff,
	computev1.PowerState_POWER_STATE_SLEEP:       powerSleep,
	computev1.PowerState_POWER_STATE_RESET:       powerReset,
	computev1.PowerState_POWER_STATE_HIBERNATE:   powerHibernate,
}

type DeviceID string

func (id DeviceID) GetTenantID() string {
	return strings.Split(string(id), "_")[0]
}

func (id DeviceID) GetHostUUID() string {
	return strings.Split(string(id), "_")[1]
}

func (id DeviceID) String() string {
	return fmt.Sprintf("[tenantID=%s, hostID=%s]", id.GetTenantID(), id.GetHostUUID())
}

func NewDeviceID(tenantID, hostUUID string) DeviceID {
	return DeviceID(tenantID + "_" + hostUUID)
}

type DeviceController struct {
	MpsClient          mps.ClientWithResponsesInterface
	RpsClient          rps.ClientWithResponsesInterface
	InventoryRmClient  client.TenantAwareInventoryClient // manages Current* fields
	InventoryAPIClient client.TenantAwareInventoryClient // manages Desired* fields
	TermChan           chan bool
	ReadyChan          chan bool
	EventsWatcher      chan *client.WatchEvents
	WaitGroup          *sync.WaitGroup
	DeviceController   *rec_v2.Controller[DeviceID]

	ReconcilePeriod time.Duration
	RequestTimeout  time.Duration
}

func (dc *DeviceController) Start() {
	ticker := time.NewTicker(dc.ReconcilePeriod)
	dc.ReadyChan <- true
	log.Info().Msgf("Starting periodic reconciliation for devices")
	dc.ReconcileAll()
	for {
		select {
		case <-ticker.C:
			dc.ReconcileAll()
		case <-dc.TermChan:
			log.Info().Msgf("Stopping periodic reconciliation")
			ticker.Stop()
			dc.Stop()
			return
		case event, ok := <-dc.EventsWatcher:
			if !ok {
				ticker.Stop()
				dc.Stop()
				return
			}
			log.Info().Msgf("received %v event for %v",
				event.Event.GetEventKind().String(), event.Event.GetResource().GetHost().GetUuid())
			err := dc.DeviceController.Reconcile(NewDeviceID(
				event.Event.GetResource().GetHost().GetTenantId(),
				event.Event.GetResource().GetHost().GetUuid()),
			)
			if err != nil {
				log.Err(err).Msgf("failed to add event for %v to the reconciler", event.Event.GetResource().GetHost().GetUuid())
			}
		}
	}
}

func (dc *DeviceController) ReconcileAll() {
	ctx, cancel := context.WithTimeout(context.Background(), dc.RequestTimeout)
	defer cancel()
	hosts, err := dc.InventoryRmClient.ListAll(ctx, &inventoryv1.ResourceFilter{
		Resource: &inventoryv1.Resource{Resource: &inventoryv1.Resource_Host{}},
	})
	if err != nil {
		log.Error().Err(err).Msgf("Failed to list hosts")
		return
	}

	for _, host := range hosts {
		err := dc.DeviceController.Reconcile(NewDeviceID(host.GetHost().GetTenantId(), host.GetHost().GetUuid()))
		if err != nil {
			log.Err(err).Msgf("failed to reconcile device")
		}
	}
	log.Debug().Msgf("reconciliation of devices is done")
}

func (dc *DeviceController) Stop() {
	dc.WaitGroup.Done()
}

func (dc *DeviceController) Reconcile(ctx context.Context, request rec_v2.Request[DeviceID]) rec_v2.Directive[DeviceID] {
	log.Debug().Msgf("started device reconciliation for %v", request.ID)

	invHost, err := dc.InventoryRmClient.GetHostByUUID(ctx, request.ID.GetTenantID(), request.ID.GetHostUUID())
	if err != nil {
		log.Err(err).Msgf("couldn't get device from inventory")
		return request.Fail(err)
	}

	log.Debug().Msgf("desired state is %v[%v], current state is %v[%v] for %v",
		invHost.GetDesiredAmtState().String(), invHost.GetDesiredPowerState().String(),
		invHost.GetCurrentAmtState().String(), invHost.GetCurrentPowerState(), request.ID)

	switch {
	case invHost.GetDesiredAmtState() == invHost.GetCurrentAmtState() &&
		invHost.GetDesiredPowerState() == invHost.GetCurrentPowerState():
		log.Debug().Msgf("desired state is equal to current state for %v, nothing to do", request.ID.GetHostUUID())
		return request.Ack()

	case invHost.GetCurrentAmtState() == computev1.AmtState_AMT_STATE_PROVISIONED &&
		invHost.GetDesiredPowerState() != invHost.GetCurrentPowerState():
		return dc.handlePowerChange(ctx, request, invHost)
	}

	return request.Ack()
}

func (dc *DeviceController) handlePowerChange(
	ctx context.Context, request rec_v2.Request[DeviceID], invHost *computev1.HostResource,
) rec_v2.Directive[DeviceID] {
	log.Info().Msgf("trying to change power state for %v from %v to %v", request.ID,
		invHost.GetCurrentPowerState(), invHost.GetDesiredPowerState())
	powerAction, err := dc.MpsClient.PostApiV1AmtPowerActionGuidWithResponse(ctx, request.ID.GetHostUUID(),
		mps.PostApiV1AmtPowerActionGuidJSONRequestBody{
			Action: powerMapping[invHost.GetDesiredPowerState()],
		})
	if err != nil {
		log.Err(err).Msgf("failed to send power action to MPS")
		return request.Fail(err)
	}

	log.Debug().Msgf("power action response for %v with status code %v - %v", request.ID.GetHostUUID(),
		powerAction.HTTPResponse, string(powerAction.Body))

	if powerAction.StatusCode() != http.StatusOK {
		log.Err(errors.Errorf("%v", string(powerAction.Body))).
			Msgf("expected to get 2XX, but got %v", powerAction.StatusCode())
		return request.Fail(err)
	}

	// intentionally comparing whole body, as there are cases where MPS defines variable as lowercase
	// but it is uppercase instead
	// "Body":{"ReturnValue":0,"ReturnValueStr":"SUCCESS"}}
	if !strings.Contains(strings.ToUpper(string(powerAction.Body)), "SUCCESS") {
		log.Err(errors.Errorf("power request sent successfully, but received unexpected response")).
			Msgf("expected to receive SUCCESS, but got %s", string(powerAction.Body))
		return request.Fail(err)
	}

	currentPowerState := invHost.GetDesiredPowerState()
	// prevent reboot loop on host
	if invHost.GetDesiredPowerState() == computev1.PowerState_POWER_STATE_RESET {
		_, err = dc.InventoryAPIClient.Update(ctx, request.ID.GetTenantID(), invHost.GetResourceId(),
			&fieldmaskpb.FieldMask{Paths: []string{
				computev1.HostResourceFieldDesiredPowerState,
			}}, &inventoryv1.Resource{
				Resource: &inventoryv1.Resource_Host{
					Host: &computev1.HostResource{
						DesiredPowerState: computev1.PowerState_POWER_STATE_ON,
					},
				},
			})
		if err != nil {
			log.Err(err).Msgf("failed to update device info")
			return request.Fail(err)
		}
		currentPowerState = computev1.PowerState_POWER_STATE_ON
	}
	_, err = dc.InventoryRmClient.Update(ctx, request.ID.GetTenantID(), invHost.GetResourceId(),
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.HostResourceFieldCurrentPowerState,
		}}, &inventoryv1.Resource{
			Resource: &inventoryv1.Resource_Host{
				Host: &computev1.HostResource{
					CurrentPowerState: currentPowerState,
				},
			},
		})
	if err != nil {
		log.Err(err).Msgf("failed to update device info")
		return request.Fail(err)
	}
	return request.Ack()
}
