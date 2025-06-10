/*
 * // SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * // SPDX-License-Identifier: Apache-2.0
 */

package device

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
	statusv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/status/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	inv_util "github.com/open-edge-platform/infra-core/inventory/v2/pkg/util"
	"github.com/open-edge-platform/infra-external/dm-manager/pkg/api/mps"
	rec_v2 "github.com/open-edge-platform/orch-library/go/pkg/controller/v2"
)

const (
	minDelay = 1 * time.Second
	maxDelay = 5 * time.Second

	powerOn    = mps.PowerActionRequestActionN2
	powerOff   = mps.PowerActionRequestActionN8
	powerReset = mps.PowerActionRequestActionN10
	powerCycle = mps.PowerActionRequestActionN5
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
	computev1.PowerState_POWER_STATE_POWER_CYCLE: powerCycle,
}

var powerStateMapping = map[mps.PowerActionRequestAction]computev1.PowerState{
	mps.PowerActionRequestActionN8: computev1.PowerState_POWER_STATE_OFF,
	mps.PowerActionRequestActionN2: computev1.PowerState_POWER_STATE_ON,
}

type ID string

func (id ID) GetTenantID() string {
	return strings.Split(string(id), "_")[0]
}

func (id ID) GetHostUUID() string {
	return strings.Split(string(id), "_")[1]
}

func (id ID) String() string {
	return fmt.Sprintf("[tenantID=%s, hostID=%s]", id.GetTenantID(), id.GetHostUUID())
}

func NewID(tenantID, hostUUID string) ID {
	return ID(tenantID + "_" + hostUUID)
}

type Controller struct {
	MpsClient          mps.ClientWithResponsesInterface
	InventoryRmClient  client.TenantAwareInventoryClient // manages Current* fields
	InventoryAPIClient client.TenantAwareInventoryClient // manages Desired* fields
	TermChan           chan bool
	ReadyChan          chan bool
	EventsWatcher      chan *client.WatchEvents
	WaitGroup          *sync.WaitGroup
	DeviceController   *rec_v2.Controller[ID]

	ReconcilePeriod time.Duration
	RequestTimeout  time.Duration
}

func (dc *Controller) Start() {
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
			err := dc.DeviceController.Reconcile(NewID(
				event.Event.GetResource().GetHost().GetTenantId(),
				event.Event.GetResource().GetHost().GetUuid()),
			)
			if err != nil {
				log.Err(err).Msgf("failed to add event for %v to the reconciler", event.Event.GetResource().GetHost().GetUuid())
			}
		}
	}
}

func (dc *Controller) ReconcileAll() {
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
		err := dc.DeviceController.Reconcile(NewID(host.GetHost().GetTenantId(), host.GetHost().GetUuid()))
		if err != nil {
			log.Err(err).Msgf("failed to reconcile device")
		}
	}
	log.Debug().Msgf("reconciliation of devices is done")
}

func (dc *Controller) Stop() {
	dc.WaitGroup.Done()
}

func (dc *Controller) Reconcile(ctx context.Context, request rec_v2.Request[ID]) rec_v2.Directive[ID] {
	log.Debug().Msgf("started device reconciliation for %v", request.ID)

	invHost, err := dc.InventoryRmClient.GetHostByUUID(ctx, request.ID.GetTenantID(), request.ID.GetHostUUID())
	if err != nil {
		log.Err(err).Msgf("couldn't get device from inventory")
		return request.Fail(err)
	}

	log.Debug().Msgf("desired state is %v[%v], current state is %v[%v] for %v",
		invHost.GetDesiredAmtState().String(), invHost.GetDesiredPowerState().String(),
		invHost.GetCurrentAmtState().String(), invHost.GetCurrentPowerState().String(), request.ID)

	switch {
	case invHost.GetDesiredAmtState() == invHost.GetCurrentAmtState() &&
		invHost.GetDesiredPowerState() == invHost.GetCurrentPowerState():
		return dc.syncPowerStatus(ctx, request, invHost)

	case invHost.GetCurrentAmtState() == computev1.AmtState_AMT_STATE_PROVISIONED &&
		invHost.GetDesiredPowerState() != invHost.GetCurrentPowerState():
		req, status, err := dc.handlePowerChange(ctx, request, invHost)
		if err != nil {
			_, updateError := dc.updateStatus(ctx, request.ID.GetTenantID(), invHost.GetResourceId(),
				err.Error(),
				status,
			)
			if updateError != nil {
				log.Err(updateError).Msgf("failed to update device status")
				return request.Fail(updateError)
			}
		}

		return req
	}

	return request.Ack()
}

func (dc *Controller) syncPowerStatus(
	ctx context.Context, request rec_v2.Request[ID], invHost *computev1.HostResource,
) rec_v2.Directive[ID] {
	// due to latency and mps not returning responses instantly, it is not possible to check states like reboot.
	// for SLEEP/HYBERNATE, it returns 2 (POWER_ON)
	if invHost.GetDesiredPowerState() == computev1.PowerState_POWER_STATE_ON ||
		invHost.GetDesiredPowerState() == computev1.PowerState_POWER_STATE_OFF {
		currentPowerState, err := dc.MpsClient.GetApiV1AmtPowerStateGuidWithResponse(ctx, invHost.GetUuid())
		if err != nil {
			log.Err(err).Msgf("failed to check current power state for %v", invHost.GetUuid())
			return request.Fail(err)
		}

		if currentPowerState.StatusCode() != http.StatusOK {
			err = errors.Errorf("%v", string(currentPowerState.Body))
			log.Err(err).
				Msgf("expected to get 2XX, but got %v", currentPowerState.StatusCode())
		}

		//nolint: gosec // overflow is unlikely, correct values are <1000
		powerStateCode := int32(*currentPowerState.JSON200.Powerstate)
		if powerStateCode != int32(invHost.GetDesiredPowerState().Enum().Number()) {
			log.Info().Msgf("%v host desired state is %v, but current power state is %v",
				invHost.GetUuid(), powerMapping[invHost.GetDesiredPowerState()], powerStateCode)

			updateHost := &computev1.HostResource{}
			updateHost.PowerStatusTimestamp, err = inv_util.Int64ToUint64(time.Now().Unix())
			if err != nil {
				log.InfraSec().InfraErr(err).Msgf("failed to parse current time")
				// this error is unlikely, but in such case, set timestamp = 0
				updateHost.PowerStatusTimestamp = 0
			}
			updateHost.PowerStatus = "mismatch between desired and current power state"
			updateHost.PowerStatusIndicator = statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS
			updateHost.CurrentPowerState = powerStateMapping[mps.PowerActionRequestAction(powerStateCode)]

			_, err = dc.InventoryRmClient.Update(ctx, invHost.GetTenantId(), invHost.GetResourceId(),
				&fieldmaskpb.FieldMask{Paths: []string{
					computev1.HostResourceFieldCurrentPowerState,
					computev1.HostResourceFieldPowerStatus,
					computev1.HostResourceFieldPowerStatusIndicator,
					computev1.HostResourceFieldPowerStatusTimestamp,
				}}, &inventoryv1.Resource{
					Resource: &inventoryv1.Resource_Host{
						Host: updateHost,
					},
				})
			if err != nil {
				log.Err(err).Msgf("failed to update device info")
				return request.Fail(err)
			}
			return request.Retry(err).With(rec_v2.ExponentialBackoff(minDelay, maxDelay))
		}

		log.Debug().Msgf("%v host desired state is %v, which matches current power state",
			invHost.GetResourceId(), invHost.GetDesiredPowerState().String())
	} else {
		log.Debug().Msgf("%v host desired state is %v, which cannot be verified in runtime",
			invHost.GetResourceId(), invHost.GetDesiredPowerState().String())
	}

	return request.Ack()
}

func (dc *Controller) updateStatus(
	ctx context.Context, tenantID, hostID, powerStatus string, powerStatusIndicator statusv1.StatusIndication,
) (*inventoryv1.Resource, error) {
	invHost := &computev1.HostResource{
		PowerStatus:          powerStatus,
		PowerStatusIndicator: powerStatusIndicator,
	}

	var err error
	invHost.PowerStatusTimestamp, err = inv_util.Int64ToUint64(time.Now().Unix())
	if err != nil {
		log.InfraSec().InfraErr(err).Msgf("failed to parse current time")
		// this error is unlikely, but in such case, set timestamp = 0
		invHost.PowerStatusTimestamp = 0
	}

	return dc.InventoryAPIClient.Update(ctx, tenantID, hostID,
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.HostResourceFieldPowerStatus,
			computev1.HostResourceFieldPowerStatusIndicator,
			computev1.HostResourceFieldPowerStatusTimestamp,
		}}, &inventoryv1.Resource{
			Resource: &inventoryv1.Resource_Host{
				Host: invHost,
			},
		})
}

func (dc *Controller) handlePowerChange(
	ctx context.Context, request rec_v2.Request[ID], invHost *computev1.HostResource,
) (rec_v2.Directive[ID], statusv1.StatusIndication, error) {
	log.Info().Msgf("trying to change power state for %v from %v to %v", request.ID,
		invHost.GetCurrentPowerState(), invHost.GetDesiredPowerState())

	_, err := dc.updateStatus(ctx, request.ID.GetTenantID(), invHost.GetResourceId(),
		invHost.GetDesiredPowerState().String(),
		statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS,
	)
	if err != nil {
		log.Err(err).Msgf("failed to update device info")
		return request.Fail(err), statusv1.StatusIndication_STATUS_INDICATION_ERROR, err
	}

	// assumption is that we don't have to check if power actions are supported, as AMT supports it since 1.0.0
	// https://en.wikipedia.org/wiki/Intel_AMT_versions
	powerAction, err := dc.MpsClient.PostApiV1AmtPowerActionGuidWithResponse(ctx, request.ID.GetHostUUID(),
		mps.PostApiV1AmtPowerActionGuidJSONRequestBody{
			Action: powerMapping[invHost.GetDesiredPowerState()],
		})
	if err != nil {
		log.Err(err).Msgf("failed to send power action to MPS")
		return request.Fail(err), statusv1.StatusIndication_STATUS_INDICATION_ERROR, err
	}

	log.Debug().Msgf("power action response for %v with status code %v - %v", request.ID.GetHostUUID(),
		powerAction.HTTPResponse, string(powerAction.Body))

	if powerAction.StatusCode() != http.StatusOK {
		err = errors.Errorf("%v", string(powerAction.Body))
		log.Err(err).
			Msgf("expected to get 2XX, but got %v", powerAction.StatusCode())
		return request.Fail(err), statusv1.StatusIndication_STATUS_INDICATION_ERROR, err
	}

	// intentionally comparing whole body, as there are cases where MPS defines variable as lowercase
	// but it is uppercase instead
	if !strings.EqualFold(*powerAction.JSON200.Body.ReturnValueStr, "SUCCESS") {
		log.Err(errors.Errorf("power request sent successfully, but received unexpected response")).
			Msgf("expected to receive SUCCESS, but got %s", string(powerAction.Body))

		// NOT_READY is returned when device is powered off but someone tries to reboot it
		// due to incorrect start state. Most of actions require POWER_ON as start state.
		// https://device-management-toolkit.github.io/docs/2.27/Reference/powerstates/
		if strings.EqualFold(*powerAction.JSON200.Body.ReturnValueStr, "NOT_READY") {
			return dc.forcePowerOn(ctx, request)
		}

		return request.Fail(err), statusv1.StatusIndication_STATUS_INDICATION_ERROR, err
	}

	updateHost := &computev1.HostResource{}
	updateHost.PowerStatusTimestamp, err = inv_util.Int64ToUint64(time.Now().Unix())
	if err != nil {
		log.InfraSec().InfraErr(err).Msgf("failed to parse current time")
		// this error is unlikely, but in such case, set timestamp = 0
		invHost.PowerStatusTimestamp = 0
	}
	updateHost.CurrentPowerState = invHost.GetDesiredPowerState()
	updateHost.PowerStatusIndicator = statusv1.StatusIndication_STATUS_INDICATION_IDLE
	updateHost.PowerStatus = invHost.GetDesiredPowerState().String()

	_, err = dc.InventoryRmClient.Update(ctx, request.ID.GetTenantID(), invHost.GetResourceId(),
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.HostResourceFieldCurrentPowerState,
			computev1.HostResourceFieldPowerStatus,
			computev1.HostResourceFieldPowerStatusIndicator,
			computev1.HostResourceFieldPowerStatusTimestamp,
		}}, &inventoryv1.Resource{
			Resource: &inventoryv1.Resource_Host{
				Host: updateHost,
			},
		})
	if err != nil {
		log.Err(err).Msgf("failed to update device info")
		return request.Fail(err), statusv1.StatusIndication_STATUS_INDICATION_ERROR, err
	}

	return request.Ack(), statusv1.StatusIndication_STATUS_INDICATION_IDLE, nil
}

func (dc *Controller) forcePowerOn(
	ctx context.Context, request rec_v2.Request[ID],
) (rec_v2.Directive[ID], statusv1.StatusIndication, error) {
	powerAction, err := dc.MpsClient.PostApiV1AmtPowerActionGuidWithResponse(ctx, request.ID.GetHostUUID(),
		mps.PostApiV1AmtPowerActionGuidJSONRequestBody{
			Action: powerMapping[computev1.PowerState_POWER_STATE_ON],
		})
	if err != nil {
		log.Err(err).Msgf("failed to send power action to MPS")
		return request.Fail(err), statusv1.StatusIndication_STATUS_INDICATION_ERROR, err
	}

	if powerAction.StatusCode() != http.StatusOK {
		err = errors.Errorf("%v", string(powerAction.Body))
		log.Err(err).
			Msgf("expected to get 2XX, but got %v", powerAction.StatusCode())
		return request.Fail(err), statusv1.StatusIndication_STATUS_INDICATION_ERROR, err
	}

	return request.Retry(errors.Errorf("powering on")).With(
		rec_v2.ExponentialBackoff(minDelay, maxDelay)), statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS, nil
}

//
//func (dc *Controller) updateHost(
//	ctx context.Context, tenantID, invResourceID string, fields []string, invHost *computev1.HostResource,
//) error {
//	if invHost == nil {
//		err := errors.Errorfc(codes.InvalidArgument, "no resource provided")
//		log.InfraSec().InfraErr(err).Msg("Empty resource is provided")
//		return err
//	}
//
//	if len(fields) == 0 {
//		log.InfraSec().Debug().
//			Msgf("Skipping, no fields selected to update for an inventory resource: %v, tenantID=%s",
//				invHost.GetResourceId(), tenantID)
//		return nil
//	}
//
//	resource := &inventoryv1.Resource{
//		Resource: &inventoryv1.Resource_Host{
//			Host: invHost,
//		},
//	}
//
//	fieldMask, err := fieldmaskpb.New(resource, fields...)
//	if err != nil {
//		log.InfraSec().InfraErr(err).Msg("Failed to construct a fieldmask")
//		return errors.Wrap(err)
//	}
//
//	err = inv_util.ValidateMaskAndFilterMessage(resource, fieldMask, true)
//	if err != nil {
//		log.InfraSec().InfraErr(err).Msg("Failed to validate a fieldmask and filter message")
//		return err
//	}
//
//	_, err = dc.InventoryRmClient.Update(ctx, tenantID, invResourceID, fieldMask, resource)
//	if err != nil {
//		log.InfraSec().InfraErr(err).Msgf("Failed to update resource (%s) for tenantID=%s", invResourceID, tenantID)
//		return err
//	}
//
//	return nil
//}
