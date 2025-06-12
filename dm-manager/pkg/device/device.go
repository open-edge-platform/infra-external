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

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
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

var powerMappingToInProgressState = map[computev1.PowerState]string{
	computev1.PowerState_POWER_STATE_UNSPECIFIED: "Unspecified",
	computev1.PowerState_POWER_STATE_ON:          "Powering on",
	computev1.PowerState_POWER_STATE_OFF:         "Powering off",
	computev1.PowerState_POWER_STATE_SLEEP:       "Sleeping",
	computev1.PowerState_POWER_STATE_RESET:       "Resetting",
	computev1.PowerState_POWER_STATE_HIBERNATE:   "Hibernating",
	computev1.PowerState_POWER_STATE_POWER_CYCLE: "Power cycling",
}

var powerMappingToIdleState = map[computev1.PowerState]string{
	computev1.PowerState_POWER_STATE_UNSPECIFIED: "Unspecified",
	computev1.PowerState_POWER_STATE_ON:          "Powered on",
	computev1.PowerState_POWER_STATE_OFF:         "Powered off",
	computev1.PowerState_POWER_STATE_SLEEP:       "Sleep state",
	computev1.PowerState_POWER_STATE_RESET:       "Reset successful",
	computev1.PowerState_POWER_STATE_HIBERNATE:   "Hibernate state",
	computev1.PowerState_POWER_STATE_POWER_CYCLE: "Power cycle successful",
}

//nolint: godot // copied from swagger file
/*
2 = On - corresponding to ACPI state G0 or S0 or D0.
3 = Sleep - Light, corresponding to ACPI state G1, S1/S2, or D1.
4 = Sleep - Deep, corresponding to ACPI state G1, S3, or D2.
6 = Off - Hard, corresponding to ACPI state G3, S5, or D3.
7 = Hibernate (Off - Soft), corresponding to ACPI state S4,
where the state of the managed element is preserved and will be recovered upon powering on.
8 = Off - Soft, corresponding to ACPI state G2, S5, or D3.
9 = Power Cycle (Off-Hard), corresponds to the managed element reaching the ACPI state G3 followed by ACPI state S0.
12	Power down/off (soft)	Powered up/on	Transition to a very minimal power state	G2/S5
13 = Off - Hard Graceful
equivalent to Off Hard but preceded by a request to the managed element to perform an orderly shutdown.
due to latency and mps not returning responses instantly, it is not always possible to check states like reboot.
for SLEEP/HIBERNATE, as MPS it returns 2 (POWER_ON)
14	Soft reset	Powered up/on	Perform a shutdown and then a hardware reset	N/A
*/
var allowedPowerStates = map[computev1.PowerState][]int32{
	computev1.PowerState_POWER_STATE_UNSPECIFIED: {},
	computev1.PowerState_POWER_STATE_ON:          {2},
	computev1.PowerState_POWER_STATE_OFF:         {6, 8, 12, 13},
	computev1.PowerState_POWER_STATE_SLEEP:       {2, 3, 4},
	computev1.PowerState_POWER_STATE_RESET:       {2, 14},
	computev1.PowerState_POWER_STATE_HIBERNATE:   {2, 7},
	computev1.PowerState_POWER_STATE_POWER_CYCLE: {2, 9},
}

var mpsPowerStateToInventoryPowerState = map[int32]computev1.PowerState{
	2:  computev1.PowerState_POWER_STATE_ON,
	3:  computev1.PowerState_POWER_STATE_SLEEP,
	4:  computev1.PowerState_POWER_STATE_SLEEP,
	6:  computev1.PowerState_POWER_STATE_OFF,
	8:  computev1.PowerState_POWER_STATE_OFF,
	12: computev1.PowerState_POWER_STATE_OFF,
	13: computev1.PowerState_POWER_STATE_OFF,
	7:  computev1.PowerState_POWER_STATE_HIBERNATE,
	9:  computev1.PowerState_POWER_STATE_POWER_CYCLE,
	14: computev1.PowerState_POWER_STATE_RESET,
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
	MpsClient         mps.ClientWithResponsesInterface
	InventoryRmClient client.TenantAwareInventoryClient
	TermChan          chan bool
	ReadyChan         chan bool
	EventsWatcher     chan *client.WatchEvents
	WaitGroup         *sync.WaitGroup
	DeviceController  *rec_v2.Controller[ID]

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
				log.InfraSec().Fatal().Msg("gRPC stream with Inventory closed")
				return
			}
			log.Info().Msgf("received %v event for %v",
				event.Event.GetEventKind().String(), event.Event.GetResource().GetHost().GetUuid())
			host := event.Event.GetResource().GetHost()
			if !(host.GetPowerStatusIndicator() == statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS ||
				host.GetPowerStatusIndicator() == statusv1.StatusIndication_STATUS_INDICATION_ERROR) {
				err := dc.DeviceController.Reconcile(NewID(
					event.Event.GetResource().GetHost().GetTenantId(),
					event.Event.GetResource().GetHost().GetUuid()),
				)
				if err != nil {
					log.Err(err).Msgf("failed to add event for %v to the reconciler",
						event.Event.GetResource().GetHost().GetUuid())
				}
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
	case invHost.GetCurrentAmtState() == computev1.AmtState_AMT_STATE_PROVISIONED &&
		invHost.GetDesiredPowerState() == invHost.GetCurrentPowerState():
		return dc.syncPowerStatus(ctx, request, invHost)

	case invHost.GetCurrentAmtState() == computev1.AmtState_AMT_STATE_PROVISIONED &&
		invHost.GetDesiredPowerState() != invHost.GetCurrentPowerState():
		req, status, err := dc.handlePowerChange(ctx, request, invHost, invHost.GetDesiredPowerState())
		if err != nil {
			updateError := dc.updateHost(ctx, request.ID.GetTenantID(), invHost.GetResourceId(),
				&fieldmaskpb.FieldMask{Paths: []string{
					computev1.HostResourceFieldPowerStatus,
					computev1.HostResourceFieldPowerStatusIndicator,
				}}, &computev1.HostResource{
					PowerStatus:          err.Error(),
					PowerStatusIndicator: status,
				})
			if updateError != nil {
				log.Err(updateError).Msgf("failed to update device status")
				return request.Fail(updateError)
			}
		}

		return req
	default:
		log.Debug().Msgf("device %v is in %v [%v]", request.ID, invHost.GetCurrentAmtState(), invHost.GetCurrentPowerState())
	}

	return request.Ack()
}

func (dc *Controller) syncPowerStatus(
	ctx context.Context, request rec_v2.Request[ID], invHost *computev1.HostResource,
) rec_v2.Directive[ID] {
	currentPowerState, err := dc.MpsClient.GetApiV1AmtPowerStateGuidWithResponse(ctx, invHost.GetUuid())
	if err != nil {
		log.Err(err).Msgf("failed to check current power state for %v", invHost.GetUuid())
		return request.Fail(err)
	}

	if currentPowerState.StatusCode() != http.StatusOK {
		err = errors.Errorf("%v", string(currentPowerState.Body))
		log.Err(err).
			Msgf("expected to get 2XX, but got %v", currentPowerState.StatusCode())
		return request.Fail(err)
	}

	//nolint: gosec // overflow is unlikely, correct values are <1000
	powerStateCode := int32(*currentPowerState.JSON200.Powerstate)

	if !contains(allowedPowerStates[invHost.GetDesiredPowerState()], powerStateCode) {
		log.Info().Msgf("%v host desired state is %v, but current power state is %v",
			invHost.GetUuid(), powerMapping[invHost.GetDesiredPowerState()], powerStateCode)

		err = dc.updateHost(ctx, invHost.GetTenantId(), invHost.GetResourceId(),
			&fieldmaskpb.FieldMask{Paths: []string{
				computev1.HostResourceFieldCurrentPowerState,
				computev1.HostResourceFieldPowerStatus,
				computev1.HostResourceFieldPowerStatusIndicator,
			}}, &computev1.HostResource{
				PowerStatus:          "mismatch between desired and current power state",
				PowerStatusIndicator: statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS,
				CurrentPowerState:    mpsPowerStateToInventoryPowerState[powerStateCode],
			})
		if err != nil {
			log.Err(err).Msgf("failed to update device info")
			return request.Fail(err)
		}
		return request.Retry(err).With(rec_v2.ExponentialBackoff(minDelay, maxDelay))
	}

	log.Debug().Msgf("%v host desired state is %v, which matches current power state",
		invHost.GetResourceId(), invHost.GetDesiredPowerState().String())

	err = dc.updateHost(ctx, request.ID.GetTenantID(), invHost.GetResourceId(),
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.HostResourceFieldPowerStatus,
			computev1.HostResourceFieldPowerStatusIndicator,
		}}, &computev1.HostResource{
			PowerStatus:          invHost.GetPowerStatus(),
			PowerStatusIndicator: invHost.GetPowerStatusIndicator(),
		})
	if err != nil {
		log.Err(err).Msgf("failed to update device info")
		return request.Retry(err).With(rec_v2.ExponentialBackoff(minDelay, maxDelay))
	}

	return request.Ack()
}

func (dc *Controller) handlePowerChange(
	ctx context.Context, request rec_v2.Request[ID], invHost *computev1.HostResource, desiredPowerState computev1.PowerState,
) (rec_v2.Directive[ID], statusv1.StatusIndication, error) {
	log.Info().Msgf("trying to change power state for %v from %v to %v", request.ID,
		invHost.GetCurrentPowerState(), desiredPowerState)

	err := dc.updateHost(ctx, request.ID.GetTenantID(), invHost.GetResourceId(),
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.HostResourceFieldPowerStatus,
			computev1.HostResourceFieldPowerStatusIndicator,
		}}, &computev1.HostResource{
			PowerStatus:          desiredPowerState.String(),
			PowerStatusIndicator: statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS,
		})
	if err != nil {
		log.Err(err).Msgf("failed to update device info")
		return request.Fail(err), statusv1.StatusIndication_STATUS_INDICATION_ERROR, err
	}

	// assumption is that we don't have to check if power actions are supported, as AMT supports it since 1.0.0
	// https://en.wikipedia.org/wiki/Intel_AMT_versions
	powerAction, err := dc.MpsClient.PostApiV1AmtPowerActionGuidWithResponse(ctx, request.ID.GetHostUUID(),
		mps.PostApiV1AmtPowerActionGuidJSONRequestBody{
			Action: powerMapping[desiredPowerState],
		})
	if err != nil {
		log.Err(err).Msgf("failed to send power action to MPS")
		return request.Fail(err),
			statusv1.StatusIndication_STATUS_INDICATION_ERROR, err
	}

	log.Debug().Msgf("power action response for %v with status code %v - %v", request.ID.GetHostUUID(),
		powerAction.HTTPResponse, string(powerAction.Body))

	if powerAction.StatusCode() != http.StatusOK {
		log.Err(err).
			Msgf("expected to get 2XX, but got %v", powerAction.StatusCode())

		if powerAction.StatusCode() == http.StatusNotFound {
			err = errors.Errorf("Device not found/connected")
			return request.Retry(err).With(rec_v2.ExponentialBackoff(minDelay, maxDelay)),
				statusv1.StatusIndication_STATUS_INDICATION_ERROR, err
		}

		return request.Fail(err),
			statusv1.StatusIndication_STATUS_INDICATION_ERROR, errors.Errorf("%v", toUserFriendlyError(string(powerAction.Body)))
	}

	// intentionally comparing whole body, as there are cases where MPS defines variable as lowercase
	// but it is uppercase instead
	if !strings.EqualFold(*powerAction.JSON200.Body.ReturnValueStr, "SUCCESS") {
		log.Err(errors.Errorf("power request sent successfully, but received unexpected response")).
			Msgf("expected to receive SUCCESS, but got %s", string(powerAction.Body))
		err = errors.Errorf("%v", string(powerAction.Body))

		return request.Fail(err), statusv1.StatusIndication_STATUS_INDICATION_ERROR, err
	}

	err = dc.updateHost(ctx, request.ID.GetTenantID(), invHost.GetResourceId(),
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.HostResourceFieldCurrentPowerState,
			computev1.HostResourceFieldPowerStatusIndicator,
		}}, &computev1.HostResource{
			CurrentPowerState:    desiredPowerState,
			PowerStatusIndicator: statusv1.StatusIndication_STATUS_INDICATION_IDLE,
		})
	if err != nil {
		log.Err(err).Msgf("failed to update device info")
		return request.Retry(err).With(rec_v2.ExponentialBackoff(minDelay, maxDelay)),
			statusv1.StatusIndication_STATUS_INDICATION_ERROR, err
	}

	return request.Ack(), statusv1.StatusIndication_STATUS_INDICATION_IDLE, nil
}

func toUserFriendlyError(err string) string {
	switch {
	case strings.Contains(err, "context deadline exceeded"):
		return "timeout while waiting response"
	case strings.Contains(err, "Device not found/connected"):
		return "Device not found/connected"
	case strings.Contains(err, "NOT_READY"):
		return "Device must be powered on first"
	default:
		log.Error().Msgf("unknown error occurred: %s", err)
		return "Unknown error occurred. Check logs for more details."
	}
}

func contains[T ~int | ~int8 | ~int16 | ~int32 | ~int64 | ~string](slice []T, elem T) bool {
	for _, v := range slice {
		if v == elem {
			return true
		}
	}
	return false
}

//nolint:cyclop // all checks are necessary
func (dc *Controller) updateHost(
	ctx context.Context, tenantID, invResourceID string, fieldMask *fieldmaskpb.FieldMask, invHost *computev1.HostResource,
) error {
	if invHost == nil {
		err := errors.Errorfc(codes.InvalidArgument, "no resource provided")
		log.InfraSec().InfraErr(err).Msg("Empty resource is provided")
		return err
	}

	if len(fieldMask.Paths) == 0 {
		log.InfraSec().Debug().
			Msgf("Skipping, no fields selected to update for an inventory resource: %v, tenantID=%s",
				invHost.GetResourceId(), tenantID)
		return nil
	}

	var err error
	invHost.PowerStatusTimestamp, err = inv_util.Int64ToUint64(time.Now().Unix())
	if err != nil {
		log.InfraSec().InfraErr(err).Msgf("failed to parse current time")
		// this error is unlikely, but in such case, set timestamp = 0
		invHost.PowerStatusTimestamp = 0
	}
	if !contains(fieldMask.Paths, computev1.HostResourceFieldPowerStatusTimestamp) {
		fieldMask.Paths = append(fieldMask.Paths, computev1.HostResourceFieldPowerStatusTimestamp)
	}

	switch invHost.PowerStatusIndicator {
	case statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS:
		invHost.PowerStatus = powerMappingToInProgressState[invHost.GetCurrentPowerState()]
	case statusv1.StatusIndication_STATUS_INDICATION_IDLE:
		invHost.PowerStatus = powerMappingToIdleState[invHost.GetCurrentPowerState()]
	case statusv1.StatusIndication_STATUS_INDICATION_ERROR:
		invHost.PowerStatus = toUserFriendlyError(invHost.PowerStatus)
	default:
		invHost.PowerStatus = "Unknown"
	}
	fieldMask.Paths = append(fieldMask.Paths, computev1.HostResourceFieldPowerStatus)

	resCopy := proto.Clone(invHost)
	fieldMask, err = fieldmaskpb.New(resCopy, fieldMask.Paths...)
	if err != nil {
		log.InfraSec().InfraErr(err).Msg("Failed to construct a fieldmask")
		return errors.Wrap(err)
	}

	err = inv_util.ValidateMaskAndFilterMessage(resCopy, fieldMask, true)
	if err != nil {
		log.InfraSec().InfraErr(err).Msg("Failed to validate a fieldMask and filter message")
		return err
	}

	_, err = dc.InventoryRmClient.Update(ctx, tenantID, invResourceID, fieldMask, &inventoryv1.Resource{
		Resource: &inventoryv1.Resource_Host{
			Host: invHost,
		},
	})
	if err != nil {
		log.InfraSec().InfraErr(err).Msgf("Failed to update resource (%s) for tenantID=%s", invResourceID, tenantID)
		return err
	}

	return nil
}
