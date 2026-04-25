// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

// Package kvm implements the KVM session lifecycle reconciler.
// It watches Inventory for desired_kvm_state changes and drives the
// session start/stop/consent flow.
//
// relay token acquisition. kvm-manager only handles:
//   - Feature check and consent trigger (KVM_STATE_AWAITING_CONSENT)
//   - Acknowledgement of KVM_STATE_CONSENT_RECEIVED
//   - KVM_STATE_REDIRECTION_RECEIVED and sets current_kvm_state=KVM_STATE_START
//   - KVM_STATE_STOP teardown
package kvm

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
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	inv_util "github.com/open-edge-platform/infra-core/inventory/v2/pkg/util"
	"github.com/open-edge-platform/infra-external/kvm-manager/pkg/api/mps"
	rec_v2 "github.com/open-edge-platform/orch-library/go/pkg/controller/v2"
)

const (
	minDelay = 1 * time.Second
	maxDelay = 5 * time.Second
)

var log = logging.GetLogger("KvmReconciler")

// ID uniquely identifies a reconciliation work item: tenantID + host UUID.
type ID string

type contextValue string

// GetTenantID returns the tenant portion of the reconciler ID.
func (id ID) GetTenantID() string {
	return strings.Split(string(id), "_")[0]
}

// GetHostUUID returns the host UUID portion of the reconciler ID.
func (id ID) GetHostUUID() string {
	return strings.Split(string(id), "_")[1]
}

func (id ID) String() string {
	return fmt.Sprintf("[tenantID=%s, hostUUID=%s]", id.GetTenantID(), id.GetHostUUID())
}

// NewID constructs a reconciler ID from tenantID and AMT device UUID.
func NewID(tenantID, hostUUID string) ID {
	return ID(tenantID + "_" + hostUUID)
}

// Controller is the KVM resource manager. It watches Inventory for
// desired_kvm_state changes on HostResource and drives the KVM session
// lifecycle by calling MPS REST APIs.
type Controller struct {
	MpsClient         mps.ClientWithResponsesInterface
	InventoryRmClient client.TenantAwareInventoryClient
	TermChan          chan bool
	ReadyChan         chan bool
	EventsWatcher     chan *client.WatchEvents
	WaitGroup         *sync.WaitGroup
	KvmController     *rec_v2.Controller[ID]

	ReconcilePeriod time.Duration
	RequestTimeout  time.Duration
}

// Start begins event-driven and periodic reconciliation.
func (kc *Controller) Start() {
	ticker := time.NewTicker(kc.ReconcilePeriod)
	kc.ReadyChan <- true
	log.Info().Msg("KVM manager started")
	kc.ReconcileAll()
	for {
		select {
		case <-ticker.C:
			kc.ReconcileAll()
		case <-kc.TermChan:
			log.Info().Msg("KVM manager stopping")
			ticker.Stop()
			kc.Stop()
			return
		case event, ok := <-kc.EventsWatcher:
			if !ok {
				ticker.Stop()
				kc.Stop()
				log.InfraSec().Fatal().Msg("gRPC stream with Inventory closed")
				return
			}
			host := event.Event.GetResource().GetHost()
			log.Info().Msgf("received %v event for host %v",
				event.Event.GetEventKind().String(), host.GetUuid())
			if err := kc.KvmController.Reconcile(
				NewID(host.GetTenantId(), host.GetUuid())); err != nil {
				log.Err(err).Msgf("failed to enqueue reconcile for host %v", host.GetUuid())
			}
		}
	}
}

// ReconcileAll lists all hosts and triggers reconciliation for those that
// have a non-unspecified desired_kvm_state.
func (kc *Controller) ReconcileAll() {
	ctx, cancel := context.WithTimeout(context.Background(), kc.RequestTimeout)
	defer cancel()
	hosts, err := kc.InventoryRmClient.ListAll(ctx, &inventoryv1.ResourceFilter{
		Resource: &inventoryv1.Resource{Resource: &inventoryv1.Resource_Host{}},
	})
	if err != nil {
		log.Error().Err(err).Msg("failed to list hosts during periodic reconcile")
		return
	}
	for _, h := range hosts {
		host := h.GetHost()
		if host.GetDesiredKvmState() == computev1.KvmState_KVM_STATE_UNSPECIFIED {
			continue
		}
		if err := kc.KvmController.Reconcile(
			NewID(host.GetTenantId(), host.GetUuid())); err != nil {
			log.Err(err).Msgf("failed to enqueue reconcile for host %v", host.GetUuid())
		}
	}
	log.Debug().Msg("periodic KVM reconciliation complete")
}

// Stop signals the WaitGroup that this goroutine has finished.
func (kc *Controller) Stop() {
	kc.WaitGroup.Done()
}

// Reconcile is called by the controller framework for each host ID.
func (kc *Controller) Reconcile(ctx context.Context, request rec_v2.Request[ID]) rec_v2.Directive[ID] {
	log.Debug().Msgf("KVM reconcile started for %v", request.ID)

	invHost, err := kc.InventoryRmClient.GetHostByUUID(
		ctx, request.ID.GetTenantID(), request.ID.GetHostUUID())
	if err != nil {
		log.Err(err).Msgf("failed to get host from inventory for %v", request.ID)
		return request.Fail(err)
	}

	log.Debug().Msgf("host %v: desiredKvmState=%v currentKvmState=%v desiredPowerState=%v",
		request.ID,
		invHost.GetDesiredKvmState(),
		invHost.GetCurrentKvmState(),
		invHost.GetDesiredPowerState())

	// reject power ops while a KVM session is active.
	if blocked, dir := kc.blockDisruptivePowerOp(ctx, request, invHost); blocked {
		return dir
	}

	switch {
	case kc.shouldStartKVMSession(invHost):
		return kc.handleStartKVMSession(ctx, request, invHost)
	case kc.shouldStopKVMSession(invHost):
		return kc.handleStopKVMSession(ctx, request, invHost)
	case invHost.GetDesiredKvmState() == computev1.KvmState_KVM_STATE_CONSENT_RECEIVED:
		// orch-cli has submitted the consent code directly to MPS
		log.Info().Msgf("host %v: KVM_STATE_CONSENT_RECEIVED acknowledged", request.ID)
		return request.Ack()
	case invHost.GetDesiredKvmState() == computev1.KvmState_KVM_STATE_REDIRECTION_RECEIVED:
		// orch-cli has obtained the relay token directly from MPS
		return kc.handleRedirectionReceived(ctx, request, invHost)
	default:
		log.Debug().Msgf("host %v: no KVM action needed (desired=%v current=%v)",
			request.ID, invHost.GetDesiredKvmState(), invHost.GetCurrentKvmState())
	}
	return request.Ack()
}

// isDisruptivePowerOp returns true for power states that
// would terminate an active KVM session.
func isDisruptivePowerOp(ps computev1.PowerState) bool {
	switch ps { //nolint:exhaustive
	case computev1.PowerState_POWER_STATE_OFF,
		computev1.PowerState_POWER_STATE_RESET,
		computev1.PowerState_POWER_STATE_RESET_REPEAT:
		return true
	default:
		return false
	}
}

// kvmStartInProgress returns true whenever a KVM start has been requested.
func kvmStartInProgress(invHost *computev1.HostResource) bool {
	switch invHost.GetDesiredKvmState() { //nolint:exhaustive
	case computev1.KvmState_KVM_STATE_START,
		computev1.KvmState_KVM_STATE_CONSENT_RECEIVED,
		computev1.KvmState_KVM_STATE_REDIRECTION_RECEIVED:
		return true
	}
	switch invHost.GetCurrentKvmState() { //nolint:exhaustive
	case computev1.KvmState_KVM_STATE_AWAITING_CONSENT,
		computev1.KvmState_KVM_STATE_START:
		return true
	}
	return false
}

// blockDisruptivePowerOp checks whether a disruptive power operation has been
// requested at any point during the KVM start phase
// then it resets desired_power_state to UNSPECIFIED,
// writes warning to kvm_session_status and returns true so that operator can
// Ack without further action.
func (kc *Controller) blockDisruptivePowerOp(
	ctx context.Context,
	request rec_v2.Request[ID],
	invHost *computev1.HostResource,
) (bool, rec_v2.Directive[ID]) {
	if !kvmStartInProgress(invHost) {
		return false, request.Ack()
	}
	desiredPower := invHost.GetDesiredPowerState()
	if !isDisruptivePowerOp(desiredPower) {
		return false, request.Ack()
	}
	tenantID := request.ID.GetTenantID()
	resourceID := invHost.GetResourceId()
	hostUUID := request.ID.GetHostUUID()
	msg := fmt.Sprintf(
		"power operation %v rejected: KVM session is active on host %v — stop KVM session before changing power state",
		desiredPower, hostUUID)
	log.Warn().Msg(msg)
	if updateErr := kc.updateHost(ctx, tenantID, resourceID,
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.HostResourceFieldDesiredPowerState,
			computev1.HostResourceFieldKvmSessionStatus,
		}},
		&computev1.HostResource{
			DesiredPowerState: computev1.PowerState_POWER_STATE_UNSPECIFIED,
			KvmSessionStatus:  msg,
		},
	); updateErr != nil {
		log.Err(updateErr).Msgf("failed to reset desired_power_state for host %v", hostUUID)
		return true, request.Fail(updateErr)
	}
	return true, request.Ack()
}

// shouldStartKVMSession returns true when the operator requested KVM_STATE_START
// and the session is not yet active.
func (kc *Controller) shouldStartKVMSession(invHost *computev1.HostResource) bool {
	return invHost.GetDesiredKvmState() == computev1.KvmState_KVM_STATE_START &&
		invHost.GetCurrentKvmState() != computev1.KvmState_KVM_STATE_START
}

// shouldStopKVMSession returns true when the operator requested KVM_STATE_STOP
// and the session has not yet been torn down.
func (kc *Controller) shouldStopKVMSession(invHost *computev1.HostResource) bool {
	return invHost.GetDesiredKvmState() == computev1.KvmState_KVM_STATE_STOP &&
		invHost.GetCurrentKvmState() != computev1.KvmState_KVM_STATE_STOP
}

// handleStartKVMSession drives the KVM start lifecycle:
//  1. Pre-condition: host must be AMT_STATE_PROVISIONED.
//  2. GET /api/v1/amt/features/{guid} — verify KVM enabled, read userConsent.
//  3. CCM only: trigger on-screen consent code display, write KVM_STATE_AWAITING_CONSENT.
//     orch-cli submits the code directly to MPS and signals KVM_STATE_CONSENT_RECEIVED.
//  4. ACM: write KVM_STATE_AWAITING_CONSENT skipped; orch-cli will signal KVM_STATE_REDIRECTION_RECEIVED
//     after obtaining the relay token directly from MPS.
func (kc *Controller) handleStartKVMSession(
	ctx context.Context,
	request rec_v2.Request[ID],
	invHost *computev1.HostResource,
) rec_v2.Directive[ID] {
	hostUUID := request.ID.GetHostUUID()
	tenantID := request.ID.GetTenantID()
	resourceID := invHost.GetResourceId()

	// device must be fully provisioned via RPS.
	if invHost.GetCurrentAmtState() != computev1.AmtState_AMT_STATE_PROVISIONED {
		errMsg := fmt.Sprintf(
			"KVM_STATE_START rejected: host %v AMT state is %v, must be AMT_STATE_PROVISIONED",
			hostUUID, invHost.GetCurrentAmtState())
		log.Error().Msg(errMsg)
		return kc.writeKvmError(ctx, request, tenantID, resourceID, errMsg)
	}

	updatedCtx := context.WithValue(ctx, contextValue("tenantId"), tenantID)

	// Step 1 — GET AMT features from MPS.
	log.Debug().Msgf("host %v: GET /api/v1/amt/features", hostUUID)
	featResp, err := kc.MpsClient.GetApiV1AmtFeaturesGuidWithResponse(
		updatedCtx, hostUUID, clientCallback())
	if err != nil {
		log.Err(err).Msgf("GET /amt/features failed for host %v", hostUUID)
		return request.Fail(err)
	}
	if featResp.StatusCode() != http.StatusOK {
		errMsg := fmt.Sprintf("GET /amt/features returned %d: %s",
			featResp.StatusCode(), string(featResp.Body))
		log.Error().Msg(errMsg)
		return kc.writeKvmError(ctx, request, tenantID, resourceID, errMsg)
	}
	log.Debug().Msgf("host %v: GET /amt/features response: %s", hostUUID, string(featResp.Body))
	features := featResp.JSON200
	if features == nil {
		errMsg := fmt.Sprintf("GET /amt/features returned empty body for host %v", hostUUID)
		log.Error().Msg(errMsg)
		return kc.writeKvmError(ctx, request, tenantID, resourceID, errMsg)
	}
	log.Debug().Msgf("host %v: AMT features — KVM=%v userConsent=%v redirection=%v",
		hostUUID, features.KVM, features.UserConsent, features.Redirection)

	// Step 3 — Consent flow for CCM devices.
	// CCM requires user consent, ACM does not.
	isCCM := invHost.GetAmtControlMode() == computev1.AmtControlMode_AMT_CONTROL_MODE_CCM
	log.Debug().Msgf("host %v: amtControlMode=%v isCCM=%v",
		hostUUID, invHost.GetAmtControlMode(), isCCM)
	if isCCM {
		log.Info().Msgf("host %v: CCM device — consent flow required", hostUUID)
		return kc.handleConsentFlow(
			ctx, updatedCtx, request, invHost, tenantID, resourceID, hostUUID)
	}

	// Step 2 — ACM: signal ready for orch-cli to acquire token.
	// orch-cli will call MPS GET /authorize/redirection and signal KVM_STATE_REDIRECTION_RECEIVED.
	log.Info().Msgf("host %v: ACM device — waiting for orch-cli to acquire relay token", hostUUID)
	if updateErr := kc.updateHost(ctx, tenantID, resourceID,
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.HostResourceFieldCurrentKvmState,
			computev1.HostResourceFieldKvmSessionStatus,
		}},
		&computev1.HostResource{
			CurrentKvmState:  computev1.KvmState_KVM_STATE_AWAITING_CONSENT,
			KvmSessionStatus: "Waiting for orch-cli to obtain relay token from MPS",
		},
	); updateErr != nil {
		log.Err(updateErr).Msgf("failed to set ready state for host %v", hostUUID)
		return request.Fail(updateErr)
	}
	return request.Ack()
}

// handleConsentFlow manages the CCM user-consent sub-flow.
// Triggers the on-screen code display and writes KVM_STATE_AWAITING_CONSENT.
// orch-cli is responsible for prompting the operator, submitting the code
// directly to MPS, and signalling KVM_STATE_CONSENT_RECEIVED.
func (kc *Controller) handleConsentFlow(
	ctx context.Context,
	updatedCtx context.Context,
	request rec_v2.Request[ID],
	invHost *computev1.HostResource,
	tenantID, resourceID, hostUUID string,
) rec_v2.Directive[ID] {
	// Already awaiting consent — nothing more for kvm-manager to do until orch-cli signals.
	if invHost.GetCurrentKvmState() == computev1.KvmState_KVM_STATE_AWAITING_CONSENT {
		log.Info().Msgf("host %v: waiting for orch-cli to submit consent code to MPS", hostUUID)
		return request.Ack()
	}

	// Trigger on-screen 6-digit code display.
	log.Info().Msgf("host %v: triggering user consent code display via MPS", hostUUID)
	consentResp, err := kc.MpsClient.GetApiV1AmtUserConsentCodeGuidWithResponse(
		updatedCtx, hostUUID, clientCallback())
	if err != nil {
		// MPS returns Header.RelatesTo as an integer but the generated client expects string,
		// causing a JSON unmarshal error. The parser only runs after HTTP 200 is confirmed,
		// so a json/unmarshal error here means the request succeeded. Proceed.
		if consentResp != nil && (strings.Contains(err.Error(), "json") || strings.Contains(err.Error(), "unmarshal")) {
			// HTTP 200 was received; the parse error is a known Header.RelatesTo type mismatch — proceed.
			log.Info().Msgf("host %v: GET /amt/userConsentCode HTTP 200 (parse skipped: Header.RelatesTo mismatch)", hostUUID)
		} else {
			log.Err(err).Msgf("GET /amt/userConsentCode failed for host %v", hostUUID)
			return request.Fail(err)
		}
	}
	if consentResp != nil && consentResp.StatusCode() != http.StatusOK {
		body := string(consentResp.Body)
		if !strings.Contains(body, "NOT_READY") {
			// NOT_READY means the code is already displayed — treat as success and proceed.
			// Any other non-OK status is a fatal error.
			errMsg := fmt.Sprintf("GET /amt/userConsentCode returned %d: %s", consentResp.StatusCode(), body)
			log.Error().Msg(errMsg)
			return kc.writeKvmError(ctx, request, tenantID, resourceID, errMsg)
		}
		log.Info().Msgf("host %v: consent code already displayed (NOT_READY), proceeding", hostUUID)
	}
	log.Debug().Msgf("host %v: consent code display triggered, setting AWAITING_CONSENT", hostUUID)
	if updateErr := kc.updateHost(ctx, tenantID, resourceID,
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.HostResourceFieldCurrentKvmState,
			computev1.HostResourceFieldKvmSessionStatus,
		}},
		&computev1.HostResource{
			CurrentKvmState:  computev1.KvmState_KVM_STATE_AWAITING_CONSENT,
			KvmSessionStatus: "Waiting for operator to enter consent code from device screen",
		},
	); updateErr != nil {
		log.Err(updateErr).Msgf("failed to set AWAITING_CONSENT for host %v", hostUUID)
		return request.Fail(updateErr)
	}
	log.Info().Msgf("host %v: set current_kvm_state=KVM_STATE_AWAITING_CONSENT, waiting for orch-cli to submit consent", hostUUID)
	return request.Ack()
}

// handleRedirectionReceived is called when orch-cli signals KVM_STATE_REDIRECTION_RECEIVED,
// relay token has been created from MPS.
// set current_kvm_state=KVM_STATE_START to confirm the session is active.
func (kc *Controller) handleRedirectionReceived(
	ctx context.Context,
	request rec_v2.Request[ID],
	invHost *computev1.HostResource,
) rec_v2.Directive[ID] {
	tenantID := request.ID.GetTenantID()
	resourceID := invHost.GetResourceId()
	hostUUID := request.ID.GetHostUUID()

	log.Info().Msgf("host %v: KVM_STATE_REDIRECTION_RECEIVED — activating session", hostUUID)
	if updateErr := kc.updateHost(ctx, tenantID, resourceID,
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.HostResourceFieldCurrentKvmState,
			computev1.HostResourceFieldKvmStatus,
			computev1.HostResourceFieldKvmSessionStatus,
		}},
		&computev1.HostResource{
			CurrentKvmState:  computev1.KvmState_KVM_STATE_START,
			KvmStatus:        computev1.KvmStatus_KVM_STATUS_ACTIVATED,
			KvmSessionStatus: "KVM session active",
		},
	); updateErr != nil {
		log.Err(updateErr).Msgf("failed to activate KVM session for host %v", hostUUID)
		return request.Retry(updateErr).With(rec_v2.ExponentialBackoff(minDelay, maxDelay))
	}
	log.Info().Msgf("host %v: KVM_STATE_START written — session active", hostUUID)
	return request.Ack()
}

// handleStopKVMSession tears down the KVM session. The relay token expires
// naturally once the browser disconnects; kvm-manager simply clears the URL
// and marks the state as KVM_STATE_STOP.
func (kc *Controller) handleStopKVMSession(
	ctx context.Context,
	request rec_v2.Request[ID],
	invHost *computev1.HostResource,
) rec_v2.Directive[ID] {
	tenantID := request.ID.GetTenantID()
	resourceID := invHost.GetResourceId()
	hostUUID := request.ID.GetHostUUID()

	log.Info().Msgf("host %v: stopping KVM session", hostUUID)

	if updateErr := kc.updateHost(ctx, tenantID, resourceID,
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.HostResourceFieldCurrentKvmState,
			computev1.HostResourceFieldKvmStatus,
			computev1.HostResourceFieldKvmSessionStatus,
		}},
		&computev1.HostResource{
			CurrentKvmState:  computev1.KvmState_KVM_STATE_STOP,
			KvmStatus:        computev1.KvmStatus_KVM_STATUS_DEACTIVATED,
			KvmSessionStatus: "KVM session stopped",
		},
	); updateErr != nil {
		log.Err(updateErr).Msgf("failed to stop KVM session for host %v", hostUUID)
		return request.Fail(updateErr)
	}

	log.Info().Msgf("host %v: KVM session stopped", hostUUID)
	return request.Ack()
}

// writeKvmError writes KVM_STATE_ERROR and status message to inventory and
// returns request.Fail
func (kc *Controller) writeKvmError(
	ctx context.Context,
	request rec_v2.Request[ID],
	tenantID, resourceID, errMsg string,
) rec_v2.Directive[ID] {
	updateErr := kc.updateHost(ctx, tenantID, resourceID,
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.HostResourceFieldCurrentKvmState,
			computev1.HostResourceFieldKvmSessionStatus,
		}},
		&computev1.HostResource{
			CurrentKvmState:  computev1.KvmState_KVM_STATE_ERROR,
			KvmSessionStatus: errMsg,
		})
	if updateErr != nil {
		log.Err(updateErr).Msg("failed to write KVM_STATE_ERROR to inventory")
	}
	return request.Fail(errors.Errorf("%s", errMsg))
}

// updateHost applies a field-masked update to a HostResource in inventory.
func (kc *Controller) updateHost(
	ctx context.Context,
	tenantID, invResourceID string,
	fieldMask *fieldmaskpb.FieldMask,
	invHost *computev1.HostResource,
) error {
	if invHost == nil {
		err := errors.Errorfc(codes.InvalidArgument, "nil resource provided")
		log.InfraSec().InfraErr(err).Msg("nil resource passed to updateHost")
		return err
	}
	if len(fieldMask.GetPaths()) == 0 {
		log.Debug().Msgf("skipping updateHost: no fields selected for tenantID=%s", tenantID)
		return nil
	}

	resCopy := proto.Clone(invHost)
	updatedMask, err := fieldmaskpb.New(resCopy, fieldMask.GetPaths()...)
	if err != nil {
		log.InfraSec().InfraErr(err).Msg("failed to construct fieldmask")
		return errors.Wrap(err)
	}

	if err = inv_util.ValidateMaskAndFilterMessage(resCopy, updatedMask, true); err != nil {
		log.InfraSec().InfraErr(err).Msg("failed to validate fieldmask")
		return err
	}

	_, err = kc.InventoryRmClient.Update(ctx, tenantID, invResourceID, updatedMask,
		&inventoryv1.Resource{
			Resource: &inventoryv1.Resource_Host{Host: invHost},
		})
	if err != nil {
		log.InfraSec().InfraErr(err).Msgf(
			"failed to update inventory resource %s for tenantID=%s", invResourceID, tenantID)
		return err
	}
	return nil
}

// clientCallback injects the tenantId ActiveProjectId header into MPS requests.
func clientCallback() mps.RequestEditorFn {
	return func(ctx context.Context, req *http.Request) error {
		tenantID, ok := ctx.Value(contextValue("tenantId")).(string)
		if ok {
			req.Header.Add("ActiveProjectId", tenantID)
		}
		req.Header.Add("User-Agent", "kvm-manager")
		return nil
	}
}
