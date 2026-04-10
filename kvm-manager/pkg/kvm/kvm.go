// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

// Package kvm implements the KVM session lifecycle reconciler.
// It watches Inventory for desired_kvm_state changes and drives the
// session start/stop/consent flow by calling MPS REST APIs.
package kvm

import (
	"context"
	"encoding/json"
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

	// mpsWssRelayPathTemplate is the WebSocket relay URL written into inventory after a
	// redirect token is acquired. orch-cli reads this URL and opens the relay directly.
	mpsWssRelayPathTemplate = "wss://%s/relay/webrelay.ashx?token=%s&host=%s"

	// userConsentNone is sent to MPS POST /features in ACM mode to disable consent prompts.
	userConsentNone = "none"

	// userConsentKVM / userConsentAll are returned by GET /features for CCM devices that
	// require operator consent before a KVM session can begin.
	userConsentKVM = "kvm"
	userConsentAll = "all"
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

	// MpsDomain is the public MPS WebSocket relay hostname written into kvm_session_url,
	// e.g. "mps-wss.example.com". Set via --mpsDomain flag.
	MpsDomain string

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
	default:
		log.Debug().Msgf("host %v: no KVM action needed (desired=%v current=%v)",
			request.ID, invHost.GetDesiredKvmState(), invHost.GetCurrentKvmState())
	}
	return request.Ack()
}

// isDisruptivePowerOp returns true for power states that would terminate an active
// KVM session
func isDisruptivePowerOp(ps computev1.PowerState) bool {
	switch ps {
	case computev1.PowerState_POWER_STATE_OFF,
		computev1.PowerState_POWER_STATE_RESET,
		computev1.PowerState_POWER_STATE_RESET_REPEAT:
		return true
	default:
		return false
	}
}

// kvmStartInProgress returns true whenever a KVM start has been requested
func kvmStartInProgress(invHost *computev1.HostResource) bool {
	if invHost.GetDesiredKvmState() == computev1.KvmState_KVM_STATE_START {
		return true
	}
	switch invHost.GetCurrentKvmState() {
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
) (blocked bool, dir rec_v2.Directive[ID]) {
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
			computev1.HostResourceFieldKvmSessionStatusIndicator,
		}},
		&computev1.HostResource{
			DesiredPowerState:         computev1.PowerState_POWER_STATE_UNSPECIFIED,
			KvmSessionStatus:          msg,
			KvmSessionStatusIndicator: statusv1.StatusIndication_STATUS_INDICATION_ERROR,
		},
	); updateErr != nil {
		log.Err(updateErr).Msgf("failed to reset desired_power_state for host %v", hostUUID)
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

// handleStartKVMSession drives the full KVM start lifecycle:
//  1. Pre-condition: host must be AMT_STATE_PROVISIONED.
//  2. GET /api/v1/amt/features/{guid} — verify KVM enabled, read userConsent.
//  3. If KVM disabled: POST /api/v1/amt/features/{guid} to enable it.
//  4. Consent flow (CCM only): trigger on-screen code, write AWAITING_CONSENT,
//     wait for desired_consent_code, submit to MPS.
//  5. GET /api/v1/authorize/redirection/{guid} — obtain short-lived relay token.
//  6. Write current_kvm_state=KVM_STATE_START + kvm_session_url to inventory.
func (kc *Controller) handleStartKVMSession(
	ctx context.Context,
	request rec_v2.Request[ID],
	invHost *computev1.HostResource,
) rec_v2.Directive[ID] {
	hostUUID := request.ID.GetHostUUID()
	tenantID := request.ID.GetTenantID()
	resourceID := invHost.GetResourceId()

	// Pre-condition: device must be fully provisioned via RPS.
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

	// Step 4 — ACM: only token acquisition.
	log.Info().Msgf("host %v: ACM device — skipping consent, acquiring token", hostUUID)
	return kc.acquireTokenAndActivate(ctx, updatedCtx, request, tenantID, resourceID, hostUUID)
}

// handleConsentFlow manages the CCM user-consent sub-flow.
// On first entry it triggers the on-screen code display and writes
// KVM_STATE_AWAITING_CONSENT. On subsequent entries (when desired_consent_code
// is populated by orch-cli) it submits the code to MPS.
func (kc *Controller) handleConsentFlow(
	ctx context.Context,
	updatedCtx context.Context,
	request rec_v2.Request[ID],
	invHost *computev1.HostResource,
	tenantID, resourceID, hostUUID string,
) rec_v2.Directive[ID] {
	// If already AWAITING_CONSENT, check whether the operator has responded.
	if invHost.GetCurrentKvmState() == computev1.KvmState_KVM_STATE_AWAITING_CONSENT {
		consentCode := invHost.GetDesiredConsentCode()
		if consentCode == "" {
			log.Info().Msgf("host %v: waiting for operator consent code", invHost.GetUuid())
			return request.Ack()
		}
		return kc.submitConsentCode(
			ctx, updatedCtx, request, tenantID, resourceID, hostUUID, consentCode)
	}

	// First pass: trigger on-screen 6-digit code display.
	log.Info().Msgf("host %v: triggering user consent code display via MPS", hostUUID)
	log.Debug().Msgf("host %v: GET /api/v1/amt/userConsentCode/%s", hostUUID, hostUUID)
	consentResp, err := kc.MpsClient.GetApiV1AmtUserConsentCodeGuidWithResponse(
		updatedCtx, hostUUID, clientCallback())
	if err != nil {
		log.Err(err).Msgf("GET /amt/userConsentCode failed for host %v", hostUUID)
		return request.Fail(err)
	}
	if consentResp.StatusCode() != http.StatusOK {
		body := string(consentResp.Body)
		if strings.Contains(body, "NOT_READY") {
			// ReturnValue=2: consent code is already being displayed on the device
			// screen from a previous trigger. Proceed to AWAITING_CONSENT.
			log.Info().Msgf("host %v: consent already active on device (NOT_READY), proceeding to AWAITING_CONSENT", hostUUID)
		} else if strings.Contains(body, "INVALID_PT_MODE") {
			// ReturnValue=3: device is in ACM mode
			log.Info().Msgf("host %v: StartOptIn returned INVALID_PT_MODE — device in ACM, skipping consent and acquiring token", hostUUID)
			return kc.acquireTokenAndActivate(ctx, updatedCtx, request, tenantID, resourceID, hostUUID)
		} else {
			errMsg := fmt.Sprintf("GET /amt/userConsentCode returned %d: %s",
				consentResp.StatusCode(), body)
			log.Error().Msg(errMsg)
			return kc.writeKvmError(ctx, request, tenantID, resourceID, errMsg)
		}
	}
	log.Debug().Msgf("host %v: GET /amt/userConsentCode response: %s", hostUUID, string(consentResp.Body))
	// Write KVM_STATE_AWAITING_CONSENT so orch-cli prompts the operator.
	if updateErr := kc.updateHost(ctx, tenantID, resourceID,
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.HostResourceFieldCurrentKvmState,
			computev1.HostResourceFieldKvmSessionStatus,
			computev1.HostResourceFieldKvmSessionStatusIndicator,
		}},
		&computev1.HostResource{
			CurrentKvmState:           computev1.KvmState_KVM_STATE_AWAITING_CONSENT,
			KvmSessionStatus:          "Waiting for operator to enter consent code from device screen",
			KvmSessionStatusIndicator: statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS,
		},
	); updateErr != nil {
		log.Err(updateErr).Msgf("failed to set AWAITING_CONSENT for host %v", hostUUID)
		return request.Fail(updateErr)
	}
	log.Info().Msgf("host %v: set current_kvm_state=KVM_STATE_AWAITING_CONSENT", hostUUID)
	return request.Ack()
}

// submitConsentCode sends the operator-entered 6-digit code to MPS.
// On success it proceeds to token acquisition.
func (kc *Controller) submitConsentCode(
	ctx context.Context,
	updatedCtx context.Context,
	request rec_v2.Request[ID],
	tenantID, resourceID, hostUUID, consentCode string,
) rec_v2.Directive[ID] {
	log.Info().Msgf("host %v: submitting consent code to MPS", hostUUID)
	log.Debug().Msgf("host %v: POST /api/v1/amt/userConsentCode/%s consentCode=%s", hostUUID, hostUUID, consentCode)
	var codeInt int
	if _, scanErr := fmt.Sscanf(consentCode, "%d", &codeInt); scanErr != nil {
		errMsg := fmt.Sprintf("invalid consent code format for host %v: %q", hostUUID, consentCode)
		log.Error().Msg(errMsg)
		return kc.writeKvmError(ctx, request, tenantID, resourceID, errMsg)
	}

	submitResp, err := kc.MpsClient.PostApiV1AmtUserConsentCodeGuidWithResponse(
		updatedCtx, hostUUID,
		mps.UserConsentRequest{ConsentCode: codeInt},
		clientCallback())
	if err != nil {
		log.Err(err).Msgf("POST /amt/userConsentCode failed for host %v", hostUUID)
		return request.Fail(err)
	}
	log.Debug().Msgf("host %v: POST /amt/userConsentCode HTTP status=%d body=%s",
		hostUUID, submitResp.StatusCode(), string(submitResp.Body))
	if submitResp.StatusCode() != http.StatusOK {
		errMsg := fmt.Sprintf("POST /amt/userConsentCode returned %d: %s",
			submitResp.StatusCode(), string(submitResp.Body))
		log.Error().Msg(errMsg)
		return kc.writeKvmError(ctx, request, tenantID, resourceID, errMsg)
	}

	// Parse only ReturnValue from response body
	var consentResult struct {
		Body struct {
			ReturnValue int `json:"ReturnValue"`
		} `json:"Body"`
	}
	if jsonErr := json.Unmarshal(submitResp.Body, &consentResult); jsonErr != nil {
		log.Warn().Msgf("host %v: could not parse consent response body (proceeding): %v", hostUUID, jsonErr)
	} else if consentResult.Body.ReturnValue != 0 {
		errMsg := fmt.Sprintf("consent code rejected by MPS for host %v: ReturnValue=%d",
			hostUUID, consentResult.Body.ReturnValue)
		log.Error().Msg(errMsg)
		return kc.writeKvmError(ctx, request, tenantID, resourceID, errMsg)
	}

	// Clear desired_consent_code
	if updateErr := kc.updateHost(ctx, tenantID, resourceID,
		&fieldmaskpb.FieldMask{Paths: []string{computev1.HostResourceFieldDesiredConsentCode}},
		&computev1.HostResource{DesiredConsentCode: ""},
	); updateErr != nil {
		log.Err(updateErr).Msgf("failed to clear desired_consent_code for host %v", hostUUID)
	}

	log.Info().Msgf("host %v: consent accepted, calling GET /api/v1/authorize/redirection/%s for relay token", hostUUID, hostUUID)
	return kc.acquireTokenAndActivate(ctx, updatedCtx, request, tenantID, resourceID, hostUUID)
}

// acquireTokenAndActivate calls GET /api/v1/authorize/redirection/{guid} to get
// a short-lived relay token, then writes kvm_session_url and
// current_kvm_state=KVM_STATE_START to inventory.
func (kc *Controller) acquireTokenAndActivate(
	ctx, updatedCtx context.Context,
	request rec_v2.Request[ID],
	tenantID, resourceID, hostUUID string,
) rec_v2.Directive[ID] {
	log.Debug().Msgf("host %v: GET /api/v1/authorize/redirection/%s", hostUUID, hostUUID)
	tokenResp, err := kc.MpsClient.GetApiV1AuthorizeRedirectionGuidWithResponse(
		updatedCtx, hostUUID, clientCallback())
	if err != nil {
		log.Err(err).Msgf("GET /authorize/redirection failed for host %v", hostUUID)
		return request.Fail(err)
	}
	if tokenResp.StatusCode() != http.StatusOK {
		errMsg := fmt.Sprintf("GET /authorize/redirection returned %d: %s",
			tokenResp.StatusCode(), string(tokenResp.Body))
		log.Error().Msg(errMsg)
		return kc.writeKvmError(ctx, request, tenantID, resourceID, errMsg)
	}
	log.Debug().Msgf("host %v: GET /authorize/redirection response HTTP %d (token present=%v)",
		hostUUID, tokenResp.StatusCode(), tokenResp.JSON200 != nil && tokenResp.JSON200.Token != nil)
	if tokenResp.JSON200 == nil || tokenResp.JSON200.Token == nil {
		errMsg := fmt.Sprintf("GET /authorize/redirection returned empty token for host %v", hostUUID)
		log.Error().Msg(errMsg)
		return kc.writeKvmError(ctx, request, tenantID, resourceID, errMsg)
	}

	token := *tokenResp.JSON200.Token
	sessionURL := fmt.Sprintf(mpsWssRelayPathTemplate, kc.MpsDomain, token, hostUUID)
	log.Info().Msgf("host %v: relay token acquired, writing KVM session URL", hostUUID)
	log.Debug().Msgf("host %v: session URL = %s", hostUUID, sessionURL)

	if updateErr := kc.updateHost(ctx, tenantID, resourceID,
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.HostResourceFieldCurrentKvmState,
			computev1.HostResourceFieldKvmSessionUrl,
			computev1.HostResourceFieldKvmSessionStatus,
			computev1.HostResourceFieldKvmSessionStatusIndicator,
		}},
		&computev1.HostResource{
			CurrentKvmState:           computev1.KvmState_KVM_STATE_START,
			KvmStatus:                 computev1.KvmStatus_KVM_STATUS_ACTIVATED,
			KvmSessionUrl:             sessionURL,
			KvmSessionStatus:          "KVM session active",
			KvmSessionStatusIndicator: statusv1.StatusIndication_STATUS_INDICATION_IDLE,
		},
	); updateErr != nil {
		log.Err(updateErr).Msgf("failed to activate KVM session for host %v", hostUUID)
		return request.Retry(updateErr).With(rec_v2.ExponentialBackoff(minDelay, maxDelay))
	}

	log.Info().Msgf("host %v: KVM_STATE_START written, session URL in inventory", hostUUID)
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
			computev1.HostResourceFieldKvmSessionUrl,
			computev1.HostResourceFieldKvmSessionStatus,
			computev1.HostResourceFieldKvmSessionStatusIndicator,
		}},
		&computev1.HostResource{
			CurrentKvmState:           computev1.KvmState_KVM_STATE_STOP,
			KvmStatus:                 computev1.KvmStatus_KVM_STATUS_DEACTIVATED,
			KvmSessionUrl:             "",
			KvmSessionStatus:          "KVM session stopped",
			KvmSessionStatusIndicator: statusv1.StatusIndication_STATUS_INDICATION_IDLE,
		},
	); updateErr != nil {
		log.Err(updateErr).Msgf("failed to stop KVM session for host %v", hostUUID)
		return request.Fail(updateErr)
	}

	log.Info().Msgf("host %v: KVM session stopped", hostUUID)
	return request.Ack()
}

// writeKvmError writes KVM_STATE_ERROR + status message to inventory and
// returns request.Fail (no automatic retry).
func (kc *Controller) writeKvmError(
	ctx context.Context,
	request rec_v2.Request[ID],
	tenantID, resourceID, errMsg string,
) rec_v2.Directive[ID] {
	updateErr := kc.updateHost(ctx, tenantID, resourceID,
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.HostResourceFieldCurrentKvmState,
			computev1.HostResourceFieldKvmSessionUrl,
			computev1.HostResourceFieldKvmSessionStatus,
			computev1.HostResourceFieldKvmSessionStatusIndicator,
		}},
		&computev1.HostResource{
			CurrentKvmState:           computev1.KvmState_KVM_STATE_ERROR,
			KvmSessionUrl:             "",
			KvmSessionStatus:          errMsg,
			KvmSessionStatusIndicator: statusv1.StatusIndication_STATUS_INDICATION_ERROR,
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

// clientCallback injects the tenantId ActiveProjectId header into MPS requests
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
