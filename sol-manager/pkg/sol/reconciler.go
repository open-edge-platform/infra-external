// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

// Package sol implements the SOL session lifecycle reconciler.
// It watches Inventory for desired_sol_state changes and drives the
// session start/stop/consent flow.
//
// New design: orch-cli calls MPS directly for consent code submission and
// relay token acquisition. sol-manager only handles:
//   - Feature check and consent trigger (SOL_STATE_AWAITING_CONSENT)
//   - Acknowledgement of SOL_STATE_CONSENT_RECEIVED (orch-cli submitted code)
//   - SOL_STATE_REDIRECTION_RECEIVED → sets current_sol_state=SOL_STATE_START
//   - SOL_STATE_STOP teardown
package sol

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
	"github.com/open-edge-platform/infra-external/sol-manager/pkg/api/mps"
	rec_v2 "github.com/open-edge-platform/orch-library/go/pkg/controller/v2"
)

const (
	minDelay = 1 * time.Second
	maxDelay = 5 * time.Second
)

var log = logging.GetLogger("SolReconciler")

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

// Controller is the SOL resource manager. It watches Inventory for
// desired_sol_state changes on HostResource and drives the SOL session
// lifecycle by calling MPS REST APIs.
type Controller struct {
	MpsClient         mps.ClientWithResponsesInterface
	InventoryRmClient client.TenantAwareInventoryClient
	TermChan          chan bool
	ReadyChan         chan bool
	EventsWatcher     chan *client.WatchEvents
	WaitGroup         *sync.WaitGroup
	SOLController     *rec_v2.Controller[ID]

	ReconcilePeriod time.Duration
	RequestTimeout  time.Duration
	Insecure        bool
}

// Start begins event-driven and periodic reconciliation.
func (sc *Controller) Start() {
	ticker := time.NewTicker(sc.ReconcilePeriod)
	sc.ReadyChan <- true
	log.Info().Msg("SOL manager started")
	sc.ReconcileAll()
	for {
		select {
		case <-ticker.C:
			sc.ReconcileAll()
		case <-sc.TermChan:
			log.Info().Msg("SOL manager stopping")
			ticker.Stop()
			sc.Stop()
			return
		case event, ok := <-sc.EventsWatcher:
			if !ok {
				ticker.Stop()
				sc.Stop()
				log.InfraSec().Fatal().Msg("gRPC stream with Inventory closed")
				return
			}
			host := event.Event.GetResource().GetHost()
			log.Info().Msgf("received %v event for host %v",
				event.Event.GetEventKind().String(), host.GetUuid())
			if err := sc.SOLController.Reconcile(
				NewID(host.GetTenantId(), host.GetUuid())); err != nil {
				log.Err(err).Msgf("failed to enqueue reconcile for host %v", host.GetUuid())
			}
		}
	}
}

// ReconcileAll lists all hosts and triggers reconciliation for those that
// have a non-unspecified desired_sol_state.
func (sc *Controller) ReconcileAll() {
	ctx, cancel := context.WithTimeout(context.Background(), sc.RequestTimeout)
	defer cancel()
	hosts, err := sc.InventoryRmClient.ListAll(ctx, &inventoryv1.ResourceFilter{
		Resource: &inventoryv1.Resource{Resource: &inventoryv1.Resource_Host{}},
	})
	if err != nil {
		log.Error().Err(err).Msg("failed to list hosts during periodic reconcile")
		return
	}
	for _, h := range hosts {
		host := h.GetHost()
		if host.GetDesiredSolState() == computev1.SolState_SOL_STATE_UNSPECIFIED {
			continue
		}
		if err := sc.SOLController.Reconcile(
			NewID(host.GetTenantId(), host.GetUuid())); err != nil {
			log.Err(err).Msgf("failed to enqueue reconcile for host %v", host.GetUuid())
		}
	}
	log.Debug().Msg("periodic SOL reconciliation complete")
}

// Stop signals the WaitGroup that this goroutine has finished.
func (sc *Controller) Stop() {
	sc.WaitGroup.Done()
}

// Reconcile is called by the controller framework for each host ID.
func (sc *Controller) Reconcile(ctx context.Context, request rec_v2.Request[ID]) rec_v2.Directive[ID] {
	log.Debug().Msgf("SOL reconcile started for %v", request.ID)

	invHost, err := sc.InventoryRmClient.GetHostByUUID(
		ctx, request.ID.GetTenantID(), request.ID.GetHostUUID())
	if err != nil {
		log.Err(err).Msgf("failed to get host from inventory for %v", request.ID)
		return request.Fail(err)
	}

	log.Debug().Msgf("host %v: desiredSolState=%v currentSolState=%v",
		request.ID,
		invHost.GetDesiredSolState(),
		invHost.GetCurrentSolState())

	switch {
	case sc.shouldStartSOLSession(invHost):
		return sc.handleStartSOLSession(ctx, request, invHost)
	case sc.shouldStopSOLSession(invHost):
		return sc.handleStopSOLSession(ctx, request, invHost)
	case invHost.GetDesiredSolState() == computev1.SolState_SOL_STATE_CONSENT_RECEIVED:
		// orch-cli has submitted the consent code directly to MPS
		log.Info().Msgf("host %v: SOL_STATE_CONSENT_RECEIVED acknowledged", request.ID)
		return request.Ack()
	case invHost.GetDesiredSolState() == computev1.SolState_SOL_STATE_REDIRECTION_RECEIVED:
		// orch-cli has obtained the relay token directly from MPS
		return sc.handleRedirectionReceived(ctx, request, invHost)
	default:
		log.Debug().Msgf("host %v: no SOL action needed (desired=%v current=%v)",
			request.ID, invHost.GetDesiredSolState(), invHost.GetCurrentSolState())
	}
	return request.Ack()
}

// shouldStartSOLSession returns true when the operator requested SOL_STATE_START
// and the session is not yet active.
func (sc *Controller) shouldStartSOLSession(invHost *computev1.HostResource) bool {
	return invHost.GetDesiredSolState() == computev1.SolState_SOL_STATE_START &&
		invHost.GetCurrentSolState() != computev1.SolState_SOL_STATE_START
}

// shouldStopSOLSession returns true when the operator requested SOL_STATE_STOP
// and the session has not yet been torn down.
func (sc *Controller) shouldStopSOLSession(invHost *computev1.HostResource) bool {
	return invHost.GetDesiredSolState() == computev1.SolState_SOL_STATE_STOP &&
		invHost.GetCurrentSolState() != computev1.SolState_SOL_STATE_STOP
}

// handleStartSOLSession drives the SOL start lifecycle:
//  1. Pre-condition: host must be AMT_STATE_PROVISIONED.
//  2. GET /api/v1/amt/features/{guid} — verify SOL is already enabled.
//  3. CCM only: trigger on-screen consent code display, write SOL_STATE_AWAITING_CONSENT.
//     orch-cli submits the code directly to MPS and signals SOL_STATE_CONSENT_RECEIVED.
//  4. ACM: write SOL_STATE_AWAITING_CONSENT (orch-cli will signal SOL_STATE_REDIRECTION_RECEIVED
//     after obtaining the relay token directly from MPS).
func (sc *Controller) handleStartSOLSession(
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
			"SOL_STATE_START rejected: host %v AMT state is %v, must be AMT_STATE_PROVISIONED",
			hostUUID, invHost.GetCurrentAmtState())
		log.Error().Msg(errMsg)
		return sc.writeSolError(ctx, request, tenantID, resourceID, errMsg)
	}

	updatedCtx := context.WithValue(ctx, contextValue("tenantId"), tenantID)

	// Step 1 — GET AMT features from MPS.
	log.Debug().Msgf("host %v: GET /api/v1/amt/features", hostUUID)
	featResp, err := sc.MpsClient.GetApiV1AmtFeaturesGuidWithResponse(
		updatedCtx, hostUUID, sc.clientCallback(updatedCtx, tenantID, hostUUID))
	if err != nil {
		log.Err(err).Msgf("GET /amt/features failed for host %v", hostUUID)
		return request.Fail(err)
	}
	if featResp.StatusCode() != http.StatusOK {
		errMsg := fmt.Sprintf("GET /amt/features returned %d: %s",
			featResp.StatusCode(), string(featResp.Body))
		log.Error().Msg(errMsg)
		return sc.writeSolError(ctx, request, tenantID, resourceID, errMsg)
	}
	log.Debug().Msgf("host %v: GET /amt/features response: %s", hostUUID, string(featResp.Body))
	features := featResp.JSON200
	if features == nil {
		errMsg := fmt.Sprintf("GET /amt/features returned empty body for host %v", hostUUID)
		log.Error().Msg(errMsg)
		return sc.writeSolError(ctx, request, tenantID, resourceID, errMsg)
	}
	log.Debug().Msgf("host %v: AMT features — SOL=%v userConsent=%v",
		hostUUID, features.SOL, features.UserConsent)

	// Step 2 — SOL must already be enabled via AMT profile during provisioning.
	solActivated := features.SOL != nil && *features.SOL
	if !solActivated {
		errMsg := fmt.Sprintf(
			"SOL is not enabled on host %v; it must be activated during profile creation", hostUUID)
		log.Error().Msg(errMsg)
		return sc.writeSolError(ctx, request, tenantID, resourceID, errMsg)
	}

	// Step 3 — Consent flow for CCM devices.
	// CCM requires user consent, ACM does not.
	isCCM := invHost.GetAmtControlMode() == computev1.AmtControlMode_AMT_CONTROL_MODE_CCM
	log.Debug().Msgf("host %v: amtControlMode=%v isCCM=%v",
		hostUUID, invHost.GetAmtControlMode(), isCCM)
	if isCCM {
		log.Info().Msgf("host %v: CCM device — consent flow required", hostUUID)
		return sc.handleConsentFlow(
			ctx, updatedCtx, request, invHost, tenantID, resourceID, hostUUID)
	}

	// Step 4 — ACM: signal ready for orch-cli to acquire token.
	// orch-cli will call MPS GET /authorize/redirection and signal SOL_STATE_REDIRECTION_RECEIVED.
	log.Info().Msgf("host %v: ACM device — waiting for orch-cli to acquire relay token", hostUUID)
	if updateErr := sc.updateHost(ctx, tenantID, resourceID,
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.HostResourceFieldCurrentSolState,
			computev1.HostResourceFieldSolSessionStatus,
		}},
		&computev1.HostResource{
			CurrentSolState:  computev1.SolState_SOL_STATE_AWAITING_CONSENT,
			SolSessionStatus: "Waiting for orch-cli to obtain relay token from MPS",
		},
	); updateErr != nil {
		log.Err(updateErr).Msgf("failed to set ready state for host %v", hostUUID)
		return request.Fail(updateErr)
	}
	return request.Ack()
}

// handleConsentFlow manages the CCM user-consent sub-flow.
// Triggers the on-screen code display and writes SOL_STATE_AWAITING_CONSENT.
// orch-cli is responsible for prompting the operator, submitting the code
// directly to MPS, and signaling SOL_STATE_CONSENT_RECEIVED.
func (sc *Controller) handleConsentFlow(
	ctx context.Context,
	updatedCtx context.Context,
	request rec_v2.Request[ID],
	invHost *computev1.HostResource,
	tenantID, resourceID, hostUUID string,
) rec_v2.Directive[ID] {
	// Already awaiting consent — nothing more for sol-manager to do until orch-cli signals.
	if invHost.GetCurrentSolState() == computev1.SolState_SOL_STATE_AWAITING_CONSENT {
		log.Info().Msgf("host %v: waiting for orch-cli to submit consent code to MPS", hostUUID)
		return request.Ack()
	}

	// Trigger on-screen 6-digit code display.
	log.Info().Msgf("host %v: triggering user consent code display via MPS", hostUUID)
	consentResp, err := sc.MpsClient.GetApiV1AmtUserConsentCodeGuidWithResponse(
		updatedCtx, hostUUID, sc.clientCallback(updatedCtx, tenantID, hostUUID))
	if err != nil {
		// MPS returns Header.RelatesTo as an integer but the generated client expects string,
		// causing a JSON unmarshal error. The parser only runs after HTTP 200 is confirmed,
		// so a json/unmarshal error here means the request succeeded. Proceed.
		if consentResp != nil && (strings.Contains(err.Error(), "json") || strings.Contains(err.Error(), "unmarshal")) {
			log.Info().Msgf(
				"host %v: GET /amt/userConsentCode HTTP 200 received "+
					"(response parse skipped due to Header.RelatesTo type mismatch), proceeding",
				hostUUID)
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
			return sc.writeSolError(ctx, request, tenantID, resourceID, errMsg)
		}
		log.Info().Msgf("host %v: consent code already displayed (NOT_READY), proceeding", hostUUID)
	}
	log.Debug().Msgf("host %v: consent code display triggered, setting AWAITING_CONSENT", hostUUID)
	if updateErr := sc.updateHost(ctx, tenantID, resourceID,
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.HostResourceFieldCurrentSolState,
			computev1.HostResourceFieldSolSessionStatus,
		}},
		&computev1.HostResource{
			CurrentSolState:  computev1.SolState_SOL_STATE_AWAITING_CONSENT,
			SolSessionStatus: "Waiting for operator to enter consent code from device screen",
		},
	); updateErr != nil {
		log.Err(updateErr).Msgf("failed to set AWAITING_CONSENT for host %v", hostUUID)
		return request.Fail(updateErr)
	}
	log.Info().Msgf("host %v: set current_sol_state=SOL_STATE_AWAITING_CONSENT, waiting for orch-cli to submit consent", hostUUID)
	return request.Ack()
}

// handleRedirectionReceived is called when orch-cli signals SOL_STATE_REDIRECTION_RECEIVED,
// meaning it has already obtained the relay token directly from MPS.
// sol-manager simply sets current_sol_state=SOL_STATE_START to confirm the session is active.
func (sc *Controller) handleRedirectionReceived(
	ctx context.Context,
	request rec_v2.Request[ID],
	invHost *computev1.HostResource,
) rec_v2.Directive[ID] {
	tenantID := request.ID.GetTenantID()
	resourceID := invHost.GetResourceId()
	hostUUID := request.ID.GetHostUUID()

	log.Info().Msgf("host %v: SOL_STATE_REDIRECTION_RECEIVED — activating session", hostUUID)
	if updateErr := sc.updateHost(ctx, tenantID, resourceID,
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.HostResourceFieldCurrentSolState,
			computev1.HostResourceFieldSolStatus,
			computev1.HostResourceFieldSolSessionStatus,
		}},
		&computev1.HostResource{
			CurrentSolState:  computev1.SolState_SOL_STATE_START,
			SolStatus:        computev1.SolStatus_SOL_STATUS_ACTIVATED,
			SolSessionStatus: "SOL session active",
		},
	); updateErr != nil {
		log.Err(updateErr).Msgf("failed to activate SOL session for host %v", hostUUID)
		return request.Retry(updateErr).With(rec_v2.ExponentialBackoff(minDelay, maxDelay))
	}
	log.Info().Msgf("host %v: SOL_STATE_START written — session active", hostUUID)
	return request.Ack()
}

// handleStopSOLSession tears down the active SOL WebSocket session,
// clears the URL, and marks the state as SOL_STATE_STOP.
func (sc *Controller) handleStopSOLSession(
	ctx context.Context,
	request rec_v2.Request[ID],
	invHost *computev1.HostResource,
) rec_v2.Directive[ID] {
	tenantID := request.ID.GetTenantID()
	resourceID := invHost.GetResourceId()
	hostUUID := request.ID.GetHostUUID()

	log.Info().Msgf("host %v: stopping SOL session", hostUUID)

	if updateErr := sc.updateHost(ctx, tenantID, resourceID,
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.HostResourceFieldCurrentSolState,
			computev1.HostResourceFieldSolStatus,
			computev1.HostResourceFieldSolSessionStatus,
		}},
		&computev1.HostResource{
			CurrentSolState:  computev1.SolState_SOL_STATE_STOP,
			SolStatus:        computev1.SolStatus_SOL_STATUS_DEACTIVATED,
			SolSessionStatus: "SOL_SESSION_STATUS_DEACTIVATED",
		},
	); updateErr != nil {
		log.Err(updateErr).Msgf("failed to stop SOL session for host %v", hostUUID)
		return request.Fail(updateErr)
	}

	log.Info().Msgf("host %v: SOL session stopped", hostUUID)
	return request.Ack()
}

// writeSolError writes SOL_STATE_ERROR + status message to inventory and
// returns request.Fail (no automatic retry).
func (sc *Controller) writeSolError(
	ctx context.Context,
	request rec_v2.Request[ID],
	tenantID, resourceID, errMsg string,
) rec_v2.Directive[ID] {
	updateErr := sc.updateHost(ctx, tenantID, resourceID,
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.HostResourceFieldCurrentSolState,
			computev1.HostResourceFieldSolStatus,
			computev1.HostResourceFieldSolSessionStatus,
		}},
		&computev1.HostResource{
			CurrentSolState:  computev1.SolState_SOL_STATE_ERROR,
			SolStatus:        computev1.SolStatus_SOL_STATUS_DEACTIVATED,
			SolSessionStatus: "SOL_SESSION_STATUS_DEACTIVATED",
		})
	if updateErr != nil {
		log.Err(updateErr).Msg("failed to write SOL_STATE_ERROR to inventory")
	}
	return request.Fail(errors.Errorf("%s", errMsg))
}

// updateHost applies a field-masked update to a HostResource in inventory.
func (sc *Controller) updateHost(
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

	_, err = sc.InventoryRmClient.Update(ctx, tenantID, invResourceID, updatedMask,
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
func (sc *Controller) clientCallback(_ context.Context, tenantID, _ string) mps.RequestEditorFn {
	return func(_ context.Context, req *http.Request) error {
		if tenantID != "" {
			req.Header.Add("ActiveProjectId", tenantID)
		}
		req.Header.Add("User-Agent", "sol-manager")
		return nil
	}
}
