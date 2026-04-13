// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

// Package sol implements the SOL session lifecycle reconciler.
// It watches Inventory for desired_sol_state changes and drives the
// session start/stop flow by calling MPS REST APIs.
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
	statusv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/status/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	inv_util "github.com/open-edge-platform/infra-core/inventory/v2/pkg/util"
	"github.com/open-edge-platform/infra-external/sol-manager/pkg/api/mps"
	solws "github.com/open-edge-platform/infra-external/sol-manager/pkg/websocket"
	rec_v2 "github.com/open-edge-platform/orch-library/go/pkg/controller/v2"
)

const (
	minDelay = 1 * time.Second
	maxDelay = 5 * time.Second

	// solSessionHandshakeTimeout is how long we wait for the AMT SOL protocol handshake
	// (0x10→0x11→0x13→0x14→0x20→0x21→0x27) before declaring a timeout.
	solSessionHandshakeTimeout = 30 * time.Second

	// solProxyURLTemplate is the WebSocket proxy URL written into inventory.
	// UI/CLI connects here to get clean terminal data; sol-manager proxies to/from AMT.
	solProxyURLTemplate = "wss://%s/ws/sol/%s"

	// userConsentNone is sent to MPS POST /features in ACM mode to disable consent prompts.
	userConsentNone = "none"
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

// activeSession tracks a running AMT SOL WebSocket session.
type activeSession struct {
	session    *solws.SOLSession
	resourceID string
	tenantID   string
	deviceGUID string
}

// Controller is the SOL resource manager. It watches Inventory for
// desired_sol_state changes on HostResource and drives the SOL session
// lifecycle by calling MPS REST APIs + AMT SOL WebSocket protocol.
type Controller struct {
	MpsClient         mps.ClientWithResponsesInterface
	InventoryRmClient client.TenantAwareInventoryClient
	TermChan          chan bool
	ReadyChan         chan bool
	EventsWatcher     chan *client.WatchEvents
	WaitGroup         *sync.WaitGroup
	SOLController     *rec_v2.Controller[ID]

	// MpsDomain is the MPS WebSocket relay hostname used both for connecting
	// to AMT (via relay) and for the sol_session_url written to inventory.
	MpsDomain string

	// SOLProxyDomain is the public hostname of the sol-manager WebSocket proxy.
	// Written into sol_session_url so UI/CLI knows where to connect.
	// e.g. "sol-manager.orch-infra.svc" or a public ingress hostname.
	SOLProxyDomain string

	ReconcilePeriod time.Duration
	RequestTimeout  time.Duration
	Insecure        bool

	// activeSessions tracks running SOL WebSocket sessions keyed by resourceID.
	activeSessions   map[string]*activeSession
	activeSessionsMu sync.Mutex
}

// GetSession returns the active SOL session for the given resourceID, or nil.
func (sc *Controller) GetSession(resourceID string) *solws.SOLSession {
	sc.activeSessionsMu.Lock()
	defer sc.activeSessionsMu.Unlock()
	if sess, ok := sc.activeSessions[resourceID]; ok {
		return sess.session
	}
	return nil
}

// Start begins event-driven and periodic reconciliation.
func (sc *Controller) Start() {
	sc.activeSessionsMu.Lock()
	if sc.activeSessions == nil {
		sc.activeSessions = make(map[string]*activeSession)
	}
	sc.activeSessionsMu.Unlock()

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
			sc.stopAllSessions()
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

// handleStartSOLSession drives the full SOL start lifecycle:
//  1. Pre-condition: host must be AMT_STATE_PROVISIONED.
//  2. GET /api/v1/amt/features/{guid} — verify SOL is already enabled (from profile creation).
//  3. CCM consent flow (if amt_control_mode == CCM): trigger on-screen code,
//     write AWAITING_CONSENT, wait for desired_consent_code, submit to MPS.
//  4. GET /api/v1/authorize/redirection/{guid} — obtain short-lived relay token.
//  5. Write current_sol_state=SOL_STATE_START + sol_session_url to inventory.
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

	// Step 1 — GET AMT features.
	featResp, err := sc.MpsClient.GetApiV1AmtFeaturesGuidWithResponse(
		updatedCtx, hostUUID, clientCallback())
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

	features := featResp.JSON200

	// Step 2 — SOL must already be enabled via AMT profile during provisioning.
	solActivated := features.SOL != nil && *features.SOL
	if !solActivated {
		errMsg := fmt.Sprintf(
			"SOL is not enabled on host %v; it must be activated during profile creation", hostUUID)
		log.Error().Msg(errMsg)
		return sc.writeSolError(ctx, request, tenantID, resourceID, errMsg)
	}

	// Step 3 — Consent flow for CCM devices (check amt_control_mode from inventory).
	if invHost.GetAmtControlMode() == computev1.AmtControlMode_AMT_CONTROL_MODE_CCM {
		return sc.handleConsentFlow(
			ctx, updatedCtx, request, invHost, tenantID, resourceID, hostUUID)
	}

	// Step 4 — ACM mode: go straight to token acquisition (no consent needed).
	return sc.acquireTokenAndActivate(ctx, updatedCtx, request, tenantID, resourceID, hostUUID)
}

// handleConsentFlow manages the CCM user-consent sub-flow.
// On first entry it triggers the on-screen code display and writes
// SOL_STATE_AWAITING_CONSENT. On subsequent entries (when desired_consent_code
// is populated by orch-cli) it submits the code to MPS.
func (sc *Controller) handleConsentFlow(
	ctx context.Context,
	updatedCtx context.Context,
	request rec_v2.Request[ID],
	invHost *computev1.HostResource,
	tenantID, resourceID, hostUUID string,
) rec_v2.Directive[ID] {
	// If already AWAITING_CONSENT, check whether the operator has responded.
	if invHost.GetCurrentSolState() == computev1.SolState_SOL_STATE_AWAITING_CONSENT {
		consentCode := invHost.GetDesiredConsentCode()
		if consentCode == "" {
			log.Info().Msgf("host %v: waiting for operator consent code", invHost.GetUuid())
			return request.Ack()
		}
		return sc.submitConsentCode(
			ctx, updatedCtx, request, tenantID, resourceID, hostUUID, consentCode)
	}

	// First pass: trigger on-screen 6-digit code display.
	log.Info().Msgf("host %v: triggering user consent code display via MPS", hostUUID)
	consentResp, err := sc.MpsClient.GetApiV1AmtUserConsentCodeGuidWithResponse(
		updatedCtx, hostUUID, clientCallback())
	if err != nil {
		log.Err(err).Msgf("GET /amt/userConsentCode failed for host %v", hostUUID)
		return request.Fail(err)
	}
	if consentResp.StatusCode() != http.StatusOK {
		errMsg := fmt.Sprintf("GET /amt/userConsentCode returned %d: %s",
			consentResp.StatusCode(), string(consentResp.Body))
		log.Error().Msg(errMsg)
		return sc.writeSolError(ctx, request, tenantID, resourceID, errMsg)
	}

	// Write SOL_STATE_AWAITING_CONSENT so orch-cli prompts the operator.
	if updateErr := sc.updateHost(ctx, tenantID, resourceID,
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.HostResourceFieldCurrentSolState,
			computev1.HostResourceFieldSolSessionStatus,
			computev1.HostResourceFieldSolSessionStatusIndicator,
		}},
		&computev1.HostResource{
			CurrentSolState:           computev1.SolState_SOL_STATE_AWAITING_CONSENT,
			SolSessionStatus:          computev1.SolSessionStatus_SOL_SESSION_STATUS_ACTIVATED,
			SolSessionStatusIndicator: statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS,
		},
	); updateErr != nil {
		log.Err(updateErr).Msgf("failed to set AWAITING_CONSENT for host %v", hostUUID)
		return request.Fail(updateErr)
	}
	log.Info().Msgf("host %v: set current_sol_state=SOL_STATE_AWAITING_CONSENT", hostUUID)
	return request.Ack()
}

// submitConsentCode sends the operator-entered 6-digit code to MPS.
// On success it clears desired_consent_code and proceeds to token acquisition.
func (sc *Controller) submitConsentCode(
	ctx context.Context,
	updatedCtx context.Context,
	request rec_v2.Request[ID],
	tenantID, resourceID, hostUUID, consentCode string,
) rec_v2.Directive[ID] {
	log.Info().Msgf("host %v: submitting consent code to MPS", hostUUID)

	var codeInt int
	if _, scanErr := fmt.Sscanf(consentCode, "%d", &codeInt); scanErr != nil {
		errMsg := fmt.Sprintf("invalid consent code format for host %v: %q", hostUUID, consentCode)
		log.Error().Msg(errMsg)
		return sc.writeSolError(ctx, request, tenantID, resourceID, errMsg)
	}

	submitResp, err := sc.MpsClient.PostApiV1AmtUserConsentCodeGuidWithResponse(
		updatedCtx, hostUUID,
		mps.UserConsentRequest{ConsentCode: codeInt},
		clientCallback())
	if err != nil {
		log.Err(err).Msgf("POST /amt/userConsentCode failed for host %v", hostUUID)
		return request.Fail(err)
	}
	if submitResp.StatusCode() != http.StatusOK {
		errMsg := fmt.Sprintf("POST /amt/userConsentCode returned %d: %s",
			submitResp.StatusCode(), string(submitResp.Body))
		log.Error().Msg(errMsg)
		return sc.writeSolError(ctx, request, tenantID, resourceID, errMsg)
	}
	if submitResp.JSON200 != nil && submitResp.JSON200.Body != nil &&
		submitResp.JSON200.Body.ReturnValueStr != nil &&
		!strings.EqualFold(*submitResp.JSON200.Body.ReturnValueStr, "SUCCESS") {
		errMsg := fmt.Sprintf("consent code rejected by MPS for host %v: %s",
			hostUUID, *submitResp.JSON200.Body.ReturnValueStr)
		log.Error().Msg(errMsg)
		return sc.writeSolError(ctx, request, tenantID, resourceID, errMsg)
	}

	// Clear desired_consent_code — it has been consumed.
	if updateErr := sc.updateHost(ctx, tenantID, resourceID,
		&fieldmaskpb.FieldMask{Paths: []string{computev1.HostResourceFieldDesiredConsentCode}},
		&computev1.HostResource{DesiredConsentCode: ""},
	); updateErr != nil {
		log.Err(updateErr).Msgf("failed to clear desired_consent_code for host %v", hostUUID)
	}

	log.Info().Msgf("host %v: consent accepted, acquiring redirect token", hostUUID)
	return sc.acquireTokenAndActivate(ctx, updatedCtx, request, tenantID, resourceID, hostUUID)
}

// acquireTokenAndActivate calls GET /api/v1/authorize/redirection/{guid} to get
// a short-lived relay token, then establishes the AMT SOL WebSocket session via
// sol-websocket.go, and finally writes sol_session_url + SOL_STATE_START to inventory.
func (sc *Controller) acquireTokenAndActivate(
	ctx, updatedCtx context.Context,
	request rec_v2.Request[ID],
	tenantID, resourceID, hostUUID string,
) rec_v2.Directive[ID] {
	// Step 1 — Get redirect token from MPS.
	tokenResp, err := sc.MpsClient.GetApiV1AuthorizeRedirectionGuidWithResponse(
		updatedCtx, hostUUID, clientCallback())
	if err != nil {
		log.Err(err).Msgf("GET /authorize/redirection failed for host %v", hostUUID)
		return request.Fail(err)
	}
	if tokenResp.StatusCode() != http.StatusOK {
		errMsg := fmt.Sprintf("GET /authorize/redirection returned %d: %s",
			tokenResp.StatusCode(), string(tokenResp.Body))
		log.Error().Msg(errMsg)
		return sc.writeSolError(ctx, request, tenantID, resourceID, errMsg)
	}
	if tokenResp.JSON200 == nil || tokenResp.JSON200.Token == nil {
		errMsg := fmt.Sprintf("empty redirect token from MPS for host %v", hostUUID)
		log.Error().Msg(errMsg)
		return sc.writeSolError(ctx, request, tenantID, resourceID, errMsg)
	}
	redirectToken := *tokenResp.JSON200.Token
	log.Info().Msgf("host %v: relay token acquired, establishing SOL WebSocket session", hostUUID)

	// Step 2 — Open WebSocket to MPS relay + run AMT SOL protocol handshake.
	cfg := solws.SessionConfig{
		MPSHost:    sc.MpsDomain,
		DeviceGUID: hostUUID,
		Port:       16994,
		Mode:       "sol",
		Insecure:   sc.Insecure,
		AMTUser:    "admin", // TODO: retrieve from vault/secrets
		AMTPass:    "",      // TODO: retrieve from vault/secrets
	}
	session, sessErr := solws.NewSOLSessionWithToken(cfg, redirectToken)
	if sessErr != nil {
		errMsg := fmt.Sprintf("failed to create SOL WebSocket session for host %v: %v", hostUUID, sessErr)
		log.Error().Msg(errMsg)
		return sc.writeSolError(ctx, request, tenantID, resourceID, errMsg)
	}

	// Step 4 — Wait for AMT SOL handshake to complete (SolReady channel).
	select {
	case <-session.SolReady:
		log.Info().Msgf("host %v: AMT SOL handshake complete, session is ACTIVE", hostUUID)
	case <-time.After(solSessionHandshakeTimeout):
		session.Close()
		errMsg := fmt.Sprintf("SOL handshake timed out for host %v", hostUUID)
		log.Error().Msg(errMsg)
		return sc.writeSolError(ctx, request, tenantID, resourceID, errMsg)
	case <-session.Done:
		errMsg := fmt.Sprintf("SOL session closed during handshake for host %v", hostUUID)
		log.Error().Msg(errMsg)
		return sc.writeSolError(ctx, request, tenantID, resourceID, errMsg)
	}

	// Step 5 — Track the active session.
	sc.activeSessionsMu.Lock()
	sc.activeSessions[resourceID] = &activeSession{
		session:    session,
		resourceID: resourceID,
		tenantID:   tenantID,
		deviceGUID: hostUUID,
	}
	sc.activeSessionsMu.Unlock()

	// Step 6 — Write SOL_STATE_START + proxy URL to inventory.
	sessionURL := fmt.Sprintf(solProxyURLTemplate, sc.SOLProxyDomain, resourceID)
	if updateErr := sc.updateHost(ctx, tenantID, resourceID,
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.HostResourceFieldCurrentSolState,
			computev1.HostResourceFieldSolSessionUrl,
			computev1.HostResourceFieldSolStatus,
			computev1.HostResourceFieldSolSessionStatus,
			computev1.HostResourceFieldSolSessionStatusIndicator,
		}},
		&computev1.HostResource{
			CurrentSolState:           computev1.SolState_SOL_STATE_START,
			SolSessionUrl:             sessionURL,
			SolStatus:                 computev1.SolStatus_SOL_STATUS_ACTIVATED,
			SolSessionStatus:          computev1.SolSessionStatus_SOL_SESSION_STATUS_ACTIVATED,
			SolSessionStatusIndicator: statusv1.StatusIndication_STATUS_INDICATION_IDLE,
		},
	); updateErr != nil {
		log.Err(updateErr).Msgf("failed to activate SOL session for host %v", hostUUID)
		return request.Retry(updateErr).With(rec_v2.ExponentialBackoff(minDelay, maxDelay))
	}

	// Step 7 — Monitor session lifetime in background.
	go sc.monitorSession(resourceID)

	log.Info().Msgf("host %v: SOL_STATE_START written, session URL=%s", hostUUID, sessionURL)
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

	// Close the active WebSocket session if one exists.
	sc.closeSession(resourceID)

	if updateErr := sc.updateHost(ctx, tenantID, resourceID,
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.HostResourceFieldCurrentSolState,
			computev1.HostResourceFieldSolSessionUrl,
			computev1.HostResourceFieldSolStatus,
			computev1.HostResourceFieldSolSessionStatus,
			computev1.HostResourceFieldSolSessionStatusIndicator,
		}},
		&computev1.HostResource{
			CurrentSolState:           computev1.SolState_SOL_STATE_STOP,
			SolSessionUrl:             "",
			SolStatus:                 computev1.SolStatus_SOL_STATUS_DEACTIVATED,
			SolSessionStatus:          computev1.SolSessionStatus_SOL_SESSION_STATUS_DEACTIVATED,
			SolSessionStatusIndicator: statusv1.StatusIndication_STATUS_INDICATION_IDLE,
		},
	); updateErr != nil {
		log.Err(updateErr).Msgf("failed to stop SOL session for host %v", hostUUID)
		return request.Fail(updateErr)
	}

	log.Info().Msgf("host %v: SOL session stopped", hostUUID)
	return request.Ack()
}

// closeSession closes and removes an active SOL session by resourceID.
func (sc *Controller) closeSession(resourceID string) {
	sc.activeSessionsMu.Lock()
	sess, exists := sc.activeSessions[resourceID]
	if exists {
		delete(sc.activeSessions, resourceID)
	}
	sc.activeSessionsMu.Unlock()
	if exists && sess.session != nil {
		sess.session.Close()
	}
}

// stopAllSessions tears down all active SOL WebSocket sessions.
func (sc *Controller) stopAllSessions() {
	sc.activeSessionsMu.Lock()
	sessions := make(map[string]*activeSession, len(sc.activeSessions))
	for k, v := range sc.activeSessions {
		sessions[k] = v
	}
	sc.activeSessionsMu.Unlock()

	for _, sess := range sessions {
		log.Info().Msgf("stopping SOL session for host %s on shutdown", sess.resourceID)
		sc.closeSession(sess.resourceID)
	}
}

// monitorSession watches an active SOL session and marks it as ERROR
// in inventory if the WebSocket connection drops unexpectedly.
func (sc *Controller) monitorSession(resourceID string) {
	sc.activeSessionsMu.Lock()
	sess, exists := sc.activeSessions[resourceID]
	sc.activeSessionsMu.Unlock()
	if !exists {
		return
	}

	select {
	case <-sess.session.Done:
		// Session terminated — check if it was a deliberate stop or unexpected.
		sc.activeSessionsMu.Lock()
		_, stillActive := sc.activeSessions[resourceID]
		if stillActive {
			delete(sc.activeSessions, resourceID)
		}
		sc.activeSessionsMu.Unlock()

		if stillActive {
			log.Warn().Msgf("SOL session for %s terminated unexpectedly", resourceID)
			ctx, cancel := context.WithTimeout(context.Background(), sc.RequestTimeout)
			defer cancel()
			_ = sc.updateHost(ctx, sess.tenantID, resourceID,
				&fieldmaskpb.FieldMask{Paths: []string{
					computev1.HostResourceFieldCurrentSolState,
					computev1.HostResourceFieldSolSessionUrl,
					computev1.HostResourceFieldSolStatus,
					computev1.HostResourceFieldSolSessionStatus,
					computev1.HostResourceFieldSolSessionStatusIndicator,
				}},
				&computev1.HostResource{
					CurrentSolState:           computev1.SolState_SOL_STATE_ERROR,
					SolSessionUrl:             "",
					SolStatus:                 computev1.SolStatus_SOL_STATUS_DEACTIVATED,
					SolSessionStatus:          computev1.SolSessionStatus_SOL_SESSION_STATUS_DEACTIVATED,
					SolSessionStatusIndicator: statusv1.StatusIndication_STATUS_INDICATION_ERROR,
				})
		}
	case <-sc.TermChan:
		return
	}
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
			computev1.HostResourceFieldSolSessionUrl,
			computev1.HostResourceFieldSolStatus,
			computev1.HostResourceFieldSolSessionStatus,
			computev1.HostResourceFieldSolSessionStatusIndicator,
		}},
		&computev1.HostResource{
			CurrentSolState:           computev1.SolState_SOL_STATE_ERROR,
			SolSessionUrl:             "",
			SolStatus:                 computev1.SolStatus_SOL_STATUS_DEACTIVATED,
			SolSessionStatus:          computev1.SolSessionStatus_SOL_SESSION_STATUS_DEACTIVATED,
			SolSessionStatusIndicator: statusv1.StatusIndication_STATUS_INDICATION_ERROR,
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
func clientCallback() mps.RequestEditorFn {
	return func(ctx context.Context, req *http.Request) error {
		tenantID, ok := ctx.Value(contextValue("tenantId")).(string)
		if ok {
			req.Header.Add("ActiveProjectId", tenantID)
		}
		req.Header.Add("User-Agent", "sol-manager")
		return nil
	}
}
