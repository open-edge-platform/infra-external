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
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	inv_util "github.com/open-edge-platform/infra-core/inventory/v2/pkg/util"
	"github.com/open-edge-platform/infra-external/sol-manager/pkg/api/mps"
	"github.com/open-edge-platform/infra-external/sol-manager/pkg/auth"
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
// lifecycle by calling MPS REST APIs. It writes session connection info
// (MPS URL, tokens, AMT credentials) into sol_session_url for orch-cli
// to consume directly.
type Controller struct {
	MpsClient         mps.ClientWithResponsesInterface
	InventoryRmClient client.TenantAwareInventoryClient
	TermChan          chan bool
	ReadyChan         chan bool
	EventsWatcher     chan *client.WatchEvents
	WaitGroup         *sync.WaitGroup
	SOLController     *rec_v2.Controller[ID]

	// MpsDomain is the MPS WebSocket relay hostname written into sol_session_url
	// so orch-cli can connect directly to the MPS relay.
	MpsDomain string

	ReconcilePeriod time.Duration
	RequestTimeout  time.Duration
	Insecure        bool

	// TokenProvider obtains Keycloak JWT tokens for MPS auth using
	// the inventory auth package (GetCredentialsByUUID + client_credentials grant).
	TokenProvider *auth.TokenProvider
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
	default:
		log.Debug().Msgf("host %v: no SOL action needed (desired=%v current=%v)",
			request.ID, invHost.GetDesiredSolState(), invHost.GetCurrentSolState())
	}
	return request.Ack()
}

// shouldStartSOLSession returns true when the operator requested SOL_STATE_START
// and the session is not yet active. Also handles CONSENT_RECEIVED and
// REDIRECTION_RECEIVED desired states from orch-cli.
func (sc *Controller) shouldStartSOLSession(invHost *computev1.HostResource) bool {
	desired := invHost.GetDesiredSolState()
	current := invHost.GetCurrentSolState()

	switch desired {
	case computev1.SolState_SOL_STATE_START:
		// Not yet started — normal start flow (triggers consent for CCM or direct for ACM).
		if current != computev1.SolState_SOL_STATE_START {
			return true
		}
		return false

	case computev1.SolState_SOL_STATE_CONSENT_RECEIVED:
		// orch-cli has submitted the consent code directly to MPS.
		// sol-manager should ACK and wait for orch-cli to get redirect token.
		return true

	case computev1.SolState_SOL_STATE_REDIRECTION_RECEIVED:
		// orch-cli has obtained the redirect token from MPS.
		// sol-manager should set current_sol_state=SOL_STATE_START.
		return true
	}
	return false
}

// shouldStopSOLSession returns true when the operator requested SOL_STATE_STOP
// and the session has not yet been torn down.
func (sc *Controller) shouldStopSOLSession(invHost *computev1.HostResource) bool {
	return invHost.GetDesiredSolState() == computev1.SolState_SOL_STATE_STOP &&
		invHost.GetCurrentSolState() != computev1.SolState_SOL_STATE_STOP
}

// handleStartSOLSession drives the SOL start lifecycle:
//
//  1. Pre-condition: host must be AMT_STATE_PROVISIONED.
//  2. GET /api/v1/amt/features/{guid} — verify SOL is already enabled.
//  3. CCM devices: trigger consent code display, set AWAITING_CONSENT.
//     orch-cli prompts operator → POSTs consent to MPS → PATCHes CONSENT_RECEIVED.
//  4. On CONSENT_RECEIVED: ACK, wait for orch-cli to get redirect token.
//     orch-cli GETs redirect token → PATCHes REDIRECTION_RECEIVED.
//  5. On REDIRECTION_RECEIVED: set current_sol_state=SOL_STATE_START.
//  6. ACM devices: set current_sol_state=SOL_STATE_START directly (orch-cli handles token+connect).
func (sc *Controller) handleStartSOLSession(
	ctx context.Context,
	request rec_v2.Request[ID],
	invHost *computev1.HostResource,
) rec_v2.Directive[ID] {
	hostUUID := request.ID.GetHostUUID()
	tenantID := request.ID.GetTenantID()
	resourceID := invHost.GetResourceId()
	desired := invHost.GetDesiredSolState()

	// Handle REDIRECTION_RECEIVED: orch-cli has the redirect token, confirm START.
	if desired == computev1.SolState_SOL_STATE_REDIRECTION_RECEIVED {
		log.Info().Msgf("host %v: REDIRECTION_RECEIVED — setting SOL_STATE_START", hostUUID)
		if updateErr := sc.updateHost(ctx, tenantID, resourceID,
			&fieldmaskpb.FieldMask{Paths: []string{
				computev1.HostResourceFieldCurrentSolState,
				computev1.HostResourceFieldSolStatus,
				computev1.HostResourceFieldSolSessionStatus,
			}},
			&computev1.HostResource{
				CurrentSolState:  computev1.SolState_SOL_STATE_START,
				SolStatus:        computev1.SolStatus_SOL_STATUS_ACTIVATED,
				SolSessionStatus: "SOL_SESSION_STATUS_ACTIVATED",
			},
		); updateErr != nil {
			log.Err(updateErr).Msgf("failed to set SOL_STATE_START for host %v", hostUUID)
			return request.Fail(updateErr)
		}
		log.Info().Msgf("host %v: SOL_STATE_START confirmed (orch-cli connects directly)", hostUUID)
		return request.Ack()
	}

	// Handle CONSENT_RECEIVED: orch-cli submitted consent code to MPS, now wait
	// for orch-cli to get redirect token and send REDIRECTION_RECEIVED.
	if desired == computev1.SolState_SOL_STATE_CONSENT_RECEIVED {
		log.Info().Msgf("host %v: CONSENT_RECEIVED — waiting for orch-cli to obtain redirect token", hostUUID)
		return request.Ack()
	}

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

	features := featResp.JSON200

	// Step 2 — SOL must already be enabled via AMT profile during provisioning.
	solActivated := features.SOL != nil && *features.SOL
	if !solActivated {
		errMsg := fmt.Sprintf(
			"SOL is not enabled on host %v; it must be activated during profile creation", hostUUID)
		log.Error().Msg(errMsg)
		return sc.writeSolError(ctx, request, tenantID, resourceID, errMsg)
	}

	// Step 3 — CCM devices: trigger consent code display on device screen.
	// orch-cli will prompt for code, POST to MPS, then PATCH CONSENT_RECEIVED.
	if invHost.GetAmtControlMode() == computev1.AmtControlMode_AMT_CONTROL_MODE_CCM {
		return sc.handleConsentFlow(ctx, updatedCtx, request, invHost, tenantID, resourceID, hostUUID)
	}

	// Step 4 — ACM mode: set current_sol_state=SOL_STATE_START directly.
	// orch-cli handles redirect token acquisition and MPS WebSocket connection.
	log.Info().Msgf("host %v: ACM mode — setting SOL_STATE_START (orch-cli connects directly)", hostUUID)
	if updateErr := sc.updateHost(ctx, tenantID, resourceID,
		&fieldmaskpb.FieldMask{Paths: []string{
			computev1.HostResourceFieldCurrentSolState,
			computev1.HostResourceFieldSolStatus,
			computev1.HostResourceFieldSolSessionStatus,
		}},
		&computev1.HostResource{
			CurrentSolState:  computev1.SolState_SOL_STATE_START,
			SolStatus:        computev1.SolStatus_SOL_STATUS_ACTIVATED,
			SolSessionStatus: "SOL_SESSION_STATUS_ACTIVATED",
		},
	); updateErr != nil {
		log.Err(updateErr).Msgf("failed to set SOL_STATE_START for host %v", hostUUID)
		return request.Fail(updateErr)
	}
	log.Info().Msgf("host %v: SOL_STATE_START written for ACM device", hostUUID)
	return request.Ack()
}

// handleConsentFlow manages the CCM user-consent sub-flow.
// On first entry it triggers the on-screen code display via GET /amt/userConsentCode
// and writes SOL_STATE_AWAITING_CONSENT. orch-cli will then prompt the operator,
// POST the code directly to MPS, and PATCH desired_sol_state=CONSENT_RECEIVED.
// On subsequent entries (already AWAITING_CONSENT), sol-manager just ACKs.
func (sc *Controller) handleConsentFlow(
	ctx context.Context,
	updatedCtx context.Context,
	request rec_v2.Request[ID],
	invHost *computev1.HostResource,
	tenantID, resourceID, hostUUID string,
) rec_v2.Directive[ID] {
	// If already AWAITING_CONSENT, just ACK — waiting for orch-cli to submit consent.
	if invHost.GetCurrentSolState() == computev1.SolState_SOL_STATE_AWAITING_CONSENT {
		log.Info().Msgf("host %v: still AWAITING_CONSENT, waiting for orch-cli to submit consent and PATCH CONSENT_RECEIVED", hostUUID)
		return request.Ack()
	}

	// First pass: trigger on-screen 6-digit code display via MPS.
	log.Info().Msgf("host %v: CCM mode — triggering user consent code display via MPS", hostUUID)
	consentResp, err := sc.MpsClient.GetApiV1AmtUserConsentCodeGuidWithResponse(
		updatedCtx, hostUUID, sc.clientCallback(updatedCtx, tenantID, hostUUID))
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
		}},
		&computev1.HostResource{
			CurrentSolState:  computev1.SolState_SOL_STATE_AWAITING_CONSENT,
			SolSessionStatus: "SOL_SESSION_STATUS_AWAITING_CONSENT",
		},
	); updateErr != nil {
		log.Err(updateErr).Msgf("failed to set AWAITING_CONSENT for host %v", hostUUID)
		return request.Fail(updateErr)
	}
	log.Info().Msgf("host %v: set current_sol_state=SOL_STATE_AWAITING_CONSENT", hostUUID)
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

// clientCallback injects the tenantId ActiveProjectId header and Keycloak JWT into MPS requests.
// It uses the TokenProvider (backed by GetCredentialsByUUID) to obtain a JWT.
func (sc *Controller) clientCallback(ctx context.Context, tenantID, hostUUID string) mps.RequestEditorFn {
	return func(_ context.Context, req *http.Request) error {
		if tenantID != "" {
			req.Header.Add("ActiveProjectId", tenantID)
		}
		req.Header.Add("User-Agent", "sol-manager")

		// Inject Keycloak JWT for MPS authentication.
		if sc.TokenProvider != nil {
			if token, err := sc.TokenProvider.GetTokenForHost(ctx, tenantID, hostUUID); err == nil {
				req.AddCookie(&http.Cookie{Name: "jwt", Value: token})
			} else {
				log.Warn().Err(err).Msg("failed to get Keycloak token for MPS request")
			}
		}
		return nil
	}
}
