// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package websocket

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
)

var log = logging.GetLogger("sol-websocket")

// SessionConfig holds the configuration needed to establish a SOL WebSocket session.
type SessionConfig struct {
	MPSHost       string // MPS hostname (e.g. "mps-wss.example.com")
	DeviceGUID    string // AMT device GUID
	Port          int    // SOL port (default 16994)
	Mode          string // Connection mode (default "sol")
	KeycloakToken string // Keycloak JWT for MPS auth
	Insecure      bool   // Skip TLS verification
	AMTUser       string // AMT digest-auth username (typically "admin")
	AMTPass       string // AMT digest-auth password
}

// RedirectTokenResponse represents the MPS API response for redirect token.
type RedirectTokenResponse struct {
	Token string `json:"token"`
}

// SOLSession manages the AMT SOL protocol state machine over a WebSocket connection.
type SOLSession struct {
	conn        *websocket.Conn
	mu          sync.Mutex
	amtSequence uint32
	SolReady    chan struct{}
	output      strings.Builder
	outputMu    sync.Mutex
	user        string
	pass        string
	authURI     string
	Done        chan struct{}
	stopOnce    sync.Once
}

// intToLE writes a uint32 as 4 little-endian bytes.
func intToLE(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// shortToLE writes a uint16 as 2 little-endian bytes.
func shortToLE(v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return b
}

// nextSequence returns the next AMT sequence number (thread-safe).
func (s *SOLSession) nextSequence() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq := s.amtSequence
	s.amtSequence++
	return seq
}

// sendBinary sends a binary WebSocket message (thread-safe).
func (s *SOLSession) sendBinary(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn.WriteMessage(websocket.BinaryMessage, data)
}

// SendSOLData wraps terminal data in an AMT SOL data frame (0x28) and sends it.
// Frame: 0x28 0x00 0x00 0x00 + IntToLE(sequence) + ShortToLE(len) + data
func (s *SOLSession) SendSOLData(data string) error {
	seq := s.nextSequence()
	frame := []byte{0x28, 0x00, 0x00, 0x00}
	frame = append(frame, intToLE(seq)...)
	frame = append(frame, shortToLE(uint16(len(data)))...)
	frame = append(frame, []byte(data)...)
	log.Debug().Msgf("[SOL-TX] Sending %d bytes: %q", len(data), data)
	return s.sendBinary(frame)
}

// AppendOutput collects SOL terminal output (thread-safe).
func (s *SOLSession) AppendOutput(data string) {
	s.outputMu.Lock()
	defer s.outputMu.Unlock()
	s.output.WriteString(data)
}

// GetOutput returns all collected SOL output so far.
func (s *SOLSession) GetOutput() string {
	s.outputMu.Lock()
	defer s.outputMu.Unlock()
	return s.output.String()
}

// ClearOutput resets the collected output buffer.
func (s *SOLSession) ClearOutput() {
	s.outputMu.Lock()
	defer s.outputMu.Unlock()
	s.output.Reset()
}

// IsReady returns true if the SOL session is active and ready for data.
func (s *SOLSession) IsReady() bool {
	select {
	case <-s.SolReady:
		return true
	default:
		return false
	}
}

// Close tears down the WebSocket connection and signals Done.
func (s *SOLSession) Close() {
	s.stopOnce.Do(func() {
		if s.conn != nil {
			s.conn.Close()
		}
		select {
		case <-s.Done:
		default:
			close(s.Done)
		}
	})
}

// hexMD5 returns the hex-encoded MD5 hash of the input string.
func hexMD5(str string) string {
	h := md5.Sum([]byte(str))
	return hex.EncodeToString(h[:])
}

// generateRandomNonce generates a random hex nonce.
func generateRandomNonce(byteLen int) string {
	b := make([]byte, byteLen)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// sendDigestAuthInitial sends the initial digest auth request (method 4).
func (s *SOLSession) sendDigestAuthInitial() error {
	user := s.user
	uri := s.authURI
	dataLen := uint32(len(user) + len(uri) + 8)
	msg := []byte{0x13, 0x00, 0x00, 0x00, 0x04}
	msg = append(msg, intToLE(dataLen)...)
	msg = append(msg, byte(len(user)))
	msg = append(msg, []byte(user)...)
	msg = append(msg, 0x00, 0x00)
	msg = append(msg, byte(len(uri)))
	msg = append(msg, []byte(uri)...)
	msg = append(msg, 0x00, 0x00, 0x00, 0x00)
	log.Debug().Msgf("[AUTH] Sending Digest Auth initial (user=%q)", user)
	return s.sendBinary(msg)
}

// sendDigestAuthResponse computes and sends the digest auth response (RFC 2617).
func (s *SOLSession) sendDigestAuthResponse(realm, nonce, qop string) error {
	user := s.user
	pass := s.pass
	uri := s.authURI
	cnonce := generateRandomNonce(16)
	snc := "00000002"
	ha1 := hexMD5(user + ":" + realm + ":" + pass)
	ha2 := hexMD5("POST:" + uri)
	responseStr := ha1 + ":" + nonce + ":" + snc + ":" + cnonce + ":" + qop + " :" + ha2
	digest := hexMD5(responseStr)

	totalLen := len(user) + len(realm) + len(nonce) + len(uri) +
		len(cnonce) + len(snc) + len(digest) + len(qop) + 8
	msg := []byte{0x13, 0x00, 0x00, 0x00, 0x04}
	msg = append(msg, intToLE(uint32(totalLen))...)
	msg = append(msg, byte(len(user)))
	msg = append(msg, []byte(user)...)
	msg = append(msg, byte(len(realm)))
	msg = append(msg, []byte(realm)...)
	msg = append(msg, byte(len(nonce)))
	msg = append(msg, []byte(nonce)...)
	msg = append(msg, byte(len(uri)))
	msg = append(msg, []byte(uri)...)
	msg = append(msg, byte(len(cnonce)))
	msg = append(msg, []byte(cnonce)...)
	msg = append(msg, byte(len(snc)))
	msg = append(msg, []byte(snc)...)
	msg = append(msg, byte(len(digest)))
	msg = append(msg, []byte(digest)...)
	msg = append(msg, byte(len(qop)))
	msg = append(msg, []byte(qop)...)
	log.Debug().Msgf("[AUTH] Sending Digest Auth response (%d bytes)", len(msg))
	return s.sendBinary(msg)
}

// sendSOLSettings sends the SOL configuration message (0x20) to the AMT device.
// MaxTxBuffer=10000, TxTimeout=100, TxOverflowTimeout=0,
// RxTimeout=10000, RxFlushTimeout=100, Heartbeat=0
func (s *SOLSession) sendSOLSettings() {
	seq := s.nextSequence()
	msg := []byte{0x20, 0x00, 0x00, 0x00}
	msg = append(msg, intToLE(seq)...)
	msg = append(msg, shortToLE(10000)...) // MaxTxBuffer
	msg = append(msg, shortToLE(100)...)   // TxTimeout
	msg = append(msg, shortToLE(0)...)     // TxOverflowTimeout
	msg = append(msg, shortToLE(10000)...) // RxTimeout
	msg = append(msg, shortToLE(100)...)   // RxFlushTimeout
	msg = append(msg, shortToLE(0)...)     // Heartbeat
	msg = append(msg, 0x00, 0x00, 0x00, 0x00)

	log.Debug().Msgf("[SOL] Sending SOL settings (0x20)")
	if err := s.sendBinary(msg); err != nil {
		log.Error().Err(err).Msg("Failed to send SOL settings")
	}
}

// GetMPSRedirectToken retrieves the WebSocket redirect token from MPS API.
func GetMPSRedirectToken(mpsHost, deviceGUID, keycloakToken string, insecure bool) (string, error) {
	url := fmt.Sprintf("https://%s/api/v1/authorize/redirection/%s", mpsHost, deviceGUID)
	log.Debug().Msgf("Redirect token URL: %s", url)

	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	if insecure {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // insecure for development
			},
		}
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.AddCookie(&http.Cookie{Name: "jwt", Value: keycloakToken})
	req.Header.Set("ActiveProjectID", "")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp RedirectTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return tokenResp.Token, nil
}

// NewSOLSession creates a new SOL WebSocket session connected to the given MPS/device.
// It performs the full AMT redirection handshake (auth + SOL setup) in a background goroutine.
// Callers should wait on session.SolReady to know when the terminal is active.
func NewSOLSession(cfg SessionConfig) (*SOLSession, error) {
	// Get redirect token from MPS
	redirectToken, err := GetMPSRedirectToken(cfg.MPSHost, cfg.DeviceGUID, cfg.KeycloakToken, cfg.Insecure)
	if err != nil {
		return nil, fmt.Errorf("failed to get MPS redirect token: %w", err)
	}
	return NewSOLSessionWithToken(cfg, redirectToken)
}

// NewSOLSessionWithToken creates a new SOL WebSocket session using a pre-acquired
// MPS redirect token. Use this when the token has already been obtained (e.g. by the
// reconciler via MPS REST API). The handshake runs in a background goroutine;
// callers should wait on session.SolReady to know when the terminal is active.
func NewSOLSessionWithToken(cfg SessionConfig, redirectToken string) (*SOLSession, error) {
	if cfg.Port == 0 {
		cfg.Port = 16994
	}
	if cfg.Mode == "" {
		cfg.Mode = "sol"
	}

	// Build WebSocket URL
	wsURL := fmt.Sprintf("wss://%s/relay/webrelay.ashx?p=2&host=%s&port=%d&tls=0&tls1only=0&mode=%s",
		cfg.MPSHost, cfg.DeviceGUID, cfg.Port, cfg.Mode)

	log.Info().Msgf("Connecting SOL WebSocket xxx to %s (device=%s), url=%s", cfg.MPSHost, cfg.DeviceGUID, wsURL)

	// Setup dialer
	dialer := websocket.Dialer{}
	if cfg.Insecure {
		dialer.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // insecure for development
		}
	}

	headers := http.Header{}
	headers.Add("Sec-WebSocket-Protocol", redirectToken)
	headers.Add("Cookie", fmt.Sprintf("jwt=%s", cfg.KeycloakToken))

	conn, resp, err := dialer.Dial(wsURL, headers)
	if err != nil {
		errMsg := fmt.Sprintf("WebSocket dial failed: %v", err)
		if resp != nil {
			body, _ := io.ReadAll(resp.Body)
			errMsg += fmt.Sprintf(" (HTTP %s: %s)", resp.Status, string(body))
		}
		return nil, fmt.Errorf("%s", errMsg)
	}

	session := &SOLSession{
		conn:     conn,
		SolReady: make(chan struct{}),
		Done:     make(chan struct{}),
		user:     cfg.AMTUser,
		pass:     cfg.AMTPass,
		authURI:  "",
	}

	// Send StartRedirectionSession for SOL: 0x10 0x00 0x00 0x00 "SOL "
	solStartCmd := []byte{0x10, 0x00, 0x00, 0x00, 0x53, 0x4F, 0x4C, 0x20}
	log.Info().Msg("Sending StartRedirectionSession (SOL)")
	if err := session.sendBinary(solStartCmd); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send SOL start: %w", err)
	}

	// Start protocol reader goroutine
	go session.protocolReader()

	return session, nil
}

// protocolReader handles the full AMT SOL protocol state machine.
// Protocol flow:
//  1. → 0x10 StartRedirectionSession (SOL)
//  2. ← 0x11 StartRedirectionSessionReply
//  3. → 0x13 AuthenticateSession
//  4. ← 0x14 AuthenticateSessionReply
//  5. → 0x20 SOL settings
//  6. ← 0x21 SOL settings response
//  7. → 0x27 Finalize session
//  8. SOL active — data via 0x28 (TX) / 0x2A (RX)
func (s *SOLSession) protocolReader() {
	defer func() {
		select {
		case <-s.Done:
		default:
			close(s.Done)
		}
	}()

	for {
		_, message, err := s.conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				log.Info().Msg("SOL WebSocket closed normally")
			} else {
				log.Error().Err(err).Msg("SOL WebSocket read error")
			}
			return
		}

		if len(message) == 0 {
			continue
		}

		switch message[0] {
		case 0x11: // StartRedirectionSessionReply
			if len(message) < 4 {
				log.Error().Msgf("0x11 message too short (%d bytes)", len(message))
				continue
			}
			status := message[1]
			if status != 0 {
				log.Error().Msgf("StartRedirectionSession failed: status=%d", status)
				return
			}
			log.Info().Msg("StartRedirectionSession succeeded, sending auth query")
			authQuery := []byte{0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
			if err := s.sendBinary(authQuery); err != nil {
				log.Error().Err(err).Msg("Failed to send auth query")
				return
			}

		case 0x14: // AuthenticateSessionReply
			if len(message) < 9 {
				log.Error().Msgf("0x14 message too short (%d bytes)", len(message))
				continue
			}
			status := message[1]
			authType := message[4]
			authDataLen := int(binary.LittleEndian.Uint32(message[5:9]))

			if status == 0 && authType == 0 {
				// Query response — check for digest auth
				var authMethods []byte
				if len(message) >= 9+authDataLen {
					authMethods = message[9 : 9+authDataLen]
				}
				hasDigest := false
				for _, m := range authMethods {
					if m == 4 {
						hasDigest = true
						break
					}
				}
				if hasDigest {
					log.Info().Msg("Digest Auth required, sending initial request")
					if err := s.sendDigestAuthInitial(); err != nil {
						log.Error().Err(err).Msg("Failed to send digest auth initial")
						return
					}
				} else {
					log.Info().Msg("No digest auth required, sending SOL settings")
					s.sendSOLSettings()
				}
			} else if status == 0 {
				log.Info().Msgf("Auth successful (authType=%d), sending SOL settings", authType)
				s.sendSOLSettings()
			} else if status == 1 && (authType == 3 || authType == 4) {
				// Digest challenge
				if len(message) < 9+authDataLen {
					log.Error().Msg("Auth challenge too short")
					return
				}
				authData := message[9 : 9+authDataLen]
				curPtr := 0
				realmLen := int(authData[curPtr])
				curPtr++
				realm := string(authData[curPtr : curPtr+realmLen])
				curPtr += realmLen
				nonceLen := int(authData[curPtr])
				curPtr++
				nonce := string(authData[curPtr : curPtr+nonceLen])
				curPtr += nonceLen
				qop := ""
				if authType == 4 && curPtr < len(authData) {
					qopLen := int(authData[curPtr])
					curPtr++
					if curPtr+qopLen <= len(authData) {
						qop = string(authData[curPtr : curPtr+qopLen])
					}
				}
				log.Debug().Msgf("Digest challenge: realm=%q nonce=%q qop=%q", realm, nonce, qop)
				if err := s.sendDigestAuthResponse(realm, nonce, qop); err != nil {
					log.Error().Err(err).Msg("Failed to send digest response")
					return
				}
			} else {
				log.Error().Msgf("Authentication failed: status=%d authType=%d", status, authType)
				return
			}

		case 0x21: // SOL Settings Response
			log.Info().Msg("SOL Settings accepted, finalizing session")
			seq := s.nextSequence()
			finalizeMsg := []byte{0x27, 0x00, 0x00, 0x00}
			finalizeMsg = append(finalizeMsg, intToLE(seq)...)
			finalizeMsg = append(finalizeMsg, 0x00, 0x00, 0x1B, 0x00, 0x00, 0x00)
			if err := s.sendBinary(finalizeMsg); err != nil {
				log.Error().Err(err).Msg("Failed to send session finalization")
				return
			}
			log.Info().Msg("SOL session is now ACTIVE")
			select {
			case <-s.SolReady:
			default:
				close(s.SolReady)
			}

		case 0x29: // Serial Settings
			log.Debug().Msg("Serial settings received")

		case 0x2A: // Incoming display data (terminal output)
			if len(message) < 10 {
				continue
			}
			dataLen := int(message[8]) | int(message[9])<<8
			if len(message) < 10+dataLen {
				dataLen = len(message) - 10
			}
			termData := string(message[10 : 10+dataLen])
			s.AppendOutput(termData)
			log.Debug().Msgf("[SOL-RX] %d bytes: %s", dataLen,
				strings.ReplaceAll(termData, "\n", "\\n"))

		case 0x2B: // Keep alive
			log.Debug().Msg("Keep alive received")

		default:
			log.Debug().Msgf("Unknown AMT command 0x%02X (%d bytes)", message[0], len(message))
		}
	}
}
