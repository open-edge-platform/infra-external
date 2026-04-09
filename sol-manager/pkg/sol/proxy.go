// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package sol

import (
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // TODO: restrict to allowed origins in production
	},
}

// ProxyServer serves WebSocket connections for active SOL sessions.
// UI/CLI connects here; the proxy reads clean terminal data from the
// SOLSession and forwards keyboard input back to the AMT device.
type ProxyServer struct {
	controller *Controller
}

// NewProxyServer creates a proxy backed by the given SOL controller.
func NewProxyServer(controller *Controller) *ProxyServer {
	return &ProxyServer{controller: controller}
}

// ServeHTTP handles WebSocket upgrade requests.
// URL pattern: /ws/sol/{resourceID}
func (p *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Extract resourceID from URL path: /ws/sol/{resourceID}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(parts) < 3 || parts[0] != "ws" || parts[1] != "sol" {
		http.Error(w, "invalid path, expected /ws/sol/{resourceID}", http.StatusBadRequest)
		return
	}
	resourceID := parts[2]

	session := p.controller.GetSession(resourceID)
	if session == nil {
		http.Error(w, "no active SOL session for resource "+resourceID, http.StatusNotFound)
		return
	}

	// Upgrade HTTP to WebSocket.
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Error().Err(err).Msgf("WebSocket upgrade failed for resource %s", resourceID)
		return
	}
	defer conn.Close()

	log.Info().Msgf("SOL proxy connected for resource %s", resourceID)

	// Writer goroutine: read SOL terminal output and forward to client.
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Poll the session output buffer for new data.
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				output := session.GetOutput()
				if output == "" {
					continue
				}
				session.ClearOutput()
				if writeErr := conn.WriteMessage(websocket.TextMessage, []byte(output)); writeErr != nil {
					log.Debug().Err(writeErr).Msgf("SOL proxy write error for %s", resourceID)
					return
				}
			case <-session.Done:
				// Session ended — flush remaining output and close.
				if remaining := session.GetOutput(); remaining != "" {
					_ = conn.WriteMessage(websocket.TextMessage, []byte(remaining))
				}
				_ = conn.WriteMessage(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, "SOL session ended"))
				return
			}
		}
	}()

	// Reader loop: read keyboard input from client and send to AMT via SOL.
	for {
		_, message, readErr := conn.ReadMessage()
		if readErr != nil {
			if websocket.IsCloseError(readErr, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				log.Info().Msgf("SOL proxy client disconnected for %s", resourceID)
			} else {
				log.Debug().Err(readErr).Msgf("SOL proxy read error for %s", resourceID)
			}
			break
		}
		if len(message) > 0 {
			if sendErr := session.SendSOLData(string(message)); sendErr != nil {
				log.Error().Err(sendErr).Msgf("Failed to forward input to SOL session %s", resourceID)
				break
			}
		}
	}

	<-done
	log.Info().Msgf("SOL proxy session ended for resource %s", resourceID)
}
