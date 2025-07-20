// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

const (
	keycloakTokenURL   = "/realms/master/protocol/openid-connect/token"
	vaultK8SLoginURL   = `/v1/auth/kubernetes/login`
	vaultSecretBaseURL = `/v1/secret/data/`                                    // #nosec
	vaultRevokeSelfURL = `/v1/auth/token/revoke-self`                          // #nosec
	vaultK8STokenFile  = `/var/run/secrets/kubernetes.io/serviceaccount/token` // #nosec G101
)

var (
	K8STokenFile = vaultK8STokenFile
)

type AuthTestSuite struct {
	suite.Suite
	ctx    context.Context
	cancel context.CancelFunc
}

func (s *AuthTestSuite) SetupSuite() {
}

func (s *AuthTestSuite) TearDownSuite() {
}

func (s *AuthTestSuite) SetupTest() {
	s.ctx, s.cancel = context.WithTimeout(context.Background(), 3*time.Minute)
}

func (s *AuthTestSuite) TearDownTest() {
}

type TestHTTPServer struct {
	K8SLoginReadHandler  func(w http.ResponseWriter)
	SecretHandler        func(w http.ResponseWriter, r *http.Request)
	RevokeHandler        func(w http.ResponseWriter)
	KeycloakTokenHandler func(w http.ResponseWriter, r *http.Request)
	Server               *httptest.Server
}

func (t *TestHTTPServer) WithK8SLoginReadHandler(K8SLoginReadHANDLER func(w http.ResponseWriter)) *TestHTTPServer {
	t.K8SLoginReadHandler = K8SLoginReadHANDLER
	return t
}

func (t *TestHTTPServer) WithSecretHandler(SecretHandler func(w http.ResponseWriter, r *http.Request)) *TestHTTPServer {
	t.SecretHandler = SecretHandler
	return t
}

func (t *TestHTTPServer) WithKeycloakTokenHandler(KeycloakTokenHandler func(w http.ResponseWriter, r *http.Request)) *TestHTTPServer {
	t.KeycloakTokenHandler = KeycloakTokenHandler
	return t
}

func (t *TestHTTPServer) WithRevokeHandler(RevokeHandler func(w http.ResponseWriter)) *TestHTTPServer {
	t.RevokeHandler = RevokeHandler
	return t
}

func (s *AuthTestSuite) NewTestHTTPServer() *TestHTTPServer {
	return &TestHTTPServer{
		K8SLoginReadHandler:  s.handleK8SLogin,
		SecretHandler:        s.handleSecret,
		RevokeHandler:        s.handleRevoke,
		KeycloakTokenHandler: s.handleKeycloakToken,
	}
}

var (
	VaultServer    string
	KeycloakServer string
)

func (t *TestHTTPServer) Start() *TestHTTPServer {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case vaultK8SLoginURL:
			t.K8SLoginReadHandler(w)
		case vaultSecretBaseURL + `catalog-bootstrap-m2m-client-secret`:
			t.SecretHandler(w, r)
		case vaultRevokeSelfURL:
			t.RevokeHandler(w)
		case keycloakTokenURL:
			t.KeycloakTokenHandler(w, r)
		}
	}))
	secrets[vaultSecretBaseURL+`catalog-bootstrap-m2m-client-secret`] = `{"data":{"data":{"value":"` + `secret` + `"}}}`
	t.Server = server
	VaultServer = server.URL
	KeycloakServer = server.URL
	K8STokenFile = `testdata/k8stoken` // #nosec
	return t
}

func (t *TestHTTPServer) Stop() {
	t.Server.Close()
}

func (s *AuthTestSuite) handleK8SLogin(w http.ResponseWriter) {
	w.WriteHeader(http.StatusOK)
	var loginResp struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
		Errors []string `json:"errors"`
	}
	loginResp.Auth.ClientToken = "token"
	js, err := json.Marshal(loginResp)
	s.NoError(err)
	_, _ = w.Write(js)
}

func (s *AuthTestSuite) HandleK8SLoginBadJSON(w http.ResponseWriter) {
	w.WriteHeader(http.StatusOK)
	var loginResp struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
		Errors []string `json:"errors"`
	}
	loginResp.Auth.ClientToken = "token"
	_, _ = w.Write([]byte("This is not the JSON you are looking for"))
}

func (s *AuthTestSuite) handleRevoke(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *AuthTestSuite) HandleRevokeHTTPError(w http.ResponseWriter) {
	w.WriteHeader(http.StatusBadRequest)
}

var secrets = map[string]string{}

func (s *AuthTestSuite) handleSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		w.WriteHeader(http.StatusOK)
		secretData := map[string]interface{}{}
		rawData, err := io.ReadAll(r.Body)
		s.NoError(err)
		err = json.Unmarshal(rawData, &secretData)
		s.NoError(err)
		data := secretData["data"].(map[string]interface{})
		s.NotNil(data)
		secret := data["value"].(string)
		secretJSON := `{"data":{"data":{"value":"` + secret + `"}}}`
		secrets[r.URL.Path] = secretJSON
	} else if r.Method == http.MethodGet {
		secretJSON, ok := secrets[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
		} else {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(secretJSON))
		}
	} else if r.Method == http.MethodDelete {
		w.WriteHeader(http.StatusOK)
		delete(secrets, r.URL.Path)
	}
}

func (s *AuthTestSuite) handleKeycloakToken(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var tokenResp struct {
			AccessToken string `json:"access_token"`
		}
		tokenResp.AccessToken = "token"
		w.WriteHeader(http.StatusOK)
		b, err := json.Marshal(tokenResp)
		s.NoError(err)
		count, err := w.Write(b)
		s.NoError(err)
		s.Len(b, count)
	}
}

func (s *AuthTestSuite) HandleSecretBadHTTPStatus(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusBadRequest)
}

func (s *AuthTestSuite) TestGetToken() {
	server := s.NewTestHTTPServer().Start()
	defer server.Stop()

	s.NoError(os.Setenv("USE_M2M_TOKEN", "true"))
	s.NoError(os.Setenv("KEYCLOAK_SERVER", KeycloakServer))
	s.NoError(os.Setenv("VAULT_SERVER", VaultServer))
	s.NoError(os.Setenv("SERVICE_ACCOUNT", "test-svc"))
	ctx, err := GetToken(context.Background())
	s.NoError(err)
	_, ok := ctx.Value("Authorization").(string)
	s.Equal(true, ok)
}

func TestAuth(t *testing.T) {
	suite.Run(t, &AuthTestSuite{})
}
