// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package testutils

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/open-edge-platform/infra-external/loca-templates/pkg/config"
)

const serverModel = "serverModel"

func MockTemplatesManagerConfigWithSingleRepo(t *testing.T) *http.Client {
	t.Helper()

	srv := httptest.NewTLSServer(nil)
	cp := x509.NewCertPool()
	cp.AddCert(srv.Certificate())
	secureClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				RootCAs:    cp,
			},
		},
	}

	tmConfig := config.TemplatesManagerConfig{
		SupportedServers:        []string{serverModel},
		TemplateCreationTimeout: time.Second,
	}
	configFile, err := os.Create(t.TempDir() + "/config")
	assert.NoError(t, err)
	configBytes, err := json.Marshal(tmConfig)
	assert.NoError(t, err)
	_, err = configFile.Write(configBytes)
	assert.NoError(t, err)
	config.Path = configFile.Name()

	return secureClient
}

func MockTemplatesManagerConfig(t *testing.T) {
	t.Helper()
	configFile, err := os.Create(t.TempDir() + "/config")
	assert.NoError(t, err)
	_, err = configFile.WriteString("{}")
	assert.NoError(t, err)
	config.Path = configFile.Name()
}
