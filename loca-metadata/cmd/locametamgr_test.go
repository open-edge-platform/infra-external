// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"os"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/client"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/util"
)

func TestPrintSummary(t *testing.T) {
	assertHook := util.NewTestAssertHook("Starting")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}
	printSummary()
	assertHook.Assert(t)
}

// Test setupTracing function.
func TestSetupTracing(t *testing.T) {
	assertHook := util.NewTestAssertHook("Tracing enabled")
	zlog = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}
	_ = setupTracing("https://127.0.0.1:5000")
	time.Sleep(5 * time.Second)
	assertHook.Assert(t)
}

// Test getSecurityConfig function.
func TestGetSecurityConfigs(t *testing.T) {
	err := flag.Set(client.InsecureGrpc, "true")
	require.NoError(t, err)
	config := getSecurityConfig()
	assert.True(t, config.Insecure, "Insecure flag should be true by default")
}

// test startMetricsServer.
func TestStartMetricsServer(t *testing.T) {
	// This function starts a metrics server, which is difficult to test directly.
	// Instead, we can check if it runs without panicking.
	assert.NotPanics(t, startMetricsServer)
}
