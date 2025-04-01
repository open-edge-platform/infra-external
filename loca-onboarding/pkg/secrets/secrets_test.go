// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

//nolint:testpackage // testing internal functions
package secrets

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/flags"
)

func TestInit_happyPath(t *testing.T) {
	*flags.FlagDisableCredentialsManagement = true
	secretNames := []string{"test-sn-1", "test-sn-2"}

	err := Init(context.Background(), secretNames)
	require.NoError(t, err)
}

func TestInit(t *testing.T) {
	*flags.FlagDisableCredentialsManagement = true
	var secretNames []string

	err := Init(context.Background(), secretNames)
	require.ErrorContains(t, err, "Init called with empty secrets")
}
