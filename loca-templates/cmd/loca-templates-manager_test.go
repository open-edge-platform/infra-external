// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_setupTracingShouldNotReturnError(t *testing.T) {
	tracing := setupTracing("telemetry.com")
	err := tracing(context.TODO())
	assert.NoError(t, err)
}
