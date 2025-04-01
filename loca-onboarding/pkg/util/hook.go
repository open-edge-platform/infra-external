// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"strings"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

// TestAssertHook Hook that acts as assert for string in log output.
// Used when some of the functions do not return error (e.g. resource already exists) but we want to test specific test path.
type TestAssertHook struct {
	mutex           *sync.Mutex
	expectedMessage string
	caughtMessage   *bool
}

func (h TestAssertHook) Run(_ *zerolog.Event, _ zerolog.Level, message string) {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	if strings.Contains(message, h.expectedMessage) {
		*h.caughtMessage = true
	}
}

func (h TestAssertHook) Assert(t *testing.T) {
	t.Helper()
	h.mutex.Lock()
	defer h.mutex.Unlock()
	assert.True(t, *h.caughtMessage)
}

func NewTestAssertHook(message string) *TestAssertHook {
	b := false
	return &TestAssertHook{
		mutex:           &sync.Mutex{},
		expectedMessage: message,
		caughtMessage:   &b,
	}
}
