// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

//nolint // util is an acceptable package name for utility functions
package util

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

const hookTickDuration = 10 * time.Millisecond

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

func (h TestAssertHook) AssertWithTimeout(t *testing.T, timeout time.Duration) {
	t.Helper()

	ticker := time.NewTicker(hookTickDuration)
	select {
	case <-ticker.C:
		h.mutex.Lock()
		if *h.caughtMessage {
			assert.True(t, *h.caughtMessage)
		}
		h.mutex.Unlock()
	case <-time.After(timeout):
		assert.Fail(t, "Expected message not caught within timeout", h.expectedMessage)
	}
}

func NewTestAssertHook(message string) *TestAssertHook {
	b := false
	return &TestAssertHook{
		mutex:           &sync.Mutex{},
		expectedMessage: message,
		caughtMessage:   &b,
	}
}
