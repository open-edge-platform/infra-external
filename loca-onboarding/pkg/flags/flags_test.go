// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package flags

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseReconciliationPeriod_whenInvalidDurationProvidedShouldSetDefaultValue(t *testing.T) {
	*reconciliationPeriod = time.Duration(0)

	period := ParseReconciliationPeriod()

	assert.Equal(t, defaultReconciliationPeriod, period)
}

func TestParseReconciliationPeriod_whenValidDurationProvidedShouldUseIt(t *testing.T) {
	*reconciliationPeriod = time.Hour

	period := ParseReconciliationPeriod()

	assert.Equal(t, time.Hour, period)
}
