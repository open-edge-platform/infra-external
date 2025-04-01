// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package flags

import (
	"flag"
	"time"

	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
)

const (
	name                        = "LOCAFlags"
	defaultReconciliationPeriod = 1 * time.Minute
)

var (
	zlog                 = logging.GetLogger(name)
	reconciliationPeriod = flag.Duration("reconciliationPeriod", defaultReconciliationPeriod, "Reconciliation period")
)

func ParseReconciliationPeriod() time.Duration {
	if *reconciliationPeriod < defaultReconciliationPeriod {
		zlog.InfraSec().Warn().Msgf("Invalid reconciliation period setting to its default value: %v", defaultReconciliationPeriod)
		*reconciliationPeriod = defaultReconciliationPeriod
	}
	return *reconciliationPeriod
}
