// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"fmt"
	"strings"
	"time"
)

// Constants used for the exp retries.
const (
	minDelay = 1 * time.Second
	maxDelay = 30 * time.Second
)

// Inventory resource IDs + tenant IDs are used to feed reconciler functions.
type ReconcilerID string

func (id ReconcilerID) String() string {
	return fmt.Sprintf("[tenantID=%s, resourceID=%s, name=%s]", id.GetTenantID(), id.GetResourceID(), id.GetName())
}

func (id ReconcilerID) GetTenantID() string {
	return strings.Split(string(id), "_")[0]
}

func (id ReconcilerID) GetResourceID() string {
	return strings.Split(string(id), "_")[1]
}

func (id ReconcilerID) GetName() string {
	return strings.Split(string(id), "_")[2]
}

func NewReconcilerID(tenantID, resourceID, name string) ReconcilerID {
	return ReconcilerID(fmt.Sprintf("%s_%s_%s", tenantID, resourceID, name))
}
