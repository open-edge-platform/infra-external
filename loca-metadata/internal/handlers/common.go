// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

// Package handlers provides reconciliation handlers for LOC-A metadata synchronization.
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

// ReconcilerID represents a unique identifier combining tenant ID, resource ID, and name for reconciler functions.
type ReconcilerID string

func (id ReconcilerID) String() string {
	return fmt.Sprintf("[tenantID=%s, resourceID=%s, name=%s]", id.GetTenantID(), id.GetResourceID(), id.GetName())
}

// GetTenantID extracts and returns the tenant ID from the reconciler ID.
func (id ReconcilerID) GetTenantID() string {
	return strings.Split(string(id), "_")[0]
}

// GetResourceID extracts and returns the resource ID from the reconciler ID.
func (id ReconcilerID) GetResourceID() string {
	return strings.Split(string(id), "_")[1]
}

// GetName extracts and returns the name from the reconciler ID.
func (id ReconcilerID) GetName() string {
	return strings.Split(string(id), "_")[2]
}

// NewReconcilerID creates a new ReconcilerID from the given tenant ID, resource ID, and name.
func NewReconcilerID(tenantID, resourceID, name string) ReconcilerID {
	return ReconcilerID(fmt.Sprintf("%s_%s_%s", tenantID, resourceID, name))
}
