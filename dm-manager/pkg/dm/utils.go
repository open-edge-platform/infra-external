// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package dm

import (
	"fmt"
	"strconv"
	"strings"
)

type ReconcilerID string

func (r ReconcilerID) String() string {
	return string(r)
}

func (r ReconcilerID) isCreate() bool {
	boolPart := strings.Split(string(r), ":")[1]
	isCreate, err := strconv.ParseBool(boolPart)
	if err != nil {
		log.Info().Msgf("Failed to parse isCreate from ReconcilerID: %v", r)
		return true
	}
	return isCreate
}

func (r ReconcilerID) GetTenantID() string {
	return strings.Split(string(r), ":")[0]
}

func NewReconcilerID(isCreate bool, tenantID string) ReconcilerID {
	return ReconcilerID(fmt.Sprintf("%s:%s", tenantID, strconv.FormatBool(isCreate)))
}

func convertCertToCertBlob(cert []byte) string {
	certString := string(cert)
	certString = strings.ReplaceAll(certString, "-----BEGIN CERTIFICATE-----", "")
	certString = strings.ReplaceAll(certString, "-----END CERTIFICATE-----", "")
	certString = strings.ReplaceAll(certString, "\r", "")
	certString = strings.ReplaceAll(certString, "\n", "")
	return certString
}

func findExtraElements(left, right []string) []string {
	diff := []string{}
	m := make(map[string]bool)

	// Add all elements of b to a map
	for _, item := range right {
		m[item] = true
	}

	// Check if elements of a are not in the map
	for _, item := range left {
		if !m[item] {
			diff = append(diff, item)
		}
	}

	return diff
}

func Ptr[T any](v T) *T {
	return &v
}
