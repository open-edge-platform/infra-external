// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/open-edge-platform/infra-external/loca-metadata/internal/handlers"
)

func Test_NewReconcilerID(t *testing.T) {
	// Test cases
	tests := []struct {
		tenantID   string
		resourceID string
		name       string
		expected   handlers.ReconcilerID
	}{
		{"tenant1", "resource1", "name1", "tenant1_resource1_name1"},
		{"tenant2", "resource2", "name2", "tenant2_resource2_name2"},
		{"", "resource3", "", "_resource3_"},
		{"tenant4", "", "", "tenant4__"},
		{"", "", "name5", "__name5"},
		{"", "", "", "__"},
	}

	for _, test := range tests {
		result := handlers.NewReconcilerID(test.tenantID, test.resourceID, test.name)
		assert.Equal(t, test.expected, result, "Expected %s but got %s for tenantID: %s, resourceID: %s, name: %s",
			test.expected, result, test.tenantID, test.resourceID, test.name)
	}
}

func TestReconcilerID_String(t *testing.T) {
	tests := []struct {
		input    handlers.ReconcilerID
		expected string
	}{
		{input: "tenant_12345_name", expected: "[tenantID=tenant, resourceID=12345, name=name]"},
		{input: "res_98765_site-1234", expected: "[tenantID=res, resourceID=98765, name=site-1234]"},
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			result := tt.input.String()
			if result != tt.expected {
				t.Errorf("Expected %v, but got %v", tt.expected, result)
			}
		})
	}
}

func TestGetTenantID(t *testing.T) {
	tests := []struct {
		input    handlers.ReconcilerID
		expected string
	}{
		{input: "tenant_12345", expected: "tenant"},
		{input: "res_98765", expected: "res"},
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			result := tt.input.GetTenantID()
			if result != tt.expected {
				t.Errorf("Expected %v, but got %v", tt.expected, result)
			}
		})
	}
}

func TestGetResourceID(t *testing.T) {
	tests := []struct {
		input    handlers.ReconcilerID
		expected string
	}{
		{input: "res_12345", expected: "12345"},
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			result := tt.input.GetResourceID()
			if result != tt.expected {
				t.Errorf("Expected %v, but got %v", tt.expected, result)
			}
		})
	}
}
