// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package dm_test

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/open-edge-platform/infra-external/dm-manager/pkg/api"
	"github.com/open-edge-platform/infra-external/dm-manager/pkg/dm"
)

func strPtr(s string) *string {
	return &s
}

func TestDMReconciler_Start(t *testing.T) {
	json200Struct := struct {
		Token *string `json:"token,omitempty"`
	}{Token: strPtr("1234567890")}
	mockAPIClient := new(api.MockClientWithResponsesInterface)
	mockAPIClient.On("PostApiV1AuthorizeWithResponse", mock.Anything, mock.Anything, mock.Anything).
		Return(&api.PostApiV1AuthorizeResponse{JSON200: &json200Struct}, nil)
	mockAPIClient.On("GetApiV1DevicesWithResponse", mock.Anything, mock.Anything, mock.Anything).
		Return(&api.GetApiV1DevicesResponse{JSON200: &[]api.Device{}}, nil)

	termChan := make(chan bool, 1)
	readyChan := make(chan bool, 1)
	wg := &sync.WaitGroup{}

	dmr := &dm.Reconciler{
		APIClient: mockAPIClient,
		TermChan:  termChan,
		ReadyChan: readyChan,
		WaitGroup: wg,
	}

	wg.Add(1)
	go dmr.Start()

	select {
	case readyEvent := <-readyChan:
		assert.True(t, readyEvent)
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for ReadyChan signal")
	}

	termChan <- true

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for reconciler to stop")
	}

	assert.True(t, true, "Reconciler stopped successfully")
}
