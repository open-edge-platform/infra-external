// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/test/bufconn"

	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/oam"
)

func Test_setupOamServer_shouldStartUp(t *testing.T) {
	oam.TestBufconn = bufconn.Listen(1)

	setupOamServer(true, "bufconn")
	readyEvent := <-readyChan
	assert.True(t, readyEvent)

	termChan <- true

	wg.Wait()
}
