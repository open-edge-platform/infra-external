// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"time"

	"github.com/open-edge-platform/orch-library/go/pkg/controller/v2"
)

func main() {
	time.Sleep(time.Hour * 24)
}

type ID string

func (id ID) String() string {
	return "12345678"
}

func SampleReconcile(_ context.Context, request controller.Request[ID]) controller.Directive[ID] {
	return request.Ack()
}
