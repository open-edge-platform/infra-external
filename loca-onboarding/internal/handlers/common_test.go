// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package handlers_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	inv_errors "github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/internal/handlers"
	"github.com/open-edge-platform/orch-library/go/pkg/controller/v2"
)

func Test_handleInventoryError(t *testing.T) {
	request := controller.Request[handlers.ReconcilerID]{}
	request.ID = "some ID"

	type args struct {
		err error
	}
	tests := []struct {
		name          string
		args          args
		wantDirective bool
		wantType      interface{}
	}{
		{
			name: "NoError",
			args: args{
				err: nil,
			},
			wantDirective: false,
		},
		{
			name: "NotFound",
			args: args{
				err: inv_errors.Errorfc(codes.NotFound, ""),
			},
			wantDirective: true,
			wantType:      &controller.Ack[handlers.ReconcilerID]{},
		},
		{
			name: "AlreadyExists",
			args: args{
				err: inv_errors.Errorfc(codes.AlreadyExists, ""),
			},
			wantDirective: true,
			wantType:      &controller.Ack[handlers.ReconcilerID]{},
		},
		{
			name: "OtherGRPCError",
			args: args{
				err: inv_errors.Errorfc(codes.Internal, ""),
			},
			wantDirective: true,
			wantType:      &controller.RetryWith[handlers.ReconcilerID]{},
		},
		{
			name: "NonInventoryError",
			args: args{
				err: errors.New(""),
			},
			wantDirective: true,
			wantType:      &controller.Ack[handlers.ReconcilerID]{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			directive := handlers.HandleInventoryError(tt.args.err, request)
			require.Equal(t, directive != nil, tt.wantDirective)
			if tt.wantDirective {
				assert.IsType(t, tt.wantType, directive)
			}
		})
	}
}
