// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

//nolint:mnd // timeouts as var do not make sense
package loca

import (
	"context"
	"strings"
	"sync"

	"google.golang.org/grpc/codes"

	inv_errors "github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
)

var (
	log = logging.GetLogger("tasks")

	DefaultTaskTracker = TaskTracker{}
)

type TaskTracker struct {
	runningTasks sync.Map
}

func (tt *TaskTracker) addTask(resourceID, taskUUID string) {
	tt.runningTasks.Store(resourceID, taskUUID)
}

func (tt *TaskTracker) removeTask(resourceID string) {
	tt.runningTasks.Delete(resourceID)
}

func (tt *TaskTracker) TaskIsRunningFor(locaClient *LocaCli, resourceID string) (bool, error) {
	value, running := tt.runningTasks.Load(resourceID)

	// task is not yet tracked or has already finished
	if !running {
		return false, nil
	}

	taskUUID, ok := value.(string)
	if !ok {
		err := inv_errors.Errorfc(codes.Internal, "Failed to cast value to string for resourceID: %v", resourceID)
		log.Error().Err(err).Msgf("")
		return false, err
	}

	getResponse, err := locaClient.GetTask(context.Background(), taskUUID)
	if err != nil {
		return false, err
	}
	status := getResponse.Payload.Data.Status
	if strings.EqualFold(status, "failed") || strings.EqualFold(status, "successful") {
		log.Debug().Msgf("Task %v is %v. Removing it from tracked.", taskUUID, status)
		tt.removeTask(resourceID)
		return false, nil
	}

	log.Debug().Msgf("Task %v is still running. Waiting for it to end.", taskUUID)
	return true, nil
}

func (tt *TaskTracker) TrackTask(resourceID string, taskUUIDs []string) error {
	taskUUID := ""
	switch l := len(taskUUIDs); {
	case l == 0:
		err := inv_errors.Errorf("Got empty list of taskUUIDs for resourceID: %v", resourceID)
		log.Error().Err(err).Msgf("")
		return err
	case l == 1:
		taskUUID = taskUUIDs[0]
	case l >= 2:
		log.Warn().Msgf("expected to get exactly 1 taskUUID, but got %v instead. Tracking only last task.", l)
		taskUUID = taskUUIDs[len(taskUUIDs)-1]
	}
	tt.addTask(resourceID, taskUUID)
	return nil
}
