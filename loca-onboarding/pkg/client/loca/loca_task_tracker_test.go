// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package loca

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/model"
	loca_testing "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/testing"
)

func TestTaskIsRunningFor(t *testing.T) {
	resourceUUID := uuid.New().String()
	taskUUID := loca_testing.LocaTaskUUID

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer locaTS.StopDummyLOCAServer()

	locaClient := InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)

	t.Run("TaskNotYetTracked", func(t *testing.T) {
		// confirm task is not running before adding it
		running, err := DefaultTaskTracker.TaskIsRunningFor(locaClient, resourceUUID)
		require.NoError(t, err)
		assert.False(t, running)
	})

	t.Run("TaskIsInRunningState", func(t *testing.T) {
		defer DefaultTaskTracker.removeTask(resourceUUID)

		DefaultTaskTracker.addTask(resourceUUID, taskUUID)

		// confirm task is running after adding it
		running, err := DefaultTaskTracker.TaskIsRunningFor(locaClient, resourceUUID)
		require.NoError(t, err)
		assert.True(t, running)
	})

	t.Run("TaskFinished", func(t *testing.T) {
		defer DefaultTaskTracker.removeTask(resourceUUID)

		DefaultTaskTracker.addTask(resourceUUID, taskUUID)

		// confirm task is running after adding it
		running, err := DefaultTaskTracker.TaskIsRunningFor(locaClient, resourceUUID)
		require.NoError(t, err)
		assert.True(t, running)

		// finish the task
		locaTS.Override(loca_testing.InventoryDevicesPath, loca_testing.DeletedDevice)
		locaTS.Override(loca_testing.TaskManagementTasksIDPath, loca_testing.SuccessfulGetTask)

		// confirm task is not running after task is finished
		running, err = DefaultTaskTracker.TaskIsRunningFor(locaClient, resourceUUID)
		require.NoError(t, err)
		assert.False(t, running)
	})

	t.Run("ErrorInGetTaskByUUID", func(t *testing.T) {
		taskUUID = "missingTaskUUID"
		locaTS.Override(loca_testing.TaskManagementTasksIDPath, func(writer http.ResponseWriter, request *http.Request) {
			loca_testing.WriteStructToResponse(writer, request, &model.DtoErrResponse{}, http.StatusInternalServerError)
		})
		defer DefaultTaskTracker.removeTask(resourceUUID)

		DefaultTaskTracker.addTask(resourceUUID, taskUUID)

		// confirm task is running after adding it
		running, err := DefaultTaskTracker.TaskIsRunningFor(locaClient, resourceUUID)
		require.Error(t, err)
		assert.False(t, running)
	})

	t.Run("FailedToCastUUIDTaskToString", func(t *testing.T) {
		defer DefaultTaskTracker.removeTask(resourceUUID)

		intTaskUUID := 123
		DefaultTaskTracker.runningTasks.Store(resourceUUID, intTaskUUID)

		// expect error when taskUUID is not a string
		running, err := DefaultTaskTracker.TaskIsRunningFor(locaClient, resourceUUID)
		require.ErrorContains(t, err, "Failed to cast value to string for resourceID")
		assert.False(t, running)
	})
}

func TestTrackTask_TrackTaskWhenEmptyListIsProvidedThenErrorShouldBeReturned(t *testing.T) {
	resourceUUID := uuid.New().String()
	err := DefaultTaskTracker.TrackTask(resourceUUID, []string{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Got empty list of taskUUIDs for resourceID")
}

func TestTrackTask_TrackTaskWhenSingleTaskIsProvidedThenShouldTrackTask(t *testing.T) {
	resourceUUID := uuid.New().String()
	taskUUID := uuid.New().String()
	defer DefaultTaskTracker.removeTask(resourceUUID)

	err := DefaultTaskTracker.TrackTask(resourceUUID, []string{taskUUID})
	require.NoError(t, err)

	value, running := DefaultTaskTracker.runningTasks.Load(resourceUUID)
	assert.True(t, running)
	stringValue, ok := value.(string)
	assert.True(t, ok)
	assert.Equal(t, taskUUID, stringValue)
}

func TestTrackTask_TrackTaskWhenMultipleTasksAreProvidedThenShouldTrackLastTask(t *testing.T) {
	resourceUUID := uuid.New().String()
	taskUUID1 := uuid.New().String()
	taskUUID2 := uuid.New().String()
	defer DefaultTaskTracker.removeTask(resourceUUID)

	err := DefaultTaskTracker.TrackTask(resourceUUID, []string{taskUUID1, taskUUID2})
	require.NoError(t, err)

	value, running := DefaultTaskTracker.runningTasks.Load(resourceUUID)
	assert.True(t, running)
	stringValue, ok := value.(string)
	assert.True(t, ok)
	assert.Equal(t, taskUUID2, stringValue)
}
