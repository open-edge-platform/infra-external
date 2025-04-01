// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package status

import (
	statusv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/status/v1"
	inv_status "github.com/open-edge-platform/infra-core/inventory/v2/pkg/status"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/util"
)

var (
	// Device-related statuses.
	DeviceStatusActive = inv_status.New(util.DeviceStatusActiveDescription,
		statusv1.StatusIndication_STATUS_INDICATION_IDLE)
	DeviceStatusStaged = inv_status.New(util.DeviceStatusStagedDescription,
		statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS)
	DeviceStatusInventory = inv_status.New(util.DeviceStatusInventoryDescription,
		statusv1.StatusIndication_STATUS_INDICATION_IDLE)
	// Device-related statuses (Failed).
	DeviceStatusActiveFailed = inv_status.New(util.DeviceStatusActiveDescription,
		statusv1.StatusIndication_STATUS_INDICATION_ERROR)
	DeviceStatusStagedFailed = inv_status.New(util.DeviceStatusStagedDescription,
		statusv1.StatusIndication_STATUS_INDICATION_ERROR)
	DeviceStatusInventoryFailed = inv_status.New(util.DeviceStatusInventoryDescription,
		statusv1.StatusIndication_STATUS_INDICATION_ERROR)
	// Instance-related statuses.
	InstanceStatusOnboarded = inv_status.New(util.StatusInstanceOnboarded,
		statusv1.StatusIndication_STATUS_INDICATION_IDLE)
	InstanceStatusConfiguring = inv_status.New(util.StageConfiguringDescription,
		statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS)
	InstanceStatusDeviceProfileApplying = inv_status.New(util.StageDeviceProfileApplyingDescription,
		statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS)
	InstanceStatusOsInstalling = inv_status.New(util.StageOsInstallingDescription,
		statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS)
	InstanceStatusInstanceInstalling = inv_status.New(util.StageInstanceInstallingDescription,
		statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS)
	InstanceStatusInstancePostconfigured = inv_status.New(util.StageInstancePostconfiguredDescription,
		statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS)
	InstanceStatusInstanceConfiguring = inv_status.New(util.StageInstanceConfiguringDescription,
		statusv1.StatusIndication_STATUS_INDICATION_IN_PROGRESS)
	InstanceStatusInstalled = inv_status.New(util.StatusInstanceProvisioned,
		statusv1.StatusIndication_STATUS_INDICATION_IDLE)
	// Instance-related statuses (Failed).
	InstanceStatusOnboardedFailed = inv_status.New(util.StageOnboardedDescription,
		statusv1.StatusIndication_STATUS_INDICATION_ERROR)
	InstanceStatusConfiguringFailed = inv_status.New(util.StageConfiguringDescription,
		statusv1.StatusIndication_STATUS_INDICATION_ERROR)
	InstanceStatusDeviceProfileApplyingFailed = inv_status.New(util.StageDeviceProfileApplyingDescription,
		statusv1.StatusIndication_STATUS_INDICATION_ERROR)
	InstanceStatusOsInstallingFailed = inv_status.New(util.StageOsInstallingDescription,
		statusv1.StatusIndication_STATUS_INDICATION_ERROR)
	InstanceStatusInstanceInstallingFailed = inv_status.New(util.StageInstanceInstallingDescription,
		statusv1.StatusIndication_STATUS_INDICATION_ERROR)
	InstanceStatusInstancePostconfiguredFailed = inv_status.New(util.StageInstancePostconfiguredDescription,
		statusv1.StatusIndication_STATUS_INDICATION_ERROR)
	InstanceStatusInstanceConfiguringFailed = inv_status.New(util.StageInstanceConfiguringDescription,
		statusv1.StatusIndication_STATUS_INDICATION_ERROR)
	InstanceStatusInstalledFailed = inv_status.New(util.StageInstalledDescription,
		statusv1.StatusIndication_STATUS_INDICATION_ERROR)
	HostStatusInvalidated     = inv_status.New("Host is invalidated", statusv1.StatusIndication_STATUS_INDICATION_IDLE)
	InstanceStatusInvalidated = inv_status.New("Instance is invalidated", statusv1.StatusIndication_STATUS_INDICATION_IDLE)
	DeviceStatusDoesNotExist  = inv_status.New("Device does not exist in LOC-A",
		statusv1.StatusIndication_STATUS_INDICATION_ERROR)
	InstanceStatusDoesNotExist = inv_status.New("Instance does not exist in LOC-A",
		statusv1.StatusIndication_STATUS_INDICATION_ERROR)
)
