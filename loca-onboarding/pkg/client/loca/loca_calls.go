// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package loca

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"

	"google.golang.org/grpc/codes"

	inv_errors "github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/client/deployment"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/client/inventory"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/client/task_management"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/model"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/util"
)

const (
	chunkSize = 100000000 // size in bytes
)

// GetTemplateByTemplateName returns the LOC-A template with the given name.
func (lc *LocaCli) GetTemplateByTemplateName(ctx context.Context, templateName string) (*model.DtoTemplate, error) {
	filter := fmt.Sprintf("[{\"attributes\":\"name\",\"values\":%q}]", templateName)

	templatesList, err := lc.LocaAPI.Deployment.GetAPIV1DeploymentTemplates(
		&deployment.GetAPIV1DeploymentTemplatesParams{Context: ctx, FilterEquals: &filter}, lc.AuthWriter)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msg("Failed to get templates from LOC-A")
		return nil, err
	}

	// check if the template is found
	if templatesList.GetPayload().Data.Count != 1 {
		err = inv_errors.Errorfc(codes.Internal, "Failed to get a single template matching the template name (%s)", templateName)
		zlog.InfraSec().InfraErr(err).Msg("")
		return nil, err
	}
	return templatesList.GetPayload().Data.Results[0], nil
}

// ProvisionInstance provisions an Instance in LOC-A using the specified template and siteID
// It returns the task UUID associated with the Instance creation.
func (lc *LocaCli) ProvisionInstance(ctx context.Context, templateName, hostSN, hostUUID, siteName string) (
	string, error,
) {
	// Get template from LOC-A based on the template name
	template, err := lc.GetTemplateByTemplateName(ctx, templateName)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to get template (%s) from LOC-A", templateName)
		return "", err
	}

	// Get the Device ID by Serial Number and UUID
	deviceID, err := lc.getDeviceIDBySnAndUUID(ctx, hostSN, hostUUID)
	if err != nil {
		zlog.InfraSec().InfraErr(err).
			Msgf("Failed to get Device ID by Serial Number (%s) and UUID (%s) from LOC-A", hostSN, hostUUID)
		return "", err
	}

	// Get the Site ID by Site Code
	locaSiteID, err := lc.getSiteIDBySiteName(ctx, siteName)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to get Site ID by Site name (%s) from LOC-A", siteName)
		return "", err
	}

	// Create an Instance in LOC-A
	instance, err := lc.createInstance(ctx, template.ID, deviceID, locaSiteID)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to create Instance in LOC-A")
		return "", err
	}

	// Deploy the created Instance in LOC-A
	err = lc.deployInstance(ctx, instance.Name)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to deploy Instance (%s) in LOC-A", instance.Name)
		return "", err
	}

	return instance.ID, nil
}

func (lc *LocaCli) createInstance(ctx context.Context, templateID, deviceID, siteID string) (*model.DtoInstance, error) {
	createResp, err := lc.LocaAPI.Deployment.PostAPIV1DeploymentInstancesCreate(
		&deployment.PostAPIV1DeploymentInstancesCreateParams{
			Context: ctx,
			Body: &model.DtoCreateInstanceRequest{
				Instances: []*model.DtoInstanceInfo{
					{
						Devices: []string{deviceID},
						SiteID:  &siteID,
					},
				},
				TemplateID: &templateID,
			},
		}, lc.AuthWriter)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to create Instance in LOC-A")
		return nil, err
	}

	if len(createResp.GetPayload().Data.Results) != 1 {
		err = inv_errors.Errorfc(codes.Internal, "Obtained non-singular Instance from LOC-A")
		zlog.InfraSec().InfraErr(err).Msgf("")
		return nil, err
	}
	return createResp.GetPayload().Data.Results[0], nil
}

func (lc *LocaCli) deployInstance(ctx context.Context, instanceName string) error {
	//nolint:errcheck // no need to check return struct
	_, err := lc.LocaAPI.Deployment.PostAPIV1DeploymentInstancesDeploy(&deployment.PostAPIV1DeploymentInstancesDeployParams{
		Context: ctx,
		Body: &model.DtoDeployInstancesRequest{
			InstancesName: []string{instanceName},
		},
	}, lc.AuthWriter)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to deploy Instance (%s) in LOC-A", instanceName)
		return err
	}
	return nil
}

func (lc *LocaCli) getSiteIDBySiteName(ctx context.Context, siteName string) (string, error) {
	siteResp, err := lc.LocaAPI.Inventory.GetAPIV1InventorySites(&inventory.GetAPIV1InventorySitesParams{
		Context: ctx,
		Name:    &siteName,
	}, lc.AuthWriter)
	if err != nil {
		zlog.InfraSec().InfraErr(err).Msgf("Failed to get Site by Site name (%s) from LOC-A", siteName)
		return "", err
	}

	if len(siteResp.GetPayload().Data.Results) != 1 {
		err = inv_errors.Errorfc(codes.InvalidArgument, "Obtained non-singular Site from LOC-A")
		zlog.InfraSec().InfraErr(err).Msgf("")
		return "", err
	}
	return siteResp.GetPayload().Data.Results[0].ID, err
}

func (lc *LocaCli) getDeviceIDBySnAndUUID(ctx context.Context, hostSN, hostUUID string) (string, error) {
	filter := fmt.Sprintf(`[{"attributes":"uuid","values":%q}]`, util.ConvertUUIDToLOCAUUID(hostUUID))

	deviceResp, err := lc.LocaAPI.Inventory.GetAPIV1InventoryDevices(&inventory.GetAPIV1InventoryDevicesParams{
		Context:      ctx,
		SerialNumber: &hostSN,
		FilterEquals: &filter,
	}, lc.AuthWriter)
	if err != nil {
		zlog.InfraSec().InfraErr(err).
			Msgf("Failed to get Device by Serial Number (%s) and UUID (%s) from LOC-A", hostSN, hostUUID)
		return "", err
	}

	if len(deviceResp.GetPayload().Data.Results) != 1 {
		err = inv_errors.Errorfc(codes.InvalidArgument, "Obtained non-singular Device from LOC-A")
		zlog.InfraSec().InfraErr(err).Msgf("")
		return "", err
	}
	return deviceResp.GetPayload().Data.Results[0].ID, nil
}

func (lc *LocaCli) GetTask(ctx context.Context, taskUUID string) (*task_management.GetAPIV1TaskManagementTasksUUIDOK, error) {
	taskResp, err := lc.LocaAPI.TaskManagement.GetAPIV1TaskManagementTasksUUID(
		&task_management.GetAPIV1TaskManagementTasksUUIDParams{
			Context: ctx,
			UUID:    taskUUID,
		}, lc.AuthWriter)
	if err != nil {
		return nil, err
	}
	return taskResp, nil
}

func (lc *LocaCli) GetInstanceIDFromTaskDetails(taskResp *task_management.GetAPIV1TaskManagementTasksUUIDOK) (string, error) {
	params, ok := taskResp.GetPayload().Data.Params.(map[string]interface{})
	if !ok {
		err := inv_errors.Errorfc(codes.InvalidArgument, "Invalid params format")
		zlog.InfraErr(err).Msg("")
		return "", err
	}
	instanceID, ok := params["id"].(string)
	if !ok {
		err := inv_errors.Errorfc(codes.InvalidArgument, "Invalid LOC-A InstanceID format")
		zlog.InfraErr(err).Msg("")
		return "", err
	}
	return instanceID, nil
}

func (lc *LocaCli) UploadImage(ctx context.Context, fileName string) (*model.DtoRepositoryUploadResponse, error) {
	fileStat, err := os.Stat(fileName)
	if err != nil {
		zlog.InfraErr(err).Msgf("failed to stat %v file", fileName)
		return nil, err
	}

	chunkTotal := int64(0)
	if fileStat.Size()%chunkSize == 0 {
		chunkTotal = fileStat.Size() / chunkSize
	} else {
		chunkTotal = (fileStat.Size() / chunkSize) + 1
	}
	var lastPostResponse *model.DtoRepositoryUploadResponse

	for chunkIndex := int64(0); chunkIndex < chunkTotal; chunkIndex++ {
		lastPostResponse, err = lc.handleChunk(ctx, fileName, chunkIndex, chunkTotal, fileStat.Size())
		if err != nil {
			return nil, err
		}
	}
	zlog.Info().Msgf("Uploaded image to LOC-A")
	return lastPostResponse, nil
}

func (lc *LocaCli) handleChunk(
	ctx context.Context, fileName string, chunkIndex, chunkTotal, filesize int64,
) (*model.DtoRepositoryUploadResponse, error) {
	log.Info().Msgf("chunk %v out of %v", chunkIndex, chunkTotal)

	fileReader, err := newChunkFileReader(fileName, chunkIndex)
	if err != nil {
		return nil, err
	}

	postResp, err := lc.LocaAPI.Inventory.PostAPIV1InventoryRepositoryUpload(&inventory.PostAPIV1InventoryRepositoryUploadParams{
		Context:    ctx,
		Chunkindex: fmt.Sprintf("%v", chunkIndex),
		Chunktotal: fmt.Sprintf("%v", chunkTotal),
		FileType:   "iso",
		Filesize:   fmt.Sprintf("%v", filesize),
		File:       fileReader,
	}, lc.AuthWriter)
	if err != nil {
		return nil, err
	}
	return postResp.Payload, nil
}

type chunkFileReader struct {
	file       *os.File
	chunkIndex int64
	buff       *bytes.Buffer
}

func newChunkFileReader(fileName string, chunkIndex int64) (*chunkFileReader, error) {
	file, err := os.Open(fileName)
	if err != nil {
		zlog.InfraErr(err).Msgf("failed to open %v file", fileName)
		return nil, err
	}
	c := chunkFileReader{
		file:       file,
		chunkIndex: chunkIndex,
	}

	partBuff := make([]byte, chunkSize)
	read, err := c.file.ReadAt(partBuff, c.chunkIndex*chunkSize)
	if err != nil {
		//nolint:errorlint // error is not wrapped and errors lib doesn't supports EOF as error
		if err != io.EOF { // EOF is expected for last chunk
			zlog.InfraErr(err).Msgf("cannot read - %v", err)
			return nil, err
		}
	}
	c.buff = bytes.NewBuffer(partBuff[0:read])
	return &c, nil
}

func (c chunkFileReader) Read(p []byte) (n int, err error) {
	return c.buff.Read(p)
}

func (c chunkFileReader) Close() error {
	return c.file.Close()
}

func (c chunkFileReader) Name() string {
	return c.file.Name()
}
