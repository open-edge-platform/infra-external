// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package images

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"path"
	"sync"

	"google.golang.org/grpc/codes"

	osv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/os/v1"
	inverror "github.com/open-edge-platform/infra-core/inventory/v2/pkg/errors"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/client/inventory"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/loca"
	"github.com/open-edge-platform/infra-external/loca-templates/pkg/config"
)

var (
	log              = logging.GetLogger("images")
	imagesInProgress = sync.Map{}
)

const (
	workdir = "/tmp/"
)

func HandleImage(locaClient *loca.LocaCli, operatingSystem *osv1.OperatingSystemResource) error {
	if operatingSystem == nil {
		err := inverror.Errorfc(codes.FailedPrecondition, "operating system is nil")
		log.Error().Err(err).Msgf("")
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), config.GetConfig().TemplateCreationTimeout)
	defer cancel()

	if imageIsAlreadyUploaded(ctx, locaClient, operatingSystem.GetImageUrl()) {
		log.Info().Msgf("skipping uploading of image from  %v to LOC-A, as it is already exists", operatingSystem.GetImageUrl())
		return nil
	}

	if _, downloadStarted := imagesInProgress.LoadOrStore(operatingSystem.GetImageUrl(), true); downloadStarted {
		log.Debug().Msgf("wanted to download image from %v, but another download from that URL is already in-progress",
			operatingSystem.GetImageUrl())
		return nil
	}

	defer imagesInProgress.Delete(operatingSystem.GetImageUrl())

	dir, err := os.MkdirTemp(workdir, "")
	if err != nil {
		log.InfraErr(err).Msgf("failed to create tmp dir")
		return err
	}
	defer os.RemoveAll(dir)

	secureClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
			},
		},
		Timeout: config.GetConfig().TemplateCreationTimeout,
	}

	file, downloadErr := downloadImageFromUbuntuServer(ctx, secureClient, operatingSystem.GetImageUrl(), dir)
	if downloadErr != nil {
		err = inverror.Errorfc(codes.Internal, "failed to download image from %v URL - %v",
			operatingSystem.GetImageUrl(), downloadErr)
		log.Error().Err(err).Msgf("")
		return err
	}

	_, uploadErr := locaClient.UploadImage(ctx, file.Name())
	if uploadErr != nil {
		err = inverror.Errorfc(codes.Internal, "failed to upload image to LOC-A - %v", uploadErr)
		log.Error().Err(err).Msgf("")
		return err
	}
	return nil
}

func imageIsAlreadyUploaded(ctx context.Context, locaClient *loca.LocaCli,
	imageURL string,
) bool {
	imageName := path.Base(imageURL)
	imageResponse, err := locaClient.LocaAPI.Inventory.GetAPIV1InventoryRepository(
		&inventory.GetAPIV1InventoryRepositoryParams{Context: ctx, FilterEquals: loca.NameFilter(imageName)},
		locaClient.AuthWriter)
	if err != nil {
		log.Warn().Msgf("failed to check if %v image is already uploaded to LOC-A - %v", imageName, err)
		return false
	}

	if imageResponse.Payload.Data.Count != 0 {
		return true
	}
	return false
}

func downloadImageFromUbuntuServer(ctx context.Context, secureClient *http.Client, imageURL, dir string,
) (*os.File, error) {
	log.Info().Msgf("Downloading from %v", imageURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, imageURL, http.NoBody)
	if err != nil {
		log.InfraErr(err).Msgf("failed to create GET request")
		return nil, inverror.Errorfc(codes.Internal, "failed to create request for %v", imageURL)
	}

	resp, err := secureClient.Do(req)
	if err != nil {
		return nil, inverror.Errorfc(codes.Unavailable, "failed to do GET request - %v", err)
	}
	defer resp.Body.Close()

	if !(resp.StatusCode >= 200 && resp.StatusCode <= 299) {
		body, readAllErr := io.ReadAll(resp.Body)
		if readAllErr != nil {
			log.Error().Msgf("failed to read body - %v", readAllErr)
		}
		log.Debug().Msgf("image uploading response - %v", string(body))
		return nil, inverror.Errorfc(codes.Unavailable, "expected to GET 2XX, but got %v instead", resp.StatusCode)
	}

	file, err := os.Create(path.Join(dir, path.Base(imageURL)))
	if err != nil {
		log.InfraErr(err).Msgf("failed to create file")
		return nil, inverror.Errorfc(codes.FailedPrecondition, "failed to create file - %v", err)
	}
	defer file.Close()

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		log.InfraErr(err).Msgf("failed to write response to drive")
		return nil, inverror.Errorfc(codes.Internal, "failed to write response to drive - %v", err)
	}
	log.Info().Msgf("Downloaded and stored %v OS image from ubuntu server.", file.Name())
	return file, nil
}
