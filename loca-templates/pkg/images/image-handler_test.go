// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

//nolint:testpackage // tests private functions
package images

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	osv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/os/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/api/loca/v3.3/model"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/client/loca"
	_ "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/examples"
	loca_testing "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/testing"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/util"
	"github.com/open-edge-platform/infra-external/loca-templates/pkg/testutils"
)

const testImageURL = "https://some-random-page"

//nolint:funlen // covers several test cases with same init
func Test_HandleImage(t *testing.T) {
	t.Setenv("Parallel", "false")
	wd, err := os.Getwd()
	assert.NoError(t, err)
	projectRoot := filepath.Dir(filepath.Dir(wd))
	tempDir := filepath.Join(projectRoot, "secrets")
	err = os.Mkdir(tempDir, 0o755)
	assert.NoError(t, err)
	t.Setenv(loca.CaCertPath, projectRoot+"/secrets")

	defer func() {
		errRemoveDir := os.RemoveAll(tempDir)
		assert.NoError(t, errRemoveDir)
	}()

	filename := filepath.Join(tempDir, "ca-cert.crt")
	file, err := os.Create(filename)
	assert.NoError(t, err)
	defer file.Close()

	operatingSystem := prepareUbuntuImagesServer()
	t.Run("Happy Path", func(t *testing.T) {
		testutils.MockTemplatesManagerConfigWithSingleRepo(t)

		locaTS, locaErr := loca_testing.StartDummyLOCAServer()
		require.NoError(t, locaErr)
		defer locaTS.StopDummyLOCAServer()

		cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)

		err = HandleImage(cli, operatingSystem)
		assert.NoError(t, err)
	})
	t.Run("Empty imageURL should return error", func(t *testing.T) {
		locaTS, locaErr := loca_testing.StartDummyLOCAServer()
		require.NoError(t, locaErr)
		defer locaTS.StopDummyLOCAServer()
		locaTS.Override(loca_testing.InventoryRepositoryPath, func(writer http.ResponseWriter, request *http.Request) {
			loca_testing.WriteStructToResponse(writer, request, &model.DtoRepositoryListResponse{
				Data: &model.DtoRepositoryListData{
					Count: 0,
				},
			}, http.StatusOK)
		})

		cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)

		err = HandleImage(cli, &osv1.OperatingSystemResource{ImageUrl: ""})
		assert.ErrorContains(t, err, "failed to download image")
	})
	t.Run("with missing certs should return error", func(t *testing.T) {
		locaTS, locaErr := loca_testing.StartDummyLOCAServer()
		require.NoError(t, locaErr)
		defer locaTS.StopDummyLOCAServer()
		locaTS.Override(loca_testing.InventoryRepositoryPath, func(writer http.ResponseWriter, request *http.Request) {
			loca_testing.WriteStructToResponse(writer, request, &model.DtoRepositoryListResponse{
				Data: &model.DtoRepositoryListData{
					Count: 0,
				},
			}, http.StatusOK)
		})

		cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)

		err = HandleImage(cli, operatingSystem)
		assert.ErrorContains(t, err, "failed to verify certificate")
	})
	t.Run("When image already uploaded should return no error", func(t *testing.T) {
		assertHook := util.NewTestAssertHook("skipping uploading of image")
		zGlobalLevel := zerolog.GlobalLevel()
		defer zerolog.SetGlobalLevel(zGlobalLevel)
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

		locaTS, locaErr := loca_testing.StartDummyLOCAServer()
		require.NoError(t, locaErr)
		defer locaTS.StopDummyLOCAServer()

		cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)

		err = HandleImage(cli, operatingSystem)
		assert.NoError(t, err)
		assertHook.Assert(t)
	})
	t.Run("When image is nil then error should be returned", func(t *testing.T) {
		err = HandleImage(nil, nil)
		assert.ErrorContains(t, err, "operating system is nil")
	})
	t.Run("When image is already getting downloaded by another goroutine, then shouldn't download again ", func(t *testing.T) {
		assertHook := util.NewTestAssertHook("another download from that URL is already in-progress")
		zGlobalLevel := zerolog.GlobalLevel()
		defer zerolog.SetGlobalLevel(zGlobalLevel)
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

		locaTS, locaErr := loca_testing.StartDummyLOCAServer()
		require.NoError(t, locaErr)
		defer locaTS.StopDummyLOCAServer()
		locaTS.Override(loca_testing.InventoryRepositoryPath, func(writer http.ResponseWriter, request *http.Request) {
			loca_testing.WriteStructToResponse(writer, request, &model.DtoRepositoryListResponse{
				Data: &model.DtoRepositoryListData{
					Count: 0,
				},
			}, http.StatusOK)
		})

		cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)
		imagesInProgress.Store(operatingSystem.GetImageUrl(), true)

		err = HandleImage(cli, operatingSystem)

		assert.NoError(t, err)
		assertHook.Assert(t)
	})
}

func prepareUbuntuImagesServer() *osv1.OperatingSystemResource {
	handler := http.HandlerFunc(func(res http.ResponseWriter, _ *http.Request) {
		_, err := res.Write([]byte("mocked ubuntu server"))
		if err != nil {
			panic(err)
		}
	})
	srv := httptest.NewTLSServer(handler)

	operatingSystem := &osv1.OperatingSystemResource{
		ImageUrl: srv.URL + "/ubuntu.iso",
	}

	return operatingSystem
}

func Test_imageIsAlreadyUploaded_whenImageAlreadyPresentShouldReturnTrue(t *testing.T) {
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer locaTS.StopDummyLOCAServer()
	cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)

	uploaded := imageIsAlreadyUploaded(context.Background(), cli, testImageURL)
	assert.True(t, uploaded)
}

func Test_imageIsAlreadyUploaded_whenImageNotPresentShouldReturnFalse(t *testing.T) {
	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer locaTS.StopDummyLOCAServer()
	locaTS.Override(loca_testing.InventoryRepositoryPath, func(writer http.ResponseWriter, request *http.Request) {
		loca_testing.WriteStructToResponse(writer, request, &model.DtoRepositoryListResponse{
			Data: &model.DtoRepositoryListData{
				Count: 0,
			},
		}, http.StatusOK)
	})
	cli := loca.InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)

	uploaded := imageIsAlreadyUploaded(context.Background(), cli, testImageURL)
	assert.False(t, uploaded)
}

func Test_downloadImageFromUbuntuServer_whenURLToUbuntuIsInvalidShouldReturnError(t *testing.T) {
	client := testutils.MockTemplatesManagerConfigWithSingleRepo(t)

	file, err := downloadImageFromUbuntuServer(context.Background(), client, "not-a-protocol://test", "/tmp")

	assert.Zero(t, file)
	assert.ErrorContains(t, err, "unsupported protocol scheme")
}

func Test_downloadImageFromUbuntuServer_whenGettingTimeoutShouldReturnError(t *testing.T) {
	client := testutils.MockTemplatesManagerConfigWithSingleRepo(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()

	file, err := downloadImageFromUbuntuServer(ctx, client, testImageURL, "/tmp")

	assert.Zero(t, file)
	assert.ErrorContains(t, err, "context deadline exceeded")
}

func Test_downloadImageFromUbuntuServer_whenCannotPrepareRequestShouldReturnError(t *testing.T) {
	testutils.MockTemplatesManagerConfig(t)

	//nolint:staticcheck //intentionally passing nil for test-case
	file, err := downloadImageFromUbuntuServer(nil, nil, testImageURL, "/tmp")

	assert.Zero(t, file)
	assert.ErrorContains(t, err, "failed to create request")
}

func Test_downloadImageFromUbuntuServer_happyPath(t *testing.T) {
	client := testutils.MockTemplatesManagerConfigWithSingleRepo(t)
	operatingSystem := prepareUbuntuImagesServer()

	file, err := downloadImageFromUbuntuServer(context.Background(), client, operatingSystem.GetImageUrl(), "/tmp")

	assert.NoError(t, err)
	assert.NotZero(t, file)
}

func Test_downloadImageFromUbuntuServer_whenRecievedNon2XXShouldReturnError(t *testing.T) {
	client := testutils.MockTemplatesManagerConfigWithSingleRepo(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))

	file, err := downloadImageFromUbuntuServer(context.Background(), client, srv.URL, "/tmp")

	assert.ErrorContains(t, err, "expected to GET 2XX, but got 503 instead")
	assert.Zero(t, file)
}
