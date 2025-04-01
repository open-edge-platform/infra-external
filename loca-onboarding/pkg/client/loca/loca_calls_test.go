// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package loca

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	loca_testing "github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/testing"
)

func Test_newChunkFileReader_happyPath(t *testing.T) {
	tmpFile, err := os.CreateTemp("/tmp", "test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpFile.Name())

	testString := "abcd"
	_, err = tmpFile.WriteString(testString)
	assert.NoError(t, err)

	reader, err := newChunkFileReader(tmpFile.Name(), 0)
	assert.NoError(t, err)

	bytes := make([]byte, chunkSize)
	read, err := reader.Read(bytes)

	assert.NoError(t, err)
	assert.Equal(t, len(testString), read)
	assert.Equal(t, testString, string(bytes[0:len(testString)]))
}

func Test_newChunkFileReader_whenFileDoesntExistsShouldReturnError(t *testing.T) {
	reader, err := newChunkFileReader("file-that-doesnt-exists", 0)
	assert.ErrorContains(t, err, "no such file or directory")
	assert.Zero(t, reader)
}

func TestLocaCli_handleChunk_happyPath(t *testing.T) {
	tmpFile, err := os.CreateTemp("/tmp", "test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpFile.Name())

	testString := "testString"
	_, err = tmpFile.WriteString(testString)
	assert.NoError(t, err)

	tmpStat, err := tmpFile.Stat()
	assert.NoError(t, err)

	const chunkIndex = 0
	const chunkTotal = 1

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer locaTS.StopDummyLOCAServer()
	locaTS.Override("/api/v1/inventory/repository/upload", func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		err = request.ParseMultipartForm(chunkSize)
		assert.NoError(t, err)

		values := request.MultipartForm.Value
		assert.Equal(t, []string{fmt.Sprintf("%v", chunkIndex)}, values["chunkindex"])
		assert.Equal(t, []string{fmt.Sprintf("%v", chunkTotal)}, values["chunktotal"])
		assert.Equal(t, []string{fmt.Sprintf("%v", tmpStat.Size())}, values["filesize"])
		assert.Equal(t, []string{"iso"}, values["fileType"])
	})
	cli := InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)

	resp, err := cli.handleChunk(context.Background(), tmpFile.Name(), chunkIndex, chunkTotal, tmpStat.Size())

	assert.NoError(t, err)
	assert.NotZero(t, resp)
}

func TestLocaCli_uploadImage_whenFileIs2ChunksShouldUploadSuccessfully(t *testing.T) {
	tmpFile, err := os.CreateTemp("/tmp", "test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpFile.Name())

	// creating file that will be read twice by chunkFile reader
	_, err = tmpFile.WriteString(strings.Repeat("a", chunkSize+1))
	assert.NoError(t, err)

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer locaTS.StopDummyLOCAServer()
	endpointCalled := 0

	locaTS.Override("/api/v1/inventory/repository/upload", func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
		endpointCalled++
	})
	cli := InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)

	resp, err := cli.UploadImage(context.Background(), tmpFile.Name())

	assert.NoError(t, err)
	assert.NotZero(t, resp)
	assert.Equal(t, 2, endpointCalled)
}

func TestLocaCli_uploadImage_whenSecondChunkUploadFailedShouldReturnError(t *testing.T) {
	tmpFile, err := os.CreateTemp("/tmp", "test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpFile.Name())

	// creating file that will be read twice by chunkFile reader
	_, err = tmpFile.WriteString(strings.Repeat("a", chunkSize+1))
	assert.NoError(t, err)

	locaTS, err := loca_testing.StartDummyLOCAServer()
	require.NoError(t, err)
	defer locaTS.StopDummyLOCAServer()
	endpointCalled := 0

	locaTS.Override("/api/v1/inventory/repository/upload", func(writer http.ResponseWriter, _ *http.Request) {
		if endpointCalled == 0 {
			writer.WriteHeader(http.StatusOK)
			endpointCalled++
		} else {
			writer.WriteHeader(http.StatusBadRequest)
		}
	})
	cli := InitialiseTestLocaClient(locaTS.GetURL(), loca_testing.LocaSecret)

	resp, err := cli.UploadImage(context.Background(), tmpFile.Name())

	assert.ErrorContains(t, err, "[400]")
	assert.Zero(t, resp)
}
