// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package dm

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/open-edge-platform/infra-external/dm-manager/pkg/api/mps"
)

func TestMpsAuthHandler_MpsAuth_shouldUseStoredToken(t *testing.T) {
	token := "zxcv"
	mah := &DmtAuthHandler{
		token:     token,
		updatedAt: time.Now(),
	}

	httpReq, err := http.NewRequestWithContext(context.Background(), "http", "localhost", http.NoBody)
	assert.NoError(t, err)

	err = mah.DmtAuth(context.Background(), httpReq)
	assert.NoError(t, err)
	assert.Equal(t, "Bearer "+token, httpReq.Header.Get("Authorization"))
}

func TestMpsAuthHandler_MpsAuth_shouldRefreshStaleToken(t *testing.T) {
	token := "zxcv"
	json200Struct := struct {
		Token *string `json:"token,omitempty"`
	}{Token: &token}
	credentialsFile = mockCredentialsFile(t, "user", "pass")
	defer os.Remove(credentialsFile)

	mockAPIClient := new(mps.MockClientWithResponsesInterface)
	mockAPIClient.On("PostApiV1AuthorizeWithResponse", mock.Anything, mock.Anything).
		Return(&mps.PostApiV1AuthorizeResponse{JSON200: &json200Struct}, nil)

	mah := &DmtAuthHandler{
		MpsClient: mockAPIClient,
		token:     "old-token",
		updatedAt: time.Date(2025, 1, 1, 1, 1, 1, 1, &time.Location{}),
	}

	httpReq, err := http.NewRequestWithContext(context.Background(), "http", "localhost", http.NoBody)
	assert.NoError(t, err)

	err = mah.DmtAuth(context.Background(), httpReq)
	assert.NoError(t, err)
	assert.Equal(t, "Bearer "+token, httpReq.Header.Get("Authorization"))
}

func TestMpsAuthHandler_getToken_shouldGetTokenFromMpsServer(t *testing.T) {
	mockedUsername := "user"
	mockedPassword := "pass"

	credentialsFile = mockCredentialsFile(t, mockedUsername, mockedPassword)
	defer os.Remove(credentialsFile)

	token := "1234567890"
	json200Struct := struct {
		Token *string `json:"token,omitempty"`
	}{Token: &token}
	mockAPIClient := new(mps.MockClientWithResponsesInterface)
	mockAPIClient.On("PostApiV1AuthorizeWithResponse", mock.Anything,
		mps.PostApiV1AuthorizeJSONRequestBody{Username: mockedUsername, Password: mockedPassword}).
		Return(&mps.PostApiV1AuthorizeResponse{JSON200: &json200Struct}, nil)

	mah := &DmtAuthHandler{
		MpsClient: mockAPIClient,
	}
	assert.Zero(t, mah.token)

	err := mah.getToken(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, token, mah.token)
}

func Test_getCredentials_happyPath(t *testing.T) {
	mockedUsername := "user"
	mockedPassword := "pass"

	credentialsFile = mockCredentialsFile(t, mockedUsername, mockedPassword)
	defer os.Remove(credentialsFile)

	creds := getCredentials()
	assert.Equal(t, mockedUsername, creds.Username)
	assert.Equal(t, mockedPassword, creds.Password)
}

func mockCredentialsFile(t *testing.T, username, password string) string {
	t.Helper()
	tmpCredentials, err := os.CreateTemp("/tmp", "config.yml")
	assert.NoError(t, err)

	_, err = fmt.Fprintf(tmpCredentials, `
username: %v
password: %v`, username, password)
	assert.NoError(t, err)

	return tmpCredentials.Name()
}
