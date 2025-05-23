// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package dm

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	tenantv1 "github.com/open-edge-platform/infra-core/inventory/v2/pkg/api/tenant/v1"
	"github.com/open-edge-platform/infra-core/inventory/v2/pkg/logging"
	inv_testing "github.com/open-edge-platform/infra-core/inventory/v2/pkg/testing"
	"github.com/open-edge-platform/infra-external/dm-manager/pkg/api/mps"
	"github.com/open-edge-platform/infra-external/dm-manager/pkg/api/rps"
	"github.com/open-edge-platform/infra-external/loca-onboarding/v2/pkg/util"
)

//nolint:lll // intended long certificate blob
const cert = "-----BEGIN CERTIFICATE-----\r\nMIIEOzCCAqOgAwIBAgIDBzkQMA0GCSqGSIb3DQEBDAUAMD0xFzAVBgNVBAMTDk1Q\r\nU1Jvb3QtZDdmMDg0MRAwDgYDVQQKEwd1bmtub3duMRAwDgYDVQQGEwd1bmtub3du\r\nMCAXDTI0MDUyMDEyMjQxNVoYDzIwNTUwNTIwMTIyNDE1WjA9MRcwFQYDVQQDEw5N\r\nUFNSb290LWQ3ZjA4NDEQMA4GA1UEChMHdW5rbm93bjEQMA4GA1UEBhMHdW5rbm93\r\nbjCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBANJirZbxnlCYTsuLPzFX\r\neLXH92EF/9TO8ClA7PaPcZP0lkxCwpuRNBa5iGXvawirf2wf6Pv+nntNNNQGvvqU\r\nt1RrpVrC78yiTTTx/LJOTVkaAq+9Gm3LlJWJnXx8QMV3BJRPNO+eEOpNy1XePuWU\r\n1CpYHAYyW77sccNDvh4f8SVOzMQZW+tIE93BBLBv5k8auL8CSDw6E+oxg5RzQE2F\r\nv5lFw7fLUCKPLSOhWNq9g00ZY//aq40C5Jh8rZY7PPEHrZe37WDnlnhBckSE+3Px\r\n68bRt94ut6oKigVwaaYLDyt6s36DsYB0CTIlOotKe011j741jViMHG/H56r8wRCA\r\nb+GybWEK51iC+J1esO68wmC8a/oduh4tCBErdx9q63LbOkF15OLAbCO9uYRrl7KJ\r\nODP+TpUvg0JxPGFBbZ2k1SB/2K7KX5frXRlKdext4zjrjx4vOiL1f6kgfyD96xT/\r\nEL4JfkLkRDxnEwd/Twu4vaMQgpERoLYPdUTLC5c+FrSBeQIDAQABo0IwQDAMBgNV\r\nHRMEBTADAQH/MBEGCWCGSAGG+EIBAQQEAwIABzAdBgNVHQ4EFgQU1/CEBHJ3fPlD\r\nz8xxbEN7AjR1T84wDQYJKoZIhvcNAQEMBQADggGBALCD+mQF+GplYOEVNEcUzi8W\r\nGZBmT7JahopGAubbeZmDGF/Hf+o2QCdPc0J6sRiJq+rOKINGLsptrDOdXYnXK7gf\r\n/s07USPDYCQbrG0kWZqvGCFMbv9Ailo1YFol+XpElrehiJXg3T++6ZIqxX2kJSw6\r\ndsLMoNGb209A7NUnLHC/H8KKjLsbNk4NgH6ixvCfwpccPL//nLgip055BTPZ4Kdc\r\nxZ5/tFq+YTUHrE5H60MmmVcZYGA6bXtix6ExkPcxLW1zg+Nnk5Iu5zQgrlaiXl+4\r\nkG5JqmC1w2MGhcW5G2d/+QewXKDeOceksJ1HufqkHdgyBkb7/jVqu8m0m4w4MPpE\r\n39bdymkNrjwwiPZZpiOjzCscb0b35gvVS01SYzCl1kuUMtz2jw7aS2Xa805PLha1\r\nn+5/ioHqgXYVvZzf6DL1GxnlZzwKA0fVFBohruTNbm5jCIxUlQCs/ym24bIq8Nvj\r\nm2HouES4kKp8wWl7NWZ6gFZAkVOSzmyXmuG+1Vzerg==\r\n-----END CERTIFICATE-----\r\n"

func TestDMReconciler_Start(t *testing.T) {
	termChan := make(chan bool, 1)
	readyChan := make(chan bool, 1)
	wg := &sync.WaitGroup{}
	tmpDir := t.TempDir()
	inv_testing.StartTestingEnvironment(tmpDir, "", tmpDir)
	cli := inv_testing.TestClients[inv_testing.APIClient].GetTenantAwareInventoryClient()
	dmr := &Reconciler{
		InventoryClient: cli,
		TermChan:        termChan,
		ReadyChan:       readyChan,
		WaitGroup:       wg,
	}

	wg.Add(1)
	go dmr.Start()

	select {
	case readyEvent := <-readyChan:
		assert.True(t, readyEvent)
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for ReadyChan signal")
	}

	termChan <- true

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for reconciler to stop")
	}

	assert.True(t, true, "Reconciler stopped successfully")
}

func Test_convertCertToCertBlob(t *testing.T) {
	newCert := convertCertToCertBlob([]byte(cert))
	//nolint:lll // intended long certificate blob
	expectedCert := `MIIEOzCCAqOgAwIBAgIDBzkQMA0GCSqGSIb3DQEBDAUAMD0xFzAVBgNVBAMTDk1QU1Jvb3QtZDdmMDg0MRAwDgYDVQQKEwd1bmtub3duMRAwDgYDVQQGEwd1bmtub3duMCAXDTI0MDUyMDEyMjQxNVoYDzIwNTUwNTIwMTIyNDE1WjA9MRcwFQYDVQQDEw5NUFNSb290LWQ3ZjA4NDEQMA4GA1UEChMHdW5rbm93bjEQMA4GA1UEBhMHdW5rbm93bjCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBANJirZbxnlCYTsuLPzFXeLXH92EF/9TO8ClA7PaPcZP0lkxCwpuRNBa5iGXvawirf2wf6Pv+nntNNNQGvvqUt1RrpVrC78yiTTTx/LJOTVkaAq+9Gm3LlJWJnXx8QMV3BJRPNO+eEOpNy1XePuWU1CpYHAYyW77sccNDvh4f8SVOzMQZW+tIE93BBLBv5k8auL8CSDw6E+oxg5RzQE2Fv5lFw7fLUCKPLSOhWNq9g00ZY//aq40C5Jh8rZY7PPEHrZe37WDnlnhBckSE+3Px68bRt94ut6oKigVwaaYLDyt6s36DsYB0CTIlOotKe011j741jViMHG/H56r8wRCAb+GybWEK51iC+J1esO68wmC8a/oduh4tCBErdx9q63LbOkF15OLAbCO9uYRrl7KJODP+TpUvg0JxPGFBbZ2k1SB/2K7KX5frXRlKdext4zjrjx4vOiL1f6kgfyD96xT/EL4JfkLkRDxnEwd/Twu4vaMQgpERoLYPdUTLC5c+FrSBeQIDAQABo0IwQDAMBgNVHRMEBTADAQH/MBEGCWCGSAGG+EIBAQQEAwIABzAdBgNVHQ4EFgQU1/CEBHJ3fPlDz8xxbEN7AjR1T84wDQYJKoZIhvcNAQEMBQADggGBALCD+mQF+GplYOEVNEcUzi8WGZBmT7JahopGAubbeZmDGF/Hf+o2QCdPc0J6sRiJq+rOKINGLsptrDOdXYnXK7gf/s07USPDYCQbrG0kWZqvGCFMbv9Ailo1YFol+XpElrehiJXg3T++6ZIqxX2kJSw6dsLMoNGb209A7NUnLHC/H8KKjLsbNk4NgH6ixvCfwpccPL//nLgip055BTPZ4KdcxZ5/tFq+YTUHrE5H60MmmVcZYGA6bXtix6ExkPcxLW1zg+Nnk5Iu5zQgrlaiXl+4kG5JqmC1w2MGhcW5G2d/+QewXKDeOceksJ1HufqkHdgyBkb7/jVqu8m0m4w4MPpE39bdymkNrjwwiPZZpiOjzCscb0b35gvVS01SYzCl1kuUMtz2jw7aS2Xa805PLha1n+5/ioHqgXYVvZzf6DL1GxnlZzwKA0fVFBohruTNbm5jCIxUlQCs/ym24bIq8Nvjm2HouES4kKp8wWl7NWZ6gFZAkVOSzmyXmuG+1Vzerg==`
	assert.Equal(t, expectedCert, newCert)
}

func TestReconciler_handleTenantCreation_happyPath(t *testing.T) {
	mpsMock := new(mps.MockClientWithResponsesInterface)
	rpsMock := new(rps.MockClientWithResponsesInterface)
	config := ReconcilerConfig{
		AmtPassword:   "test1234",
		ClusterDomain: "test.com",
	}
	dmr := &Reconciler{
		MpsClient: mpsMock,
		RpsClient: rpsMock,
		Config:    &config,
	}

	assertHook := util.NewTestAssertHook("tenant is done")
	profileHook := util.NewTestAssertHook("created profile")
	CIRAHook := util.NewTestAssertHook("created CIRA config")
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook, profileHook, CIRAHook)}

	mpsMock.On("GetApiV1CiracertWithResponse", mock.Anything, mock.Anything).Return(&mps.GetApiV1CiracertResponse{
		Body: []byte(cert),
	}, nil)
	rpsMock.On("GetCIRAConfigWithResponse", mock.Anything, mock.Anything).Return(&rps.GetCIRAConfigResponse{
		JSON404: &rps.APIResponse{},
	}, nil)
	rpsMock.On("CreateCIRAConfigWithResponse",
		mock.Anything, mock.MatchedBy(func(request rps.CreateCIRAConfigJSONRequestBody) bool {
			return request.CommonName == "mps-node."+config.ClusterDomain &&
				request.MpsServerAddress == "mps-node."+config.ClusterDomain && *request.Password == config.AmtPassword
		})).Return(&rps.CreateCIRAConfigResponse{
		JSON201: &rps.CIRAConfigResponse{},
	}, nil)

	rpsMock.On("GetProfileWithResponse", mock.Anything, mock.Anything).Return(&rps.GetProfileResponse{
		JSON404: &rps.APIResponse{},
	}, nil)
	rpsMock.On("CreateProfileWithResponse", mock.Anything, mock.MatchedBy(func(request rps.CreateProfileJSONRequestBody) bool {
		return *request.AmtPassword == config.AmtPassword && *request.MebxPassword == config.AmtPassword
	})).Return(&rps.CreateProfileResponse{
		JSON201: &rps.ProfileResponse{},
	}, nil)

	dmr.handleTenantCreation("mock-tenant")

	assertHook.Assert(t)
	CIRAHook.Assert(t)
	profileHook.Assert(t)
}

func TestReconciler_handleTenantCreation_whenCannotGetCertShouldReturnError(t *testing.T) {
	mpsMock := new(mps.MockClientWithResponsesInterface)
	rpsMock := new(rps.MockClientWithResponsesInterface)
	dmr := &Reconciler{
		MpsClient: mpsMock,
		RpsClient: rpsMock,
	}

	assertHook := util.NewTestAssertHook("cannot get CIRA cert")
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	mpsMock.On("GetApiV1CiracertWithResponse", mock.Anything, mock.Anything).Return(&mps.GetApiV1CiracertResponse{
		Body: []byte(cert),
	}, fmt.Errorf("mocked error"))

	dmr.handleTenantCreation("mock-tenant")

	assertHook.Assert(t)
}

func TestReconciler_handleTenantCreation_whenCannotGetCIRAConfigShouldReturnError(t *testing.T) {
	mpsMock := new(mps.MockClientWithResponsesInterface)
	rpsMock := new(rps.MockClientWithResponsesInterface)
	dmr := &Reconciler{
		MpsClient: mpsMock,
		RpsClient: rpsMock,
	}

	assertHook := util.NewTestAssertHook("cannot get CIRA config ")
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	mpsMock.On("GetApiV1CiracertWithResponse", mock.Anything, mock.Anything).Return(&mps.GetApiV1CiracertResponse{
		Body: []byte(cert),
	}, nil)
	rpsMock.On("GetCIRAConfigWithResponse", mock.Anything, mock.Anything).Return(&rps.GetCIRAConfigResponse{
		JSON404: &rps.APIResponse{},
	}, fmt.Errorf("mocked error"))

	dmr.handleTenantCreation("mock-tenant")

	assertHook.Assert(t)
}

func TestReconciler_handleTenantCreation_whenCannotCreateCIRAConfigShouldReturnError(t *testing.T) {
	mpsMock := new(mps.MockClientWithResponsesInterface)
	rpsMock := new(rps.MockClientWithResponsesInterface)
	dmr := &Reconciler{
		MpsClient: mpsMock,
		RpsClient: rpsMock,
	}

	assertHook := util.NewTestAssertHook("cannot create CIRA config ")
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	mpsMock.On("GetApiV1CiracertWithResponse", mock.Anything, mock.Anything).Return(&mps.GetApiV1CiracertResponse{
		Body: []byte(cert),
	}, nil)
	rpsMock.On("GetCIRAConfigWithResponse", mock.Anything, mock.Anything).Return(&rps.GetCIRAConfigResponse{
		JSON404: &rps.APIResponse{},
	}, nil)
	rpsMock.On("CreateCIRAConfigWithResponse", mock.Anything, mock.Anything).Return(&rps.CreateCIRAConfigResponse{
		JSON201: &rps.CIRAConfigResponse{},
	}, fmt.Errorf("mocked error"))

	dmr.handleTenantCreation("mock-tenant")

	assertHook.Assert(t)
}

func TestReconciler_handleTenantCreation_whenCannotGetProfileShouldReturnError(t *testing.T) {
	mpsMock := new(mps.MockClientWithResponsesInterface)
	rpsMock := new(rps.MockClientWithResponsesInterface)
	dmr := &Reconciler{
		MpsClient: mpsMock,
		RpsClient: rpsMock,
	}

	assertHook := util.NewTestAssertHook("cannot get profile")
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	mpsMock.On("GetApiV1CiracertWithResponse", mock.Anything, mock.Anything).Return(&mps.GetApiV1CiracertResponse{
		Body: []byte(cert),
	}, nil)
	rpsMock.On("GetCIRAConfigWithResponse", mock.Anything, mock.Anything).Return(&rps.GetCIRAConfigResponse{
		JSON404: &rps.APIResponse{},
	}, nil)
	rpsMock.On("CreateCIRAConfigWithResponse", mock.Anything, mock.Anything).Return(&rps.CreateCIRAConfigResponse{
		JSON201: &rps.CIRAConfigResponse{},
	}, nil)

	rpsMock.On("GetProfileWithResponse", mock.Anything, mock.Anything).Return(&rps.GetProfileResponse{
		JSON404: &rps.APIResponse{},
	}, fmt.Errorf("mocked error"))

	dmr.handleTenantCreation("mock-tenant")

	assertHook.Assert(t)
}

func TestReconciler_handleTenantCreation_whenCannotCreateProfileShouldReturnError(t *testing.T) {
	mpsMock := new(mps.MockClientWithResponsesInterface)
	rpsMock := new(rps.MockClientWithResponsesInterface)
	dmr := &Reconciler{
		MpsClient: mpsMock,
		RpsClient: rpsMock,
	}

	assertHook := util.NewTestAssertHook("cannot create profile")
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	mpsMock.On("GetApiV1CiracertWithResponse", mock.Anything, mock.Anything).Return(&mps.GetApiV1CiracertResponse{
		Body: []byte(cert),
	}, nil)
	rpsMock.On("GetCIRAConfigWithResponse", mock.Anything, mock.Anything).Return(&rps.GetCIRAConfigResponse{
		JSON404: &rps.APIResponse{},
	}, nil)
	rpsMock.On("CreateCIRAConfigWithResponse", mock.Anything, mock.Anything).Return(&rps.CreateCIRAConfigResponse{
		JSON201: &rps.CIRAConfigResponse{},
	}, nil)

	rpsMock.On("GetProfileWithResponse", mock.Anything, mock.Anything).Return(&rps.GetProfileResponse{
		JSON404: &rps.APIResponse{},
	}, nil)
	rpsMock.On("CreateProfileWithResponse", mock.Anything, mock.Anything).Return(&rps.CreateProfileResponse{
		JSON201: &rps.ProfileResponse{},
	}, fmt.Errorf("mocked error"))

	dmr.handleTenantCreation("mock-tenant")

	assertHook.Assert(t)
}

func TestReconciler_handleTenantRemoval(t *testing.T) {
	mpsMock := new(mps.MockClientWithResponsesInterface)
	rpsMock := new(rps.MockClientWithResponsesInterface)
	dmr := &Reconciler{
		MpsClient: mpsMock,
		RpsClient: rpsMock,
		Config: &ReconcilerConfig{
			RequestTimeout: 10 * time.Second,
		},
	}

	rpsMock.On("RemoveProfileWithResponse", mock.Anything, mock.Anything).Return(&rps.RemoveProfileResponse{}, nil)
	rpsMock.On("RemoveCIRAConfigWithResponse", mock.Anything, mock.Anything).Return(&rps.RemoveCIRAConfigResponse{}, nil)
	assertHook := util.NewTestAssertHook("Finished tenant removal")
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook)}

	dmr.handleTenantRemoval("mock-tenant")

	assertHook.Assert(t)
}

func TestReconciler_whenFailedToRemoveShouldLogAndContinue(t *testing.T) {
	mpsMock := new(mps.MockClientWithResponsesInterface)
	rpsMock := new(rps.MockClientWithResponsesInterface)
	dmr := &Reconciler{
		MpsClient: mpsMock,
		RpsClient: rpsMock,
		Config: &ReconcilerConfig{
			RequestTimeout: 10 * time.Second,
		},
	}

	rpsMock.On("RemoveProfileWithResponse", mock.Anything, mock.Anything).
		Return(&rps.RemoveProfileResponse{}, fmt.Errorf("mock error"))
	rpsMock.On("RemoveCIRAConfigWithResponse", mock.Anything, mock.Anything).
		Return(&rps.RemoveCIRAConfigResponse{}, fmt.Errorf("mock error"))
	assertHook := util.NewTestAssertHook("Finished tenant removal")
	profileHook := util.NewTestAssertHook("cannot remove profile")
	CIRAHook := util.NewTestAssertHook("cannot remove CIRA")
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(assertHook, profileHook, CIRAHook)}

	dmr.handleTenantRemoval("mock-tenant")

	assertHook.Assert(t)
	CIRAHook.Assert(t)
	profileHook.Assert(t)
}

func Test_findExtraElements_whenLeftHasExtraElementThenItShouldBeDetected(t *testing.T) {
	left := []string{"a", "b", "c"}
	right := []string{"a", "b"}

	diff := findExtraElements(left, right)

	assert.Len(t, diff, 1)
	assert.Equal(t, diff[0], "c")
}

func Test_findExtraElements_whenRightHasExtraElementThenItShouldBeIgnored(t *testing.T) {
	left := []string{"a", "b"}
	right := []string{"a", "b", "c"}

	diff := findExtraElements(left, right)

	assert.Len(t, diff, 0)
}

func TestReconciler_ReconcileRemove_shouldRemoveExcessiveConfigs(t *testing.T) {
	mpsMock := new(mps.MockClientWithResponsesInterface)
	rpsMock := new(rps.MockClientWithResponsesInterface)
	profileHook := util.NewTestAssertHook("willBeRemoved profile doesn't has matching tenant ")
	CIRAHook := util.NewTestAssertHook("deleteMe CIRA config doesn't has matching tenant")
	log = logging.InfraLogger{Logger: zerolog.New(os.Stdout).Hook(profileHook, CIRAHook)}

	termChan := make(chan bool, 1)
	readyChan := make(chan bool, 1)
	wg := &sync.WaitGroup{}
	tmpDir := t.TempDir()
	inv_testing.StartTestingEnvironment(tmpDir, "", tmpDir)
	cli := inv_testing.TestClients[inv_testing.APIClient].GetTenantAwareInventoryClient()
	dmr := &Reconciler{
		InventoryClient: cli,
		TermChan:        termChan,
		ReadyChan:       readyChan,
		RpsClient:       rpsMock,
		MpsClient:       mpsMock,
		WaitGroup:       wg,
		Config: &ReconcilerConfig{
			RequestTimeout: time.Minute,
		},
	}

	tenantID := inv_testing.CreateTenant(t, inv_testing.TenantDesiredState(tenantv1.TenantState_TENANT_STATE_CREATED)).TenantId

	rpsMock.On("GetAllProfilesWithResponse", mock.Anything, mock.Anything).Return(&rps.GetAllProfilesResponse{
		JSON200: &[]rps.ProfileResponse{{ProfileName: "willBeRemoved"}, {ProfileName: tenantID}},
	}, nil)
	rpsMock.On("GetAllCIRAConfigsWithResponse", mock.Anything, mock.Anything).Return(&rps.GetAllCIRAConfigsResponse{
		JSON200: &[]rps.CIRAConfigResponse{{ConfigName: "deleteMe"}, {CommonName: tenantID}},
	}, nil)

	rpsMock.On("RemoveProfileWithResponse", mock.Anything, mock.Anything).Return(&rps.RemoveProfileResponse{}, nil)
	rpsMock.On("RemoveCIRAConfigWithResponse", mock.Anything, mock.Anything).Return(&rps.RemoveCIRAConfigResponse{}, nil)

	dmr.ReconcileRemove()

	profileHook.Assert(t)
	CIRAHook.Assert(t)
}
