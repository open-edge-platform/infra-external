// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

package dm

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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

func Test_convertCertToCertBlob(t *testing.T) {
	newCert := convertCertToCertBlob([]byte(cert))
	//nolint:lll // intended long certificate blob
	expectedCert := `MIIEOzCCAqOgAwIBAgIDBzkQMA0GCSqGSIb3DQEBDAUAMD0xFzAVBgNVBAMTDk1QU1Jvb3QtZDdmMDg0MRAwDgYDVQQKEwd1bmtub3duMRAwDgYDVQQGEwd1bmtub3duMCAXDTI0MDUyMDEyMjQxNVoYDzIwNTUwNTIwMTIyNDE1WjA9MRcwFQYDVQQDEw5NUFNSb290LWQ3ZjA4NDEQMA4GA1UEChMHdW5rbm93bjEQMA4GA1UEBhMHdW5rbm93bjCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBANJirZbxnlCYTsuLPzFXeLXH92EF/9TO8ClA7PaPcZP0lkxCwpuRNBa5iGXvawirf2wf6Pv+nntNNNQGvvqUt1RrpVrC78yiTTTx/LJOTVkaAq+9Gm3LlJWJnXx8QMV3BJRPNO+eEOpNy1XePuWU1CpYHAYyW77sccNDvh4f8SVOzMQZW+tIE93BBLBv5k8auL8CSDw6E+oxg5RzQE2Fv5lFw7fLUCKPLSOhWNq9g00ZY//aq40C5Jh8rZY7PPEHrZe37WDnlnhBckSE+3Px68bRt94ut6oKigVwaaYLDyt6s36DsYB0CTIlOotKe011j741jViMHG/H56r8wRCAb+GybWEK51iC+J1esO68wmC8a/oduh4tCBErdx9q63LbOkF15OLAbCO9uYRrl7KJODP+TpUvg0JxPGFBbZ2k1SB/2K7KX5frXRlKdext4zjrjx4vOiL1f6kgfyD96xT/EL4JfkLkRDxnEwd/Twu4vaMQgpERoLYPdUTLC5c+FrSBeQIDAQABo0IwQDAMBgNVHRMEBTADAQH/MBEGCWCGSAGG+EIBAQQEAwIABzAdBgNVHQ4EFgQU1/CEBHJ3fPlDz8xxbEN7AjR1T84wDQYJKoZIhvcNAQEMBQADggGBALCD+mQF+GplYOEVNEcUzi8WGZBmT7JahopGAubbeZmDGF/Hf+o2QCdPc0J6sRiJq+rOKINGLsptrDOdXYnXK7gf/s07USPDYCQbrG0kWZqvGCFMbv9Ailo1YFol+XpElrehiJXg3T++6ZIqxX2kJSw6dsLMoNGb209A7NUnLHC/H8KKjLsbNk4NgH6ixvCfwpccPL//nLgip055BTPZ4KdcxZ5/tFq+YTUHrE5H60MmmVcZYGA6bXtix6ExkPcxLW1zg+Nnk5Iu5zQgrlaiXl+4kG5JqmC1w2MGhcW5G2d/+QewXKDeOceksJ1HufqkHdgyBkb7/jVqu8m0m4w4MPpE39bdymkNrjwwiPZZpiOjzCscb0b35gvVS01SYzCl1kuUMtz2jw7aS2Xa805PLha1n+5/ioHqgXYVvZzf6DL1GxnlZzwKA0fVFBohruTNbm5jCIxUlQCs/ym24bIq8Nvjm2HouES4kKp8wWl7NWZ6gFZAkVOSzmyXmuG+1Vzerg==`
	assert.Equal(t, expectedCert, newCert)
}

func TestNewReconcilerID(t *testing.T) {
	reconcilerID := NewReconcilerID(true, "tenant123")
	assert.Equal(t, "tenant123:true", reconcilerID.String())
	assert.Equal(t, "tenant123", reconcilerID.GetTenantID())
	assert.True(t, reconcilerID.isCreate())

	reconcilerID = NewReconcilerID(false, "zxc")
	assert.Equal(t, "zxc:false", reconcilerID.String())
	assert.Equal(t, "zxc", reconcilerID.GetTenantID())
	assert.False(t, reconcilerID.isCreate())

	reconcilerID = NewReconcilerID(false, "")
	assert.Equal(t, ":false", reconcilerID.String())
	assert.Equal(t, "", reconcilerID.GetTenantID())
	assert.False(t, reconcilerID.isCreate())
}
