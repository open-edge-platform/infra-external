/*
 * // SPDX-FileCopyrightText: (C) 2025 Intel Corporation
 * // SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_getMpsAddress_happyPath(t *testing.T) {
	tmpFile, err := os.CreateTemp("/tmp", "")
	assert.NoError(t, err)

	_, err = fmt.Fprintf(tmpFile, `%v: test:1234`, orchMpsHostKey)
	assert.NoError(t, err)

	address, port := getMpsAddress(tmpFile.Name())

	assert.Equal(t, "test", address)
	assert.Equal(t, int32(1234), port)
}
