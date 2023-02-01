package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vouch/vouch-proxy/pkg/cfg"
)

func Test_listenUds(t *testing.T) {
	setUp(t, "testing/socket_basic.yml")
	defer cleanUp()
	tempDir, err := os.MkdirTemp("", "")
	assert.NoError(t, err)
	defer func() {
		_ = os.RemoveAll(tempDir)
	}()
	socketPath := filepath.Join(tempDir, "socket0")

	cfg.Cfg.Listen = strings.Join([]string{"unix", socketPath}, ":")
	lis, cleanupFn, err := listen()
	assert.NoError(t, err)
	assertSocket(t, socketPath)

	fi, err := os.Stat(socketPath)
	assert.NoError(t, err)
	assert.Equal(t, fs.FileMode(0660), fi.Mode().Perm())

	assert.NotNil(t, lis)
	assert.NoError(t, lis.Close())
	cleanupFn()
	_, err = os.Stat(socketPath)
	assert.True(t, os.IsNotExist(err))
}

// check that socket listening works when the socket path already exists
func Test_listenUds_alreadyExists(t *testing.T) {
	setUp(t, "testing/socket_basic.yml")
	defer cleanUp()
	tempDir, err := os.MkdirTemp("", "")
	assert.NoError(t, err)
	defer func() {
		_ = os.RemoveAll(tempDir)
	}()
	socketPath := filepath.Join(tempDir, "socket0")
	assert.NoError(t, os.WriteFile(socketPath, []byte("stuff in the socket file"), 0600))

	cfg.Cfg.Listen = strings.Join([]string{"unix", socketPath}, ":")
	lis, cleanupFn, err := listen()
	assert.NoError(t, err)
	assertSocket(t, socketPath)

	assert.NotNil(t, lis)
	assert.NoError(t, lis.Close())
	cleanupFn()
}

// check that the socket mode is adjusted when the SocketMode configuration is present
func Test_listenUds_mode(t *testing.T) {
	setUp(t, "config/testing/socket_mode.yml")
	defer cleanUp()
	tempDir, err := os.MkdirTemp("", "")
	assert.NoError(t, err)
	defer func() {
		_ = os.RemoveAll(tempDir)
	}()
	socketPath := filepath.Join(tempDir, "socket0")
	cfg.Cfg.Listen = strings.Join([]string{"unix", socketPath}, ":")

	lis, cleanupFn, err := listen()
	assert.NoError(t, err)
	assert.NotNil(t, lis)
	assertSocket(t, socketPath)

	stat, err := os.Stat(socketPath)
	assert.NoError(t, err)
	assert.Equal(t, fs.FileMode(cfg.Cfg.SocketMode), stat.Mode().Perm())

	assert.NoError(t, lis.Close())
	cleanupFn()
}

func assertSocket(t *testing.T, socketPath string) {
	fi, err := os.Stat(socketPath)
	assert.NoError(t, err)
	assert.Equal(t, os.ModeSocket, fi.Mode()&os.ModeSocket)
}

func setUp(t *testing.T, configFile string) {
	assert.NoError(t, os.Setenv(cfg.Branding.UCName+"_CONFIG", configFile))
	cfg.InitForTestPurposes()
}

func cleanUp() {
	os.Clearenv()
}
