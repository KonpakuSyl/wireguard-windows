/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// RuntimeDir is the directory for pid files and logs. WGCTL_RUNTIME_DIR
// overrides it; otherwise it is the directory containing the executable,
// so the program can be copied and run from anywhere.
func RuntimeDir() (string, error) {
	if d := os.Getenv("WGCTL_RUNTIME_DIR"); d != "" {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return "", err
		}
		return d, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(exe), nil
}

// LogFile returns the per-tunnel log next to the pid file.
func LogFile(tunnelName string) (string, error) {
	if !TunnelNameIsValid(tunnelName) {
		return "", errors.New("Tunnel name is not valid")
	}
	dir, err := RuntimeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, tunnelName+".log"), nil
}

// PidFile returns the pid file used to find a running tunnel.
func PidFile(tunnelName string) (string, error) {
	if !TunnelNameIsValid(tunnelName) {
		return "", errors.New("Tunnel name is not valid")
	}
	dir, err := RuntimeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, tunnelName+".pid"), nil
}

// NameFromPath returns the tunnel name from a *.conf path.
func NameFromPath(path string) (string, error) {
	name := filepath.Base(path)
	const suffix = ".conf"
	if len(name) <= len(suffix) || !strings.HasSuffix(strings.ToLower(name), suffix) {
		return "", errors.New("Path must end in .conf")
	}
	name = name[:len(name)-len(suffix)]
	if !TunnelNameIsValid(name) {
		return "", errors.New("Tunnel name is not valid")
	}
	return name, nil
}

// LoadFromPath reads a plaintext wg-quick configuration.
func LoadFromPath(path string) (*Config, error) {
	name, err := NameFromPath(path)
	if err != nil {
		return nil, err
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return FromWgQuickWithUnknownEncoding(string(bytes), name)
}
