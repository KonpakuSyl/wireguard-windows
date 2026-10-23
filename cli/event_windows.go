/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package cli

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/conf"
)

type stopEvent struct {
	handle windows.Handle
}

func eventName(tunnelName string) (string, error) {
	if !conf.TunnelNameIsValid(tunnelName) {
		return "", fmt.Errorf("tunnel name %q is not valid", tunnelName)
	}
	return "Global\\WireGuardTunnel-" + tunnelName, nil
}

func createStopEvent(tunnelName string) (*stopEvent, error) {
	name, err := eventName(tunnelName)
	if err != nil {
		return nil, err
	}
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	// SY and BA get full access. Everyone (WD) may only synchronize, so a
	// non-admin can wait but cannot signal the tunnel to stop.
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00100000;;;WD)")
	if err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}
	h, err := windows.CreateEvent(&sa, 1, 0, name16)
	if err != nil {
		return nil, err
	}
	return &stopEvent{handle: h}, nil
}

func signalStop(tunnelName string) error {
	name, err := eventName(tunnelName)
	if err != nil {
		return err
	}
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	h, err := windows.OpenEvent(windows.EVENT_MODIFY_STATE, false, name16)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.SetEvent(h)
}
