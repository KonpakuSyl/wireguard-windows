/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"os"

	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/windows/cli"
)

func main() {
	// LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32
	const applicationDir = 0x00000200
	if windows.SetDllDirectory("") != nil || windows.SetDefaultDllDirectories(windows.LOAD_LIBRARY_SEARCH_SYSTEM32|applicationDir) != nil {
		panic("failed to restrict dll search path")
	}
	os.Exit(cli.Main(os.Args))
}
