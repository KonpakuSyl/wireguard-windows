/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package cli

import (
	"os"
	"os/signal"

	"golang.org/x/sys/windows"
)

func waitConsoleClose(done chan struct{}) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, windows.SIGTERM)
	go func() {
		<-ch
		close(done)
	}()
}
