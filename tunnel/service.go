/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/elevate"
	"golang.zx2c4.com/wireguard/windows/services"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// RunForeground brings the tunnel in confPath up and blocks until stop is
// closed, then tears the adapter, routes, DNS and firewall back down.
// stop is typically closed by Ctrl+C or by another process signaling the
// tunnel's named stop event. This replaces the Windows service control loop:
// StartServiceCtrlDispatcher only succeeds when the process was started by
// the Service Control Manager.
func RunForeground(confPath string, stop <-chan struct{}) error {
	var watcher *interfaceWatcher
	var adapter *driver.Adapter
	var luid winipcfg.LUID
	var config *conf.Config
	var err error
	serviceError := services.ErrorSuccess

	defer func() {
		stopIt := make(chan bool, 1)
		go func() {
			t := time.NewTicker(time.Second * 30)
			defer t.Stop()
			select {
			case <-t.C:
				buf := make([]byte, 1024)
				for {
					n := runtime.Stack(buf, true)
					if n < len(buf) {
						buf = buf[:n]
						break
					}
					buf = make([]byte, 2*len(buf))
				}
				lines := bytes.Split(buf, []byte{'\n'})
				log.Println("Failed to shutdown after 30 seconds. Probably dead locked. Printing stack and killing.")
				for _, line := range lines {
					if len(bytes.TrimSpace(line)) > 0 {
						log.Println(string(line))
					}
				}
				os.Exit(777)
			case <-stopIt:
				return
			}
		}()

		if err == nil && serviceError == services.ErrorSuccess && adapter != nil && config != nil {
			if scriptErr := runScriptCommand(config.Interface.PreDown, config.Name); scriptErr != nil {
				log.Printf("PreDown: %v", scriptErr)
			}
		}
		if watcher != nil {
			watcher.Destroy()
		}
		if adapter != nil {
			adapter.Close()
		}
		if err == nil && serviceError == services.ErrorSuccess && adapter != nil && config != nil {
			if scriptErr := runScriptCommand(config.Interface.PostDown, config.Name); scriptErr != nil {
				log.Printf("PostDown: %v", scriptErr)
			}
		}
		stopIt <- true
		log.Println("Shutting down")
	}()

	config, err = conf.LoadFromPath(confPath)
	if err != nil {
		serviceError = services.ErrorLoadConfiguration
		return services.CombineErrors(err, serviceError)
	}
	config.DeduplicateNetworkEntries()

	log.SetPrefix(fmt.Sprintf("[%s] ", config.Name))
	log.Printf("Starting %s", "WireGuard tunnel")

	evaluateStaticPitfalls()

	log.Println("Watching network interfaces")
	watcher, err = watchInterface()
	if err != nil {
		serviceError = services.ErrorSetNetConfig
		return services.CombineErrors(err, serviceError)
	}

	log.Println("Resolving DNS names")
	err = config.ResolveEndpoints()
	if err != nil {
		serviceError = services.ErrorDNSLookup
		return services.CombineErrors(err, serviceError)
	}

	log.Println("Creating network adapter")
	adapter, err = driver.CreateAdapter(config.Name, "WireGuard", deterministicGUID(config))
	if err != nil {
		err = fmt.Errorf("Error creating adapter: %w", err)
		serviceError = services.ErrorCreateNetworkAdapter
		return services.CombineErrors(err, serviceError)
	}
	luid = adapter.LUID()
	driverVersion, derr := driver.RunningVersion()
	if derr != nil {
		log.Printf("Warning: unable to determine driver version: %v", derr)
	} else {
		log.Printf("Using WireGuardNT/%d.%d", (driverVersion>>16)&0xffff, driverVersion&0xffff)
	}
	err = adapter.SetLogging(driver.AdapterLogOn)
	if err != nil {
		err = fmt.Errorf("Error enabling adapter logging: %w", err)
		serviceError = services.ErrorCreateNetworkAdapter
		return services.CombineErrors(err, serviceError)
	}

	err = runScriptCommand(config.Interface.PreUp, config.Name)
	if err != nil {
		serviceError = services.ErrorRunScript
		return services.CombineErrors(err, serviceError)
	}

	err = enableFirewall(config, luid)
	if err != nil {
		serviceError = services.ErrorFirewall
		return services.CombineErrors(err, serviceError)
	}

	log.Println("Dropping privileges")
	err = elevate.DropAllPrivileges(true)
	if err != nil {
		serviceError = services.ErrorDropPrivileges
		return services.CombineErrors(err, serviceError)
	}

	log.Println("Setting interface configuration")
	driverConfig, driverConfigSize := config.ToDriverConfiguration()
	err = adapter.SetConfiguration(driverConfig, driverConfigSize)
	if err != nil {
		serviceError = services.ErrorDeviceSetConfig
		return services.CombineErrors(err, serviceError)
	}
	err = adapter.SetAdapterState(driver.AdapterStateUp)
	if err != nil {
		serviceError = services.ErrorDeviceBringUp
		return services.CombineErrors(err, serviceError)
	}
	watcher.Configure(adapter, config, luid)

	err = runScriptCommand(config.Interface.PostUp, config.Name)
	if err != nil {
		serviceError = services.ErrorRunScript
		return services.CombineErrors(err, serviceError)
	}

	var started bool
	for {
		select {
		case <-stop:
			return nil
		case family := <-watcher.started:
			if !started {
				log.Printf("Startup complete (%v)", family)
				started = true
			}
		case e := <-watcher.errors:
			serviceError, err = e.serviceError, e.err
			return services.CombineErrors(err, serviceError)
		}
	}
}
