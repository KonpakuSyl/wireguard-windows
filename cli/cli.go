/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package cli

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/elevate"
	"golang.zx2c4.com/wireguard/windows/tunnel"
)

const usageText = `wgctl — portable WireGuard tunnel for Windows

Usage:
  wgctl up [-f] CONFIG.conf     bring the tunnel up; -f returns after forking
  wgctl down CONFIG.conf|NAME   ask a running tunnel to shut down
  wgctl show [NAME]             show running tunnel(s)
  wgctl genkey                  print a new private key
  wgctl pubkey                  print the public key of a private key on stdin

The process must be an elevated administrator. wireguard.dll must sit next
to wgctl.exe. Pid files and logs are written to the executable directory,
or to WGCTL_RUNTIME_DIR when that is set.
`

func Main(args []string) int {
	if len(args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		return 2
	}
	switch args[1] {
	case "genkey":
		return genkey(args[2:])
	case "pubkey":
		return pubkey(args[2:])
	case "up":
		return up(args[2:])
	case "down":
		return down(args[2:])
	case "show":
		return show(args[2:])
	case "-h", "--help", "help":
		fmt.Fprint(os.Stdout, usageText)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", args[1], usageText)
		return 2
	}
}

func requireElevated() int {
	if elevate.IsElevated() {
		return 0
	}
	fmt.Fprintln(os.Stderr, "wgctl must be run from an elevated administrator console")
	return 1
}

func genkey(args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "usage: wgctl genkey")
		return 2
	}
	fmt.Println(conf.NewPrivateKey().String())
	return 0
}

func pubkey(args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "usage: wgctl pubkey")
		return 2
	}
	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read stdin: %v\n", err)
		return 1
	}
	key, err := conf.NewPrivateKeyFromString(strings.TrimSpace(string(in)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid private key: %v\n", err)
		return 1
	}
	fmt.Println(key.Public().String())
	return 0
}

func up(args []string) int {
	foregroundFork := false
	rest := args
	if len(rest) > 0 && rest[0] == "-f" {
		foregroundFork = true
		rest = rest[1:]
	}
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "usage: wgctl up [-f] CONFIG.conf")
		return 2
	}
	if code := requireElevated(); code != 0 {
		return code
	}
	confPath, err := filepath.Abs(rest[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "config path: %v\n", err)
		return 1
	}
	name, err := conf.NameFromPath(confPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	if _, err := conf.LoadFromPath(confPath); err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		return 1
	}
	pidPath, err := conf.PidFile(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	if existing, ok := readLivePid(pidPath); ok {
		fmt.Fprintf(os.Stderr, "tunnel %s is already running as pid %d\n", name, existing)
		return 1
	}
	if foregroundFork {
		return forkUp(confPath)
	}
	return runUp(name, confPath, pidPath)
}

func forkUp(confPath string) int {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "executable: %v\n", err)
		return 1
	}
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fork: %v\n", err)
		return 1
	}
	defer devNull.Close()
	proc, err := os.StartProcess(exe, []string{exe, "up", confPath}, &os.ProcAttr{
		Dir: filepath.Dir(exe),
		Env: os.Environ(),
		Sys: &syscall.SysProcAttr{
			HideWindow:    true,
			CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS,
		},
		Files: []*os.File{devNull, devNull, devNull},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "fork: %v\n", err)
		return 1
	}
	pid := proc.Pid
	_ = proc.Release()
	name, err := conf.NameFromPath(confPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	pidPath, err := conf.PidFile(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if got, ok := readLivePid(pidPath); ok && got == pid {
			fmt.Printf("started %s (pid %d)\n", name, pid)
			return 0
		}
		if !processAlive(pid) {
			fmt.Fprintf(os.Stderr, "tunnel %s exited before it was ready; see %s.log\n", name, name)
			return 1
		}
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Fprintf(os.Stderr, "tunnel %s did not become ready\n", name)
	return 1
}

func runUp(name, confPath, pidPath string) int {
	logPath, err := conf.LogFile(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "log: %v\n", err)
		return 1
	}
	defer logFile.Close()
	log.SetOutput(io.MultiWriter(os.Stderr, logFile))
	log.SetFlags(log.LstdFlags)
	fmt.Fprintf(os.Stderr, "logging to %s\n", logPath)

	stop, err := createStopEvent(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stop event: %v\n", err)
		return 1
	}
	defer windows.CloseHandle(stop.handle)

	pidFile, err := os.OpenFile(pidPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pid file: %v\n", err)
		return 1
	}
	if _, err := fmt.Fprintf(pidFile, "%d\n%s\n", os.Getpid(), confPath); err != nil {
		pidFile.Close()
		os.Remove(pidPath)
		fmt.Fprintf(os.Stderr, "pid file: %v\n", err)
		return 1
	}
	pidFile.Close()
	defer os.Remove(pidPath)

	stopped := make(chan struct{})
	go func() {
		windows.WaitForSingleObject(stop.handle, windows.INFINITE)
		close(stopped)
	}()
	ctrl := make(chan struct{})
	waitConsoleClose(ctrl)
	stopCh := make(chan struct{})
	go func() {
		select {
		case <-stopped:
		case <-ctrl:
		}
		close(stopCh)
	}()

	if err := tunnel.RunForeground(confPath, stopCh); err != nil {
		fmt.Fprintf(os.Stderr, "tunnel: %v\n", err)
		return 1
	}
	return 0
}

func down(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: wgctl down CONFIG.conf|NAME")
		return 2
	}
	if code := requireElevated(); code != 0 {
		return code
	}
	name, pidPath, err := resolveName(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	pid, ok := readLivePid(pidPath)
	if !ok {
		if _, statErr := os.Stat(pidPath); statErr == nil {
			os.Remove(pidPath)
		}
		fmt.Fprintf(os.Stderr, "tunnel %s is not running\n", name)
		return 1
	}
	if err := signalStop(name); err != nil {
		fmt.Fprintf(os.Stderr, "signal: %v\n", err)
		return 1
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			os.Remove(pidPath)
			fmt.Printf("stopped %s\n", name)
			return 0
		}
		time.Sleep(200 * time.Millisecond)
	}
	fmt.Fprintf(os.Stderr, "tunnel %s (pid %d) did not exit\n", name, pid)
	return 1
}

func show(args []string) int {
	if len(args) > 1 {
		fmt.Fprintln(os.Stderr, "usage: wgctl show [NAME]")
		return 2
	}
	if code := requireElevated(); code != 0 {
		return code
	}
	var names []string
	if len(args) == 1 {
		name, _, err := resolveName(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return 1
		}
		names = []string{name}
	} else {
		var err error
		names, err = runningNames()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return 1
		}
	}
	if len(names) == 0 {
		fmt.Println("no running tunnels")
		return 0
	}
	for _, name := range names {
		if err := printTunnel(name); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
			return 1
		}
	}
	return 0
}

func printTunnel(name string) error {
	pidPath, err := conf.PidFile(name)
	if err != nil {
		return err
	}
	pid, lines, err := readPidFile(pidPath)
	if err != nil {
		return fmt.Errorf("not running")
	}
	adapter, err := driver.OpenAdapter(name)
	if err != nil {
		return err
	}
	defer adapter.Close()
	stored := &conf.Config{Name: name}
	if len(lines) >= 2 {
		if c, err := conf.LoadFromPath(lines[1]); err == nil {
			stored = c
		}
	}
	runtimeConfig, err := adapter.Configuration()
	if err != nil {
		return err
	}
	cfg := conf.FromDriverConfiguration(runtimeConfig, stored)
	fmt.Printf("interface: %s\n", name)
	fmt.Printf("  pid: %d\n", pid)
	if cfg.Interface.ListenPort != 0 {
		fmt.Printf("  listening port: %d\n", cfg.Interface.ListenPort)
	}
	if pub := cfg.Interface.PrivateKey.Public(); pub != nil && !cfg.Interface.PrivateKey.IsZero() {
		fmt.Printf("  public key: %s\n", pub.String())
	}
	for _, peer := range cfg.Peers {
		fmt.Printf("peer: %s\n", peer.PublicKey.String())
		if !peer.Endpoint.IsEmpty() {
			fmt.Printf("  endpoint: %s\n", peer.Endpoint.String())
		}
		if len(peer.AllowedIPs) > 0 {
			parts := make([]string, len(peer.AllowedIPs))
			for i, a := range peer.AllowedIPs {
				parts[i] = a.String()
			}
			fmt.Printf("  allowed ips: %s\n", strings.Join(parts, ", "))
		}
		if !peer.LastHandshakeTime.IsEmpty() {
			fmt.Printf("  latest handshake: %s\n", peer.LastHandshakeTime.String())
		}
		fmt.Printf("  transfer: %s received, %s sent\n", peer.RxBytes.String(), peer.TxBytes.String())
	}
	return nil
}

func resolveName(arg string) (name, pidPath string, err error) {
	if strings.HasSuffix(strings.ToLower(arg), ".conf") {
		name, err = conf.NameFromPath(arg)
	} else {
		name = arg
		if !conf.TunnelNameIsValid(name) {
			err = fmt.Errorf("tunnel name %q is not valid", name)
		}
	}
	if err != nil {
		return "", "", err
	}
	pidPath, err = conf.PidFile(name)
	return name, pidPath, err
}

func runningNames() ([]string, error) {
	dir, err := conf.RuntimeDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pid") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".pid")
		if _, ok := readLivePid(filepath.Join(dir, e.Name())); ok {
			names = append(names, name)
		}
	}
	return names, nil
}

func readPidFile(path string) (int, []string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, nil, err
	}
	lines := strings.Split(strings.TrimRight(string(b), "\r\n"), "\n")
	if len(lines) < 1 {
		return 0, nil, fmt.Errorf("empty pid file")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(lines[0]))
	if err != nil || pid <= 0 {
		return 0, nil, fmt.Errorf("bad pid file")
	}
	return pid, lines, nil
}

func readLivePid(path string) (int, bool) {
	pid, _, err := readPidFile(path)
	if err != nil || !processAlive(pid) {
		return 0, false
	}
	return pid, true
}

func processAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	const stillActive = 259 // STILL_ACTIVE
	return code == stillActive
}
