# WireGuard Windows CLI (portable)

A portable command-line WireGuard client for Windows, cut down from the official [WireGuard for Windows](https://www.wireguard.com/) client. There is no installer, no system-tray UI, no manager service, and no auto-updater. Copy one directory and run it.

The tunnel itself is still WireGuardNT: creating the adapter, routes, DNS, and the kill-switch firewall requires an elevated administrator. Portable means nothing is installed, not that a normal user can bring a tunnel up.

## Layout

```text
wgctl.exe
wireguard.dll
```

`wireguard.dll` must sit next to `wgctl.exe`. The build copies the official WireGuardNT build into that directory. Pid files (`<name>.pid`) and logs (`<name>.log`) are written next to the executable, unless `WGCTL_RUNTIME_DIR` is set.

## Commands

```text
wgctl up [-f] CONFIG.conf      bring the tunnel up and block until Ctrl+C
wgctl down CONFIG.conf|NAME    ask that tunnel process to shut down
wgctl show [NAME]              handshake, transfer, and endpoint of running tunnels
wgctl genkey                   print a new private key
wgctl pubkey                   read a private key on stdin, print its public key
```

`up` stays in the foreground so closing the console or pressing Ctrl+C tears the adapter down. `up -f` starts that same process in the background and returns immediately. `down` signals it through a named event (`Global\WireGuardTunnel-<name>`) and waits until it exits. A second `up` of the same tunnel name fails while the first pid is still alive.

Configurations are ordinary plaintext `wg-quick(8)` files. The tunnel name is the file name without `.conf`, and must match `^[A-Za-z0-9_=+.-]{1,32}$`. PreUp/PostUp/PreDown/PostDown still run only when `HKLM\Software\WireGuard\DangerousScriptExecution` is set; they are skipped otherwise.

## Build

From Linux or macOS, with Go and `bsdtar`:

```text
make
```

This downloads the pinned WireGuardNT zip, checks its SHA-256, and writes `amd64/`, `x86/`, and `arm64/`, each containing `wgctl.exe` and `wireguard.dll`.

## What was removed

The tray UI, MSI installer, manager service, auto-updater, DPAPI configuration store under `%ProgramFiles%\WireGuard`, and the localization catalogs are gone. A tunnel is one process, not a Windows service, because `StartServiceCtrlDispatcher` only succeeds for processes the Service Control Manager started.

## License

MIT. Copyright (C) 2018-2026 WireGuard LLC. All Rights Reserved. See [COPYING](COPYING).
