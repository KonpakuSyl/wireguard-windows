/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/windows/conf"
)

func TestGenkeyAndPubkey(t *testing.T) {
	out := capture(t, func() int { return Main([]string{"wgctl", "genkey"}) })
	key := strings.TrimSpace(out)
	if _, err := conf.NewPrivateKeyFromString(key); err != nil {
		t.Fatalf("genkey produced invalid key %q: %v", key, err)
	}

	old := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(key + "\n")); err != nil {
		t.Fatal(err)
	}
	w.Close()
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old })

	pub := strings.TrimSpace(capture(t, func() int { return Main([]string{"wgctl", "pubkey"}) }))
	parsed, err := conf.NewPrivateKeyFromString(key)
	if err != nil {
		t.Fatal(err)
	}
	if pub != parsed.Public().String() {
		t.Fatalf("pubkey %q != %q", pub, parsed.Public().String())
	}
}

func TestUsage(t *testing.T) {
	if code := Main([]string{"wgctl"}); code != 2 {
		t.Fatalf("no args code = %d", code)
	}
	if code := Main([]string{"wgctl", "nope"}); code != 2 {
		t.Fatalf("unknown code = %d", code)
	}
	if code := Main([]string{"wgctl", "help"}); code != 0 {
		t.Fatalf("help code = %d", code)
	}
}

func TestResolveName(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WGCTL_RUNTIME_DIR", dir)
	name, pidPath, err := resolveName("office.conf")
	if err != nil {
		t.Fatal(err)
	}
	if name != "office" {
		t.Fatalf("name = %q", name)
	}
	want, err := conf.PidFile("office")
	if err != nil {
		t.Fatal(err)
	}
	if pidPath != want || filepath.Dir(pidPath) != dir {
		t.Fatalf("pid path %q, want %q", pidPath, want)
	}
	if _, _, err := resolveName("bad name"); err == nil {
		t.Fatal("expected invalid tunnel name")
	}
	if _, err := eventName("office"); err != nil {
		t.Fatal(err)
	}
	if _, err := eventName("../x"); err == nil {
		t.Fatal("expected invalid event name")
	}
}

func TestReadLivePidIgnoresDead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "office.pid")
	if err := os.WriteFile(path, []byte("1\nC:\\office.conf\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pid, lines, err := readPidFile(path)
	if err != nil || pid != 1 || len(lines) != 2 {
		t.Fatalf("pid=%d lines=%v err=%v", pid, lines, err)
	}
}

func capture(t *testing.T, fn func() int) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	code := fn()
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("exit %d, output %q", code, buf.String())
	}
	return buf.String()
}
