GOOS := windows
export GOOS
export PATH := $(CURDIR)/.deps/go/bin:$(PATH)

GOFLAGS := -trimpath -buildvcs=false -ldflags="-s -w"

rwildcard=$(foreach d,$(filter-out .deps,$(wildcard $1*)),$(call rwildcard,$d/,$2) $(filter $(subst *,%,$2),$d))
SOURCE_FILES := $(call rwildcard,,*.go) go.mod go.sum

all: amd64/wgctl.exe x86/wgctl.exe arm64/wgctl.exe

define download =
.distfiles/$(1):
	mkdir -p .distfiles
	if ! curl -L#o $$@.unverified $(2); then rm -f $$@.unverified; exit 1; fi
	if ! echo "$(3)  $$@.unverified" | sha256sum -c; then rm -f $$@.unverified; exit 1; fi
	if ! mv $$@.unverified $$@; then rm -f $$@.unverified; exit 1; fi
endef

$(eval $(call download,wireguard-nt.zip,https://download.wireguard.com/wireguard-nt/wireguard-nt-1.1.zip,dceb30a9bc4be48cce0f74160fc88a585a2c2627366e8f846fc6658f9038dace))

.deps/wireguard-nt/prepared: .distfiles/wireguard-nt.zip
	mkdir -p .deps
	rm -rf .deps/wireguard-nt
	bsdtar -C .deps -xf .distfiles/wireguard-nt.zip
	touch $$@

amd64/wgctl.exe: export GOARCH := amd64
amd64/wgctl.exe: $(SOURCE_FILES) .deps/wireguard-nt/prepared
	go build $(GOFLAGS) -o $$@
	cp .deps/wireguard-nt/bin/amd64/wireguard.dll amd64/

x86/wgctl.exe: export GOARCH := 386
x86/wgctl.exe: $(SOURCE_FILES) .deps/wireguard-nt/prepared
	go build $(GOFLAGS) -o $$@
	cp .deps/wireguard-nt/bin/x86/wireguard.dll x86/

arm64/wgctl.exe: export GOARCH := arm64
arm64/wgctl.exe: $(SOURCE_FILES) .deps/wireguard-nt/prepared
	go build $(GOFLAGS) -o $$@
	cp .deps/wireguard-nt/bin/arm64/wireguard.dll arm64/

fmt:
	go fmt ./...

clean:
	rm -rf x86/ amd64/ arm64/ .deps

distclean: clean
	rm -rf .distfiles

.PHONY: all clean distclean fmt
