BINARY ?= yscan
PREFIX ?= /usr/local
DESTDIR ?=
TARGET_OS ?= linux
TARGET_ARCH ?= amd64
PLATFORM := $(TARGET_OS)-$(TARGET_ARCH)
LDFLAGS := -s -w

.PHONY: build test install release clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) .

test:
	go test -count=1 ./...
	go vet ./...

install: build
	install -d "$(DESTDIR)$(PREFIX)/bin"
	install -m 0755 "$(BINARY)" "$(DESTDIR)$(PREFIX)/bin/$(BINARY)"

release:
	mkdir -p dist
	CGO_ENABLED=1 GOOS=$(TARGET_OS) GOARCH=$(TARGET_ARCH) go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-$(PLATFORM) .
	sha256sum dist/$(BINARY)-$(PLATFORM) > dist/SHA256SUMS

clean:
	rm -rf dist
	rm -f "$(BINARY)"
