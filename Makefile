BINARY ?= yscan
PREFIX ?= /usr/local
DESTDIR ?=
YSCAN_HOME ?= /opt/yscan
YSCAN_USER ?= yscan
YSCAN_GROUP ?= yscan
SYSTEMD_UNIT_DIR ?= /etc/systemd/system
TARGET_OS ?= linux
TARGET_ARCH ?= amd64
PLATFORM := $(TARGET_OS)-$(TARGET_ARCH)
LDFLAGS := -s -w

.PHONY: build test install uninstall release clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) .

test:
	go test -count=1 ./...
	go vet ./...

install: build
	install -d -m 0750 -o root -g "$(YSCAN_GROUP)" "$(DESTDIR)$(YSCAN_HOME)"
	install -m 0555 -o root -g root "$(BINARY)" "$(DESTDIR)$(YSCAN_HOME)/$(BINARY)"
	install -d -m 0750 -o "$(YSCAN_USER)" -g "$(YSCAN_GROUP)" \
		"$(DESTDIR)$(YSCAN_HOME)/data" "$(DESTDIR)$(YSCAN_HOME)/reports" \
		"$(DESTDIR)$(YSCAN_HOME)/logs" "$(DESTDIR)$(YSCAN_HOME)/run"
	@if [ ! -e "$(DESTDIR)$(YSCAN_HOME)/.env" ]; then \
		install -m 0600 -o "$(YSCAN_USER)" -g "$(YSCAN_GROUP)" /dev/null "$(DESTDIR)$(YSCAN_HOME)/.env"; \
	fi
	install -d -m 0755 "$(DESTDIR)$(SYSTEMD_UNIT_DIR)"
	install -m 0644 deploy/yscan.service "$(DESTDIR)$(SYSTEMD_UNIT_DIR)/yscan.service"

uninstall:
	-systemctl disable --now yscan.service
	rm -f "$(DESTDIR)$(SYSTEMD_UNIT_DIR)/yscan.service"
	-systemctl daemon-reload
	@echo "yscan unit removed; remove $(DESTDIR)$(YSCAN_HOME) explicitly after backing up data"

release:
	mkdir -p dist
	CGO_ENABLED=1 GOOS=$(TARGET_OS) GOARCH=$(TARGET_ARCH) go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-$(PLATFORM) .
	sha256sum dist/$(BINARY)-$(PLATFORM) > dist/SHA256SUMS

clean:
	rm -rf dist
	rm -f "$(BINARY)"
