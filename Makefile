ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
VERSION=$(shell cat $(ROOT_DIR)/version/current_version)
VERSION_MAJOR=$(shell echo $(VERSION) | cut -c2)
VERSION_MINOR=$(shell echo $(VERSION) | cut -c4)
VERSION_MICRO=$(shell echo $(VERSION) | cut -c6)
CLIB_HEADER=fasttls.h
CLIB_PKG_CONFIG=fasttls.pc
PREFIX ?= /usr/local
CC='gcc'
CXX='g++'

OS_NAME := $(shell uname -s | tr A-Z a-z)

CPU_BITS = $(shell getconf LONG_BIT)
ifeq ($(CPU_BITS), 32)
    LIBDIR ?= $(PREFIX)/lib
else
    LIBDIR ?= $(PREFIX)/lib$(CPU_BITS)
endif

INCLUDE_DIR ?= $(PREFIX)/include
PKG_CONFIG_LIBDIR ?= $(LIBDIR)/pkgconfig
MAN_DIR ?= $(PREFIX)/share/man

all: headers build

headers: $(CLIB_HEADER) $(CLIB_PKG_CONFIG)

.PHONY: build
build:
	cargo build --release

.PHONY: benchmark
benchmark: headers build benchmark_go

.PHONY: benchmark_rustls
benchmark_rustls: headers build
	go test -run='^$$' -bench=. -tags=rustls

.PHONY: benchmark_go
benchmark_go:
	go test -run='^$$' -bench=.

.PHONY: benchmark_go_verbose
benchmark_go_verbose:
	go test -run='^$$' -bench=. -v

.PHONY: test
test: headers build test_rust test_go

.PHONY: test_verbose
test_verbose: headers build test_rust_verbose test_go_verbose

.PHONY: test_rust
test_rust:
	cargo test

.PHONY: test_rust_verbose
test_rust_verbose:
	cargo test -- --nocapture

.PHONY: test_go
test_go:
	go test ./...

.PHONY: test_go_verbose
test_go_verbose:
	go test ./... -v

.PHONY: $(CLIB_HEADER)
$(CLIB_HEADER): $(CLIB_HEADER).in
	cp $(CLIB_HEADER).in $(CLIB_HEADER)
	sed -i -e 's/@_VERSION_MAJOR@/$(VERSION_MAJOR)/' \
		$(CLIB_HEADER)
	sed -i -e 's/@_VERSION_MINOR@/$(VERSION_MINOR)/' \
		$(CLIB_HEADER)
	sed -i -e 's/@_VERSION_MICRO@/$(VERSION_MICRO)/' \
		$(CLIB_HEADER)

.PHONY: $(CLIB_PKG_CONFIG)
$(CLIB_PKG_CONFIG): $(CLIB_PKG_CONFIG).in
	cp $(CLIB_PKG_CONFIG).in $(CLIB_PKG_CONFIG)
	sed -i -e 's|@_VERSION_MAJOR@|$(VERSION_MAJOR)|' $(CLIB_PKG_CONFIG)
	sed -i -e 's|@_VERSION_MINOR@|$(VERSION_MINOR)|' $(CLIB_PKG_CONFIG)
	sed -i -e 's|@_VERSION_MICRO@|$(VERSION_MICRO)|' $(CLIB_PKG_CONFIG)
	sed -i -e 's|@PREFIX@|$(PREFIX)|' $(CLIB_PKG_CONFIG)
	sed -i -e 's|@LIBDIR@|$(LIBDIR)|' $(CLIB_PKG_CONFIG)
	sed -i -e 's|@INCLUDE_DIR@|$(INCLUDE_DIR)|' $(CLIB_PKG_CONFIG)