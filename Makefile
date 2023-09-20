.ONESHELL:
SHELL = /bin/bash

ARCH=$(shell uname -m)

CC = clang
GO = /usr/local/go/bin/go
MAKE=/usr/bin/make

MAIN = task

TAG ?= latest
BASE_TAG ?= latest
DEBUG ?= 1

BUILD_DIR = build
TARGET_CLI_STATIC := $(BUILD_DIR)/$(MAIN)-cli-static
TARGET_CLI_DYN := $(BUILD_DIR)/$(MAIN)-cli-dynamic
TARGET_K8S_STATIC := $(BUILD_DIR)/$(MAIN)-k8s-static
TARGET_K8S_DYN := $(BUILD_DIR)/$(MAIN)-k8s-dynamic
TARGET_BPF := $(BUILD_DIR)/$(MAIN).bpf.o

# $make in libbpf/src will create libbpf.a, libbpf.so
PRJ_DIR := $(shell pwd)
LIBBPF_DIR ?= $(PRJ_DIR)/libbpf/src
LIBBPF_STATIC_LIB = $(LIBBPF_DIR)/libbpf.a
LIBBPF_INCLUDES = $(LIBBPF_DIR)
LIBBPF_DYN_LIB_PATH = $(LIBBPF_DIR)
LIBBPF_DYN_LIB = $(LIBBPF_DIR)/libbpf.so

CMD_CLI_GO_SRC := ./cmd/cli/*.go
CMD_K8S_GO_SRC := ./cmd/kubernetes/*.go
BPF_SRC := $(wildcard ./kernel/*.c)
BPF_HEADERS := $(wildcard ./kernel/*.h)


CFLAGS = -g -O2 -Wall -fpie
LDFLAGS = $(LDFLAGS)

CGO_CFLAGS = "-I$(abspath $(LIBBPF_INCLUDES))"
#CGO_LDFLAGS_STATIC = "-lelf -lz $(LIBBPF_STATIC_LIB)"
GO_EXTLDFLAGS_STATIC = '-w -extldflags "-static $(LIBBPF_STATIC_LIB) -lelf -lz"'
GO_EXTLDFLAGS_DYN = '-extldflags "-lelf -lz  -Wl,-rpath=$(LIBBPF_DYN_LIB_PATH) -L$(LIBBPF_DYN_LIB_PATH) -lbpf"'

VMLINUX_H := ./kernel/vmlinux.h

.PHONY: static
static: clean $(LIBBPF_STATIC_LIB) $(TARGET_BPF) $(TARGET_CLI_STATIC)

.PHONY: dynamic
dynamic: clean $(LIBBPF_DYN_LIB) $(TARGET_BPF) $(TARGET_CLI_DYN)

$(BPF_SRC): $(BPF_HEADERS) $(VMLINUX_H)

$(LIBBPF_STATIC_LIB): $(wildcard $(LIBBPF_DIR)/*.c) $(wildcard $(LIBBPF_DIR)/*.h)
	BUILD_STATIC_ONLY=y $(MAKE) -C $(LIBBPF_DIR)

$(LIBBPF_DYN_LIB): $(wildcard $(LIBBPF_DIR)/*.c) $(wildcard $(LIBBPF_DIR)/*.h)
	$(MAKE) -C $(LIBBPF_DIR)

$(TARGET_BPF): $(BPF_SRC)
	$(CC) \
		-MJ compile_commands.json \
	    -g \
	    -Wall \
	    -fpie \
		-D__TARGET_ARCH_$(ARCH) \
		-I$(LIBBPF_INCLUDES) \
		-DDEBUG=$(DEBUG) \
		-O2 \
		-target bpf \
		-c $^ \
		-o $@

$(TARGET_CLI_STATIC): $(LIBBPF_STATIC_LIB) $(CMD_CLI_GO_SRC) $(TARGET_BPF)
	CGO_CFLAGS=$(CGO_CFLAGS) $(GO) build \
	-tags netgo -ldflags $(GO_EXTLDFLAGS_STATIC) \
	-o $@ ./cmd/cli/$(MAIN).go

$(TARGET_CLI_DYN): $(LIBBPF_DYN_LIB) $(CMD_CLI_GO_SRC) $(TARGET_BPF)
	HCGO_CFLAGS=$(CGO_CFLAGS) $(GO) build \
	-tags netgo -ldflags $(GO_EXTLDFLAGS_DYN) \
	-o $@ ./cmd/cli/$(MAIN).go

.PHONY: clean
clean:
	$(GO) clean -i
	rm -f ./build/*

$(VMLINUX_H):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./kernel/vmlinux.h


.PHONY: docker
docker:
	docker build -t maciekleks/$(MAIN):$(TAG) -t maciekleks/l7egg-base:$(TAG) -f Dockerfile .
	docker push  maciekleks/$(MAIN)$(TAG)
