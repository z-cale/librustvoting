# Root Makefile — delegates to sdk/
SDK_DIR = sdk

.PHONY: install install-ffi init init-ffi start clean build fmt lint \
	test test-unit test-integration test-api \
	fixtures-ts circuits circuits-test fixtures \
	test-halo2 test-halo2-ante test-redpallas test-redpallas-ante test-all-ffi

install:
	$(MAKE) -C $(SDK_DIR) install

install-ffi:
	$(MAKE) -C $(SDK_DIR) install-ffi

build:
	$(MAKE) -C $(SDK_DIR) build

init:
	$(MAKE) -C $(SDK_DIR) init

init-ffi:
	$(MAKE) -C $(SDK_DIR) init-ffi

start:
	$(MAKE) -C $(SDK_DIR) start

clean:
	$(MAKE) -C $(SDK_DIR) clean

fmt:
	$(MAKE) -C $(SDK_DIR) fmt

lint:
	$(MAKE) -C $(SDK_DIR) lint

test-unit:
	$(MAKE) -C $(SDK_DIR) test-unit

test-integration:
	$(MAKE) -C $(SDK_DIR) test-integration

test:
	$(MAKE) -C $(SDK_DIR) test

test-api:
	$(MAKE) -C $(SDK_DIR) test-api

fixtures-ts:
	$(MAKE) -C $(SDK_DIR) fixtures-ts

circuits:
	$(MAKE) -C $(SDK_DIR) circuits

circuits-test:
	$(MAKE) -C $(SDK_DIR) circuits-test

fixtures:
	$(MAKE) -C $(SDK_DIR) fixtures

test-halo2:
	$(MAKE) -C $(SDK_DIR) test-halo2

test-halo2-ante:
	$(MAKE) -C $(SDK_DIR) test-halo2-ante

test-redpallas:
	$(MAKE) -C $(SDK_DIR) test-redpallas

test-redpallas-ante:
	$(MAKE) -C $(SDK_DIR) test-redpallas-ante

test-all-ffi:
	$(MAKE) -C $(SDK_DIR) test-all-ffi
