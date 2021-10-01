all: build

SHELL := /bin/bash
MINERVA_MBEDTLS := $(shell realpath .)

# TODO support arch: `x86`, `xtensa`

# TODO refactor this into internal crate logic
MBEDCRYPTO_ENVS := \
    MBEDTLS_LIB_DIR=$(MINERVA_MBEDTLS)/mbedtls-v3-x86_64/__local/lib \
    MBEDTLS_INCLUDE_DIR=$(MINERVA_MBEDTLS)/mbedtls-v3-x86_64/__local/include \
    MBEDCRYPTO_STATIC=1

build:
	$(MBEDCRYPTO_ENVS) cargo build --lib --release

test:
	make build
	cargo test --no-default-features
	cargo test --no-default-features --features "std"
	$(MBEDCRYPTO_ENVS) cargo test
	$(MBEDCRYPTO_ENVS) cargo test --features "std"
	make -C examples/voucher-x86_64-std test
