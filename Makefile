all: build

SHELL := /bin/bash
MINERVA_MBEDTLS := $(shell realpath .)

# TODO support arch: `x86`, `xtensa`

build:
	cargo build --lib --release

test:
	make build
	cargo test --no-default-features
	cargo test --no-default-features --features "std"
	cargo test
	cargo test --features "std"
	make -C examples/voucher-x86_64-std test
