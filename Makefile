all: build

SHELL := /bin/bash

# 'test' or 'ci'
TARGET ?= test
ci:
	TARGET=ci make test

init-rust-toolchains:
	rustup toolchain install nightly-x86_64-unknown-linux-gnu
	rustup toolchain install nightly-i686-unknown-linux-gnu
	rustup target add x86_64-unknown-linux-gnu
	rustup target add i686-unknown-linux-gnu --toolchain nightly
	rustup default nightly
	# TODO xtensa
	rustup show

NAMES := voucher-x86_64-std voucher-x86-no_std
test-examples:
	for name in $(NAMES); do \
        make -C ./examples/$$name test || exit 1; done

build:
	cargo build --lib --release

test-psa-ifce:
	cargo test test_psa_ifce
	cargo test test_psa_ifce --features "std"
	cargo test test_psa_ifce --target i686-unknown-linux-gnu
	cargo test test_psa_ifce --target i686-unknown-linux-gnu --features "std"
	make test-examples

test-v3-x86_64:#DEPRECATED
	cargo build --lib --release
	cargo test
	cargo test --features "std"

test-v3-x86:#DEPRECATED
	cargo build --lib --release --target i686-unknown-linux-gnu
	cargo test --target i686-unknown-linux-gnu
	cargo test --target i686-unknown-linux-gnu --features "std"

test:
	make build
	make test-examples
	make test-psa-ifce
	rm -rf target && make test-v3-x86_64
	rm -rf target && make test-v3-x86
