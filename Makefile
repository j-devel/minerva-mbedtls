all: build

SHELL := /bin/bash

# 'test' or 'ci'
TARGET ?= test
ci:
	TARGET=ci make test

init-rust-xtensa:
	true  # TODO
init-rust-i686-nightly:
	rustup target add i686-unknown-linux-gnu
	rustup toolchain install nightly-i686-unknown-linux-gnu
init-rust-x86_64-nightly:
	rustup toolchain install nightly-x86_64-unknown-linux-gnu
	rustup target add x86_64-unknown-linux-gnu

NAMES := voucher-x86_64-std voucher-x86-no_std
test-examples:
	for name in $(NAMES); do \
        make -C ./examples/$$name test || exit 1; done

build:
	cargo build --lib --release

test-v3-x86_64:
	cargo build --lib --release
	cargo test
	cargo test --features "std"

test-lts-x86_64:
	cargo build --lib --release --no-default-features
	cargo test --no-default-features
	cargo test --no-default-features --features "std"

test-v3-x86:
	cargo build --lib --release --target i686-unknown-linux-gnu
	cargo test --target i686-unknown-linux-gnu
	cargo test --target i686-unknown-linux-gnu --features "std"

test-lts-x86:
	cargo build --lib --release --target i686-unknown-linux-gnu --no-default-features
	cargo test --target i686-unknown-linux-gnu --no-default-features
	cargo test --target i686-unknown-linux-gnu --no-default-features --features "std"

test:
	make build
	make test-examples
	rm -rf target && make test-v3-x86_64
	rm -rf target && make test-lts-x86_64
	rm -rf target && make test-v3-x86
	rm -rf target && make test-lts-x86
