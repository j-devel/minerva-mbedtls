all: build

SHELL := /bin/bash

# 'test' or 'ci'
TARGET ?= test
ci:
	TARGET=ci make test

init-rust-xtensa:
	true  # TODO
init-rust-i686-nightly:
	rustup toolchain install nightly-i686-unknown-linux-gnu
	rustup target add i686-unknown-linux-gnu
init-rust-x86_64-nightly:
	rustup toolchain install nightly-x86_64-unknown-linux-gnu
	rustup target add x86_64-unknown-linux-gnu

NAMES := voucher-x86_64-std
test-examples:
	for name in $(NAMES); do \
        make -C ./examples/$$name test || exit 1; done

build:
	cargo build --lib --release
	cargo +nightly-i686-unknown-linux-gnu build --lib --release --target i686-unknown-linux-gnu --no-default-features
	## FIXME: need building `bindgen` of `psa-crypto-sys` in 32bit context ## cargo +nightly-i686-unknown-linux-gnu build --lib --release --target i686-unknown-linux-gnu

test:
	make build
	cargo +nightly-i686-unknown-linux-gnu test --target i686-unknown-linux-gnu --no-default-features
	cargo test --no-default-features
	cargo test --no-default-features --features "std"
	cargo test
	cargo test --features "std"
	make test-examples
