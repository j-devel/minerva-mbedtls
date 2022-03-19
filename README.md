# minerva-mbedtls wrapper

[![MIT licensed][mit-badge]][mit-url]
[![CI][actions-badge]][actions-url]

[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/AnimaGUS-minerva/minerva-mbedtls/blob/master/LICENSE
[actions-badge]: https://github.com/AnimaGUS-minerva/minerva-mbedtls/workflows/CI/badge.svg
[actions-url]: https://github.com/AnimaGUS-minerva/minerva-mbedtls/actions

This crate wraps mbedtls using the PSA interfaces for the purpose of signing COSE objects.

It is designed to work in no_std environment.

It is very incomplete.  It can load PKIX certificates from a byte string, private keys,
create and verify signatures using ECDSA keys.


