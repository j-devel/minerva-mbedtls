
CONFIG_H_FILE := include/mbedtls/config.h
patch-config-xtensa:
	sed -i -E 's/^(#define MBEDTLS_FS_IO)/\/\/\0/g' $(CONFIG_H_FILE)
	sed -i -E 's/^(#define MBEDTLS_NET_C)/\/\/\0/g' $(CONFIG_H_FILE)
	sed -i -E 's/^(#define MBEDTLS_TIMING_C)/\/\/\0/g' $(CONFIG_H_FILE)
	sed -i -E 's/^(#define MBEDTLS_HAVE_TIME_DATE)/\/\/\0/g' $(CONFIG_H_FILE)

CIPHER_C_FILE := library/cipher.c
patch-cipher-info-from-string-xtensa:
	sed -i -E 's/^(const mbedtls_cipher_info_t \*mbedtls_cipher_info_from_string)/int strcmp_one\( const char \*s1, const char \*s2 \) \{ return 1; \}  \0/g' $(CIPHER_C_FILE)
	sed -i -E 's/strcmp\(/strcmp_one\(/g' $(CIPHER_C_FILE)

v3-xtensa: patch-config-xtensa patch-cipher-info-from-string-xtensa
	make -j CC=$(XTENSA_GCC) CFLAGS="-O2 -DMBEDTLS_NO_PLATFORM_ENTROPY=1 -DMBEDTLS_USE_PSA_CRYPTO=1" lib
lts-xtensa: patch-config-xtensa patch-cipher-info-from-string-xtensa
	make -j CC=$(XTENSA_GCC) CFLAGS="-O2 -DMBEDTLS_NO_PLATFORM_ENTROPY=1 -DMBEDTLS_ARIA_C=1" lib

# cross build of mbedtls -- https://developer.trustedfirmware.org/w/mbed-tls/testing/ci/

v3-x86:
	make -j CFLAGS="-m32 -O2 -DMBEDTLS_USE_PSA_CRYPTO=1" LDFLAGS="-m32" lib
lts-x86:
	make -j CC=gcc CFLAGS="-m32 -O2 -DMBEDTLS_ARIA_C=1" LDFLAGS="-m32" lib

v3-x86_64:
	make -j CFLAGS="-O2 -DMBEDTLS_USE_PSA_CRYPTO=1" lib
lts-x86_64:
	make -j CFLAGS="-O2 -DMBEDTLS_ARIA_C=1" lib
