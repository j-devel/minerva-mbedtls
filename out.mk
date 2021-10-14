# cross build of mbedtls -- https://developer.trustedfirmware.org/w/mbed-tls/testing/ci/

v3-xtensa:
	##TODO## make -j CC=gcc CFLAGS="-O2 -DMBEDTLS_USE_PSA_CRYPTO=ON" lib

lts-xtensa:
	##TODO## make -j CC=gcc CFLAGS="-m32 -O2 -DMBEDTLS_ARIA_C=ON" LDFLAGS="-m32" lib

v3-x86:
	make -j CFLAGS="-m32 -O2 -DMBEDTLS_USE_PSA_CRYPTO=ON" LDFLAGS="-m32" lib

lts-x86:
	make -j CC=gcc CFLAGS="-m32 -O2 -DMBEDTLS_ARIA_C=ON" LDFLAGS="-m32" lib

v3-x86_64:
	make -j CFLAGS="-O2 -DMBEDTLS_USE_PSA_CRYPTO=ON" lib

lts-x86_64:
	make -j CFLAGS="-O2 -DMBEDTLS_ARIA_C=ON" lib
