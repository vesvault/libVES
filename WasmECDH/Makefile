#/***************************************************************************
# *          ___       ___
# *         /   \     /   \    VESvault
# *         \__ /     \ __/    Encrypt Everything without fear of losing the Key
# *            \\     //                   https://vesvault.com https://ves.host
# *             \\   //
# *     ___      \\_//
# *    /   \     /   \         libVES:                      VESvault API library
# *    \__ /     \ __/
# *       \\     //
# *        \\   //
# *         \\_//              - Key Management and Exchange
# *         /   \              - Item Encryption and Sharing
# *         \___/              - VESrecovery (TM)
# *
# *
# * (c) 2018 - 2026 VESvault Corp
# * Jim Zubov <jz@vesvault.com>
# *
# * SPDX-License-Identifier: Apache-2.0
# *
# * Licensed under the Apache License, Version 2.0 (the "License");
# * you may not use this file except in compliance with the License.
# * You may obtain a copy of the License in the accompanying LICENSE
# * file, or at http://www.apache.org/licenses/LICENSE-2.0
# *
# * Unless required by applicable law or agreed to in writing, software
# * distributed under the License is distributed on an "AS IS" BASIS,
# * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# * implied.  See the License for the specific language governing
# * permissions and limitations under the License.
# *
# ***************************************************************************/


# This makefile has to be invoked with emscripten:
# > emmake make



# Path to the source directory
ROOT=$(shell pwd)


# Path to OpenSSL's libcrypto, built for wasm with emscripten before invoking
# this makefile: $(OSSL)/libcrypto.a and $(OSSL)/include. The release build
# uses OpenSSL 3.5.9 (the 3.5 LTS line), configured as:
# > git clone --depth 1 --branch openssl-3.5.9 https://github.com/openssl/openssl.git
# > cd openssl
# > emconfigure ./Configure linux-generic32 no-asm no-threads no-shared no-dso \
#       no-engine no-module no-legacy no-sock no-ui-console no-tests no-apps \
#       no-docs no-afalgeng no-async no-secure-memory no-autoload-config \
#       no-filenames no-err no-stdio no-autoalginit no-autoerrinit \
#       no-aria no-argon2 no-bf no-blake2 no-camellia no-cast no-chacha no-cmac \
#       no-cmp no-cms no-comp no-ct no-des no-dgram no-dh no-dsa no-ecdsa no-ecx \
#       no-gost no-http no-idea no-md4 no-mdc2 no-ml-dsa no-ml-kem no-ocb \
#       no-ocsp no-poly1305 no-quic no-rc2 no-rc4 no-rfc3779 no-rmd160 \
#       no-scrypt no-seed no-siphash no-siv no-slh-dsa no-sm4 no-srp no-ts \
#       no-whirlpool no-ssl no-tls no-dtls \
#       --with-rand-seed=getrandom CC=emcc AR=emar RANLIB=emranlib -Oz -flto \
#       -ffile-prefix-map=$PWD=/src/openssl -fmacro-prefix-map=$PWD=/src/openssl
# > sed -i 's|^CROSS_COMPILE=.*|CROSS_COMPILE=|' Makefile
# > emmake make build_generated libcrypto.a
# Everything the engine does not use is left out: the default provider
# otherwise links every algorithm OpenSSL has (1.6 MB of wasm against 760 KB).
# EC with both prime and binary curves, SM2's curve, AES and SHA for the
# random generator stay. The prefix maps keep the build directory out of the
# output, so a build anywhere produces the same bytes.
OSSL=/usr/src/openssl-wasm


# Wasm build options
# ALLOW_MEMORY_GROWTH: a full heap grows instead of aborting, which would take
# every ECDH key in the page with it. libVES.Algo.js takes a fresh view of HEAPU8
# on every call and copies results out, so growth leaves no stale view behind.
WASMMOD=WasmECDH
LDFLAGS=$(OSSL)/libcrypto.a -sMODULARIZE -s EXPORT_NAME="'$(WASMMOD)'" -s EXPORTED_RUNTIME_METHODS='["HEAPU8"]' -sALLOW_MEMORY_GROWTH=1 -Oz -flto
SINGLEFLAGS=-sSINGLE_FILE=1
CFLAGS=-I$(OSSL)/include -Oz -flto
EMOBJS=$(ROOT)/WasmECDH.o
TARGET=$(ROOT)/$(WASMMOD)


all:	sidecar single

# Sidecar: WasmECDH.js loader + a separate WasmECDH.wasm (lazy-loaded fallback, e.g. from ves.host/pub)
sidecar:	$(EMOBJS)
	$(CC) $(LDFLAGS) -o $(TARGET).js $(EMOBJS)

# Single-file: WasmECDH.single.js with the .wasm base64-embedded (self-contained, no sidecar)
single:	$(EMOBJS)
	$(CC) $(LDFLAGS) $(SINGLEFLAGS) -o $(TARGET).single.js $(EMOBJS)

clean:
	rm -f $(EMOBJS) $(TARGET).js $(TARGET).wasm $(TARGET).single.js
