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


# liboqs (https://github.com/open-quantum-safe/liboqs), built for wasm before
# the engine: `emmake make liboqs` builds the source tree at $(LIBOQS_SRC) into
# $(LIBOQS), which then holds lib/liboqs.a and include/. build-release.sh
# fetches the commit build-inputs.json pins and runs it. The full algorithm set
# stays: libVES defaults to ML-KEM, but a key can use any liboqs algorithm.
# OQS_DIST_BUILD=OFF is the setting the engine has always been built with
# (liboqs defaults to ON, which gives a different ML-KEM engine).
# One liboqs source path ends up in the engine, in an error message, so the
# build maps its own source path to the one the released engines carry,
# $(LIBOQS_PATH): a build in any directory produces the same bytes.
LIBOQS_SRC=/usr/src/liboqs-wasm
LIBOQS=$(LIBOQS_SRC)/build
LIBOQS_PATH=/usr/src/liboqs-wasm
LIBOQS_CMAKE=-DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF \
	-DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON -DOQS_DIST_BUILD=OFF


WASMMOD=WasmOQS
LDFLAGS=-L$(LIBOQS)/lib -loqs -sMODULARIZE -s EXPORT_NAME="'$(WASMMOD)'" -s EXPORTED_RUNTIME_METHODS='["HEAPU8"]'
SINGLEFLAGS=-sSINGLE_FILE=1
CFLAGS=-I$(ROOT)/include -I$(LIBOQS)/include
EMOBJS=$(ROOT)/WasmOQS.o
TARGET=$(ROOT)/$(WASMMOD)


all:	sidecar single

# Sidecar: WasmOQS.js loader + a separate WasmOQS.wasm (lazy-loaded, e.g. from ves.host/pub)
sidecar:	$(EMOBJS)
	$(CC) $(LDFLAGS) -o $(TARGET).js $(EMOBJS)

# Single-file: WasmOQS.single.js with the .wasm base64-embedded (self-contained, no sidecar)
single:	$(EMOBJS)
	$(CC) $(LDFLAGS) $(SINGLEFLAGS) -o $(TARGET).single.js $(EMOBJS)

clean:
	rm -f $(EMOBJS) $(TARGET).js $(TARGET).wasm $(TARGET).single.js

# liboqs itself, from its source tree (see LIBOQS_SRC above)
liboqs:
	mkdir -p $(LIBOQS)
	cd $(LIBOQS) && emcmake cmake $(LIBOQS_CMAKE) \
		-DCMAKE_C_FLAGS="-fmacro-prefix-map=$(LIBOQS_SRC)=$(LIBOQS_PATH)" $(LIBOQS_SRC)
	$(MAKE) -C $(LIBOQS) oqs

.PHONY: all sidecar single clean liboqs
