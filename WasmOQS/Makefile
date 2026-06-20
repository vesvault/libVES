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
# * (c) 2018 - 2023 VESvault Corp
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


# Path to the libqos source code
# https://github.com/open-quantum-safe/liboqs
# The liboqs project has to be built with emscripten prior to invoking this
# makefile, the output lib is expected to be at $LIBOQS/lib/liboqs.a:
# > emcmake cmake -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON -DOQS_USE_OPENSSL=OFF $LIBOQS
# > emmake make -C $LIBOQS
LIBOQS=/usr/src/liboqs


WASMMOD=WasmOQS
LDFLAGS=-L$(LIBOQS)/lib -loqs -sMODULARIZE -s EXPORT_NAME="'$(WASMMOD)'" -s EXPORTED_RUNTIME_METHODS='["HEAPU8"]'
CFLAGS=-I$(ROOT)/include -I$(LIBOQS)/include
EMOBJS=$(ROOT)/WasmOQS.o
TARGET=$(ROOT)/$(WASMMOD)


all:	$(EMOBJS)
	$(CC) $(LDFLAGS) -o $(TARGET).js $(EMOBJS)

clean:
	rm -f $(EMOBJS) $(TARGET).js $(TARGET).wasm
