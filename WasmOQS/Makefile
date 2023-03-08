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
# * GNU General Public License v3
# * You may opt to use, copy, modify, merge, publish, distribute and/or sell
# * copies of the Software, and permit persons to whom the Software is
# * furnished to do so, under the terms of the COPYING file.
# *
# * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# * KIND, either express or implied.
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
LDFLAGS=-L$(LIBOQS)/lib -loqs -sMODULARIZE -s EXPORT_NAME="'$(WASMMOD)'"
CFLAGS=-I$(ROOT)/include -I$(LIBOQS)/include
EMOBJS=$(ROOT)/WasmOQS.o
TARGET=$(ROOT)/$(WASMMOD)


all:	$(EMOBJS)
	$(CC) $(LDFLAGS) -o $(TARGET).js $(EMOBJS)

clean:
	rm -f $(EMOBJS) $(TARGET).js $(TARGET).wasm
