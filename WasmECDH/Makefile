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


# Path to the wolfssl source code
# https://github.com/open-quantum-safe/liboqs
# The wolfssl project has to be EITHER built with emscripten prior to
# invoking this makefile, OR the partial build below will be invoked.
# In the latter case, set LIBWOLF to the traget path for libwolfssl.a
WOLF=/usr/src/wolfssl
LIBWOLF=$(WOLF)/src/.libs


# WolfSSL partial build settings.
# Note - the set of files and options MAY change in future WolfSSL
# versions.
WOLFLIBS=$(LIBWOLF)/libwolfssl.a
WOLFOBJS=$(WOLF)/src/ssl.o \
    $(WOLF)/wolfcrypt/src/ecc.o \
    $(WOLF)/wolfcrypt/src/memory.o \
    $(WOLF)/wolfcrypt/src/sp_int.o \
    $(WOLF)/wolfcrypt/src/wc_port.o \
    $(WOLF)/wolfcrypt/src/random.o \
    $(WOLF)/wolfcrypt/src/wolfmath.o \
    $(WOLF)/wolfcrypt/src/sha256.o \
    $(WOLF)/wolfcrypt/src/logging.o \
    $(WOLF)/wolfcrypt/src/asn.o


# Wasm build options
WASMMOD=WasmECDH
LDFLAGS=-L$(LIBWOLF) -lwolfssl -sMODULARIZE -s EXPORT_NAME="'$(WASMMOD)'"
CFLAGS=-I$(ROOT)/include -I$(WOLF) -include $(ROOT)/include/wolf_wasm.h
EMOBJS=$(ROOT)/WasmECDH.o
TARGET=$(ROOT)/$(WASMMOD)


all:	$(EMOBJS) $(WOLFLIBS)
	$(CC) $(LDFLAGS) -o $(TARGET).js $(EMOBJS)

clean:
	rm -f $(EMOBJS) $(TARGET).js $(TARGET).wasm


# WolfSSL partial build targets:

$(WOLFLIBS):	$(WOLFOBJS)
	mkdir $(LIBWOLF) || true
	$(AR) cru $@ $(WOLFOBJS)

$(WOLF)/%.o:	$(WOLF)/%.c
	$(CC) $(CFLAGS) $(WOLFCFLAGS) -c -o $@ $<

clean-wolf:
	rm -f $(WOLFOBJS) $(WOLFLIBS)
