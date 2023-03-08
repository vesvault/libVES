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
