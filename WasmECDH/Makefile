#wasm dir
ROOT=$(shell pwd)

# WolfSSL source path
WOLF=/usr/src/wolfssl

#emcc, local cmd or docker
EMCC=docker run --rm -v $(ROOT):$(ROOT) -v $(WOLF):$(WOLF) emscripten/emsdk emcc

LDFLAGS=-L. -sMODULARIZE -s EXPORT_NAME="'WasmECDH'" -sERROR_ON_UNDEFINED_SYMBOLS=0 
EMOBJS=$(ROOT)/WasmECDH.emo
WOLFLIBS=$(WOLF)/ec.ema
TARGET=$(ROOT)/WasmECDH.js
EMAR=emar
CFLAGS=-I$(ROOT)/include -I$(WOLF) \
    -DWOLFSSL_SMALL_STACK \
    -DOPENSSL_EXTRA \
    -DHAVE_ECC \
    -DHAVE_ECC_DHE \
    -DHAVE_ALL_CURVES \
    -DWOLFSSL_CUSTOM_CURVES \
    -DHAVE_ECC_SECPR2 \
    -DHAVE_ECC_SECPR3 \
    -DHAVE_ECC_KOBLITZ \
    -DHAVE_ECC_BRAINPOOL \
    -DHAVE_COMP_KEY \
    -DWC_NO_HARDEN \
    -DWOLFSSL_MIN_ECC_BITS=32 \
    -DWOLFSSL_CERT_EXT

WOLFOBJS=$(WOLF)/src/ssl.emo \
    $(WOLF)/wolfcrypt/src/ecc.emo \
    $(WOLF)/wolfcrypt/src/memory.emo \
    $(WOLF)/wolfcrypt/src/sp_int.emo \
    $(WOLF)/wolfcrypt/src/wc_port.emo \
    $(WOLF)/wolfcrypt/src/random.emo \
    $(WOLF)/wolfcrypt/src/wolfmath.emo \
    $(WOLF)/wolfcrypt/src/sha256.emo \
    $(WOLF)/wolfcrypt/src/logging.emo \
    $(WOLF)/wolfcrypt/src/asn.emo \




all:	$(EMOBJS) $(WOLFLIBS)
	$(EMCC) $(LDFLAGS) -o $(TARGET) $(EMOBJS) $(WOLFLIBS)

$(WOLF)/ec.ema:	$(WOLFOBJS)
	$(EMAR) cru $@ $(WOLFOBJS)

$(ROOT)/%.emo:	$(ROOT)/%.c
	$(EMCC) $(CFLAGS) -c -o $@ $<

$(WOLF)/%.emo:	$(WOLF)/%.c
	$(EMCC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(EMOBJS) $(WOLFOBJS) $(WOLFLIBS)
