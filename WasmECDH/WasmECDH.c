#include <emscripten.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wolfssl/openssl/ec.h>
#include <wolfssl/openssl/ecdh.h>
#include <wolfssl/openssl/asn1.h>


const struct {
    int nid;
    const char *curve;
} WasmECDH_curves[] = {
    { NID_secp256k1, "P-256" },
    { NID_secp384r1, "P-384" },
    { NID_secp521r1, "P-521" },
    { 0, NULL }
};

EMSCRIPTEN_KEEPALIVE unsigned char WasmECDH_buf[1024];

EMSCRIPTEN_KEEPALIVE WOLFSSL_EC_KEY *WasmECDH_new(const char *curve) {
    int cidx;
    int nid = NID_undef;
    for (cidx = 0; ; cidx++) {
	const char *c = WasmECDH_curves[cidx].curve;
	if (!c) break;
	if (!strcmp(c, curve)) {
	    nid = WasmECDH_curves[cidx].nid;
	    break;
	}
    }
    if (nid == NID_undef) nid = wolfSSL_OBJ_txt2nid(curve);
    return wolfSSL_EC_KEY_new_by_curve_name(nid);
}

EMSCRIPTEN_KEEPALIVE int WasmECDH_setpub(WOLFSSL_EC_KEY *key, const unsigned char *pub, size_t len) {
    const WOLFSSL_EC_GROUP *grp = wolfSSL_EC_KEY_get0_group(key);
    WOLFSSL_EC_POINT *pt = wolfSSL_EC_POINT_new(grp);
    if (!wolfSSL_EC_POINT_oct2point(grp, pt, pub, len, NULL)) {
	wolfSSL_EC_POINT_free(pt);
	return 0;
    }
    return wolfSSL_EC_KEY_set_public_key(key, pt);
}

EMSCRIPTEN_KEEPALIVE int WasmECDH_setpriv(WOLFSSL_EC_KEY *key, const unsigned char *priv, size_t len) {
    WOLFSSL_BIGNUM *bn = wolfSSL_BN_bin2bn(priv, len, NULL);
    if (!bn) return 0;
    return wolfSSL_EC_KEY_set_private_key(key, bn);
}

EMSCRIPTEN_KEEPALIVE int WasmECDH_getpub(WOLFSSL_EC_KEY *key) {
    return wolfSSL_EC_POINT_point2oct(wolfSSL_EC_KEY_get0_group(key), wolfSSL_EC_KEY_get0_public_key(key), POINT_CONVERSION_COMPRESSED, WasmECDH_buf, sizeof(WasmECDH_buf), NULL);
}

EMSCRIPTEN_KEEPALIVE int WasmECDH_getpriv(WOLFSSL_EC_KEY *key) {
    return wolfSSL_BN_bn2bin(wolfSSL_EC_KEY_get0_private_key(key), WasmECDH_buf);
}

EMSCRIPTEN_KEEPALIVE const char *WasmECDH_getcurve(WOLFSSL_EC_KEY *key) {
    return wolfSSL_OBJ_nid2ln(wolfSSL_EC_GROUP_get_curve_name(wolfSSL_EC_KEY_get0_group(key)));
}

EMSCRIPTEN_KEEPALIVE const char *WasmECDH_getoid(WOLFSSL_EC_KEY *key) {
    WOLFSSL_ASN1_OBJECT *obj = wolfSSL_OBJ_nid2obj(wolfSSL_EC_GROUP_get_curve_name(wolfSSL_EC_KEY_get0_group(key)));
    if (!obj) return NULL;
    wolfSSL_OBJ_obj2txt((void *)WasmECDH_buf, sizeof(WasmECDH_buf), obj, 1);
    wolfSSL_ASN1_OBJECT_free(obj);
    return (void *)WasmECDH_buf;
}

EMSCRIPTEN_KEEPALIVE int WasmECDH_generate(WOLFSSL_EC_KEY *key) {
    return wolfSSL_EC_KEY_generate_key(key) && wolfSSL_EC_KEY_check_key(key);
}

EMSCRIPTEN_KEEPALIVE int WasmECDH_derive(WOLFSSL_EC_KEY *priv, WOLFSSL_EC_KEY *pub) {
    return wolfSSL_ECDH_compute_key(WasmECDH_buf, sizeof(WasmECDH_buf), wolfSSL_EC_KEY_get0_public_key(pub), priv, NULL);
}

EMSCRIPTEN_KEEPALIVE void WasmECDH_free(WOLFSSL_EC_KEY *key) {
    if (key) wolfSSL_EC_KEY_free(key);
}

