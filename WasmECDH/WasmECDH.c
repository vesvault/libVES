/***************************************************************************
 *          ___       ___
 *         /   \     /   \    VESvault
 *         \__ /     \ __/    Encrypt Everything without fear of losing the Key
 *            \\     //                   https://vesvault.com https://ves.host
 *             \\   //
 *     ___      \\_//
 *    /   \     /   \         libVES:                      VESvault API library
 *    \__ /     \ __/
 *       \\     //
 *        \\   //
 *         \\_//              - Key Management and Exchange
 *         /   \              - Item Encryption and Sharing
 *         \___/              - VESrecovery (TM)
 *
 *
 * (c) 2023 - 2026 VESvault Corp
 * Jim Zubov <jz@vesvault.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License in the accompanying LICENSE
 * file, or at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.  See the License for the specific language governing
 * permissions and limitations under the License.
 *
 * WasmECDH.c             libVES: An interface to ECDH (OpenSSL) for WASM
 *
 ***************************************************************************/

/*
 * The ECDH engine for the curves WebCrypto lacks, on OpenSSL's libcrypto
 * built for wasm (see the Makefile). It has every named curve libVES.c can
 * make a key on, under the same names and OIDs, because libVES.c uses the
 * same library.
 *
 * The EC_KEY calls are deprecated since OpenSSL 3.0 but present in the 3.5
 * LTS this is built against; they keep this file a line-for-line match of
 * the interface libVES.Algo.js calls.
 */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <emscripten.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/objects.h>
#include <openssl/bn.h>


const struct {
    int nid;
    const char *curve;
} WasmECDH_curves[] = {
    { NID_X9_62_prime256v1, "P-256" },
    { NID_secp384r1, "P-384" },
    { NID_secp521r1, "P-521" },
    { 0, NULL }
};

struct WasmECDH_curvelist {
    unsigned int ct;
    EC_builtin_curve curves[0];
};

EMSCRIPTEN_KEEPALIVE unsigned char WasmECDH_buf[1024];

EMSCRIPTEN_KEEPALIVE EC_KEY *WasmECDH_new(const char *curve) {
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
    if (nid == NID_undef) nid = OBJ_txt2nid(curve);
    if (nid == NID_undef) return NULL;
    return EC_KEY_new_by_curve_name(nid);
}

/*
 * The key keeps its own copies of the point and the scalar, so ours are
 * freed either way. oct2point refuses a point that is not on the curve;
 * EC_KEY_check_key also refuses one outside the prime-order subgroup, which
 * matters on the curves with a cofactor, and one that does not match a
 * private key already set.
 */

EMSCRIPTEN_KEEPALIVE int WasmECDH_setpub(EC_KEY *key, const unsigned char *pub, size_t len) {
    const EC_GROUP *grp = EC_KEY_get0_group(key);
    EC_POINT *pt = EC_POINT_new(grp);
    int rs;
    if (!pt) return 0;
    rs = EC_POINT_oct2point(grp, pt, pub, len, NULL)
	&& EC_KEY_set_public_key(key, pt)
	&& EC_KEY_check_key(key);
    EC_POINT_free(pt);
    return rs;
}

/* 0 < priv < order: EC_KEY_set_private_key does not check the range. */
EMSCRIPTEN_KEEPALIVE int WasmECDH_setpriv(EC_KEY *key, const unsigned char *priv, size_t len) {
    const BIGNUM *order = EC_GROUP_get0_order(EC_KEY_get0_group(key));
    BIGNUM *bn = BN_bin2bn(priv, len, NULL);
    int rs;
    if (!bn) return 0;
    rs = !BN_is_zero(bn) && order && BN_cmp(bn, order) < 0
	&& EC_KEY_set_private_key(key, bn);
    BN_clear_free(bn);
    return rs;
}

EMSCRIPTEN_KEEPALIVE int WasmECDH_getpub(EC_KEY *key) {
    const EC_POINT *pt = EC_KEY_get0_public_key(key);
    if (!pt) return 0;
    return EC_POINT_point2oct(EC_KEY_get0_group(key), pt, POINT_CONVERSION_COMPRESSED, WasmECDH_buf, sizeof(WasmECDH_buf), NULL);
}

EMSCRIPTEN_KEEPALIVE int WasmECDH_getpriv(EC_KEY *key) {
    const BIGNUM *bn = EC_KEY_get0_private_key(key);
    if (!bn || BN_num_bytes(bn) > (int)sizeof(WasmECDH_buf)) return 0;
    return BN_bn2bin(bn, WasmECDH_buf);
}

EMSCRIPTEN_KEEPALIVE const char *WasmECDH_getcurve(EC_KEY *key) {
    return OBJ_nid2ln(EC_GROUP_get_curve_name(EC_KEY_get0_group(key)));
}

/* OBJ_nid2obj returns a static object: nothing to free. */
EMSCRIPTEN_KEEPALIVE const char *WasmECDH_getoid(EC_KEY *key) {
    const ASN1_OBJECT *obj = OBJ_nid2obj(EC_GROUP_get_curve_name(EC_KEY_get0_group(key)));
    if (!obj || OBJ_obj2txt((char *)WasmECDH_buf, sizeof(WasmECDH_buf), obj, 1) <= 0) return NULL;
    return (const char *)WasmECDH_buf;
}

EMSCRIPTEN_KEEPALIVE int WasmECDH_generate(EC_KEY *key) {
    return EC_KEY_generate_key(key) && EC_KEY_check_key(key);
}

EMSCRIPTEN_KEEPALIVE int WasmECDH_derive(EC_KEY *priv, EC_KEY *pub) {
    const EC_POINT *pt = EC_KEY_get0_public_key(pub);
    if (!pt || !EC_KEY_get0_private_key(priv)) return 0;
    return ECDH_compute_key(WasmECDH_buf, sizeof(WasmECDH_buf), pt, priv, NULL);
}

EMSCRIPTEN_KEEPALIVE void WasmECDH_free(EC_KEY *key) {
    if (key) EC_KEY_free(key);
}

EMSCRIPTEN_KEEPALIVE struct WasmECDH_curvelist *WasmECDH_listinit(int ct) {
    struct WasmECDH_curvelist *lst = malloc(sizeof(struct WasmECDH_curvelist) + ct * sizeof(lst->curves[0]));
    size_t n;
    if (!lst) return NULL;
    n = EC_get_builtin_curves(lst->curves, ct);
    lst->ct = n < (size_t)ct ? n : (size_t)ct;
    return realloc(lst, sizeof(struct WasmECDH_curvelist) + lst->ct * sizeof(lst->curves[0]));
}

EMSCRIPTEN_KEEPALIVE const char *WasmECDH_listget(struct WasmECDH_curvelist *lst, unsigned int idx) {
    const char *crv;
    if (!lst || idx >= lst->ct) return NULL;
    crv = OBJ_nid2ln(lst->curves[idx].nid);
    return crv ? crv : "";
}

EMSCRIPTEN_KEEPALIVE void WasmECDH_listfree(struct WasmECDH_curvelist *lst) {
    free(lst);
}
