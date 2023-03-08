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
 * (c) 2018 VESvault Corp
 * Jim Zubov <jz@vesvault.com>
 *
 * GNU General Public License v3
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * WasmOQS.c               libVES: An interface to libOQS post-quantum suite
 *
 ***************************************************************************/

#include <emscripten.h>
#include <stdio.h>
#include <stdlib.h>
#include <oqs/kem.h>


struct WasmOQS {
    OQS_KEM *kem;
    void *priv;
    void *pub;
};

EMSCRIPTEN_KEEPALIVE char WasmOQS_secretbuf[128];
EMSCRIPTEN_KEEPALIVE char WasmOQS_ctextbuf[32640];


EMSCRIPTEN_KEEPALIVE struct WasmOQS *WasmOQS_new(const char *algo, int priv) {
    OQS_KEM *kem = OQS_KEM_new(algo);
    if (!kem) return NULL;
    struct WasmOQS *oqs = malloc(sizeof(struct WasmOQS));
    if (oqs) {
	oqs->kem = kem;
	oqs->priv = priv ? malloc(kem->length_secret_key) : NULL;
	if (!priv || oqs->priv) {
	    oqs->pub = malloc(kem->length_public_key);
	    if (oqs->pub) return oqs;
	    free(oqs->pub);
	}
	free(oqs->priv);
	free(oqs);
    }
    OQS_KEM_free(kem);
    return NULL;
}

EMSCRIPTEN_KEEPALIVE int WasmOQS_generate(struct WasmOQS *oqs) {
    if (!oqs || !oqs->priv || OQS_KEM_keypair(oqs->kem, oqs->pub, oqs->priv) != OQS_SUCCESS) return -1;
    return 0;
}

EMSCRIPTEN_KEEPALIVE int WasmOQS_encaps(struct WasmOQS *oqs, void *ctext, void *secret) {
    if (!ctext || !secret || OQS_KEM_encaps(oqs->kem, ctext, secret, oqs->pub) == OQS_SUCCESS) return oqs->kem->length_ciphertext;
    return -1;
}

EMSCRIPTEN_KEEPALIVE int WasmOQS_decaps(struct WasmOQS *oqs, void *secret, const void *ctext) {
    if (!secret || !ctext || OQS_KEM_decaps(oqs->kem, secret, ctext, oqs->priv) == OQS_SUCCESS) return oqs->kem->length_shared_secret;
    return -1;
}

EMSCRIPTEN_KEEPALIVE void *WasmOQS_pub(struct WasmOQS *oqs) {
    return oqs->pub;
}

EMSCRIPTEN_KEEPALIVE int WasmOQS_publen(struct WasmOQS *oqs) {
    return oqs->kem->length_public_key;
}

EMSCRIPTEN_KEEPALIVE void *WasmOQS_priv(struct WasmOQS *oqs) {
    return oqs->priv;
}

EMSCRIPTEN_KEEPALIVE int WasmOQS_privlen(struct WasmOQS *oqs) {
    return oqs->kem->length_secret_key;
}

EMSCRIPTEN_KEEPALIVE void WasmOQS_free(struct WasmOQS *oqs) {
    free(oqs->pub);
    free(oqs->priv);
    OQS_KEM_free(oqs->kem);
    free(oqs);
}

EMSCRIPTEN_KEEPALIVE const char *WasmOQS_enumalgo(int idx) {
    const char *algo = OQS_KEM_alg_identifier(idx);
    if (!algo) return NULL;
    if (OQS_KEM_alg_is_enabled(algo)) {
	return algo;
    }
    return "";
}

