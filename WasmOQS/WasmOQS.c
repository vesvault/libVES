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
 * (c) 2018 - 2026 VESvault Corp
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
 * WasmOQS.c               libVES: An interface to libOQS post-quantum suite
 *
 ***************************************************************************/

#include <emscripten.h>
#include <stdio.h>
#include <stdlib.h>
#include <oqs/kem.h>
#include <oqs/oqsconfig.h>

/* OQS_KEM_keypair_derand and kem->length_keypair_seed appear in libOQS 0.13.0. */
#if defined(OQS_VERSION_MAJOR) && (OQS_VERSION_MAJOR > 0 || OQS_VERSION_MINOR >= 13)
#define WASMOQS_HAVE_DERAND 1
#endif


struct WasmOQS {
    OQS_KEM *kem;
    void *priv;
    void *pub;
};

EMSCRIPTEN_KEEPALIVE char WasmOQS_secretbuf[128];
EMSCRIPTEN_KEEPALIVE char WasmOQS_ctextbuf[32640];
#ifdef WASMOQS_HAVE_DERAND
EMSCRIPTEN_KEEPALIVE char WasmOQS_seedbuf[256];
#endif


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

#ifdef WASMOQS_HAVE_DERAND
EMSCRIPTEN_KEEPALIVE int WasmOQS_seedlen(struct WasmOQS *oqs) {
    if (!oqs || !oqs->kem) return 0;
    return (int)oqs->kem->length_keypair_seed;
}

EMSCRIPTEN_KEEPALIVE int WasmOQS_generate_seed(struct WasmOQS *oqs, int seedlen) {
    if (!oqs || !oqs->priv) return -1;
    if (seedlen != (int)oqs->kem->length_keypair_seed) return -1;
    if (OQS_KEM_keypair_derand(oqs->kem, oqs->pub, oqs->priv, (const uint8_t *)WasmOQS_seedbuf) != OQS_SUCCESS) return -1;
    return 0;
}
#endif

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

