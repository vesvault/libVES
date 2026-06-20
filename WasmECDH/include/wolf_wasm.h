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
 * (c) 2023 VESvault Corp
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
 * wolf_wasm.h            libVES: wolfSSL build configuration for WASM ECDH
 *
 ***************************************************************************/




#define	WOLFSSL_SMALL_STACK
#define	OPENSSL_EXTRA
#define	HAVE_ECC
#define	HAVE_ECC_DHE
#define	HAVE_ALL_CURVES
#define	WOLFSSL_CUSTOM_CURVES
#define	HAVE_ECC_SECPR2
#define	HAVE_ECC_SECPR3
#define	HAVE_ECC_KOBLITZ
#define	HAVE_ECC_BRAINPOOL
#define	HAVE_COMP_KEY
#define	WC_NO_HARDEN
#define	WOLFSSL_MIN_ECC_BITS	32
#define	WOLFSSL_CERT_EXT
