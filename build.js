#!/usr/bin/env node
/*
 * build.js — concatenate libVES sources into the shipped bundles.
 * Replaces Makefile.pl with a Node-only equivalent: no Perl, no npm deps
 * unless you opt into minification.
 *
 * Usage:
 *   node build.js                 browser + node bundles
 *   node build.js --minify        also write .min.js (requires: npm i -D terser)
 *   node build.js --version=X     override the version read from ./VERSION
 *   node build.js --out DIR       write outputs to DIR (default: cwd)
 *
 * Outputs:
 *   libVES-<version>.js           script-tag bundle (OQS sidecar loader inlined; ECDH lazy)
 *   libVES-<version>.node.js      Node bundle (single-file OQS + ECDH wasm embedded)
 *   libVES-<version>.min.js       minified browser bundle (with --minify)
 *
 * Wasm engines (built on the build host with emscripten; see WasmOQS/ and WasmECDH/):
 *   - browser bundle embeds the OQS *sidecar loader* (WasmOQS.js); the .wasm is fetched
 *     from WasmOQSinit.baseUrl (ves.host/pub). ECDH stays fully lazy, as in the original.
 *   - node bundle embeds the *single-file* engines (WasmOQS.single.js + WasmECDH.single.js)
 *     with the .wasm base64-embedded — self-contained, no network and no `document`.
 */

const fs = require('fs');
const path = require('path');

const ROOT = __dirname;

const SRC = [
    'libVES-base.js', 'libVES.Util.js', 'libVES.Math.js', 'libVES.Object.js',
    'libVES.Algo.js', 'libVES.Cipher.js', 'libVES.Scramble.js', 'libVES.Recovery.js',
    'libVES.Delegate.js', 'libVES.Flow.js', 'libVES.Auth.js', 'libVES.Algo.OQS.js',
    'libVES.Watch.js', 'libVES.Vault.js', 'libVES.Item.js', 'libVES.KeyStore.js',
];

function parseArgs(argv) {
    const out = { minify: false, version: null, outDir: ROOT };
    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        if (a === '--minify') out.minify = true;
        else if (a.startsWith('--version=')) out.version = a.slice('--version='.length);
        else if (a === '--out') out.outDir = path.resolve(argv[++i]);
        else if (a.startsWith('--out=')) out.outDir = path.resolve(a.slice('--out='.length));
        else { console.error('unknown arg: ' + a); process.exit(2); }
    }
    return out;
}

const opts = parseArgs(process.argv.slice(2));
const version = opts.version || fs.readFileSync(path.join(ROOT, 'VERSION'), 'utf8').trim();

const banner = `/***************************************************************************
 *          ___       ___
 *         /   \\     /   \\    VESvault
 *         \\__ /     \\ __/    Encrypt Everything without fear of losing the Key
 *            \\\\     //                   https://vesvault.com https://ves.host
 *             \\\\   //
 *     ___      \\\\_//
 *    /   \\     /   \\         libVES:                      VESvault API library
 *    \\__ /     \\ __/
 *       \\\\     //
 *        \\\\   //
 *         \\\\_//              - Key Management and Exchange
 *         /   \\              - Item Encryption and Sharing
 *         \\___/              - VESrecovery (TM)
 *
 *
 * (c) 2017 - 2026 VESvault Corp
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
 * @title libVES
 * @dev A JavaScript end-to-end encryption interface to VESvault REST API
 * @version ${version}
 *
 * @dev Official source code: https://github.com/vesvault/libVES
 *
 * @author Jim Zubov <jz@vesvault.com> (VESvault Corp)
 *
 ***************************************************************************/
`;

// Concatenate sources, stripping comments the same way Makefile.pl did:
//   per-line: drop lines whose first non-whitespace is //
//   whole-file: drop /* ... */ blocks (non-greedy)
let body = '';
for (const f of SRC) {
    const text = fs.readFileSync(path.join(ROOT, f), 'utf8')
        .replace(/\r/g, '')
        .replace(/^\s*\/\/.*\n?/gm, '');
    body += text;
}
body = body.replace(/\/\*[\s\S]*?\*\//g, '');

// Read an emscripten glue file to inline verbatim into a bundle. The glue defines the
// global (WasmOQS / WasmECDH) that libVES.Algo.*.wasm() detects (so loadWasm is never
// reached when it's present), so it must NOT pass through the comment stripping above.
// Built on the build host with emscripten — see the Wasm*/Makefile.
function readGlue(rel, note) {
    const p = path.join(ROOT, rel);
    if (!fs.existsSync(p)) throw new Error('missing ' + rel + ' — build it first on the build host: '
        + '(cd ' + path.dirname(rel) + ' && emmake make). See ' + path.dirname(rel) + '/Makefile.');
    return '\n/* ' + rel + ' (' + note + ') */\n' + fs.readFileSync(p, 'utf8').replace(/\r/g, '');
}

// Browser bundle: inline the OQS *sidecar loader* (WasmOQS.js) — defines the global WasmOQS
// and fetches WasmOQS.wasm from WasmOQSinit.baseUrl (ves.host/pub). OQS/ML-KEM is the default
// key algo, so its loader ships eagerly; only the .wasm payload is a sidecar. ECDH stays fully
// lazy — its loader (WasmECDH.js) is fetched on demand by libVES.Algo.ECDH.wasm(), exactly as
// in the original code — so it is NOT inlined here.
const oqsSidecar = readGlue('WasmOQS/WasmOQS.js', 'sidecar loader, fetches .wasm');

// Node bundle: inline the *single-file* engines (.wasm base64-embedded) for BOTH OQS and ECDH.
// Node has no `document`, so libVES.Util.loadWasm (which injects a <script>) cannot lazy-load a
// sidecar — the engines must be self-contained: no network, no document.
const oqsSingle = readGlue('WasmOQS/WasmOQS.single.js', 'SINGLE_FILE, embedded .wasm');
const ecdhSingle = readGlue('WasmECDH/WasmECDH.single.js', 'SINGLE_FILE, embedded .wasm');

const versionLine = `libVES.version = '${version}';\n`;
const browser = banner + oqsSidecar + body + versionLine;
const nodeBundle = banner
    + "if (typeof crypto === 'undefined') {\n"
    + "    crypto = require('crypto');\n"
    + "    crypto.subtle = (crypto.webcrypto && crypto.webcrypto.subtle) || require('subtle');\n"
    + "}\n"
    + oqsSingle
    + ecdhSingle
    + body
    + versionLine
    + "\nmodule.exports = libVES;\n";

fs.mkdirSync(opts.outDir, { recursive: true });
const outPath = (suf) => path.join(opts.outDir, `libVES-${version}${suf}.js`);
const stablePath = (suf) => path.join(opts.outDir, `libVES${suf}.js`);

function write(p, content) {
    fs.writeFileSync(p, content);
    console.log('wrote', path.relative(process.cwd(), p) || p, '(' + content.length + ' bytes)');
}

// Version-stamped bundles — immutable CDN / <script> delivery
write(outPath(''), browser);
write(outPath('.node'), nodeBundle);
// Stable, unversioned bundles — npm "browser" / "main" entry points
write(stablePath(''), browser);
write(stablePath('.node'), nodeBundle);

if (opts.minify) {
    let terser;
    try { terser = require('terser'); }
    catch (e) {
        console.error('--minify needs terser. Install with: npm i -D terser');
        process.exit(1);
    }
    // Keep the leading banner; drop everything else for minify.
    terser.minify(browser, {
        format: { comments: /^\*+\s*$|VESvault|libVES|@version/ },
    }).then((out) => {
        if (out.error) throw out.error;
        write(outPath('.min'), out.code);
        write(stablePath('.min'), out.code);
    }).catch((e) => { console.error(e); process.exit(1); });
}
