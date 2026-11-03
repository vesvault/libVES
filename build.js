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
 *   libVES-<version>.js           script-tag bundle (single-file OQS embedded; ECDH lazy, pinned)
 *   libVES-<version>.node.js      Node bundle (single-file OQS + ECDH wasm embedded)
 *   libVES-<version>.min.js       minified browser bundle (with --minify)
 *   wasm-<version>/WasmECDH.*     the lazy ECDH engine, for ves.host/pub/wasm-<version>/
 *   libVES-<version>.sri          SRI hashes (sha384) of the above, to publish with the release
 *
 * Wasm engines (built on the build host with emscripten; see WasmOQS/ and WasmECDH/):
 *   - browser bundle embeds the *single-file* OQS engine: ML-KEM is the default algo, so
 *     the bundle's own SRI hash covers it. It starts with a UTF-8 BOM because emscripten
 *     embeds the .wasm as a raw-byte string, which decodes correctly only as UTF-8, and a
 *     BOM overrides the page encoding and any missing charset on the response.
 *     ECDH stays lazy (WebCrypto fallback only); the bundle carries the sha384 of
 *     WasmECDH.js/.wasm and a version-stamped baseUrl, and libVES verifies both on load.
 *   - node bundle embeds the *single-file* engines (WasmOQS.single.js + WasmECDH.single.js)
 *     with the .wasm embedded — self-contained, no network and no `document`.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

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

// Both bundles inline the *single-file* OQS engine (.wasm embedded). OQS/ML-KEM is the default
// key algo, so the browser needs it anyway, and embedding puts it under the bundle's SRI hash.
// Node has no `document`, so libVES.Util.loadWasm (which injects a <script>) cannot lazy-load a
// sidecar there — the node bundle embeds ECDH too: no network, no document.
const oqsSingle = readGlue('WasmOQS/WasmOQS.single.js', 'SINGLE_FILE, embedded .wasm');
const ecdhSingle = readGlue('WasmECDH/WasmECDH.single.js', 'SINGLE_FILE, embedded .wasm');

// Browser ECDH stays lazy — libVES.Algo.ECDH.wasm() fetches WasmECDH.js + .wasm on demand. The
// bundle pins both by hash and points at a directory stamped with this version, so a later
// release replacing them cannot break this bundle, and a swapped file fails closed.
function readArtifact(rel) {
    const p = path.join(ROOT, rel);
    if (!fs.existsSync(p)) throw new Error('missing ' + rel + ' — build it first on the build host: '
        + '(cd ' + path.dirname(rel) + ' && emmake make). See ' + path.dirname(rel) + '/Makefile.');
    return fs.readFileSync(p);
}
const sri = (buf) => 'sha384-' + crypto.createHash('sha384').update(buf).digest('base64');
const wasmDir = `wasm-${version}`;
const ecdhFiles = {};
for (const f of ['WasmECDH.js', 'WasmECDH.wasm']) ecdhFiles[f] = readArtifact('WasmECDH/' + f);
const ecdhPins = {};
for (const f in ecdhFiles) ecdhPins[f] = sri(ecdhFiles[f]);
const ecdhPinLines = `WasmECDHinit.baseUrl = 'https://ves.host/pub/${wasmDir}/';\n`
    + `WasmECDHinit.integrity = ${JSON.stringify(ecdhPins)};\n`;

const BOM = String.fromCharCode(0xFEFF);
const versionLine = `libVES.version = '${version}';\n`;
const browser = BOM + banner + oqsSingle + body + ecdhPinLines + versionLine;
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
// The lazy ECDH engine the browser bundle pins, laid out as it is served from ves.host/pub
fs.mkdirSync(path.join(opts.outDir, wasmDir), { recursive: true });
for (const f in ecdhFiles) write(path.join(opts.outDir, wasmDir, f), ecdhFiles[f]);

// SRI hashes of the version-stamped files, one "<hash>  <path>" line each, for the release
// notes and ves.host/pub. The unversioned libVES.js is left out: pinning it breaks on update.
const sums = [[`libVES-${version}.js`, browser], [`libVES-${version}.node.js`, nodeBundle]];
for (const f in ecdhFiles) sums.push([`${wasmDir}/${f}`, ecdhFiles[f]]);
function writeSums() {
    const lines = sums.map(([f, c]) => `${sri(Buffer.from(c))}  ${f}\n`).join('');
    write(path.join(opts.outDir, `libVES-${version}.sri`), lines);
    process.stdout.write(lines);
}

if (!opts.minify) writeSums();
else {
    let terser;
    try { terser = require('terser'); }
    catch (e) {
        console.error('--minify needs terser. Install with: npm i -D terser');
        process.exit(1);
    }
    // Keep the leading banner; drop everything else for minify.
    // terser drops a leading BOM; the minified file needs one for the same reason.
    terser.minify(browser.slice(BOM.length), {
        format: { comments: /^\*+\s*$|VESvault|libVES|@version/ },
    }).then((out) => {
        if (out.error) throw out.error;
        const min = BOM + out.code;
        write(outPath('.min'), min);
        write(stablePath('.min'), min);
        sums.push([`libVES-${version}.min.js`, min]);
        writeSums();
    }).catch((e) => { console.error(e); process.exit(1); });
}
