/*
 * WasmECDH engine test.
 *
 *   node ecdh-test.js <WasmECDH.js> [<reference WasmECDH.js>]
 *
 * Checks the engine against native OpenSSL (Node's crypto.createECDH, the
 * library libVES.c uses) on every curve both know, against WebCrypto on the
 * P-curves, and optionally against another build of the engine. Also checks
 * that bad public keys are refused, that keys are random, and that the heap
 * does not grow under repeated use.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
'use strict';
const path = require('path');
const crypto = require('crypto');

let failures = 0;
const fail = (msg) => { failures++; console.log('FAIL ' + msg); };
const ok = (msg) => console.log('ok   ' + msg);
const hex = (b) => Buffer.from(b).toString('hex');

async function load(file) {
    const factory = require(path.resolve(file));
    const dir = path.dirname(path.resolve(file));
    return factory({ locateFile: (f) => path.join(dir, f) });
}

// The calls libVES.Algo.js makes, with the same marshalling.
function engine(M) {
    const buf = (len) => new Uint8Array(M.HEAPU8.buffer, M._WasmECDH_buf, len);
    const str = (ptr) => {
        if (!ptr) return null;
        const b = new Uint8Array(M.HEAPU8.buffer, ptr);
        return Buffer.from(b.slice(0, b.indexOf(0))).toString('latin1');
    };
    const out = (l) => (l > 0 ? Uint8Array.from(buf(l)) : null);
    const E = {
        M,
        init(curve) {
            const a = Buffer.from(curve, 'latin1');
            const arg = buf(a.length + 1);
            arg.set(a); arg[a.length] = 0;
            const ptr = M._WasmECDH_new(arg.byteOffset);
            return ptr ? { ptr } : null;
        },
        generate: (k) => M._WasmECDH_generate(k.ptr),
        setpub(k, pub) { const a = buf(pub.length); a.set(pub); return M._WasmECDH_setpub(k.ptr, a.byteOffset, pub.length); },
        setpriv(k, priv) { const a = buf(priv.length); a.set(priv); return M._WasmECDH_setpriv(k.ptr, a.byteOffset, priv.length); },
        getpub: (k) => out(M._WasmECDH_getpub(k.ptr)),
        getpriv: (k) => out(M._WasmECDH_getpriv(k.ptr)),
        getcurve: (k) => str(M._WasmECDH_getcurve(k.ptr)),
        getoid: (k) => str(M._WasmECDH_getoid(k.ptr)),
        derive: (a, b) => out(M._WasmECDH_derive(a.ptr, b.ptr)),
        free: (k) => M._WasmECDH_free(k.ptr),
        getcurves() {
            const lst = M._WasmECDH_listinit(1024);
            const r = [];
            for (let i = 0, c; (c = M._WasmECDH_listget(lst, i)); i++) {
                const s = str(c);
                if (s) r.push(s);
            }
            M._WasmECDH_listfree(lst);
            return r;
        },
    };
    E.pubkey = (curve, pub) => {
        const k = E.init(curve);
        if (!k) return null;
        if (!E.setpub(k, pub)) { E.free(k); return null; }
        return k;
    };
    return E;
}

async function main() {
    const [file, refFile] = process.argv.slice(2);
    if (!file) { console.log('usage: node ecdh-test.js <WasmECDH.js> [<reference WasmECDH.js>]'); process.exit(2); }
    const E = engine(await load(file));
    const R = refFile ? engine(await load(refFile)) : null;

    // 1. The curve list.
    const curves = E.getcurves();
    const native = new Set(crypto.getCurves());
    console.log(`engine curves: ${curves.length}; native OpenSSL curves: ${native.size}`);
    if (R) {
        const ref = R.getcurves();
        const a = new Set(curves), b = new Set(ref);
        const onlyNew = curves.filter((c) => !b.has(c)), onlyRef = ref.filter((c) => !a.has(c));
        console.log(`reference curves: ${ref.length}; only in engine: ${onlyNew.length}; only in reference: ${onlyRef.length}`);
        if (onlyRef.length) fail('curves the reference engine has and this one lacks: ' + onlyRef.join(' '));
        else ok('every curve of the reference engine is here');
        if (onlyNew.length) console.log('     added: ' + onlyNew.join(' '));
    }

    // 2. Every curve against native OpenSSL, both directions, plus name and OID.
    let crossed = 0, skipped = [];
    for (const curve of curves) {
        const k = E.init(curve);
        if (!k) { fail(`${curve}: init`); continue; }
        if (!E.generate(k)) { fail(`${curve}: generate`); E.free(k); continue; }
        const pub = E.getpub(k);
        if (!native.has(curve)) { skipped.push(curve); E.free(k); continue; }
        const n = crypto.createECDH(curve);
        n.generateKeys();
        let s1, s2;
        try { s1 = n.computeSecret(Buffer.from(pub)); } catch (e) { fail(`${curve}: native refuses the engine's key: ${e.message}`); E.free(k); continue; }
        const np = E.pubkey(curve, n.getPublicKey(null, 'compressed'));
        if (!np) { fail(`${curve}: engine refuses the native key`); E.free(k); continue; }
        s2 = E.derive(k, np);
        if (!s2 || hex(s1) !== hex(s2)) fail(`${curve}: shared secrets differ`);
        else crossed++;
        if (R) {
            const rk = R.init(curve);
            if (rk) {
                if (R.getcurve(rk) !== E.getcurve(k)) fail(`${curve}: name ${E.getcurve(k)} vs reference ${R.getcurve(rk)}`);
                if (R.getoid(rk) !== E.getoid(k)) fail(`${curve}: OID ${E.getoid(k)} vs reference ${R.getoid(rk)}`);
                R.free(rk);
            }
        }
        E.free(np); E.free(k);
    }
    ok(`${crossed} curves agree with native OpenSSL both ways` + (skipped.length ? `; not in native OpenSSL: ${skipped.join(' ')}` : ''));

    // 3. The reference engine, key for key, on the curves both have.
    if (R) {
        let agreed = 0;
        for (const curve of R.getcurves()) {
            const a = E.init(curve), b = R.init(curve);
            if (!a || !b) continue;
            E.generate(a); R.generate(b);
            const ab = E.pubkey(curve, R.getpub(b)), ba = R.pubkey(curve, E.getpub(a));
            const s1 = ab && E.derive(a, ab), s2 = ba && R.derive(b, ba);
            if (!s1 || !s2 || hex(s1) !== hex(s2)) fail(`${curve}: differs from the reference engine`);
            else agreed++;
            [ab, a].forEach((k) => k && E.free(k)); [ba, b].forEach((k) => k && R.free(k));
        }
        ok(`${agreed} curves agree with the reference engine`);
    }

    // 4. WebCrypto on the P-curves.
    for (const [curve, len] of [['P-256', 32], ['P-384', 48], ['P-521', 66]]) {
        const w = await crypto.webcrypto.subtle.generateKey({ name: 'ECDH', namedCurve: curve }, true, ['deriveBits']);
        const wraw = new Uint8Array(await crypto.webcrypto.subtle.exportKey('raw', w.publicKey));
        const k = E.init(curve); E.generate(k);
        const wk = E.pubkey(curve, wraw);
        const epub = await crypto.webcrypto.subtle.importKey('raw', E.getpub(k).length === wraw.length ? E.getpub(k) : decompress(curve, E.getpub(k)), { name: 'ECDH', namedCurve: curve }, false, []);
        const s1 = new Uint8Array(await crypto.webcrypto.subtle.deriveBits({ name: 'ECDH', public: epub }, w.privateKey, len * 8));
        const s2 = wk && E.derive(k, wk);
        if (!s2 || hex(s1) !== hex(s2)) fail(`${curve}: differs from WebCrypto`);
        else ok(`${curve}: agrees with WebCrypto`);
        if (wk) E.free(wk); E.free(k);
    }

    // 5. Bad public keys are refused.
    const p256 = E.init('P-256'); E.generate(p256);
    const u = crypto.createECDH('prime256v1'); u.generateKeys();
    const unc = Uint8Array.from(u.getPublicKey()); unc[unc.length - 1] ^= 1;
    if (E.pubkey('P-256', unc)) fail('an off-curve P-256 point is accepted'); else ok('an off-curve point is refused');
    const k1 = crypto.createECDH('secp256k1'); k1.generateKeys();
    if (E.pubkey('P-256', k1.getPublicKey())) fail('a secp256k1 point is accepted as P-256'); else ok('a point from another curve is refused');
    if (E.pubkey('P-256', new Uint8Array([0]))) fail('the point at infinity is accepted'); else ok('the point at infinity is refused');
    if (E.init('no-such-curve')) fail('an unknown curve name gives a key'); else ok('an unknown curve name is refused');
    const p2 = E.init('P-256');
    if (E.setpriv(p2, new Uint8Array(32))) fail('a zero private key is accepted'); else ok('a zero private key is refused');
    const n256 = Buffer.from('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551', 'hex');
    if (E.setpriv(p2, n256)) fail('a private key equal to the order is accepted'); else ok('a private key equal to the order is refused');
    E.free(p2);
    const mism = E.init('P-256'); const other = E.init('P-256'); E.generate(other);
    E.setpriv(mism, E.getpriv(p256));
    if (E.setpub(mism, E.getpub(other))) fail('a public key that does not match the private key is accepted'); else ok('a mismatched public key is refused');
    E.free(mism); E.free(other); E.free(p256);

    // 6. Keys are random.
    const seen = new Set();
    for (let i = 0; i < 200; i++) { const k = E.init('secp256k1'); E.generate(k); seen.add(hex(E.getpriv(k))); E.free(k); }
    if (seen.size !== 200) fail(`only ${seen.size} distinct keys in 200`); else ok('200 generated keys, all distinct');

    // 7. The heap does not grow under repeated use.
    const before = E.M.HEAPU8.length;
    for (let i = 0; i < 3000; i++) {
        const a = E.init('brainpoolP256r1'), b = E.init('brainpoolP256r1');
        E.generate(a); E.generate(b);
        const pb = E.pubkey('brainpoolP256r1', E.getpub(b));
        E.derive(a, pb);
        E.free(pb); E.free(a); E.free(b);
    }
    const after = E.M.HEAPU8.length;
    if (after > before) fail(`heap grew from ${before} to ${after} bytes over 3000 rounds`); else ok(`heap steady at ${after} bytes over 3000 rounds`);

    console.log(failures ? `${failures} FAILED` : 'ALL PASSED');
    process.exit(failures ? 1 : 0);
}

// WebCrypto imports only uncompressed points.
function decompress(curve, c) {
    const name = { 'P-256': 'prime256v1', 'P-384': 'secp384r1', 'P-521': 'secp521r1' }[curve];
    return Uint8Array.from(crypto.ECDH.convertKey(Buffer.from(c), name, null, null, 'uncompressed'));
}

main().catch((e) => { console.log('ERROR ' + (e.stack || e)); process.exit(1); });
