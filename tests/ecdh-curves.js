/*
 * tests/ecdh-curves.js — offline test for libVES.Algo.ECDH across curve names.
 *
 * Needs no VES account and makes no network request (fetch is stubbed to
 * throw): it loads the built node bundle, which embeds the wasm ECDH engine,
 * and calls libVES.Algo.ECDH directly, without creating a libVES instance.
 *
 *   node build.js && node tests/ecdh-curves.js
 *
 * T-0202: a key on a WebCrypto curve must behave the same whichever name it
 * was generated under (P-256, or OpenSSL's prime256v1, etc.), and a P-curve
 * key on the wasm path must decrypt ciphertext made on either path. A few
 * wasm-only curves cover the wasm engine itself.
 */

const fs = require('fs');
const path = require('path');

const LIB_DIR = path.resolve(__dirname, '..');
const PKG = path.join(LIB_DIR, 'libVES.node.js');
if (!fs.existsSync(PKG)) throw new Error('missing ' + PKG
    + ' — build the node package first: (cd ' + LIB_DIR + ' && node build.js).');

// libVES talks to the network only through fetch(): refuse it outright.
global.fetch = function (url) { throw new Error('offline test, refusing fetch(' + url + ')'); };
global.libVES = require(PKG);
eval.call(global, fs.readFileSync(path.join(__dirname, 'jstest.inc.js'), 'utf8'));

var ECDH = libVES.Algo.ECDH;
var MSG = 'T-0202 ecdh-curves';

// Encrypt MSG to pub, decrypt with priv, check the opentext.
function roundtrip(pub, priv) {
    return ECDH.encrypt(pub, libVES.Util.StringToByteArray(MSG)).then(function (ct) {
        return ECDH.decrypt(priv, ct);
    }).then(function (buf) {
        var s = libVES.Util.ByteArrayToString(new Uint8Array(buf));
        if (s !== MSG) throw new Error('decrypted ' + JSON.stringify(s) + ', expected ' + JSON.stringify(MSG));
    });
}

// The private key's PEM (no password) re-imported through libVES.Algo.ECDH.import.
function reimport(priv) {
    return ECDH.export(priv, { opentext: true }).then(function (pem) {
        return ECDH.import(pem);
    });
}

function kind(k) {
    return (k instanceof CryptoKey) ? 'WebCrypto ' + k.algorithm.namedCurve : 'wasm ' + k.curve;
}

// generate under `name`, expect a key of `expect` kind, then round-trip directly and after a PEM re-import.
function sweep(t, name, expect) {
    var kp;
    return t.run(name + ': generate gives a ' + expect + ' key', function () {
        return ECDH.generate({ namedCurve: name }).then(function (k) {
            kp = k;
            if (kind(kp.privateKey) !== expect) throw new Error('got a ' + kind(kp.privateKey) + ' key');
        });
    }).then(function () {
        return t.run(name + ': encrypt/decrypt', function () {
            return roundtrip(kp.publicKey, kp.privateKey);
        });
    }).then(function () {
        return t.run(name + ': decrypt after PEM export and re-import', function () {
            return reimport(kp.privateKey).then(function (k2) {
                return roundtrip(kp.publicKey, k2);
            });
        });
    });
}

function each(list, fn) {
    return list.reduce(function (p, v) {
        return p.then(function () { return fn(v); });
    }, Promise.resolve());
}

vestest.register('ecdh-alias-curves', function (t) {
    var aliases = { 'prime256v1': 'P-256', 'secp384r1': 'P-384', 'secp521r1': 'P-521' };
    t.head('OpenSSL names of the WebCrypto curves');
    return each(Object.keys(aliases), function (name) {
        return sweep(t, name, 'WebCrypto ' + aliases[name]);
    });
});

vestest.register('ecdh-wasm-curves', function (t) {
    t.head('Curves only the wasm engine has');
    return each(['secp224r1', 'secp256k1', 'brainpoolP256r1', 'brainpoolP512r1'], function (name) {
        return sweep(t, name, 'wasm ' + name);
    });
});

// The same P-curve key on both paths: WebCrypto, and wasm as libVES.Util.EC.import
// falls back to it (importWasm with the WebCrypto curve name).
vestest.register('ecdh-mixed-paths', function (t) {
    t.head('A P-curve key on the WebCrypto and the wasm path');
    return each(['P-256', 'P-384', 'P-521'], function (crv) {
        var kp, w;
        return t.run(crv + ': the same key imported on the wasm path', function () {
            return ECDH.generate({ namedCurve: crv }).then(function (k) {
                kp = k;
                return ECDH.export(kp.privateKey, { opentext: true });
            }).then(function (pem) {
                return ECDH.importWasm(crv, libVES.Util.PEM.toDER(pem));
            }).then(function (k) {
                w = k;
                if (!w || (w instanceof CryptoKey)) throw new Error('expected a wasm key, got ' + (w && kind(w)));
            });
        }).then(function () {
            return t.run(crv + ': WebCrypto public -> wasm private', function () {
                return roundtrip(kp.publicKey, w);
            });
        }).then(function () {
            return t.run(crv + ': wasm public -> WebCrypto private', function () {
                return roundtrip(w, kp.privateKey);
            });
        }).then(function () {
            return t.run(crv + ': wasm key PEM re-imports and decrypts both', function () {
                return reimport(w).then(function (k2) {
                    return roundtrip(w, k2).then(function () {
                        return roundtrip(kp.publicKey, k2);
                    });
                });
            });
        });
    });
});

vestest.register('ecdh-methods', function (t) {
    t.head('getMethods');
    return t.run('lists each WebCrypto curve once, under its WebCrypto name', function () {
        return ECDH.getMethods().then(function (ms) {
            var names = ms.map(function (m) { return m.namedCurve; });
            ['P-256', 'P-384', 'P-521'].forEach(function (crv) {
                if (names.indexOf(crv) < 0) throw new Error(crv + ' missing');
            });
            ['prime256v1', 'secp384r1', 'secp521r1'].forEach(function (crv) {
                if (names.indexOf(crv) >= 0) throw new Error(crv + ' listed');
            });
            if (names.indexOf('secp256k1') < 0) throw new Error('wasm curves missing: ' + names.join(' '));
        });
    });
});

if (require.main === module) {
    vestest.runSelected(null, {}, null).then(function (counts) {
        process.exit(counts && counts.fail ? 1 : 0);
    }).catch(function (e) { console.error(e); process.exit(2); });
}
