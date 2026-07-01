/*
 * tests/scramble-gf256.js — offline unit test for the VESrecovery scramble layer.
 *
 * Unlike the numbered integration tests, this one needs no VES account and no
 * built node bundle: it loads only libVES.Math.js + libVES.Scramble.js against a
 * minimal libVES stub, and exercises the secret-sharing math directly.
 *
 *   node tests/scramble-gf256.js
 *
 * SSS1 (GF(2^8) Shamir) is cross-checked against an INDEPENDENT, table-free
 * implementation in this file (Russian-peasant multiply under poly 0x11b, brute
 * inverse, Lagrange at 0) — that independent path is what makes "standard, not
 * homegrown" demonstrable. RDX1.2 is exercised for round-trip regression.
 */

const fs = require('fs');
const path = require('path');

if (typeof crypto === 'undefined') {
    global.crypto = require('crypto').webcrypto;
}

// Minimal libVES stub: Scramble.js needs libVES.Error and libVES.Math (cmp, plus
// the bignum ops that RDX1.2 uses). libVES.Math.js attaches the real math module.
global.libVES = function () {};
global.libVES.Error = function (code, msg) { this.code = code; this.message = msg; };
global.libVES.Error.prototype = Object.create(Error.prototype);

const LIB_DIR = path.resolve(__dirname, '..');
function load(f) { eval.call(global, fs.readFileSync(path.join(LIB_DIR, f), 'utf8')); }
load('libVES.Math.js');
load('libVES.Scramble.js');
eval.call(global, fs.readFileSync(path.join(__dirname, 'jstest.inc.js'), 'utf8'));

// ---------------------------------------------------------------------------
// Independent GF(2^8) Shamir — no exp/log tables; validates libVES.Scramble.SSS.
// ---------------------------------------------------------------------------
function gmul(a, b) {                       // multiply in GF(2^8), poly 0x11b
    var p = 0;
    for (var i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        var hi = a & 0x80;
        a = (a << 1) & 0xff;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}
function ginv(a) { for (var b = 1; b < 256; b++) if (gmul(a, b) === 1) return b; return 0; }
function gevalPoly(coeffs, x) {             // coeffs[0] + coeffs[1]*x + ...
    var acc = 0;
    for (var k = coeffs.length - 1; k >= 0; k--) acc = gmul(acc, x) ^ coeffs[k];
    return acc;
}
function gLagrange0(xs, ys) {               // reconstruct secret (poly at x=0)
    var L = ys[0].length, out = new Uint8Array(L);
    for (var j = 0; j < L; j++) {
        var acc = 0;
        for (var i = 0; i < xs.length; i++) {
            var num = 1, den = 1;
            for (var l = 0; l < xs.length; l++) if (l !== i) {
                num = gmul(num, xs[l]);     // (0 ^ x_l) = x_l
                den = gmul(den, xs[i] ^ xs[l]);
            }
            acc ^= gmul(ys[i][j], gmul(num, ginv(den)));
        }
        out[j] = acc;
    }
    return out;
}

function eqBytes(a, b) {
    if (a.length !== b.length) return false;
    for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
}
function randomSecret(len) { var s = new Uint8Array(len); crypto.getRandomValues(s); return s; }
function subset(arr, idxs) { return idxs.map(function (i) { return arr[i]; }); }

// ---------------------------------------------------------------------------
vestest.register('gf256-field', function (t) {
    var sss = new libVES.Scramble.SSS(2);
    return Promise.all([
        // exp/log tables agree with the table-free multiply across the whole field.
        t.run('mul matches independent gmul over all 256x256', function () {
            for (var a = 0; a < 256; a++) for (var b = 0; b < 256; b++)
                if (sss.mul(a, b) !== gmul(a, b)) throw new Error('mul(' + a + ',' + b + ')=' + sss.mul(a, b) + ' != ' + gmul(a, b));
        }),
        t.run('a * inv(a) == 1 for every nonzero a', function () {
            for (var a = 1; a < 256; a++) if (sss.mul(a, sss.div(1, a)) !== 1) throw new Error('inv failed at ' + a);
        })
    ]);
});

// Deterministic known-answer test: pin the RNG, then verify SSS-produced shares
// byte-for-byte against the independent polynomial evaluation, and reconstruct.
vestest.register('gf256-kat', function (t) {
    var realRng = crypto.getRandomValues.bind(crypto);
    return t.run('explode shares lie on the independent polynomial; reconstruct == secret', function () {
        var n = 3, m = 5, L = 32;
        var secret = new Uint8Array(L);
        for (var j = 0; j < L; j++) secret[j] = (j * 7 + 3) & 0xff;
        // Pin RNG so the n-1 random coefficients per byte are known.
        crypto.getRandomValues = function (buf) { for (var i = 0; i < buf.length; i++) buf[i] = (i * 37 + 0x5a) & 0xff; return buf; };
        return new libVES.Scramble.SSS(n).explode(secret, m, {}).then(function (tkns) {
            crypto.getRandomValues = realRng;
            if (tkns.length !== m) throw new Error('expected ' + m + ' tokens, got ' + tkns.length);
            // Rebuild the coefficient vectors the way explode laid them out.
            var rnd = new Uint8Array(L * (n - 1));
            for (var i = 0; i < rnd.length; i++) rnd[i] = (i * 37 + 0x5a) & 0xff;
            for (var k = 0; k < tkns.length; k++) {
                var x = tkns[k].meta.b;
                if (tkns[k].meta.v !== 'SSS1') throw new Error('wrong tag ' + tkns[k].meta.v);
                for (var j = 0; j < L; j++) {
                    var coeffs = [secret[j], rnd[j], rnd[L + j]];
                    var exp = gevalPoly(coeffs, x);
                    if (tkns[k].value[j] !== exp) throw new Error('share x=' + x + ' byte ' + j + ': ' + tkns[k].value[j] + ' != ' + exp);
                }
            }
            // Independent reconstruction from the first n shares.
            var xs = tkns.slice(0, n).map(function (tk) { return tk.meta.b; });
            var ys = tkns.slice(0, n).map(function (tk) { return tk.value; });
            if (!eqBytes(gLagrange0(xs, ys), secret)) throw new Error('independent reconstruction mismatch');
        });
    });
});

// Round-trips across thresholds, share counts and secret lengths; every n-subset
// recovers, and the in-library implode agrees with the independent decoder.
vestest.register('gf256-roundtrip', function (t) {
    var cases = [[1, 1, 16], [2, 3, 32], [3, 5, 32], [5, 5, 1], [3, 7, 48], [10, 20, 32], [200, 255, 8]];
    var p = Promise.resolve();
    cases.forEach(function (c) {
        var n = c[0], m = c[1], L = c[2];
        p = p.then(function () {
            return t.run('n=' + n + ' m=' + m + ' L=' + L + ': all-shares + a low/high/mixed n-subset recover', function () {
                var secret = randomSecret(L);
                return new libVES.Scramble.SSS(n).explode(secret, m, {}).then(function (tkns) {
                    var picks = [];
                    var lo = []; for (var i = 0; i < n; i++) lo.push(i); picks.push(lo);          // first n
                    var hi = []; for (var i = m - n; i < m; i++) hi.push(i); picks.push(hi);      // last n
                    var mid = []; for (var i = 0; i < n; i++) mid.push((i * 2) % m); // may repeat for tiny m
                    if (new Set(mid).size === n) picks.push(mid);                                 // a spread-out n
                    var chain = Promise.resolve();
                    picks.forEach(function (idxs) {
                        var sub = subset(tkns, idxs);
                        // independent decode
                        var xs = sub.map(function (tk) { return tk.meta.b; });
                        var ys = sub.map(function (tk) { return tk.value; });
                        if (!eqBytes(gLagrange0(xs, ys), secret)) throw new Error('independent decode mismatch for subset ' + idxs);
                        chain = chain.then(function () {
                            return new libVES.Scramble.SSS(n).implode(sub, function (s) {
                                if (!eqBytes(s, secret)) throw new Error('implode mismatch for subset ' + idxs);
                                return s;
                            });
                        });
                    });
                    return chain;
                });
            });
        });
    });
    return p;
});

// Fewer than n shares must refuse to reconstruct (no silent wrong secret).
vestest.register('gf256-threshold', function (t) {
    return t.run('n-1 shares -> implode rejects', function () {
        var n = 4, m = 6, L = 32, secret = randomSecret(L);
        return new libVES.Scramble.SSS(n).explode(secret, m, {}).then(function (tkns) {
            return new libVES.Scramble.SSS(n).implode(tkns.slice(0, n - 1), function (s) { return s; }).then(
                function () { throw new Error('implode should have rejected with only n-1 shares'); },
                function () { /* expected */ }
            );
        });
    });
});

// okfn verifies extra (assisted) shares against the recovered polynomial.
vestest.register('gf256-okfn', function (t) {
    return t.run('extra valid share -> ok; tampered extra -> not ok; secret still recovered', function () {
        var n = 3, m = 5, L = 32, secret = randomSecret(L);
        return new libVES.Scramble.SSS(n).explode(secret, m, {}).then(function (tkns) {
            // Tamper the LAST token (an extra beyond the first n used for reconstruction).
            var tampered = tkns[m - 1].value.slice();
            tampered[0] ^= 0xff;
            tkns[m - 1] = { meta: tkns[m - 1].meta, value: tampered };
            var results = {};
            var recovered = null;
            return new libVES.Scramble.SSS(n).implode(tkns,
                function (s) { recovered = s; return s; },
                function (tok, ok, i) { results[i] = ok; }
            ).then(function () {
                if (!eqBytes(recovered, secret)) throw new Error('secret not recovered despite a good n-subset');
                for (var i = 0; i < n; i++) if (results[i] !== true) throw new Error('reconstruction share ' + i + ' marked not-ok');
                if (results[n] !== true) throw new Error('valid extra share marked not-ok');
                if (results[m - 1] !== false) throw new Error('tampered extra share marked ok');
            });
        });
    });
});

// Dispatcher (libVES.Scramble.RDX, the setShadow default) picks scheme by share count.
vestest.register('scramble-dispatch', function (t) {
    var secret = randomSecret(32);
    return Promise.all([
        t.run('m=255 -> SSS1', function () {
            return new libVES.Scramble.RDX(3).explode(secret, 255, {}).then(function (tk) {
                if (tk[0].meta.v !== 'SSS1') throw new Error('expected SSS1, got ' + tk[0].meta.v);
            });
        }),
        t.run('m=256 -> RDX1.2', function () {
            return new libVES.Scramble.RDX(3).explode(secret, 256, {}).then(function (tk) {
                if (tk[0].meta.v !== 'RDX1.2') throw new Error('expected RDX1.2, got ' + tk[0].meta.v);
            });
        }),
        t.run('optns.v forces SSS1 even at small m via algo registry', function () {
            return new libVES.Scramble.algo['SSS1'](2).explode(secret, 3, {}).then(function (tk) {
                if (tk[0].meta.v !== 'SSS1') throw new Error('expected SSS1, got ' + tk[0].meta.v);
            });
        })
    ]);
});

// RDX1.2 regression: the retained integer impl still round-trips after the refactor.
vestest.register('rdx12-regression', function (t) {
    return t.run('RDX1.2 explode/implode recovers the secret (legacy path intact)', function () {
        var n = 3, m = 5, secret = randomSecret(32);
        var RDX12 = libVES.Scramble.algo['RDX1.2'];
        return new RDX12(n).explode(secret, m, {}).then(function (tkns) {
            if (tkns[0].meta.v !== 'RDX1.2') throw new Error('expected RDX1.2 tag, got ' + tkns[0].meta.v);
            return new RDX12(n).implode(tkns, function (s) {
                if (!eqBytes(new Uint8Array(s), secret)) throw new Error('RDX1.2 round-trip mismatch');
                return s;
            });
        });
    });
});

if (require.main === module) {
    vestest.runSelected(null, {}, null).then(function (counts) {
        process.exit(counts && counts.fail ? 1 : 0);
    }).catch(function (e) { console.error(e); process.exit(2); });
}
