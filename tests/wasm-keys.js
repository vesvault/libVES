/*
 * tests/wasm-keys.js — offline test of the key objects the wasm engines make.
 *
 * Needs no VES account and makes no network request. In Node it loads the
 * built node bundle, with fetch stubbed to throw, as tests/ecdh-curves.js
 * does; in a browser, load it after the bundle and jstest.inc.js, once the
 * engines are loaded. The libVES instance it makes for VaultKey objects has
 * an apiUrl that cannot resolve, and nothing here asks it for a request.
 *
 *   node build.js && node tests/wasm-keys.js [wasm-bad-point wasm-key-options wasm-acquire wasm-free]
 *
 * T-0205: the wasm ECDH engine refuses a point that is not on the key's curve.
 * Decrypt and import must fail there, not go on with the unset point, which
 * derives the same all-zero secret whatever the private key.
 * T-0206: getKeyOptions and acquire on keys that are not CryptoKeys, and the
 * wasm keys one encrypt or decrypt makes are freed.
 */

if (typeof window == 'undefined') {
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
}

var WK = (function () {
    var ECDH = libVES.Algo.ECDH;
    var MSG = 'T-0205 wasm-keys';

    function msg() { return libVES.Util.StringToByteArray(MSG); }
    function opentext(buf) { return libVES.Util.ByteArrayToString(new Uint8Array(buf)); }
    function checkMsg(buf) {
        var s = opentext(buf);
        if (s !== MSG) throw new Error('decrypted ' + JSON.stringify(s) + ', expected ' + JSON.stringify(MSG));
    }

    // Encrypt MSG to pub with engine e, decrypt with priv, check the opentext.
    function roundtrip(e, pub, priv) {
        return e.encrypt(pub, msg()).then(function (ct) {
            return e.decrypt(priv, ct);
        }).then(checkMsg);
    }

    function each(list, fn) {
        return list.reduce(function (p, v) {
            return p.then(function () { return fn(v); });
        }, Promise.resolve());
    }

    function concat(a, b) {
        var r = new Uint8Array(a.byteLength + b.byteLength);
        r.set(new Uint8Array(a), 0);
        r.set(new Uint8Array(b), a.byteLength);
        return r;
    }

    // For VaultKey objects only.
    function offlineVES() {
        return new libVES({domain: 'wasm-keys.test', externalId: 'offline', apiUrl: 'https://offline.invalid/v1/'});
    }

    // ECDH ciphertext = the ephemeral's SubjectPublicKeyInfo || the AES-GCM payload
    function split(ct) {
        var data = libVES.Util.ASN1.decode(new Uint8Array(ct));
        return {oid: String(data[0][0][1]), point: data[0][1].slice(1), payload: data[1]};
    }
    function spki(oid, pt) {
        return libVES.Util.Key.toPKCS(pt, null, ECDH.asn1hdr(oid));
    }

    // Field arithmetic, to build points off the curve without asking the engine.
    function big(b) {
        var v = 0n;
        for (var i = 0; i < b.length; i++) v = (v << 8n) | BigInt(b[i]);
        return v;
    }
    function bytes(v, len) {
        var b = new Uint8Array(len);
        for (var i = len - 1; i >= 0; i--, v >>= 8n) b[i] = Number(v & 255n);
        return b;
    }
    function powmod(b, e, m) {
        var r = 1n;
        for (b %= m; e > 0n; e >>= 1n, b = b * b % m) if (e & 1n) r = r * b % m;
        return r;
    }
    // uncompressed point 04 || x || y on a 256-bit curve
    function point(x, y) {
        return concat(concat(new Uint8Array([4]), bytes(x, 32)), bytes(y, 32));
    }
    function unpack(pt) {
        return {x: big(pt.slice(1, 33)), y: big(pt.slice(33, 65))};
    }
    // Only y and p - y lie on the curve with this x, so y + 1 does not, unless y + 1 == p - y.
    function offCurve(y, p) {
        if ((2n * y + 1n) % p == 0n) throw new Error('y + 1 == p - y, pick another point');
        return (y + 1n) % p;
    }
    var P256 = 2n ** 256n - 2n ** 224n + 2n ** 192n + 2n ** 96n - 1n;
    var K1 = {
        oid: '1.3.132.0.10',
        p: 2n ** 256n - 2n ** 32n - 977n,
        on: function (x, y) { return (y * y - x * x * x - 7n) % this.p == 0n; },
        // y^2 = x^3 + 7, and p = 3 (mod 4)
        decompress: function (pt) {
            var x = big(pt.slice(1));
            var y = powmod((x * x * x + 7n) % this.p, (this.p + 1n) / 4n, this.p);
            if (!this.on(x, y)) throw new Error('not a secp256k1 x');
            if ((y & 1n) != BigInt(pt[0] & 1)) y = this.p - y;
            return {x: x, y: y};
        }
    };

    // The secret an unset point derives: SHA-384 of len zero bytes keys the AES-GCM payload.
    function zeroCipher(len) {
        return libVES.getModule(libVES.Cipher, 'AES256GCMp').then(function (m) {
            return crypto.subtle.digest({name: 'SHA-384'}, new Uint8Array(len)).then(function (h) {
                return new m(new Uint8Array(h).slice(0, m.prototype.keySize + m.prototype.ivSize));
            });
        });
    }
    function zeroPayload(len) {
        return zeroCipher(len).then(function (ci) {
            return ci.encrypt(msg(), true);
        });
    }
    function zeroOpens(ct, len) {
        return zeroCipher(len).then(function (ci) {
            return ci.decrypt(split(ct).payload, true);
        }).then(function (buf) {
            return opentext(buf) === MSG;
        }, function () {
            return false;
        });
    }

    // p must fail with the libVES.Error that importWasm throws for a refused key.
    function refused(p) {
        return Promise.resolve(p).then(function (r) {
            if (r && r.byteLength != null) throw new Error('not refused: decrypted ' + JSON.stringify(opentext(r)));
            if (!r || (r instanceof CryptoKey)) throw new Error('not refused: got ' + r);
            // an imported public key: show what encrypting to it does
            return ECDH.encrypt(r, msg()).then(function (ct) {
                return zeroOpens(ct, 32);
            }).then(function (z) {
                throw new Error('not refused: imported a wasm key' + (z ? ', and encrypt to it used the all-zero secret' : ''));
            });
        }, function (e) {
            if (!(e instanceof libVES.Error) || !/WasmECDH refused/.test(e.message)) throw new Error('not refused at the DH step: ' + (e && e.message || e));
        });
    }

    // The engine is built without memory growth: its heap is a fixed 16 MB (HEAPU8.length never
    // changes) and the engine aborts once malloc finds it full. A block too big for any freed chunk
    // comes from the top of the heap, so its address is the heap's high-water mark.
    function heapTop(w) {
        var p = w._WasmECDH_listinit(100000);
        w._WasmECDH_listfree(p);
        return p;
    }
    // heap growth per call of fn, in bytes, over n calls after a warm-up
    function growth(w, n, fn) {
        var top;
        var run = function (n) {
            var p = Promise.resolve();
            for (var i = 0; i < n; i++) p = p.then(fn);
            return p;
        };
        return run(3).then(function () {
            top = heapTop(w);
            return run(n);
        }).then(function () {
            return (heapTop(w) - top) / n;
        });
    }
    // run fn, counting the wasm ECDH keys made and freed meanwhile
    function counting(w, fn) {
        var made = 0, freed = 0;
        var mk = w._WasmECDH_new, fr = w._WasmECDH_free;
        w._WasmECDH_new = function () { made++; return mk.apply(this, arguments); };
        w._WasmECDH_free = function () { freed++; return fr.apply(this, arguments); };
        return Promise.resolve().then(fn).finally(function () {
            w._WasmECDH_new = mk;
            w._WasmECDH_free = fr;
        }).then(function (r) {
            return {made: made, freed: freed, result: r};
        });
    }

    return {ECDH: ECDH, msg: msg, checkMsg: checkMsg, roundtrip: roundtrip, each: each, concat: concat,
        offlineVES: offlineVES, split: split, spki: spki, point: point, unpack: unpack, offCurve: offCurve,
        P256: P256, K1: K1, zeroPayload: zeroPayload, refused: refused, heapTop: heapTop, growth: growth,
        counting: counting};
})();

vestest.register('wasm-bad-point', function (t) {
    var ECDH = WK.ECDH;
    var kp, kp2, eph, xy, off;
    t.head('T-0205: a point the wasm engine refuses fails at the DH step');
    return t.run('secp256k1: a real ephemeral, re-encoded uncompressed, still decrypts', function () {
        return ECDH.generate({namedCurve: 'secp256k1'}).then(function (k) {
            kp = k;
            return ECDH.generate({namedCurve: 'secp256k1'});
        }).then(function (k) {
            kp2 = k;
            return ECDH.encrypt(kp.publicKey, WK.msg());
        }).then(function (ct) {
            eph = WK.split(ct);
            if (eph.oid !== WK.K1.oid) throw new Error('ephemeral on ' + eph.oid);
            xy = WK.K1.decompress(eph.point);
            off = WK.point(xy.x, WK.offCurve(xy.y, WK.K1.p));
            return ECDH.decrypt(kp.privateKey, WK.concat(WK.spki(eph.oid, WK.point(xy.x, xy.y)), eph.payload));
        }).then(WK.checkMsg);
    }).then(function () {
        return t.run('secp256k1: the same ephemeral with y + 1, off the curve, is refused', function () {
            return WK.refused(ECDH.decrypt(kp.privateKey, WK.concat(WK.spki(eph.oid, off), eph.payload)));
        });
    }).then(function () {
        return t.run('secp256k1: a ciphertext made for the all-zero secret is refused by any key', function () {
            return WK.zeroPayload(32).then(function (pl) {
                var forged = WK.concat(WK.spki(eph.oid, off), pl);
                return WK.refused(ECDH.decrypt(kp.privateKey, forged)).then(function () {
                    return WK.refused(ECDH.decrypt(kp2.privateKey, forged));
                });
            });
        });
    }).then(function () {
        return t.run('secp256k1: a P-256 point, from the wrong curve, is refused', function () {
            return crypto.subtle.generateKey({name: 'ECDH', namedCurve: 'P-256'}, true, ['deriveBits']).then(function (wc) {
                return crypto.subtle.exportKey('raw', wc.publicKey);
            }).then(function (raw) {
                var pt = new Uint8Array(raw), q = WK.unpack(pt);
                if (WK.K1.on(q.x, q.y)) throw new Error('the P-256 point is on secp256k1 too, run again');
                return WK.zeroPayload(32).then(function (pl) {
                    return WK.refused(ECDH.decrypt(kp.privateKey, WK.concat(WK.spki(eph.oid, pt), pl)));
                });
            });
        });
    }).then(function () {
        return t.run('secp256k1: an off-curve public key PEM is refused on import', function () {
            return WK.refused(ECDH.import(libVES.Util.PEM.encode(WK.spki(eph.oid, off), 'PUBLIC KEY')));
        });
    }).then(function () {
        // a wasm P-256 key, as libVES.Util.EC.import falls back to (see tests/ecdh-curves.js)
        var wc, w, e2, off2;
        return t.run('P-256 on the wasm path: an off-curve ephemeral is refused', function () {
            return ECDH.generate({namedCurve: 'P-256'}).then(function (k) {
                wc = k;
                return ECDH.export(wc.privateKey, {opentext: true});
            }).then(function (pem) {
                return ECDH.importWasm('P-256', libVES.Util.PEM.toDER(pem));
            }).then(function (k) {
                w = k;
                return ECDH.encrypt(wc.publicKey, WK.msg());
            }).then(function (ct) {
                e2 = WK.split(ct);
                var q = WK.unpack(e2.point);
                off2 = WK.point(q.x, WK.offCurve(q.y, WK.P256));
                return ECDH.decrypt(w, ct);
            }).then(WK.checkMsg).then(function () {
                return WK.refused(ECDH.decrypt(w, WK.concat(WK.spki(e2.oid, off2), e2.payload)));
            });
        }).then(function () {
            return t.run('P-256: an off-curve public key PEM is refused on import', function () {
                return WK.refused(ECDH.import(libVES.Util.PEM.encode(WK.spki(e2.oid, off2), 'PUBLIC KEY')));
            });
        });
    });
});

vestest.register('wasm-key-options', function (t) {
    t.head('T-0206: VaultKey.getKeyOptions on each kind of key');
    return WK.each([
        ['ML-KEM-768', {oqsAlgo: 'ML-KEM-768'}, {oqsAlgo: 'ML-KEM-768'}],
        ['WebCrypto P-256', {namedCurve: 'P-256'}, {namedCurve: 'P-256'}],
        ['wasm secp256k1', {namedCurve: 'secp256k1'}, {namedCurve: 'secp256k1'}],
        ['RSA 2048', {modulusLength: 2048}, {modulusLength: 2048, publicExponent: [1, 0, 1]}]
    ], function (c) {
        return t.run(c[0], function () {
            var vk = new libVES.VaultKey({type: 'current'}, WK.offlineVES());
            return vk.generate('veskey', c[1]).then(function () {
                return vk.getKeyOptions();
            }).then(function (o) {
                if (o && o.publicExponent) o.publicExponent = Array.from(new Uint8Array(o.publicExponent));
                if (JSON.stringify(o) !== JSON.stringify(c[2])) throw new Error('got ' + JSON.stringify(o));
            });
        });
    });
});

vestest.register('wasm-acquire', function (t) {
    var ECDH = WK.ECDH, OQS = libVES.Algo.OQS;
    var kp;
    var check = function (ks, tag, priv) {
        if (!ks || !ks.engine || ks.engine.tag !== tag) throw new Error('engine ' + (ks && ks.engine && ks.engine.tag));
        if (!ks.publicKey) throw new Error('no publicKey');
        if (!priv != !ks.privateKey) throw new Error(priv ? 'no privateKey' : 'a privateKey');
    };
    t.head('T-0206: libVES.Algo.acquire on wasm keys');
    return t.run('a wasm ECDH key pair', function () {
        return ECDH.generate({namedCurve: 'secp256k1'}).then(function (k) {
            kp = k;
            return libVES.Algo.acquire(kp);
        }).then(function (ks) {
            check(ks, 'ECDH', true);
            if (ks.privateKey !== kp.privateKey) throw new Error('another privateKey');
            if (ks.publicKey.private) throw new Error('the publicKey is private');
            return WK.roundtrip(ECDH, ks.publicKey, ks.privateKey);
        });
    }).then(function () {
        return t.run('a bare wasm ECDH private key, from PEM', function () {
            return ECDH.export(kp.privateKey, {opentext: true}).then(function (pem) {
                return ECDH.import(pem);
            }).then(function (k) {
                return libVES.Algo.acquire(k);
            }).then(function (ks) {
                check(ks, 'ECDH', true);
                return WK.roundtrip(ECDH, ks.publicKey, ks.privateKey).then(function () {
                    return WK.roundtrip(ECDH, ks.publicKey, kp.privateKey);
                });
            });
        });
    }).then(function () {
        return t.run('a bare wasm ECDH public key, from PEM', function () {
            return ECDH.export(kp.publicKey).then(function (pem) {
                return ECDH.import(pem);
            }).then(function (k) {
                return libVES.Algo.acquire(k);
            }).then(function (ks) {
                check(ks, 'ECDH', false);
                return WK.roundtrip(ECDH, ks.publicKey, kp.privateKey);
            });
        });
    }).then(function () {
        return t.run('a wasm ECDH private key PEM', function () {
            return ECDH.export(kp.privateKey, {opentext: true}).then(function (pem) {
                return libVES.Algo.acquire(pem);
            }).then(function (ks) {
                check(ks, 'ECDH', true);
                return WK.roundtrip(ECDH, ks.publicKey, ks.privateKey);
            });
        });
    }).then(function () {
        return t.run('VaultKey.generate with a wasm ECDH key pair', function () {
            var vk = new libVES.VaultKey({type: 'current'}, WK.offlineVES());
            var pems;
            // generate sets algo once acquire is done, and the keys' PEMs wait for that
            return vk.generate('veskey', {privateKey: kp}).then(function () {
                return Promise.all([vk.getPublicKey(), vk.getPrivateKey()]);
            }).then(function (p) {
                pems = p;
                return vk.getAlgo();
            }).then(function (algo) {
                if (algo !== 'ECDH') throw new Error('algo ' + algo);
                if (!/ENCRYPTED PRIVATE KEY/.test(pems[1])) throw new Error('private key not encrypted');
                return Promise.all([ECDH.import(pems[0]), ECDH.import(pems[1], {password: 'veskey'})]);
            }).then(function (ks) {
                return WK.roundtrip(ECDH, ks[0], ks[1]).then(function () {
                    return WK.roundtrip(ECDH, ks[0], kp.privateKey);
                });
            });
        });
    }).then(function () {
        var okp;
        return t.run('an OQS key pair, and a bare OQS private key from PEM', function () {
            return OQS.generate({oqsAlgo: 'ML-KEM-768'}).then(function (k) {
                okp = k;
                return libVES.Algo.acquire(okp);
            }).then(function (ks) {
                check(ks, 'OQS', true);
                return WK.roundtrip(OQS, ks.publicKey, ks.privateKey);
            }).then(function () {
                return OQS.export(okp.privateKey, {opentext: true});
            }).then(function (pem) {
                return OQS.import(pem);
            }).then(function (k) {
                return libVES.Algo.acquire(k);
            }).then(function (ks) {
                check(ks, 'OQS', true);
                return WK.roundtrip(OQS, ks.publicKey, okp.privateKey);
            });
        });
    });
});

vestest.register('wasm-free', function (t) {
    var ECDH = WK.ECDH;
    var N = 100;
    var w, kp, kp2, other, ct0, keyBytes, setpubBytes;
    var ops = function (label, fn, limit) {
        return t.run(label, function () {
            var per;
            return WK.counting(w, function () {
                return WK.growth(w, N, fn).then(function (g) { per = g; });
            }).then(function (c) {
                t.info('  ' + c.made + ' wasm keys made, ' + c.freed + ' freed; heap +' + per + ' bytes per call');
                if (c.made !== c.freed) throw new Error((c.made - c.freed) + ' wasm keys not freed');
                if (per > limit) throw new Error('heap grows by ' + per + ' bytes per call, more than ' + limit);
            });
        });
    };
    t.head('T-0206: the wasm keys one encrypt or decrypt makes are freed');
    return t.run('setup', function () {
        return ECDH.wasm().then(function (wasm) {
            w = wasm;
            return ECDH.generate({namedCurve: 'secp256k1'});
        }).then(function (k) {
            kp = k;
            return ECDH.generate({namedCurve: 'secp256k1'});
        }).then(function (k) {
            kp2 = k;
            return ECDH.generate({namedCurve: 'brainpoolP256r1'});
        }).then(function (k) {
            other = k;
            return ECDH.encrypt(kp.publicKey, WK.msg());
        }).then(function (ct) {
            ct0 = ct;
            // for scale: a key never freed, and what the engine's setpub leaks by itself (WasmECDH.c)
            var keys = [];
            return WK.growth(w, 10, function () {
                var k = w.init('secp256k1');
                w.generate(k);
                keys.push(k);
            }).then(function (g) {
                keyBytes = g;
                keys.forEach(function (k) { w.free(k); });
                var pub = w.getpub(kp.publicKey);
                return WK.growth(w, 10, function () {
                    var k = w.init('secp256k1');
                    w.setpub(k, pub);
                    w.free(k);
                });
            }).then(function (g) {
                setpubBytes = g;
                t.info('  a wasm secp256k1 key takes ' + keyBytes + ' bytes; the engine\'s setpub leaks ' + setpubBytes + ' by itself');
                if (!(keyBytes > 0)) throw new Error('heap probe does not see a key');
            });
        });
    }).then(function () {
        return ops(N + ' x encrypt on secp256k1', function () {
            return ECDH.encrypt(kp.publicKey, WK.msg());
        }, 0);
    }).then(function () {
        // the ephemeral's import goes through setpub, which leaks inside the engine
        return ops(N + ' x decrypt on secp256k1', function () {
            return ECDH.decrypt(kp.privateKey, ct0).then(WK.checkMsg);
        }, setpubBytes);
    }).then(function () {
        return ECDH.encrypt(kp2.publicKey, WK.msg()).then(function (ct) {
            return ops(N + ' x decrypt with another secp256k1 key, failing AES-GCM', function () {
                return ECDH.decrypt(kp.privateKey, ct).then(function () {
                    throw new Error('decrypted with the wrong key');
                }, function (e) {
                    if (!(e instanceof libVES.Error) || !/decrypting ECIES payload/.test(e.message)) throw e;
                });
            }, setpubBytes);
        });
    }).then(function () {
        return t.run('the keys made before the loops still work', function () {
            return ECDH.decrypt(kp.privateKey, ct0).then(WK.checkMsg).then(function () {
                return WK.roundtrip(ECDH, kp.publicKey, kp.privateKey);
            }).then(function () {
                return WK.roundtrip(ECDH, other.publicKey, other.privateKey);
            });
        });
    });
});

if (typeof require != 'undefined' && typeof module != 'undefined' && require.main === module) {
    // a promise that never settles ends node quietly, with status 0
    var done = false;
    process.on('exit', function () {
        if (!done) { console.error('a test never finished'); process.exitCode = 3; }
    });
    // node tests/wasm-keys.js [test name ...]
    vestest.runSelected(process.argv.length > 2 ? process.argv.slice(2) : null, {}, null).then(function (counts) {
        done = true;
        process.exit(counts && counts.fail ? 1 : 0);
    }).catch(function (e) { console.error(e); process.exit(2); });
}
