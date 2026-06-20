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
 * (c) 2022 VESvault Corp
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
 * libVES.Algo.OQS.js             libVES: Post-quantum support via liboqs
 *
 ***************************************************************************/

libVES.Algo.OQS = {
    tag: 'OQS',
    wasm: function() {
	if (!this.wasmP) this.wasmP = (typeof(WasmOQS) == 'function' ? Promise.resolve()
	    : libVES.Util.loadWasm(WasmOQSinit.baseUrl + 'WasmOQS.js')
	).then(function() {
	    return WasmOQS(WasmOQSinit);
	});
	return this.wasmP;
    },
    checkLimits: function(k) {
	return k.pub.byteLength + k.priv.byteLength <= libVES.maxKeyLen && k.ctextlen + 64 <= libVES.maxEncDataLen;
    },
    decrypt: function(k,buf) {
	return this.wasm().then(function(wasm) {
	    var b = new Uint8Array(buf);
	    if (b.byteLength <= k.ctextlen) throw new libVES.Error('InvalidValue', 'Ciphertext is too short');
	    var secret = wasm.decaps(k, b.slice(0, k.ctextlen));
	    if (!secret) throw new libVES.Error('InvalidValue', 'OQS decryption error');
	    return libVES.Algo.OQS.cipher(secret).then(function(ci) {
		return ci.decrypt(b.slice(k.ctextlen), true).catch(function(e) {
		    if (e instanceof libVES.Error) throw e;
		    throw new libVES.Error('InvalidValue', 'Error decrypting ECIES payload: Invalid ciphertext?',{error:e});
		});
	    }).catch(function(e) {
		if (e instanceof libVES.Error) throw e;
		throw new libVES.Error('InvalidValue', 'Error negotiating ECIES cipher key: Invalid ciphertext?',{error:e});
	    });
	})
    },
    encrypt: function(k, buf) {
	return this.wasm().then(function(wasm) {
	    var ctext = wasm.encaps(k);
	    if (!ctext) throw new libVES.Error('InvalidValue', 'Error generating OQS secret');
	    return libVES.Algo.OQS.cipher(wasm.decaps(k)).then(function(ci) {
		return ci.encrypt(buf, true).then(function(ctext2) {
		    var buf = new Uint8Array(ctext.byteLength + ctext2.byteLength);
		    buf.set(new Uint8Array(ctext),0);
		    buf.set(new Uint8Array(ctext2),ctext.byteLength);
		    return buf;
		});
	    }).catch(function(e) {
		if (e instanceof libVES.Error) throw e;
		throw new libVES.Error('InvalidValue', 'Error generating ECIES cipher',{error:e});
	    });
	});
    },
    cipher: function(secret) {
	return libVES.getModule(libVES.Cipher,'AES256GCMp').then(function(m) {
	    return crypto.subtle.digest({name:'SHA-384'}, secret).then(function(buf) {
		return new m(new Uint8Array(buf).slice(0, m.prototype.keySize + m.prototype.ivSize));
	    });
	});
    },
    import: function(data,optns) {
	return libVES.Util.PEM.import(data,optns);
    },
    export: function(data, optns) {
	if (!data || !data.ptr) throw new libVES.Error('Internal', "Unknown type of key object");
	var std = libVES.Algo.OQS.MLKEM.export(data, optns);
	if (std) return std;
	var oid = [new libVES.Util.OID(libVES.Algo.OQS.OID), libVES.Util.StringToByteArray(data.algo)];
	return libVES.Util.Key.export(data.pub, data.priv, oid, optns);
    },
    generate: function(optns) {
	var algo = optns ? optns.oqsAlgo : null;
	if (!algo) algo = this.defaultAlgo;
	return this.wasm().then(function(wasm) {
	    var k = wasm.init(algo, true);
	    if (!k) throw new libVES.Error('InvalidValue', 'OQS key init failed');
	    if (!libVES.Algo.OQS.checkLimits(k)) throw wasm.free(k), new libVES.Error('Internal', 'OQS key is too large for VES');
	    if (!wasm.generate(k)) throw wasm.free(k), new libVES.Error('Internal', 'OQS generate failed');
	    var pub = new wasm.Key(k.algo);
	    for (var i in k) if (i != 'priv') pub[i] = k[i];
	    return {privateKey: k, publicKey: pub};
	});
    },
    getKeyOptions: function(key) {
	return {oqsAlgo: k.algo};
    },
    getMethods: function() {
	return this.wasm().then(function(wasm) {
	    return wasm.getalgos().filter(function(algo) {
		var k = wasm.init(algo, true);
		if (!k) return false;
		var f = libVES.Algo.OQS.checkLimits(k);
		wasm.free(k);
		return f;
	    }).map(function(algo) {
		return {oqsAlgo: algo};
	    });
	});
    },
    Util: {
	import: function(args,chain,optns) {
	    var algo = libVES.Util.ByteArrayToString(args);
	    return chain('container').then(function(der) {
		return libVES.Util.Key.fromDER(der, function(pub, priv, pubBits) {
		    return libVES.Algo.OQS.wasm().then(function(wasm) {
			var k = wasm.init(algo, !!priv);
			if (!k) throw new libVES.Error('InvalidValue', 'OQS key init failed (bad algo?)');
			var s = function(dst, src) {
			    if (!dst || !src || dst.byteLength != src.byteLength) throw wasm.free(k), new libVES.Error('InvalidValue', 'Incorrect OQS key size');
			    dst.set(src, 0);
			};
			if (priv) s(k.priv, priv);
			s(k.pub, pub);
			return k;
		    });
		});
	    });
	}
    },
    OID: '1.3.6.1.4.1.53675.3.5',
    defaultAlgo: 'Kyber768'
};

/*
 * ML-KEM standard PEM/DER encoding (FIPS 203 / draft-ietf-lamps-kyber-certificates).
 *
 *   AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ABSENT }
 *   id-alg-ml-kem-512  = 2.16.840.1.101.3.4.4.1
 *   id-alg-ml-kem-768  = 2.16.840.1.101.3.4.4.2
 *   id-alg-ml-kem-1024 = 2.16.840.1.101.3.4.4.3
 *
 *   ML-KEM-PrivateKey ::= CHOICE {
 *       seed        [0] IMPLICIT OCTET STRING,    -- 64 bytes (d || z) in current drafts
 *       expandedKey     OCTET STRING,             -- raw decapsulation key
 *       both            SEQUENCE { seed OCTET STRING, expandedKey OCTET STRING }
 *   }
 *
 * Export: emits the expandedKey CHOICE plus an outer [1] IMPLICIT BIT STRING publicKey,
 * so loaders don't have to re-expand the seed via libOQS at unlock time.
 * Import: accepts all three CHOICE forms (seed-only requires a libOQS build with
 * keypair-from-seed; expandedKey/both work with the current WasmOQS).
 */
libVES.Algo.OQS.MLKEM = {
    SPECS: {
	ML_KEM_512:  {oid: '2.16.840.1.101.3.4.4.1', oqs: 'ML-KEM-512',  pubLen: 800,  privLen: 1632},
	ML_KEM_768:  {oid: '2.16.840.1.101.3.4.4.2', oqs: 'ML-KEM-768',  pubLen: 1184, privLen: 2400},
	ML_KEM_1024: {oid: '2.16.840.1.101.3.4.4.3', oqs: 'ML-KEM-1024', pubLen: 1568, privLen: 3168}
    },
    findSpec: function(algo) {
	for (var k in this.SPECS) if (this.SPECS[k].oqs === algo) return this.SPECS[k];
	return null;
    },
    _readTLV: function(buf, off) {
	var tag = buf[off];
	var p = off + 1;
	var l = buf[p++];
	var len;
	if (l < 128) len = l;
	else {
	    len = 0;
	    for (var i = 0; i < (l & 0x7f); i++) len = (len << 8) | buf[p++];
	}
	return {tag: tag, off: p, len: len, end: p + len};
    },
    _slice: function(buf, off, len) {
	return new Uint8Array(buf.buffer, buf.byteOffset + off, len);
    },
    parsePrivChoice: function(spec, buf) {
	if (!buf || !buf.byteLength) throw new libVES.Error('InvalidValue', 'ML-KEM private key is empty');
	var t = this._readTLV(buf, 0);
	var v = this._slice(buf, t.off, t.len);
	switch (t.tag) {
	    case 0x80: // [0] IMPLICIT OCTET STRING seed
		return {seed: v};
	    case 0x04: // OCTET STRING expandedKey
		if (v.byteLength !== spec.privLen) throw new libVES.Error('InvalidValue', 'ML-KEM expandedKey length is ' + v.byteLength + ', expected ' + spec.privLen);
		return {expanded: v};
	    case 0x30: case 0xA1: { // SEQUENCE both (with or without IMPLICIT [1] tag)
		var s = this._readTLV(v, 0);
		if (s.tag !== 0x04) throw new libVES.Error('InvalidValue', 'ML-KEM CHOICE "both": expected OCTET STRING seed');
		var seed = this._slice(v, s.off, s.len);
		var e = this._readTLV(v, s.end);
		if (e.tag !== 0x04) throw new libVES.Error('InvalidValue', 'ML-KEM CHOICE "both": expected OCTET STRING expandedKey');
		var expanded = this._slice(v, e.off, e.len);
		if (expanded.byteLength !== spec.privLen) throw new libVES.Error('InvalidValue', 'ML-KEM expandedKey length mismatch');
		return {seed: seed, expanded: expanded};
	    }
	    default:
		throw new libVES.Error('InvalidValue', 'Unknown ML-KEM-PrivateKey CHOICE tag: 0x' + t.tag.toString(16));
	}
    },
    extractPubFromExpanded: function(spec, expanded) {
	// FIPS 203 §7.3: dk = (dk_PKE || ek || H(ek) || z); ek starts at dk_PKE length.
	var off = spec.privLen - 64 - spec.pubLen;
	return expanded.slice(off, off + spec.pubLen);
    },
    importKey: function(spec, der) {
	der = new Uint8Array(der);
	var top = this._readTLV(der, 0);
	if (top.tag !== 0x30) throw new libVES.Error('InvalidValue', 'Expected outer SEQUENCE');
	var off = top.off;
	var first = this._readTLV(der, off);
	if (first.tag === 0x02) {
	    // OneAsymmetricKey (PKCS#8 v2)
	    off = first.end;
	    var algo = this._readTLV(der, off); off = algo.end;
	    var priv = this._readTLV(der, off);
	    if (priv.tag !== 0x04) throw new libVES.Error('InvalidValue', 'Expected OCTET STRING privateKey');
	    var choice = this.parsePrivChoice(spec, this._slice(der, priv.off, priv.len));
	    off = priv.end;
	    var pub = null;
	    while (off < top.end) {
		var t = this._readTLV(der, off);
		if (t.tag === 0x81) { // [1] IMPLICIT BIT STRING publicKey
		    var v = this._slice(der, t.off, t.len);
		    pub = v[0] === 0x00 ? v.slice(1) : v;
		    break;
		} else if (t.tag === 0xA1) { // [1] EXPLICIT BIT STRING (defensive)
		    var w = this._slice(der, t.off, t.len);
		    var inner = this._readTLV(w, 0);
		    if (inner.tag === 0x03) {
			var b = this._slice(w, inner.off, inner.len);
			pub = b[0] === 0x00 ? b.slice(1) : b;
		    }
		    break;
		}
		off = t.end;
	    }
	    if (!pub && choice.expanded) pub = this.extractPubFromExpanded(spec, choice.expanded);
	    return this.materialize(spec, pub, choice);
	}
	if (first.tag === 0x30) {
	    // SubjectPublicKeyInfo
	    off = first.end;
	    var bits = this._readTLV(der, off);
	    if (bits.tag !== 0x03) throw new libVES.Error('InvalidValue', 'Expected BIT STRING for ML-KEM public key');
	    var v = this._slice(der, bits.off, bits.len);
	    var pub = v[0] === 0x00 ? v.slice(1) : v;
	    return this.materialize(spec, pub, null);
	}
	throw new libVES.Error('InvalidValue', 'Unknown ML-KEM key format');
    },
    materialize: function(spec, pub, choice) {
	return libVES.Algo.OQS.wasm().then(function(wasm) {
	    var k = wasm.init(spec.oqs, !!choice);
	    if (!k) throw new libVES.Error('InvalidValue', 'libOQS does not support ' + spec.oqs + ' in this build');
	    var assign = function(dst, src, label) {
		if (!dst || !src || dst.byteLength !== src.byteLength) {
		    wasm.free(k);
		    throw new libVES.Error('InvalidValue', 'Incorrect ML-KEM ' + label + ' size');
		}
		dst.set(src, 0);
	    };
	    if (choice && choice.expanded) {
		assign(k.priv, choice.expanded, 'expandedKey');
		assign(k.pub, pub || libVES.Algo.OQS.MLKEM.extractPubFromExpanded(spec, choice.expanded), 'public key');
	    } else if (choice && choice.seed) {
		if (!wasm.generateFromSeed) {
		    wasm.free(k);
		    throw new libVES.Error('InvalidValue', 'ML-KEM seed-only CHOICE requires WasmOQS rebuilt against libOQS >= 0.13 (no _WasmOQS_generate_seed export)');
		}
		if (!wasm.generateFromSeed(k, choice.seed)) {
		    wasm.free(k);
		    throw new libVES.Error('InvalidValue', 'ML-KEM seed expansion failed (seed length must be ' + (wasm.seedlen ? wasm.seedlen(k) : '?') + ' bytes for ' + spec.oqs + ')');
		}
		if (pub) for (var i = 0; i < pub.byteLength; i++) if (k.pub[i] !== pub[i]) {
		    wasm.free(k);
		    throw new libVES.Error('InvalidValue', 'ML-KEM seed import: derived public key mismatch with the imported public key');
		}
	    } else {
		if (!pub) { wasm.free(k); throw new libVES.Error('InvalidValue', 'Missing ML-KEM public key'); }
		assign(k.pub, pub, 'public key');
	    }
	    return k;
	});
    },
    exportPub: function(spec, pub) {
	var bits = new Uint8Array(pub.byteLength + 1);
	bits.set(pub, 1);
	bits.ASN1type = 3;
	return libVES.Util.ASN1.encode([[
	    [new libVES.Util.OID(spec.oid)],
	    bits
	]]);
    },
    exportPriv: function(spec, pub, priv) {
	// Inner CHOICE: expandedKey OCTET STRING (tag 0x04).
	var inner = libVES.Util.ASN1.encode([new Uint8Array(priv)]);
	// privateKey OCTET STRING whose value bytes are the CHOICE TLV.
	var privOctet = new Uint8Array(inner);
	privOctet.ASN1type = 4;
	var seq = [
	    0,
	    [new libVES.Util.OID(spec.oid)],
	    privOctet
	];
	if (pub) {
	    var pubBits = new Uint8Array(pub.byteLength + 1);
	    pubBits.set(pub, 1);
	    pubBits.ASN1type = 0x81; // [1] IMPLICIT BIT STRING
	    seq.push(pubBits);
	}
	return libVES.Util.ASN1.encode([seq]);
    },
    export: function(data, optns) {
	var spec = this.findSpec(data.algo);
	if (!spec) return null;
	if (data.priv) return libVES.Util.PKCS8.encode8(this.exportPriv(spec, data.pub, data.priv), optns);
	return libVES.Util.PEM.encode(this.exportPub(spec, data.pub), 'PUBLIC KEY');
    },
    // bind(spec) is the per-OID initializer: ASN1.import dispatches via OID.object() which
    // synchronously calls libVES.Util.OID[<oid>](), and bind returns a thenable carrying the
    // spec-specific import handler. No load-time iteration over SPECS — each OID entry below
    // is its own initialization function.
    bind: function(spec) {
	return Promise.resolve({
	    spec: spec,
	    import: function(args, chain, optns) {
		return chain('container').then(function(der) {
		    return libVES.Algo.OQS.MLKEM.importKey(spec, der);
		});
	    }
	});
    }
};

libVES.Util.OID['2.16.840.1.101.3.4.4.1'] = function() { return libVES.Algo.OQS.MLKEM.bind(libVES.Algo.OQS.MLKEM.SPECS.ML_KEM_512); };
libVES.Util.OID['2.16.840.1.101.3.4.4.2'] = function() { return libVES.Algo.OQS.MLKEM.bind(libVES.Algo.OQS.MLKEM.SPECS.ML_KEM_768); };
libVES.Util.OID['2.16.840.1.101.3.4.4.3'] = function() { return libVES.Algo.OQS.MLKEM.bind(libVES.Algo.OQS.MLKEM.SPECS.ML_KEM_1024); };

libVES.Algo.all.push('OQS');

var WasmOQSinit = {
    Key: function(algo) {
	this.algo = algo;
    },
    init: function(algo, fpriv) {
	var a = new Uint8Array(libVES.Util.StringToByteArray(algo));
	var arg1 = new Uint8Array(this.HEAPU8.buffer, 16, 48);
	arg1.set(a);
	arg1.set([0], a.byteLength);
	var ptr = this._WasmOQS_new(arg1.byteOffset, fpriv);
	if (!ptr) return null;
	var key = new this.Key(algo);
	key.ptr = ptr;
	var priv = this._WasmOQS_priv(ptr);
	if (priv) key.priv = new Uint8Array(this.HEAPU8.buffer, priv, this._WasmOQS_privlen(ptr));
	key.pub = new Uint8Array(this.HEAPU8.buffer, this._WasmOQS_pub(ptr), this._WasmOQS_publen(ptr));
	key.secretlen = this._WasmOQS_decaps(key.ptr, null, null);
	key.ctextlen = this._WasmOQS_encaps(key.ptr, null, null);
	return key;
    },
    generate: function(key) {
	return this._WasmOQS_generate(key.ptr) >= 0;
    },
    seedlen: function(key) {
	if (typeof this._WasmOQS_seedlen != 'function') return 0;
	return this._WasmOQS_seedlen(key.ptr);
    },
    generateFromSeed: function(key, seed) {
	if (typeof this._WasmOQS_generate_seed != 'function') return false;
	var sl = this._WasmOQS_seedlen(key.ptr);
	if (sl <= 0 || seed.byteLength != sl) return false;
	new Uint8Array(this.HEAPU8.buffer, this._WasmOQS_seedbuf, sl).set(new Uint8Array(seed));
	return this._WasmOQS_generate_seed(key.ptr, sl) >= 0;
    },
    encaps: function(key) {
	var arg1 = new Uint8Array(this.HEAPU8.buffer, this._WasmOQS_secretbuf, this._WasmOQS_decaps(key.ptr, null, null));
	var arg2 = new Uint8Array(this.HEAPU8.buffer, this._WasmOQS_ctextbuf, this._WasmOQS_encaps(key.ptr, null, null));
	if (this._WasmOQS_encaps(key.ptr, arg2.byteOffset, arg1.byteOffset) <= 0) return null;
	key.secret = new Uint8Array(arg1.byteLength);
	key.secret.set(arg1);
	var ctext = new Uint8Array(arg2.byteLength);
	ctext.set(arg2);
	return ctext;
    },
    decaps: function(key, ctext) {
	var arg1 = new Uint8Array(this.HEAPU8.buffer, this._WasmOQS_secretbuf, this._WasmOQS_decaps(key.ptr, null, null));
	if (ctext) {
	    if (ctext.byteLength != this._WasmOQS_encaps(key.ptr, null, null)) return null;
	    var arg2 = new Uint8Array(this.HEAPU8.buffer, this._WasmOQS_ctextbuf, ctext.byteLength);
	    arg2.set(ctext);
	    if (this._WasmOQS_decaps(key.ptr, arg1.byteOffset, arg2.byteOffset) <= 0) return null;
	}
	var secret = new Uint8Array(arg1.byteLength);
	secret.set(arg1);
	return secret;
    },
    free: function(key) {
	this._WasmOQS_free(key.ptr);
	delete(key.ptr);
    },
    getalgos: function() {
	var algos = [];
	var a;
	for (var i = 0; a = this._WasmOQS_enumalgo(i); i++) {
	    var s = new Uint8Array(this.HEAPU8.buffer, a);
	    var p = s.indexOf(0);
	    if (!p) continue;
	    algos.push(libVES.Util.ByteArrayToString(s.slice(0, p)));
	}
	return algos;
    },
    test: function(algo) {
	var k = this.init(algo, 1);
	this.generate(k);
	var ctext = this.encaps(k);
	var secret = this.decaps(k);
	console.log(secret);
	var secret2 = this.decaps(k, ctext);
	console.log(secret2);
    },
    locateFile: function(file) {
	return this.baseUrl + file;
    },
    baseUrl: 'https://ves.host/pub/'
};
