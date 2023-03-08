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
 * libVES.Algo.js             libVES: Vault Key algorithms: ECDH, RSA,
 *                                    via crypto.subtle
 *
 ***************************************************************************/
libVES.Algo = {
    ECDH: {
	tag: 'ECDH',
	defaultCurve: 'P-521',
	decrypt: function(k,buf) {
	    var b = new Uint8Array(buf);
	    var data = libVES.Util.ASN1.decode(b);
	    if (!data || data.length < 2) throw new libVES.Error('InvalidValue','Error parsing ECIES: Invalid ciphertext?');
	    return libVES.Util.ASN1.import(b.slice(0,b.byteLength - data[1].byteLength),{decoded:data[0]}).then(function(eKey) {
		return libVES.Algo.ECDH.cipher(k,eKey).then(function(ci) {
		    return ci.decrypt(data[1],true).catch(function(e) {
			if (e instanceof libVES.Error) throw e;
			throw new libVES.Error('InvalidValue','Error decrypting ECIES payload: Invalid ciphertext?',{error:e});
		    });
		}).catch(function(e) {
		    if (e instanceof libVES.Error) throw e;
		    throw new libVES.Error('InvalidValue','Error negotiating DH cipher key: Invalid ciphertext?',{error:e});
		});
	    }).catch(function(e) {
		if (e instanceof libVES.Error) throw e;
		throw new libVES.Error('InvalidValue','Error loading EC ephemeral: Invalid ciphertext?',{error:e});
	    });
	},
	encrypt: function(k,buf) {
	    return libVES.Algo.ECDH.eKey(k).then(function(eKey) {
		return libVES.Algo.ECDH.cipher(eKey.privateKey,k).then(function(ci) {
		    return Promise.all([
			((k instanceof CryptoKey)
			    ? crypto.subtle.exportKey('spki',eKey.publicKey)
			    : libVES.Algo.ECDH.wasm().then(function(wasm) {
				return libVES.Util.Key.toPKCS(wasm.getpub(eKey.publicKey), null, libVES.Algo.ECDH.asn1hdr(wasm.getoid(eKey.publicKey)));
			    })
			),
			ci.encrypt(buf,true)
		    ]).then(function(bufs) {
			var buf = new Uint8Array(bufs[0].byteLength + bufs[1].byteLength);
			buf.set(new Uint8Array(bufs[0]),0);
			buf.set(new Uint8Array(bufs[1]),bufs[0].byteLength);
			return buf;
		    });
		}).catch(function(e) {
		    if (e instanceof libVES.Error) throw e;
		    throw new libVES.Error('InvalidValue','Error generating ECIES DH cipher',{error:e});
		});
	    });
	},
	eKey: function(pub) {
	    if (pub instanceof CryptoKey) return crypto.subtle.exportKey('jwk',pub).then(function(kdata) {
		return crypto.subtle.generateKey({name:'ECDH',namedCurve: kdata.crv},true,['deriveKey','deriveBits']).catch(function(e) {
		    throw new libVES.Error('InvalidValue','Error generating ECIES ephemeral',{error: e});
		});
	    });
	    return this.wasm().then(function(wasm) {
		var k = wasm.init(pub.curve);
		wasm.generate(k);
		return wasm.privpub(k);
	    });
	},
	derive: function(priv, pub) {
	    if (pub instanceof CryptoKey) return Promise.resolve(libVES.Algo.ECDH.curveBytes[pub.algorithm.namedCurve] || crypto.subtle.exportKey('jwk', pub).then(function(jwk) {
		return jwk.x.length * 3 / 4;
	    })).then(function(len) {
		return crypto.subtle.deriveBits({name: 'ECDH', public: pub}, priv, 8 * len);
	    });
	    return this.wasm().then(function(wasm) {
		return wasm.derive(priv, pub);
	    });
	},
	cipher: function(priv, pub) {
	    return libVES.getModule(libVES.Cipher,'AES256GCMp').then(function(m) {
		return libVES.Algo.ECDH.derive(priv, pub).then(function(raw) {
		    return crypto.subtle.digest({name:'SHA-384'},raw).then(function(buf) {
			return new m(new Uint8Array(buf).slice(0,m.prototype.keySize + m.prototype.ivSize));
		    });
		});
	    });
	},
	curveBytes: {
	    'P-256': 32,
	    'P-384': 48,
	    'P-521': 66
	},
	import: function(data,optns) {
	    return libVES.Util.PEM.import(data,optns);
	},
	export: function(data,optns) {
	    if (data instanceof CryptoKey) switch (data.type) {
		case 'private': return libVES.Util.PKCS8.encode(data, optns);
		case 'public':
		    return crypto.subtle.exportKey('spki', data).then(function(der) {
			var asn = libVES.Util.ASN1.decode(new Uint8Array(der))[0];
			switch (String(asn[0][0])) {
			    case '1.2.840.10045.2.1':
				return der;
			    case '1.3.132.1.12':
			    case '1.3.132.112': // Firefox on Mac - apparently a misspelling of the former
				asn[0][0] = new libVES.Util.OID('1.2.840.10045.2.1');
				asn[1].ASN1type = 3;
				return libVES.Util.ASN1.encode([asn]);
			    default:
				console.log(asn);
				throw new libVES.Error('Internal', 'Unexpected EC pubkey format');
			}
			return der;
		    }).then(function(der) {
			return libVES.Util.PEM.encode(der, 'PUBLIC KEY');
		    });
	    } else return this.wasm().then(function(wasm) {
		return libVES.Util.Key.export(wasm.getpub(data), wasm.getpriv(data), libVES.Algo.ECDH.asn1hdr(wasm.getoid(data)), optns);
	    });
	    throw new libVES.Error('Internal', "Unknown type of key object");
	},
	generate: function(optns) {
	    var op = {name: 'ECDH', namedCurve: this.defaultCurve};
	    if (optns) for (var k in optns) op[k] = optns[k];
	    return crypto.subtle.generateKey(op, true, ['deriveKey', 'deriveBits']).catch(function(e) {
		console.log('ECDH generateKey failed, trying wasm...', e, op);
		return libVES.Algo.ECDH.wasm().then(function(wasm) {
		    var k = wasm.init(op.namedCurve);
		    if (!k || !wasm.generate(k)) throw new libVES.Error('InvalidValue', 'WasmECDH key generation error (unsupported curve?)');
		    return wasm.privpub(k);
		});
	    });
	},
	getPublic: function(priv) {
	    return crypto.subtle.exportKey('jwk',priv).then(function(k) {
		return crypto.subtle.importKey('jwk',{
		    crv: k.crv,
		    ext: true,
		    key_ops: [],
		    kty: 'EC',
		    x: k.x,
		    y: k.y
		},{name:'ECDH'},true,[]);
	    });
	},
	getKeyOptions: function(key) {
	    if (key instanceof CryptoKey) return crypto.subtle.exportKey('jwk', key).then(function(k) {
		return {namedCurve: k.crv};
	    });
	    return {namedCurve: k.curve};
	},
	asn1hdr: function(oid) {
	    return [new libVES.Util.OID(this.OID), new libVES.Util.OID(oid)];
	},
	wasm: function() {
	    if (!this.wasmP) this.wasmP = (typeof(WasmECDH) == 'function' ? Promise.resolve()
		: libVES.Util.loadWasm(WasmECDHinit.baseUrl + 'WasmECDH.js')
	    ).then(function() {
		return WasmECDH(WasmECDHinit);
	    });
	    return this.wasmP;
	},
	importWasm: function(curve, der) {
	    return libVES.Algo.ECDH.wasm().then(function(wasm) {
		return libVES.Util.Key.fromDER(der, function(pub, priv, pubBits) {
		    var k = wasm.init(curve);
		    if (!k) return null;
		    if (pub) wasm.setpub(k, pub);
		    if (priv) wasm.setpriv(k, priv);
		    return k;
		});
	    });
	},
	getMethods: function() {
	    var crvs = ['P-256', 'P-384', 'P-521'];
	    return this.wasm().then(function(wasm) {
		return crvs.concat(wasm.getcurves());
	    }).catch(function(e) {
		return crvs;
	    }).then(function(crvs) {
		return crvs.map(function(algo) {
		    return {namedCurve: algo};
		});
	    });
	},
	OID: '1.2.840.10045.2.1'
    },
    RSA: {
	tag: 'RSA',
	decrypt: function(k,buf) {
	    var self = libVES.Algo.RSA;
	    var maxl = (k.algorithm.modulusLength + 7) >> 3;
	    if (buf.byteLength <= maxl) return self.decryptRSA(k,buf);
	    var b = new Uint8Array(buf);
	    return self.decryptRSA(k,b.slice(0,maxl)).then(function(ck) {
		return self.cipher(ck).then(function(ci) {
		    return ci.decrypt(b.slice(maxl),true);
		});
	    });
	},
	decryptRSA: function(k,buf) {
	    return crypto.subtle.decrypt('RSA-OAEP',k,buf).catch(function(e) {
		throw new libVES.Error('InvalidValue','Error decrypting RSA OAEP: Invalid ciphertext?',{error:e});
	    });
	},
	encrypt: function(k,buf) {
	    var self = libVES.Algo.RSA;
	    var maxl = ((k.algorithm.modulusLength + 7) >> 3) - 48;
	    if (buf.byteLength <= maxl) return self.encryptRSA(k,buf);
	    return self.cipher().then(function(ci) {
		return Promise.all([
		    ci.getSecret().then(function(sk) {
			return self.encryptRSA(k,sk);
		    }),
		    ci.encrypt(buf,true)
		]).then(function(bufs) {
		    var rs = new Uint8Array(bufs[0].byteLength + bufs[1].byteLength);
		    rs.set(new Uint8Array(bufs[0]),0);
		    rs.set(new Uint8Array(bufs[1]),bufs[0].byteLength);
		    return rs;
		});
	    });
	},
	encryptRSA: function(k,buf) {
	    return crypto.subtle.encrypt('RSA-OAEP',k,buf).catch(function(e) {
		throw new libVES.Error('InvalidValue','Error encrypting RSA OAEP: Buffer is too long?',{error:e});
	    });;
	},
	cipher: function(secret) {
	    return libVES.getModule(libVES.Cipher,'AES256GCMp').then(function(cls) {
		return new cls(secret);
	    });
	},
	import: function(data,optns) {
	    return libVES.Util.PEM.import(data,optns);
	},
	export: function(data,optns) {
	    if (data instanceof CryptoKey) switch (data.type) {
		case 'private': return libVES.Util.PKCS8.encode(data,optns);
		case 'public': return libVES.Util.PKCS1.encode(data,optns);
	    }
	    throw new libVES.Error('Internal',"Unknown type of key object");
	},
	generate: function(optns) {
	    var op = {name:'RSA-OAEP', modulusLength:4096, publicExponent:new Uint8Array([1,0,1]), hash:'SHA-256'};
	    if (optns) for (var k in optns) op[k] = optns[k];
	    return crypto.subtle.generateKey(op,true,['decrypt','encrypt']);
	},
	getPublic: function(priv) {
	    return crypto.subtle.exportKey('jwk',priv).then(function(k) {
		return crypto.subtle.importKey('jwk',{
		    alg: k.alg,
		    e: k.e,
		    ext: true,
		    key_ops: ['encrypt'],
		    kty: 'RSA',
		    n: k.n
		},{name:'RSA-OAEP',hash:'SHA-256'},true,['encrypt']);
	    });
	},
	getKeyOptions: function(key) {
	    return crypto.subtle.exportKey('jwk', key).then(function(k) {
		return {modulusLength: ((k.n.length * 6) >> 3) * 8, publicExponent: libVES.Util.B64ToByteArray(k.e)};
	    });
	},
	getMethods: function() {
	    var bits = [];
	    var s = 128;
	    for (var i = 640; i <= 16384; i += s) {
		bits.push(i);
		if (i / s >= 8) s <<= 1;
	    }
	    return Promise.resolve(bits.map(function(b) {
		    return {modulusLength: b};
	    }));
	},
    },
    RSA_PKCS1_15: {
	tag: 'RSA_PKCS1_15',
	import: function(data,optns) {
	    throw new libVES.Error('Legacy','RSA with PKCS#1 1.5 padding is not supported');
	}
    },
    acquire: function(key,optns) {
	return Promise.resolve(key).then(function(k) {
	    if (typeof(CryptoKey) != 'undefined' && (k instanceof CryptoKey)) return k;
	    else if (typeof(k) == 'object') {
		if (k.privateKey) return k.privateKey;
		else if (k.publicKey) return k.publicKey;
		else throw new libVES.Error('Internal','Unknown key format');
	    } else return libVES.Util.PEM.import(k,optns);
	}).then(function(k) {
	    switch (k.algorithm.name) {
		case 'RSA-OAEP': return libVES.getModule(libVES.Algo,'RSA').then(function(e) {
		    var rs = {engine: e};
		    switch (k.type) {
			case 'private':
			    rs.privateKey = k;
			    return e.getPublic(k).then(function(pubk) {
				rs.publicKey = pubk;
				return rs;
			    });
			case 'public':
			    rs.publicKey = k;
			    return rs;
			default: throw new libVES.Error('Internal','Unsupported key type: ' + k.type);
		    }
		});
		default: throw new libVES.Error('Internal','Unsupported key algorithm: ' + k.algorithm.name);
	    }
	});
    },
    fromKeyOptions: function(optns) {
	if (optns.namedCurve) return 'ECDH';
	if (optns.oqsAlgo) return 'OQS';
	if (optns.modulusLength) return 'RSA';
    },
    toString: function() {
	return 'libVES.Algo';
    },
    all: ['RSA', 'ECDH']
};

WasmECDHinit = {
    Key: function() {},
    init: function(curve) {
	var a = new Uint8Array(libVES.Util.StringToByteArray(curve));
	var arg1 = this.buf(a.byteLength + 1);
	arg1.set(a);
	arg1.set([0], a.byteLength);
	var ptr = this._WasmECDH_new(arg1.byteOffset);
	if (!ptr) return null;
	var key = new this.Key();
	key.ptr = ptr;
	key.curve = this.getcurve(key);
	return key;
    },
    buf: function(len) {
	return new Uint8Array(this.asm.memory.buffer, this._WasmECDH_buf, len);
    },
    str: function(ptr) {
	if (!ptr) return null;
	var b = new Uint8Array(this.asm.memory.buffer, ptr);
	return libVES.Util.ByteArrayToString(b.slice(0, b.indexOf(0)));
    },
    generate: function(key) {
	key.private = true;
	return this._WasmECDH_generate(key.ptr);
    },
    setpub: function(key, pub) {
	var arg1 = this.buf(pub.byteLength);
	arg1.set(pub);
	return this._WasmECDH_setpub(key.ptr, arg1.byteOffset, arg1.byteLength);
    },
    setpriv: function(key, priv) {
	key.private = true;
	var arg1 = this.buf(priv.byteLength);
	arg1.set(priv);
	return this._WasmECDH_setpriv(key.ptr, arg1.byteOffset, arg1.byteLength);
    },
    getpub: function(key) {
	var l = this._WasmECDH_getpub(key.ptr);
	if (l <= 0) return null;
	var rs = new Uint8Array(l);
	rs.set(this.buf(l));
	return rs;
    },
    getpriv: function(key) {
	if (!key.private) return null;
	var l = this._WasmECDH_getpriv(key.ptr);
	if (l <= 0) return null;
	var rs = new Uint8Array(l);
	rs.set(this.buf(l));
	return rs;
    },
    getcurve: function(key) {
	return this.str(this._WasmECDH_getcurve(key.ptr));
    },
    getoid: function(key) {
	return this.str(this._WasmECDH_getoid(key.ptr));
    },
    derive: function(priv, pub) {
	var l = this._WasmECDH_derive(priv.ptr, pub.ptr);
	if (l <= 0) return null;
	var rs = new Uint8Array(l);
	rs.set(this.buf(l));
	return rs;
    },
    privpub: function(priv) {
	var pub = new this.Key();
	pub.ptr = priv.ptr;
	pub.curve = priv.curve;
	return {privateKey: priv, publicKey: pub};
    },
    free: function(key) {
	this._WasmECDH_free(key.ptr);
    },
    getcurves: function() {
	var lst = this._WasmECDH_listinit(1024);
	var crvs = [];
	var c;
	for (var i = 0; (c = this._WasmECDH_listget(lst, i)); i++) {
	    var crv = this.str(c);
	    if (crv == '') continue;
	    crvs.push(crv);
	}
	this._WasmECDH_listfree(lst);
	return crvs;
    },
    locateFile: function(file) {
       return this.baseUrl + file;
    },
    baseUrl: 'https://ves.host/pub/'
};
