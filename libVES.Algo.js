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
			crypto.subtle.exportKey('spki',eKey.publicKey),
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
	    return crypto.subtle.exportKey('jwk',pub).then(function(kdata) {
		return crypto.subtle.generateKey({name:'ECDH',namedCurve: kdata.crv},true,['deriveKey','deriveBits']).catch(function(e) {
		    throw new libVES.Error('InvalidValue','Error generating ECIES ephemeral',{error: e});
		});
	    });
	},
	cipher: function(priv,pub) {
	    return libVES.getModule(libVES.Cipher,'AES256GCMp').then(function(m) {
		return Promise.resolve(libVES.Algo.ECDH.curveBytes[pub.algorithm.namedCurve] || crypto.subtle.exportKey('jwk',pub).then(function(jwk) {
		    return jwk.x.length * 3 / 4;
		})).then(function(len) {
		    return crypto.subtle.deriveBits({name:'ECDH',public:pub},priv,8 * len).then(function(raw) {
			return crypto.subtle.digest({name:'SHA-384'},raw).then(function(buf) {
			    return new m(new Uint8Array(buf).slice(0,m.prototype.keySize + m.prototype.ivSize));
			});
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
			console.log(asn);
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
	    }
	    throw new libVES.Error('Internal', "Unknown type of key object");
	},
	generate: function(optns) {
	    var op = {name:'ECDH', namedCurve:'P-384'};
	    if (optns) for (var k in optns) op[k] = optns[k];
	    return crypto.subtle.generateKey(op,true,['deriveKey','deriveBits']);
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
	}
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
	    var op = {name:'RSA-OAEP', modulusLength:2048, publicExponent:new Uint8Array([1,0,1]), hash:'SHA-1'};
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
		},{name:'RSA-OAEP',hash:'SHA-1'},true,['encrypt']);
	    });
	}
    },
    RSA_PKCS1_15: {
	tag: 'RSA_PKCS1_15',
	import: function(data,optns) {
	    throw new libVES.Error('Legacy','RSA with PKCS#1 1.5 padding is not supported');
	}
    },
    acquire: function(key,optns) {
	return Promise.resolve(key).then(function(k) {
	    if (k instanceof window.CryptoKey) return k;
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
    toString: function() {
	return 'libVES.Algo';
    }
};
