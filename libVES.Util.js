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
 * libVES.Util.js             libVES: Internal functions: ASN, PEM, PKCSx etc
 *
 ***************************************************************************/
libVES.Util = {
    B64ToByteArray: function(s) {
	var buf = new Uint8Array(s.length);
	var boffs = 0;
	for (var i = 0; i < s.length; i++) {
	    var p = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_".indexOf(s[i]);
	    if (p >= 0) {
		if (p >= 64) p -= 2;
		buf[boffs >> 3] |= p << 2 >> (boffs & 7);
		boffs += 6;
		if ((boffs & 7) < 6) buf[boffs >> 3] |= p << (8 - (boffs & 7));
	    }
	}
	var l = boffs >> 3;
	var buf2 = new Uint8Array(l);
	for (var i = 0; i < l; i++) buf2[i] = buf[i];
	return buf2.buffer;
    },
    ByteArrayToB64D: function(b,dict) {
	var buf = new Uint8Array(b);
	var s = "";
	var boffs = 0;
	while ((boffs >> 3) < buf.byteLength) {
	    var c = (buf[boffs >> 3] << (boffs & 7)) & 0xfc;
	    boffs += 6;
	    if (((boffs & 7) < 6) && ((boffs >> 3) < buf.byteLength)) c |= (buf[boffs >> 3] >> (6 - (boffs & 7)));
	    s += dict[c >> 2];
	}
	for (; boffs & 7; boffs += 6) s += dict.substr(64);
	return s;
    },
    ByteArrayToB64: function(b) {
	return libVES.Util.ByteArrayToB64D(b,"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=");
    },
    ByteArrayToB64W: function(b) {
	return libVES.Util.ByteArrayToB64D(b,"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");
    },
    StringToByteArray: function(s) {
	if ((s instanceof ArrayBuffer) || (s instanceof Uint8Array)) return s;
	var rs = new Uint8Array(4 * s.length);
	var j = 0;
	for (var i = 0; i < s.length;i++) {
	    var c = s.charCodeAt(i);
	    if (c >= 0x80) {
		if (c >= 0x0800) {
		    if (c >= 0x10000) {
			rs[j++] = (c >> 16) | 0xf0;
			rs[j++] = ((c >> 12) & 0x3f) | 0x80;
		    } else rs[j++] = ((c >> 12) & 0x0f) | 0xe0;
		    rs[j++] = ((c >> 6) & 0x3f) | 0x80;
		} else rs[j++] = ((c >> 6) & 0x1f) | 0xc0;
		rs[j++] = (c & 0x3f) | 0x80;
	    } else rs[j++] = c;
	}
	return rs.slice(0,j).buffer;
    },
    ByteArrayToString: function(b) {
	var buf = new Uint8Array(b);
	var rs = '';
	var c;
	for (var i = 0; i < buf.length; i++) {
	    var v = buf[i];
	    if (v & 0x80) {
		if (v & 0x40) {
		    c = ((v & 0x1f) << 6) | (buf[++i] & 0x3f);
		    if (v & 0x20) {
			c = (c << 6) | (buf[++i] & 0x3f);
			if (v & 0x10) c = ((c & 0xffff) << 6) | (buf[++i] & 0x3f);
		    }
		} else c = -1;
	    } else c = buf[i];
	    rs += String.fromCharCode(c);
	}
	return rs;
    },
    fillUndefs: function(data, defs) {
        if (data instanceof Array) data.map((d) => libVES.Util.fillUndefs(d, defs));
        else if (data && defs) for (var k in defs) if (defs[k]) {
            if (data[k] === undefined) data[k] = undefined;
            else if (data[k] instanceof Object) libVES.Util.fillUndefs(data[k], defs[k]);
        }
        return data;
    },
    loadWasm: function(src) {
	return new Promise(function(resolve, reject) {
	    var sc = document.createElement('script');
	    sc.async = false;
	    sc.src = src;
	    sc.onload = resolve;
	    sc.onerror = reject;
	    document.getElementsByTagName('head')[0].appendChild(sc);
	});
    },
    PEM: {
	toDER: function(pem) {
	    var pp = pem.match(/-----BEGIN.*?-----\s*\r?\n([A-Za-z0-9\/\+\=\s\r\n]*)-----END/);
	    if (!pp) throw new libVES.Error('Internal','PEM formatted key expected');
	    return new Uint8Array(libVES.Util.B64ToByteArray(pp[1]));
	},
	decode: function(pem) {
	    return libVES.Util.ASN1.decode(libVES.Util.PEM.toDER(pem));
	},
	import: function(pem,optns) {
	    return libVES.Util.ASN1.import(libVES.Util.PEM.toDER(pem),optns);
	},
	fromDER: function(der) {
	},
	encode: function(der,sgn) {
	    return '-----BEGIN ' + sgn + '-----\r\n' + libVES.Util.ByteArrayToB64(der).match(/.{1,64}/g).join("\r\n") + '\r\n-----END ' + sgn + '-----';
	}
    },
    ASN1: {
	decode: function(der,fStruct) {
	    var p = 0;
	    var data = function() {
		var l = der[p++];
		var len;
		if (l < 128) len = l;
		else {
		    len = 0;
		    for (var i = 128; i < l; i++) len = (len << 8) | der[p++];
		}
		if (p + len > der.length) throw new libVES.Error('Internal',"Invalid ASN.1 package");
		return der.slice(p,p = p + len);
	    };
	    var rs = [];
	    for (; p < der.length;) {
		if (!fStruct && p) {
		    rs.push(der.slice(p));
		    break;
		}
		var tag = der[p++];
		switch (tag) {
		    case 48:
			rs.push(libVES.Util.ASN1.decode(data(),true));
			break;
		    case 6:
			rs.push(new libVES.Util.OID(data()));
			break;
		    case 2:
			var d = data();
			var v = 0;
			for (var i = 0; i < d.length; i++) v = (v << 8) | d[i];
			rs.push(v);
			break;
		    case 5:
			data();
			rs.push(null);
			break;
		    default:
			rs.push(data());
			break;
		}
	    }
	    return rs;
	},
	encode: function(data,fStruct) {
	    var i2a = function(v) {
		if (v < 0) throw new libVES.Error('Internal',"Negative value for ASN.1 integer!");
		var rs = [];
		do {
		    rs.push(v & 0xff);
		    v >>= 8;
		} while (v > 0);
		return rs.reverse();
	    };
	    var bufs = [];
	    var buf = function(tag,bf) {
		var b = new Uint8Array(bf);
		var l = b.length;
		var rs;
		if (l <= 127) {
		    rs = new Uint8Array(l + 2);
		    rs[1] = l; 
		    rs.set(b,2);
		} else {
		    var lb = i2a(l);
		    rs = new Uint8Array(l + lb.length + 2);
		    rs[1] = 128 + lb.length;
		    rs.set(lb,2);
		    rs.set(b,2 + lb.length);
		}
		rs[0] = tag;
		bufs.push(rs);
		return rs;
	    };
	    var d;
	    for (var i = 0; i < data.length; i++) if (fStruct || !i) switch (typeof(d = data[i])) {
		case 'object':
		    if (d == null) buf(5,new Uint8Array(0));
		    else if (d instanceof Array) buf(48,libVES.Util.ASN1.encode(d,true));
		    else if (d instanceof libVES.Util.OID) buf(6,d.getBuffer());
		    else if (d instanceof Uint8Array || d instanceof ArrayBuffer) buf((d.ASN1type || 4),d);
		    else throw new libVES.Error('Internal',"ASN.1 encode - Unknown type");
		    break;
		case 'number':
		    buf(2,i2a(d));
		    break;
		default: throw new libVES.Error('Internal',"ASN.1 encode - Unknown type");
	    } else bufs.push(d);
	    var l = 0;
	    for (var i = 0; i < bufs.length; i++) l += bufs[i].length;
	    var der = new Uint8Array(l);
	    var p = 0;
	    for (i = 0, p = 0; i < bufs.length; p += bufs[i].length, i++) der.set(bufs[i],p);
	    return der;
	},
	import: function(der,optns) {
	    var k = optns && optns.decoded || libVES.Util.ASN1.decode(der)[0];
	    if (!k) throw new libVES.Error('Internal','Empty ASN.1 package?');
	    var i = 0;
	    if (typeof(k[i]) == 'number') (optns || (optns = {})).version = k[i++];
	    if (typeof(k[i]) == 'object' && (k[i][0] instanceof libVES.Util.OID)) return k[i][0].object().then(function(m) {
		return m.import(k[i][1],function(call,optns) {
		    return new Promise(function(resolve,reject) {
			switch (call) {
			    case 'container': return resolve(der);
			    default: return resolve(k[i + 1]);
			}
		    });
		},optns);
	    });
	    // RSA PKCS #1 ?
	    return libVES.Util.ASN1.import(libVES.Util.ASN1.encode([[0,[new libVES.Util.OID('1.2.840.113549.1.1.1'),null],der]])).catch(function(e) {
		throw new libVES.Error('Internal',"Unknown key format",{error: e});
	    });
	},
	setType: function(t,buf) {
	    var rs = new Uint8Array(buf);
	    rs.ASN1type = t;
	    return rs;
	}
    },
    OID: function(s) {
	if (s instanceof Uint8Array) {
	    var rs = [ Math.floor(s[0] / 40), s[0] % 40 ];
	    var r = 0;
	    for (var p = 1; p < s.length; p++) {
		var v = s[p];
		r = (r << 7) | (v & 0x7f);
		if (!(v & 0x80)) {
		    rs.push(r);
		    r = 0;
		}
	    }
	    this.value = rs.join('.');
	} else this.value = s;
    },
    Key: {
	fromDER: function(der, callbk) {
	    var asn = libVES.Util.ASN1.decode(der)[0];
	    if (typeof(asn[0]) == 'number') {
		var asn2 = libVES.Util.ASN1.decode(asn[2])[0];
		var pub = libVES.Util.ASN1.decode(asn2[2]);
		console.log('pub', pub);
		if (pub) return callbk(pub[0].slice(1), asn2[1], pub[0][0]);
		else callbk(null, asn2[1]);
	    } else return callbk(asn[1].slice(1), null, asn[1][0]);
	},
	pubASN1: function(pub, optns) {
	    var p = new Uint8Array(pub.byteLength + 1);
	    p[0] = optns && optns.pubBits ? optns.pubBits : 0;
	    p.set(new Uint8Array(pub), 1);
	    p.ASN1type = 3;
	    return p;
	},
	toPKCS: function(pub, priv, asn1hdr, optns) {
	    if (priv) {
		var seq = [1, priv];
		if (pub) {
		    p = libVES.Util.ASN1.encode([libVES.Util.Key.pubASN1(pub, optns)]);
		    p.ASN1type = 0xa1;
		    seq.push(p);
		}
		var buf = libVES.Util.ASN1.encode([seq]);
		return libVES.Util.ASN1.encode([[0, asn1hdr, buf]]);
	    }
	    return libVES.Util.ASN1.encode([[asn1hdr, libVES.Util.Key.pubASN1(pub, optns)]]);
	},
	export: function(pub, priv, asn1hdr, optns) {
	    var pkcs = libVES.Util.Key.toPKCS(pub, priv, asn1hdr, optns);
	    if (priv) return libVES.Util.PKCS8.encode8(pkcs, optns);
	    return libVES.Util.PEM.encode(pkcs, 'PUBLIC KEY');
	}
    },
    PKCS1: {
	import: function(args,chain,optns) {
	    return chain('container',optns).then(function(der) {
		return crypto.subtle.importKey('spki',der,{name:'RSA-OAEP', hash:'SHA-1'},true,['encrypt']).catch(function(e) {
		    return crypto.subtle.importKey('pkcs8',der,{name:'RSA-OAEP', hash:'SHA-1'},true,['decrypt']);
		});
	    });
	},
	encode: function(key,optns) {
	    return crypto.subtle.exportKey('spki',key).then(function(der) {
		return libVES.Util.PEM.encode(der,'PUBLIC KEY');
	    });
	}
    },
    PKCS5: {
	import: function(args,chain,optns) {
	    var f = chain;
	    for (var i = args.length - 1; i >= 0; i--) f = (function(obj,fp) {
		if (obj[0] instanceof libVES.Util.OID) return function(call,optns) {
		    return obj[0].object().then(function(m) {
			return m[call](obj[1],fp,optns);
		    });
		};
		else return fp;
	    })(args[i],f);
	    return f('import',optns).then(function(der) {
		return libVES.Util.ASN1.import(new Uint8Array(der));
	    }).catch(function(e) {
		throw new libVES.Error('InvalidKey',"Cannot import the private key (Invalid VESkey?)");
	    });
	},
	export: function(chain,optns) {
	    var args = [];
	    var f = chain;
	    if (!optns || !(optns.members instanceof Array)) throw new libVES.Error('Internal','PKCS#5: optns.members must be an array');
	    for (var i = optns.members.length - 1; i >= 0; i--) f = (function(obj,fp,idx) {
		return function(call,optns) {
		    return obj[call](fp,optns).then(function(v) {
			if (call == 'export') args[idx] = v;
			return v;
		    });
		};
	    })(optns.members[i],f,i);
	    return f('export',optns).then(function() {
		return [new libVES.Util.OID('1.2.840.113549.1.5.13'), args];
	    });
	}
    },
    PKCS8: {
	encode: function(key, optns) {
	    return crypto.subtle.exportKey('pkcs8',key).catch(function(e) {
		console.log('PKCS8 failed, trying JWK...');
		return crypto.subtle.exportKey('jwk', key).then(function(jwk) {
		    return libVES.Util.PKCS8.fromJWK(jwk);
		});
	    }).then(function(pkcs8) {
		return libVES.Util.PKCS8.encode8(pkcs8, optns);
	    });
	},
	encode8: function(pkcs8, optns) {
	    var ops = {};
	    for (var k in optns) ops[k] = optns[k];
	    if (!ops.members) ops.members = [
		libVES.getModule(libVES.Util,'PBKDF2'),
		libVES.getModule(libVES.Cipher,'AES256CBC')
	    ];
	    return Promise.all(ops.members).then(function(ms) {
		ops.members = ms;
		ops.content = pkcs8;
		var rec = [];
		if (ops.password) return libVES.Util.PKCS5.export(function(call,optns) {
		    rec[1] = optns.content;
		    return Promise.resolve();
		},ops).then(function(data) {
		    rec[0] = data;
		    return libVES.Util.PEM.encode(libVES.Util.ASN1.encode([rec]),'ENCRYPTED PRIVATE KEY');
		});
		else if (ops.opentext) return libVES.Util.PEM.encode(pkcs8,'PRIVATE KEY');
		else throw new libVES.Error('Internal','No password for key export (opentext=true to export without password?)');
	    });
	},
	fromJWK: function(jwk) {
	    if (jwk.kty != 'EC') throw new libVES.Error('Internal', 'kty=="EC" expected (workaround for Firefox)');
	    var pubx = libVES.Util.B64ToByteArray(jwk.x);
	    var puby = libVES.Util.B64ToByteArray(jwk.y);
	    var pub = new Uint8Array(pubx.byteLength + puby.byteLength + 2);
	    pub[0] = 0;
	    pub[1] = 4;
	    pub.set(new Uint8Array(pubx), 2);
	    pub.set(new Uint8Array(puby), pubx.byteLength + 2);
	    pub.ASN1type = 3;
	    pub = libVES.Util.ASN1.encode([pub]);
	    pub.ASN1type = 0xa1;
	    return libVES.Util.ASN1.encode([[
		0,
		[
		    new libVES.Util.OID('1.2.840.10045.2.1'),
		    new libVES.Util.OID((function(crvs) {
			for (var k in crvs) if (crvs[k] == jwk.crv) return k;
			throw new libVES.Error('Internal', 'Unknown named curve: ' + jwk.crv);
		    })(libVES.Util.EC.namedCurves))
		],
		libVES.Util.ASN1.encode([[
		    1,
		    libVES.Util.B64ToByteArray(jwk.d),
		    pub
		]])
	    ]]).buffer;
	},
	toJWK: function(key) {
	    var der = libVES.Util.ASN1.decode(key)[0];
	    var idx = 0;
	    if (!(der[0] instanceof Array)) idx++;
	    switch (String(der[idx][0])) {
		case '1.2.840.10045.2.1':
		case '1.3.132.1.12':
		case '1.3.132.112': // Firefox on Mac - apparently a misspelling of the former
		    break;
		default:
		    console.log(der);
		    throw new libVES.Error('Internal', 'EC PKCS8 expected');
	    }
	    var der2 = idx ? libVES.Util.ASN1.decode(der[idx + 1])[0] : null;
	    var pub = idx ? (der2[2] ? libVES.Util.ASN1.decode(der2[2])[0] : null) : der[1];
	    var publ = 0;
	    if (pub && pub.byteLength > 2 && pub[1] == 4) publ = pub.byteLength / 2 - 1;
	    return {
		crv: libVES.Util.EC.namedCurves[der[idx][1]],
		d: (idx ? libVES.Util.ByteArrayToB64W(der2[1]) : undefined),
		ext: true,
		key_ops: (idx ? ['deriveKey', 'deriveBits'] : []),
		kty: 'EC',
		x: (publ ? libVES.Util.ByteArrayToB64W(pub.slice(2, publ + 2)) : ''),
		y: (publ ? libVES.Util.ByteArrayToB64W(pub.slice(publ + 2, 2 * publ + 2)) : '')
	    };
	}
    },
    PBKDF2: {
	deriveKey: function(args, pwd, algo) {
	    return crypto.subtle.importKey('raw', libVES.Util.StringToByteArray(pwd), 'PBKDF2', false, ['deriveKey']).then(function(k) {
		var keyargs = {name:'PBKDF2', salt:args[0], iterations:args[1]};
		var ka;
		if (args[2] && (args[2][0] instanceof libVES.Util.OID)) ka = args[2][0].object().then(function(obj) {
		    obj.setArgs(keyargs, args[2][1]);
		    return keyargs;
		});
		else {
		    keyargs.hash = 'SHA-1';
		    ka = Promise.resolve(keyargs);
		}
		return ka.then(function(keyargs) {
		    return crypto.subtle.deriveKey(keyargs, k, algo, true, ['encrypt', 'decrypt']);
		});
	    });
	},
	import: function(args,chain,optns) {
	    if (!optns || !optns.password) throw new libVES.Error('InvalidKey',"VESkey is not supplied");
	    var pwd = (typeof(optns.password) == 'function') ? optns.password() : optns.password;
	    return chain('info').then(function(info) {
		return libVES.Util.PBKDF2.deriveKey(args,pwd,info.algorithm).then(function(k) {
		    return chain('import',{key: k});
		});
	    });
	},
	export: function(chain,optns) {
	    if (!optns || !optns.password) throw new libVES.Error('InvalidKey',"VESkey is not supplied");
	    var pwd = (typeof(optns.password) == 'function') ? optns.password() : optns.password;
	    var args = [new Uint8Array(8),((optns && optns.KDF && optns.KDF.iterations) || 2048)];
	    crypto.getRandomValues(args[0]);
	    return chain('info').then(function(info) {
		return libVES.Util.PBKDF2.deriveKey(args,pwd,info.algorithm).then(function(k) {
		    optns.key = k;
		    return chain('export',optns).then(function() {
			return [new libVES.Util.OID('1.2.840.113549.1.5.12'), args];
		    });
		});
	    });
	}
    },
    EC: {
	import: function(args,chain,optns) {
	    return chain('container',optns).then(function(der) {
		var oid = String(args);
		var curve = libVES.Util.EC.namedCurves[oid] || oid;
		var a = {name:'ECDH',namedCurve: curve};
		return crypto.subtle.importKey('spki',der,a,true,[]).catch(function() {
		    return crypto.subtle.importKey('pkcs8',der,a,true,['deriveKey','deriveBits']);
		}).catch(function(e) {
		    console.log('PKCS8 failed, trying JWK...');
		    var jwk = libVES.Util.PKCS8.toJWK(der);
		    return crypto.subtle.importKey('jwk', jwk, a, true, jwk.key_ops);
		}).catch(function(e) {
		    console.log('trying WasmECDH...');
		    return libVES.Algo.ECDH.importWasm(curve, der);
		});
	    });
	},
	namedCurves: {
	    "1.3.132.0.10": "P-256",
	    "1.3.132.0.34": "P-384",
	    "1.3.132.0.35": "P-521"
	}
    },
    Hash: {
	SHA1: {
	    setArgs: function(args, optns) {
		args.hash = 'SHA-1';
		return args;
	    },
	    hash: function(buf) {
		return crypto.subtle.digest('SHA-1',buf);
	    }
	},
	SHA256: {
	    setArgs: function(args, optns) {
		args.hash = 'SHA-256';
		return args;
	    },
	    hash: function(buf) {
		return crypto.subtle.digest('SHA-256',buf);
	    }
	},
	SHA384: {
	    setArgs: function(args, optns) {
		args.hash = 'SHA-384';
		return args;
	    },
	    hash: function(buf) {
		return crypto.subtle.digest('SHA-384',buf);
	    }
	},
	SHA512: {
	    setArgs: function(args, optns) {
		args.hash = 'SHA-512';
		return args;
	    },
	    hash: function(buf) {
		return crypto.subtle.digest('SHA-512',buf);
	    }
	}
    }
};

libVES.Util.OID.prototype = {
    object: function() {
	var o = libVES.Util.OID[this.value];
	if (!o) throw new libVES.Error('Internal',"Unknown object identifier: " + this.value);
	return o();
    },
    getBuffer: function() {
	var oid = this.value.split(/\./).map(function(v) { return Number(v); });
	var rs = [oid[0] * 40 + oid[1]];
	for (var i = 2; i < oid.length; i++) {
	    var n = oid[i];
	    var v = [n & 0x7f];
	    n >>= 7;
	    while (n) {
		v.push((n & 0x7f) | 0x80);
		n >>= 7;
	    }
	    for (var j = v.length - 1; j >= 0; j--) rs.push(v[j]);
	}
	return new Uint8Array(rs);
    },
    toString: function() {
	return this.value;
    }
}

libVES.Util.OID['1.2.840.113549.1.5.13'] = libVES.getModuleFunc(libVES, ['Util', 'PKCS5']);
libVES.Util.OID['1.2.840.113549.1.5.12'] = libVES.getModuleFunc(libVES, ['Util', 'PBKDF2']);
libVES.Util.OID['2.16.840.1.101.3.4.1.42'] = libVES.getModuleFunc(libVES, ['Cipher', 'AES256CBC']);
libVES.Util.OID['1.2.840.113549.1.1.1'] = libVES.getModuleFunc(libVES, ['Util', 'PKCS1']);
libVES.Util.OID['1.2.840.10045.2.1'] = libVES.Util.OID['1.3.132.1.12'] = libVES.Util.OID['1.3.132.112'] = libVES.getModuleFunc(libVES, ['Util', 'EC']);
libVES.Util.OID['1.2.840.113549.2.7'] = libVES.getModuleFunc(libVES, ['Util', 'Hash', 'SHA1']);
libVES.Util.OID['1.2.840.113549.2.9'] = libVES.getModuleFunc(libVES, ['Util', 'Hash', 'SHA256']);
libVES.Util.OID['1.2.840.113549.2.10'] = libVES.getModuleFunc(libVES, ['Util', 'Hash', 'SHA384']);
libVES.Util.OID['1.2.840.113549.2.11'] = libVES.getModuleFunc(libVES, ['Util', 'Hash', 'SHA512']);
libVES.Util.OID['1.3.6.1.4.1.53675.3.5'] = libVES.getModuleFunc(libVES, ['Algo', 'OQS', 'Util']);
