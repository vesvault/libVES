/**
 * @title libVES.Util
 *
 * @author Jim Zubov <jz@vesvault.com> (VESvault)
 * GPL license, http://www.gnu.org/licenses/
 */
libVES.Util = {
    B64ToByteArray: function(s) {
	var buf = new Uint8Array(s.length);
	var boffs = 0;
	for (var i = 0; i < s.length; i++) {
	    var p = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".indexOf(s[i]);
	    if (p >= 0) {
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
    ByteArrayToB64: function(b) {
	var buf = new Uint8Array(b);
	var s = "";
	var boffs = 0;
	while ((boffs >> 3) < buf.byteLength) {
	    var c = (buf[boffs >> 3] << (boffs & 7)) & 0xfc;
	    boffs += 6;
	    if (((boffs & 7) < 6) && ((boffs >> 3) < buf.byteLength)) c |= (buf[boffs >> 3] >> (6 - (boffs & 7)));
	    s += "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[c >> 2];
	}
	for (; boffs & 7; boffs += 6) s += "=";
	return s;
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
    PEM: {
	toDER: function(pem) {
	    var pp = pem.match(/-----BEGIN.*?\n([A-Za-z0-9\/\+\=\s\r\n]*)-----END/s);
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
	decode: function(der) {
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
		var tag = der[p++];
		switch (tag) {
		    case 48:
			rs.push(libVES.Util.ASN1.decode(data()));
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
	encode: function(data) {
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
	    for (var i = 0; i < data.length; i++) switch (typeof(d = data[i])) {
		case 'object':
		    if (d == null) buf(5,new Uint8Array(0));
		    else if (d instanceof Array) buf(48,libVES.Util.ASN1.encode(d));
		    else if (d instanceof libVES.Util.OID) buf(6,d.getBuffer());
		    else if (d instanceof Uint8Array || d instanceof ArrayBuffer) buf((d.ASN1type || 4),d);
		    else throw new libVES.Error('Internal',"ASN.1 encode - Unknown type");
		    break;
		case 'number':
		    buf(2,i2a(d));
		    break;
		default: throw new libVES.Error('Internal',"ASN.1 encode - Unknown type");
	    }
	    var l = 0;
	    for (var i = 0; i < bufs.length; i++) l += bufs[i].length;
	    var der = new Uint8Array(l);
	    var p = 0;
	    for (i = 0, p = 0; i < bufs.length; p += bufs[i].length, i++) der.set(bufs[i],p);
	    return der;
	},
	import: function(der,optns) {
	    var k = libVES.Util.ASN1.decode(der)[0];
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
    PKCS1: {
	import: function(args,chain,optns) {
	    return chain('container',optns).then(function(der) {
		return crypto.subtle.importKey('spki',der,{name:'RSA-OAEP', hash:'SHA-1'},true,['encrypt']).catch(function(e) {
		    return crypto.subtle.importKey('pkcs8',der,{name:'RSA-OAEP', hash:'SHA-1'},true,['decrypt']);
		});
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
		return crypto.subtle.importKey('pkcs8',der,{name:'RSA-OAEP', hash:'SHA-1'},true,['decrypt']);
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
    PBKDF2: {
	deriveKey: function(args,pwd,algo) {
	    return crypto.subtle.importKey('raw',libVES.Util.StringToByteArray(pwd),'PBKDF2',false,['deriveKey']).then(function(k) {
		return crypto.subtle.deriveKey({name:'PBKDF2', salt:args[0], iterations:args[1], hash: 'SHA-1'},k,algo,true,['encrypt','decrypt']);
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

libVES.Util.OID['1.2.840.113549.1.5.13'] = libVES.getModuleFunc(libVES,['Util','PKCS5']);
libVES.Util.OID['1.2.840.113549.1.5.12'] = libVES.getModuleFunc(libVES,['Util','PBKDF2']);
libVES.Util.OID['2.16.840.1.101.3.4.1.42'] = libVES.getModuleFunc(libVES,['Cipher','AES256CBC']);
libVES.Util.OID['1.2.840.113549.1.1.1'] = libVES.getModuleFunc(libVES,['Util','PKCS1']);
