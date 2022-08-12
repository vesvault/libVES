/***************************************************************************
 *          ___       ___
 *         /   \     /   \    VESvault
 *         \__ /     \ __/    Encrypt Everything without fear of losing the Key
 *            \\     //                   https://vesvault.com https://ves.host
 *             \\   //
 *     ___      \\_//
 *    /   \     /   \         libVES.Flow: Cross-origin private context manager
 *    \__ /     \ __/
 *       \\     //
 *        \\   //
 *         \\_//
 *         /   \
 *         \___/
 *
 *
 * (c) 2022 VESvault Corp
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
 * @title libVES.Flow
 * @ Securely maintain private session data across multiple https origins
 * @version 0.1a
 *
 * @author Jim Zubov <jz@vesvault.com> (VESvault Corp)
 *
 ***************************************************************************/

libVES.Flow = function(name, optns) {
    this.name = name;
    this.origin = document.location.origin;
    this.url = this.origin + '/VESflow';
    if (optns) for (var k in optns) this[k] = optns[k];
    return this;
};

libVES.Flow.algo = {name: 'ECDH', namedCurve: 'P-256'};

libVES.Flow.keyAlgo = function(jwk) {
    if (jwk && jwk.kty == 'EC') return {name: 'ECDH', namedCurve: jwk.crv};
    return null;
};

libVES.Flow.toOrigin = function(url) {
    var a = document.createElement('a');
    a.href = url;
    return a.origin;
};

libVES.Flow.jwkPub = function(jwk) {
    delete(jwk.d);
    delete(jwk.key_ops);
    delete(jwk.ext);
    return jwk;
};

libVES.Flow.parseToken = function(src, callbk) {
    src = src.replace(/\#VESflow\.(\w+)=([^\#\&\=]+)/g, function(s, k, v) {
	var tk;
	try {
	    tk = JSON.parse(decodeURIComponent(v));
	    if (callbk(decodeURIComponent(k), tk)) return '';
	} catch(e) {
	    console.log(e);
	}
	return s;
    });
    return src;
};

libVES.Flow.logout = function() {
    for (var k in sessionStorage) if (k.match(/^VESflow\b/)) delete(sessionStorage[k]);
};

libVES.Flow.prototype.source = function(src) {
    if (src != null) history.replaceState(null, '', src);
    return document.location.href;
};

libVES.Flow.prototype.privKey = function(algo) {
    if (!algo) algo = libVES.Flow.algo;
    var a = JSON.stringify(algo);
    return Promise.resolve(sessionStorage['VESflow' + a]).then(function(k) {
	if (!k) throw null;
	return crypto.subtle.importKey('jwk', JSON.parse(k), algo, true, ['deriveBits', 'deriveKey']);
    }).catch(function(e) {
	return crypto.subtle.generateKey(algo, true, ['deriveBits', 'deriveKey']).then(function(pair) {
	    return crypto.subtle.exportKey('jwk', pair.privateKey).then(function(jwk) {
		sessionStorage['VESflow' + a] = JSON.stringify(jwk);
		return pair.privateKey;
	    });
	});
    });
};

libVES.Flow.prototype.pubJWK = function(org) {
    return ((!org || org == this.origin) ? this.privKey().then(function(priv) {
	return crypto.subtle.exportKey('jwk', priv).then(function(jwk) {
	    return libVES.Flow.jwkPub(jwk);
	});
    }) : Promise.resolve(sessionStorage['VESflow|' + org]).then(function(k) {
	if (!k) throw {code: 'NotFound', message: 'No public key stored for ' + org};
	return JSON.parse(k);
    }));
};

libVES.Flow.prototype.pubKey = function(org) {
    return this.pubJWK(org).then(function(jwk) {
	return crypto.subtle.importKey('jwk', jwk, libVES.Flow.keyAlgo(jwk), true, []);
    });
};

libVES.Flow.prototype.cipher = function(url) {
    var self = this;
    return self.pubKey(libVES.Flow.toOrigin(url)).then(function(pub) {
	return self.privKey(pub.algorithm).then(function(priv) {
	    return crypto.subtle.deriveBits({name: 'ECDH', public: pub}, priv, 8 * libVES.Algo.ECDH.curveBytes[pub.algorithm.namedCurve]);
	});
    }).then(function(raw) {
	return crypto.subtle.digest({name: 'SHA-256'}, raw).then(function(buf) {
	    return crypto.subtle.importKey('raw', buf, 'AES-GCM', false, ['encrypt', 'decrypt']);
	});
    });
};

libVES.Flow.prototype.encrypt = function(url, val) {
    var self = this;
    return Promise.resolve(val || this.value()).then(function(val) {
	if (val == null) throw {code: 'NoData', message: 'Empty value'};
	return self.cipher(url).then(function(ci) {
	    var iv = new Uint8Array(12);
	    crypto.getRandomValues(iv);
	    return crypto.subtle.encrypt({name: 'AES-GCM', iv: iv.buffer}, ci, libVES.Util.StringToByteArray(JSON.stringify(val))).then(function(ctext) {
		return libVES.Util.ByteArrayToB64W(iv) + '.' + libVES.Util.ByteArrayToB64W(ctext);
	    });
	});
    });
};

libVES.Flow.prototype.token = function(url) {
    var self = this;
    return this.pubJWK().then(function(jwk) {
	return {url: self.url, key: jwk};
    }).then(function(tk) {
	return self.encrypt(url).then(function(ctext) {
	    tk.enc = ctext;
	    self.erase(url);
	    self.sent = true;
	    return tk;
	}).catch(function(e) {
	    self.store(url).catch(function(e) {});
	    return tk;
	});
    });
};

libVES.Flow.prototype.addToken = function(url) {
    var self = this;
    return self.token(url).then(function(tk) {
	return url + '#VESflow.' + self.name + '=' + encodeURIComponent(JSON.stringify(tk));
    });
};

libVES.Flow.prototype.decrypt = function(ctext, url) {
    var self = this;
    var c = ctext.split('.');
    return self.cipher(url).then(function(ci) {
	return crypto.subtle.decrypt({name: 'AES-GCM', iv: libVES.Util.B64ToByteArray(c[0])}, ci, libVES.Util.B64ToByteArray(c[1])).then(function(ptext) {
	    return JSON.parse(libVES.Util.ByteArrayToString(ptext));
	});
    });
};

libVES.Flow.prototype.value = function() {
    var self = this;
    return Promise.resolve(history.state && history.state['VESflow.' + self.name]).then(function(ctext) {
	return self.decrypt(ctext);
    });
};

libVES.Flow.prototype.setValue = function(val) {
    var self = this;
    return Promise.resolve(val? self.encrypt(null, val) : null).then(function(ctext) {
	var s = {};
	if (history.state) for (var k in history.state) s[k] = history.state[k];
	if (ctext) s['VESflow.' + self.name] = ctext;
	else delete(s['VESflow.' + self.name]);
	history.replaceState(s, '');
	return val;
    });
};

libVES.Flow.prototype.click = function(a) {
    var self = this;
    (a.origin == this.origin ? self.store() : self.addToken(a.href).then(function(url) {
	a.href = url;
    })).catch(function(e) {
	if (!e || e.code != 'NotFound') throw e;
    }).then(function() {
	document.location.href = a.href;
    }).catch(function(e) {
	console.log(e);
    });
    return false;
};

libVES.Flow.prototype.reload = function(e) {
    if (!this.sent) this.store().catch(function(e) {});
};

libVES.Flow.prototype.recv = function(dval) {
    var self = this;
    return Promise.resolve(self.source()).then(function(src) {
	var tk = null;
	src = libVES.Flow.parseToken(src, function(k, t) {
	    if (k != self.name) return false;
	    tk = t;
	    return true;
	});
	if (tk == null) throw {code: 'NotFound', message: 'No valid token in the source url'};
	return Promise.resolve(self.source(src)).then(function() {
	    if (dval) for (var k in dval) if (tk[k] === undefined) tk[k] = dval[k];
	    return self.recvToken(tk);
	});
    });
};

libVES.Flow.prototype.recvToken = function(tk) {
    var org = libVES.Flow.toOrigin(tk.url);
    if (org != this.origin && tk.key) sessionStorage['VESflow|' + org] = JSON.stringify(tk.key);
    if (!tk.enc) return Promise.reject({url: tk.url, code: 'Incomplete', message: 'Missing encrypted data'});
    return this.decrypt(tk.enc, org);
};

libVES.Flow.prototype.get = function() {
    var self = this;
    return self.fetch().catch(function(e) {
	if (!e || e.code != 'NotFound') console.log(e);
	return null;
    }).then(function(data) {
	return self.recv().catch(function(e) {
	    if (e && e.code == 'Incomplete') {
		self.url = document.location.href;
		return self.addToken(e.url).then(function(url) {
		    document.location.replace(url);
		    throw {code: 'Reload', message: 'Completing the key exchange'};
		});
	    }
	    if (!data) throw e;
	    return data;
	});
    });
};

libVES.Flow.prototype.store = function(url) {
    if (history.state && history.state['VESflow.' + this.name]) {
	this.sent = 1;
	return Promise.resolve(sessionStorage['VESflow.' + this.name + '>' + libVES.Flow.toOrigin(url)] = history.state['VESflow.' + this.name]);
    }
    return Promise.reject({code: 'NotFound', message: 'Value is not set'});
};

libVES.Flow.prototype.fetch = function(url) {
    var self = this;
    return Promise.resolve(sessionStorage['VESflow.' + self.name + '>' + libVES.Flow.toOrigin(url)]).then(function(ctext) {
	if (!ctext) throw {code: 'NotFound', message: 'Not in the session storage'};
	return self.decrypt(ctext).then(function(data) {
	    self.erase(url);
	    return data;
	});
    });
};

libVES.Flow.prototype.erase = function(url) {
    delete(sessionStorage['VESflow.' + this.name + '>' + libVES.Flow.toOrigin(url)]);
};

libVES.Flow.prototype.logout = function() {
    this.setValue(undefined);
    return libVES.Flow.logout();
};
