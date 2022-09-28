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
 * GNU General Public License v3
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * libVES.Algo.OQS.js             libVES: Post-quantum support via liboqs
 *
 ***************************************************************************/

libVES.Algo.OQS = {
    tag: 'OQS',
    wasm: function() {
	if (!this.wasmP) this.wasmP = new Promise(function(resolve, reject) {
	    if (typeof(WasmOQS) == 'function') return resolve();
	    var sc = document.createElement('script');
	    sc.async = false;
	    sc.src = WasmOQSinit.baseUrl + 'WasmOQS.js';
	    sc.onload = resolve;
	    sc.onerror = reject;
	    document.getElementsByTagName('head')[0].appendChild(sc);
	}).then(function() {
	    return WasmOQS(WasmOQSinit);
	});
	return this.wasmP;
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
	var pub = new Uint8Array(data.pub.byteLength + 1);
	pub[0] = 0;
	pub.set(new Uint8Array(data.pub), 1);
	pub.ASN1type = 3;
	var oid = [new libVES.Util.OID(libVES.Algo.OQS.OID), libVES.Util.StringToByteArray(data.algo)];
	if (data.priv) {
	    pub = libVES.Util.ASN1.encode([pub]);
	    pub.ASN1type = 0xa1;
	    var buf = libVES.Util.ASN1.encode([[1, data.priv, pub]]);
	    var pkcs8 = libVES.Util.ASN1.encode([[0, oid, buf]]);
	    return libVES.Util.PKCS8.encode8(pkcs8, optns);
	}
	return libVES.Util.PEM.encode(libVES.Util.ASN1.encode([[oid, pub]]), 'PUBLIC KEY');
    },
    generate: function(optns) {
	var algo = optns ? optns.algo : null;
	if (!algo) algo = this.defaultAlgo;
	return this.wasm().then(function(wasm) {
	    var k = wasm.init(algo, true);
	    if (!k) throw new libVES.Error('InvalidValue', 'OQS key init failed');
	    if (!wasm.generate(k)) throw new libVES.Error('Internal', 'OQS generate failed');
	    var pub = {};
	    for (var i in k) if (i != 'priv') pub[i] = k[i];
	    return {privateKey: k, publicKey: pub};
	});
    },
    Util: {
	import: function(args,chain,optns) {
	    var algo = libVES.Util.ByteArrayToString(args);
	    return chain('container').then(function(der) {
		var asn = libVES.Util.ASN1.decode(der)[0];
		var pkey = null;
		var pub = null;
		if (typeof(asn[0]) == 'number') {
		    var asn2 = libVES.Util.ASN1.decode(asn[2])[0];
		    pkey = asn2[1];
		    pub = libVES.Util.ASN1.decode(asn2[2])[0];
		} else pkey = asn[1];
		return libVES.Algo.OQS.wasm().then(function(wasm) {
		    var k = wasm.init(algo, !!pub);
		    if (!k) throw new libVES.Error('InvalidValue', 'OQS key init failed (bad algo?)');
		    var s = function(dst, src, dif) {
			if (!dst || !src || dst.byteLength != src.byteLength - dif) throw new libVES.Error('InvalidValue', 'Incorrect OQS key size');
			dst.set(src.slice(dif), 0);
		    };
		    if (pub) {
			s(k.priv, pkey, 0);
			s(k.pub, pub, 1);
		    } else s(k.pub, pkey, 1);
		    return k;
		});
	    });
	}
    },
    OID: '1.3.6.1.4.1.53675.3.5',
    defaultAlgo: 'Kyber768'
};

var WasmOQSinit = {
    init: function(algo, priv) {
        var a = new Uint8Array(libVES.Util.StringToByteArray(algo));
        var arg1 = new Uint8Array(this.asm.memory.buffer, 16, 48);
        arg1.set(a);
        arg1.set([0], a.byteLength);
        var ptr = this._WasmOQS_new(arg1.byteOffset, priv);
        if (!ptr) return null;
        var key = { ptr: ptr };
        var priv = this._WasmOQS_priv(ptr);
        if (priv) key.priv = new Uint8Array(this.asm.memory.buffer, priv, this._WasmOQS_privlen(ptr));
        key.pub = new Uint8Array(this.asm.memory.buffer, this._WasmOQS_pub(ptr), this._WasmOQS_publen(ptr));
        key.secretlen = this._WasmOQS_decaps(key.ptr, null, null);
        key.ctextlen = this._WasmOQS_encaps(key.ptr, null, null);
        key.algo = algo;
        return key;
    },
    generate: function(key) {
        return this._WasmOQS_generate(key.ptr) >= 0;
    },
    encaps: function(key) {
        var arg1 = new Uint8Array(this.asm.memory.buffer, this._WasmOQS_secretbuf, this._WasmOQS_decaps(key.ptr, null, null));
        var arg2 = new Uint8Array(this.asm.memory.buffer, this._WasmOQS_ctextbuf, this._WasmOQS_encaps(key.ptr, null, null));
        if (this._WasmOQS_encaps(key.ptr, arg2.byteOffset, arg1.byteOffset) <= 0) return null;
        key.secret = new Uint8Array(arg1.byteLength);
        key.secret.set(arg1);
        var ctext = new Uint8Array(arg2.byteLength);
        ctext.set(arg2);
        return ctext;
    },
    decaps: function(key, ctext) {
        if (!ctext) return key.secret;
        if (ctext.byteLength != this._WasmOQS_encaps(key.ptr, null, null)) return null;
        var arg1 = new Uint8Array(this.asm.memory.buffer, this._WasmOQS_secretbuf, this._WasmOQS_decaps(key.ptr, null, null));
        var arg2 = new Uint8Array(this.asm.memory.buffer, this._WasmOQS_ctextbuf, ctext.byteLength);
        arg2.set(ctext);
        if (this._WasmOQS_decaps(key.ptr, arg1.byteOffset, arg2.byteOffset) <= 0) return null;
        key.secret = new Uint8Array(arg1.byteLength);
        key.secret.set(arg1);
        return key.secret;
    },
    free: function(key) {
        this._WasmOQS_free(key.ptr);
    },
    test: function(algo) {
        var k = this.init(algo, 1);
        this.generate(k);
        console.log(k);
        var ctext = this.encaps(k);
        console.log(k.secret, ctext);
        var secret = this.decaps(k);
        console.log(secret);
    },
    locateFile: function(file) {
	return this.baseUrl + file;
    },
    baseUrl: 'https://ves.host/pub/'
};
