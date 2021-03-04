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
 * libVES.Cipher.js           libVES: Stream Cipher
 *
 ***************************************************************************/
libVES.Cipher = function(data) {
    for (var k in data) this[k] = data[k];
};
libVES.Cipher.prototype = {
    init: function(secret) {
	if (!secret) {
	    secret = new Uint8Array(this.keySize + this.ivSize);
	    crypto.getRandomValues(secret);
	} else if (secret.length < this.keySize) throw new libVES.Error('Internal','Invalid cipher key data');
	this.key = this.buildKey(secret.slice(0,this.keySize));
	this.IV = Promise.resolve(secret.slice(0,this.keySize + this.ivSize).slice(-this.ivSize));
	try {
	    this.meta = JSON.parse(libVES.Util.ByteArrayToString(secret.slice(this.keySize + this.ivSize)));
	} catch(e) {
	    this.meta = {};
	}
    },
    getSecret: function() {
	var self = this;
	var meta = null;
	if (this.meta) for (var k in this.meta) {
	    meta = libVES.Util.StringToByteArray(JSON.stringify(this.meta));
	    break;
	}
	var buf = new Uint8Array(this.keySize + this.ivSize + (meta ? meta.byteLength : 0));
	return Promise.all([(this.algo ? this.key.then(function(key) {
	    return crypto.subtle.exportKey("raw", key);
	}) : this.key), this.IV]).then(function(data) {
	    buf.set(new Uint8Array(data[0]), 0);
	    buf.set(new Uint8Array(data[1]), data[0].byteLength);
	    if (meta) buf.set(new Uint8Array(meta), data[0].byteLength + data[1].byteLength);
	    return buf;
	});
    },
    getMeta: function() {
	return {a: this.a};
    },
    buildKey: function(key) {
	if (!this.algo) return Promise.resolve(key);
	return crypto.subtle.importKey('raw',key,this.algo,true,['encrypt','decrypt']);
    },
    process: function(buf,final,callbk,sizefn) {
	var self = this;
	buf = new Uint8Array(buf);
	if (this.processBuf) {
	    var b = new Uint8Array(buf.byteLength + this.processBuf.byteLength);
	    b.set(this.processBuf,0);
	    b.set(buf,this.processBuf.byteLength);
	    buf = b;
	}
	var over = !final;
	var fn = function(cprev) {
	    var chunkSize = sizefn();
	    if ((!buf.byteLength && over) || (!final && (!chunkSize || buf.byteLength < chunkSize))) {
		self.processBuf = buf.byteLength ? buf : null;
		return Promise.resolve(cprev);
	    }
	    var cl = (chunkSize && chunkSize < buf.byteLength) ? chunkSize : buf.byteLength;
	    if (!chunkSize || cl < chunkSize) over = true;
	    return callbk(buf.slice(0, cl)).then(function(ctext) {
		buf = buf.slice(cl);
		var r = new Uint8Array(cprev.byteLength + ctext.byteLength);
		r.set(cprev, 0);
		r.set(new Uint8Array(ctext), cprev.byteLength);
		return r;
	    }).then(fn);
	};
	return fn(new Uint8Array(0));
    },
    encryptChunk: function(buf) {
	return Promise.all([this.key,this.algoInfo()]).then(function(info) {
	    return crypto.subtle.encrypt(info[1],info[0],buf);
	});
    },
    decryptChunk: function(buf) {
	return Promise.all([this.key,this.algoInfo()]).then(function(info) {
	    return crypto.subtle.decrypt(info[1],info[0],buf);
	});
    },
    algoInfo: function() {
	return Promise.resolve(this.algo);
    },
    encrypt: function(buf,final) {
	return this.process(buf,final,this.encryptChunk.bind(this),(function() { return this.chunkSizeP; }).bind(this));
    },
    decrypt: function(buf,final) {
	return this.process(buf,final,this.decryptChunk.bind(this),(function() { return this.chunkSizeC; }).bind(this));
    }
};

libVES.Cipher.NULL = function(rec) {
    this.init(rec);
}

libVES.Cipher.AES = function(data) {
    for (var k in data) this[k] = data[k];
};

libVES.Cipher.AES256CBC = function(rec) {
    this.init(rec);
};

libVES.Cipher.AES256GCM = function(rec) {
    this.init(rec);
};

libVES.Cipher.AES256GCMp = function(rec) {
    this.init(rec);
};

libVES.Cipher.AES256GCM1K = function(rec) {
    this.init(rec);
};

libVES.Cipher.NULL.prototype = new libVES.Cipher({
    a: 'NULL',
    keySize: 0,
    ivSize: 0
});

libVES.Cipher.AES.prototype = new libVES.Cipher({
    keySize: 32,
    ivSize: 32,
    algoInfo: function() {
	var self = this;
	return this.IV.then(function(iv) {
	    return {name: self.algo, iv: iv};
	});
    }
});

libVES.Cipher.AES256CBC.prototype = new libVES.Cipher.AES({
    algo: 'AES-CBC',
    keySize: 32,
    ivSize: 16
});

libVES.Cipher.AES256CBC.import = function(args,chain,optns) {
    return chain('import').then(function(buf) {
	return crypto.subtle.decrypt({name: 'AES-CBC', iv: args},optns.key,buf);
    });
};
libVES.Cipher.AES256CBC.export = function(chain,optns) {
    var args = new Uint8Array(16);
    crypto.getRandomValues(args);
    return crypto.subtle.encrypt({name: 'AES-CBC', iv: args},optns.key,optns.content).then(function(buf) {
	return chain('export',{content: buf}).then(function() {
	    return [new libVES.Util.OID('2.16.840.1.101.3.4.1.42'), args];
	});
    });
};
libVES.Cipher.AES256CBC.info = function(chain,optns) {
    return Promise.resolve({algorithm: {name: 'AES-CBC', length: 256}});
};

libVES.Cipher.AES256GCM.prototype = new libVES.Cipher.AES({
    algo: 'AES-GCM',
    keySize: 32,
    ivSize: 12
});

libVES.Cipher.AES256GCMp.prototype = new libVES.Cipher.AES({
    algo: 'AES-GCM',
    keySize: 32,
    ivSize: 12,
    padSize: 32,
    encryptChunk: function(buf0) {
	var buf = new Uint8Array(buf0);
	var pad = this.padSize - (buf.byteLength % this.padSize) - 1;
	var bufp = new Uint8Array(buf.byteLength + pad + 1);
	bufp[0] = pad;
	bufp.set(buf,1);
	return libVES.Cipher.prototype.encryptChunk.call(this,bufp);
    },
    decryptChunk: function(buf) {
	return libVES.Cipher.prototype.decryptChunk.call(this,buf).then(function(bufp0) {
	    var bufp = new Uint8Array(bufp0);
	    return bufp.slice(1,bufp.byteLength - bufp[0]);
	});
    }
});

libVES.Cipher.AES256GCM1K.prototype = new libVES.Cipher.AES({
    algo: 'AES-GCM',
    keySize: 32,
    ivSize: 12,
    chunkSizeP: 1024,
    chunkSizeC: 16,
    algoInfo: function() {
	var self = this;
	if (!this.lastGCM) throw new libVES.Error('Internal', 'GCM HMAC is not buffered');
	return this.IV.then(function(iv) {
	    var buf = new Uint8Array(iv.byteLength + self.lastGCM.byteLength);
	    buf.set(new Uint8Array(iv), 0);
	    buf.set(new Uint8Array(self.lastGCM), iv.byteLength);
	    return libVES.Util.Hash.SHA256.hash(buf).then(function(sha) {
		return { name: self.algo, iv: sha.slice(0, self.ivSize) };
	    });
	});
    },
    encryptChunk: function(buf) {
	var self = this;
	var seed = null;
	if (!this.lastGCM) {
	    seed = new Uint8Array(16);
	    crypto.getRandomValues(seed);
	    this.lastGCM = seed;
	}
	return Promise.all([this.key, this.algoInfo()]).then(function(info) {
	    return crypto.subtle.encrypt(info[1], info[0], buf).then(function(ctext) {
		self.lastGCM = new Uint8Array(ctext.slice(-16));
		if (!seed) return ctext;
		var rs = new Uint8Array(seed.byteLength + ctext.byteLength);
		rs.set(seed, 0);
		rs.set(new Uint8Array(ctext), seed.byteLength);
		return rs;
	    });
	});
    },
    decryptChunk: function(buf) {
	var self = this;
	if (buf.byteLength < 16) throw new libVES.Error('Crypto', 'Invalid ciphertext block size');
	var rs;
	if (this.lastGCM) {
	    rs = Promise.all([this.key, this.algoInfo()]).then(function(info) {
		self.lastGCM = buf.slice(-16);
		return crypto.subtle.decrypt(info[1], info[0], buf);
	    });
	} else {
	    rs = Promise.resolve(new Uint8Array(0));
	    this.chunkSizeC = 1040;
	    this.lastGCM = buf;
	}
	return rs;
    }
});
