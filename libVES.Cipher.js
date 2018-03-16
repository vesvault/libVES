/**
 * @title libVES.Cipher
 *
 * @author Jim Zubov <jz@vesvault.com> (VESvault)
 * GPL license, http://www.gnu.org/licenses/
 */
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
	var meta = null;
	if (this.meta) for (var k in this.meta) {
	    meta = libVES.Util.StringToByteArray(JSON.stringify(this.meta));
	    break;
	}
	var buf = new Uint8Array(this.keySize + this.ivSize + (meta ? meta.byteLength : 0));
	return Promise.all([this.key,this.IV]).then(function(data) {
	    return crypto.subtle.exportKey("raw",data[0]).then(function(key) {
		buf.set(new Uint8Array(key),0);
		buf.set(new Uint8Array(data[1]),key.byteLength);
		if (meta) buf.set(meta,key.byteLength + data[1].byteLength);
		return buf;
	    });
	});
    },
    buildKey: function(key) {
	if (!this.algo) return Promise.resolve(key);
	return crypto.subtle.importKey('raw',key,this.algo,true,['encrypt','decrypt']);
    },
    process: function(buf,final,callbk,chunkSize) {
	buf = new Uint8Array(buf);
	if (this.processBuf) {
	    var b = new Uint8Array(buf.byteLength + this.processBuf.byteLength);
	    b.set(this.processBuf,0);
	    b.set(buf,this.processBuf.byteLength);
	    buf = b;
	}
	var p = final ? buf.byteLength : (chunkSize ? Math.floor(buf.byteLength / chunkSize) * chunkSize : 0);
	this.processBuf = p < buf.byteLength ? buf.slice(p) : null;
	return p > 0 || final ? callbk(buf.slice(0,p)) : Promise.resolve(new Uint8Array(0));
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
	return this.process(buf,final,this.encryptChunk.bind(this),this.chunkSizeP);
    },
    decrypt: function(buf,final) {
	return this.process(buf,final,this.decryptChunk.bind(this),this.chunkSizeC);
    }
};

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
