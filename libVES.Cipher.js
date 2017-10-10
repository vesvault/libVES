libVES.Cipher = function(data) {
    for (var k in data) this[k] = data[k];
};
libVES.Cipher.prototype = {
    init: function(rec) {
	this.key = rec.slice(0,this.keySize);
	this.IV = this.initIV = rec.slice(0,this.keySize + this.ivSize).slice(-this.ivSize);
	try {
	    this.meta = JSON.parse(libVES.Util.ByteArrayToString(rec.slice(this.keySize + this.ivSize)));
	} catch(e) {
	    this.meta = {};
	}
    },
};

libVES.Cipher.AES256 = function(rec) {
    this.init(rec);
};

libVES.Cipher.AES256CBC = function(rec) {
    this.init(rec);
};

libVES.Cipher.AES256.prototype = new libVES.Cipher({
    keySize: 32,
    ivSize: 32
});

libVES.Cipher.AES256CBC.prototype = new libVES.Cipher({
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
