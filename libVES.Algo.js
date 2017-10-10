libVES.Algo = {
    RSA: {
	tag: 'RSA',
	decrypt: function(k,buf) {
	    return crypto.subtle.decrypt('RSA-OAEP',k,buf);
	},
	encrypt: function(k,buf) {
	    return crypto.subtle.encrypt('RSA-OAEP',k,buf);
	},
	import: function(data,optns) {
	    return libVES.Util.PEM.import(data,optns);
	},
	export: function(data,optns) {
	    if (data instanceof CryptoKey) switch (data.type) {
		case 'private':
		    var ops = {};
		    for (var k in optns) ops[k] = optns[k];
		    if (!ops.members) ops.members = [
			libVES.getModule(libVES.Util,'PBKDF2'),
			libVES.getModule(libVES.Cipher,'AES256CBC')
		    ];
		    return Promise.all(ops.members).then(function(ms) {
			ops.members = ms;
			return crypto.subtle.exportKey('pkcs8',data).then(function(der) {
			    ops.content = der;
			    var rec = [];
			    if (ops.password) return libVES.Util.PKCS5.export(function(call,optns) {
				rec[1] = optns.content;
				return Promise.resolve();
			    },ops).then(function(data) {
				rec[0] = data;
				return libVES.Util.PEM.encode(libVES.Util.ASN1.encode([rec]),'ENCRYPTED PRIVATE KEY');
			    });
			    else if (ops.opentext) return crypto.subtle.exportKey('pkcs8',data).then(function(der) {
				return libVES.Util.PEM.encode(der,'PRIVATE KEY');
			    });
			    else throw libVES.Error('Internal','No password for key export (opentext=true to export without password?)');
			});
		    });
		case 'public':
		    return crypto.subtle.exportKey('spki',data).then(function(der) {
			return libVES.Util.PEM.encode(der,'PUBLIC KEY');
		    });
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
	    return libVES.Util.PEM.import(data,optns);
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
