/**
 * @title libVES base
 *
 * @author Jim Zubov <jz@vesvault.com> (VESvault)
 * GPL license, http://www.gnu.org/licenses/
 */
if (!window.libVES) window.libVES = function(optns) {
    try {
	if (!window.crypto.subtle.digest) throw new libVES.Error('Init','crypto.subtle is improperly implemented?');
    } catch (e) {
	if (e instanceof libVES.Error) throw e;
	throw new libVES.Error('Init','crypto.subtle is not usable' + (document.location.protocol.match(/https/) ? '' : ' (try https?)'));
    }
    for (var k in optns) this[k] = optns[k];
    if (this.domain) this.type = 'secondary';
    else if (this.user) this.type = 'primary';
    else throw new libVES.Error('InvalidValue','Required parameters: user || domain');
    this.unlockedKeys = {};
}

libVES.prototype = {
    apiUrl: 'https://api.ves.host/v1/',
    wwwUrl: 'https://www.vesvault.com/',
//    e2e: ['signal'],
    keyAlgo: 'ECDH',
    textCipher: 'AES256GCMp',
    defaultHash: 'SHA256',
    
    request: function(method,uri,body,optns) {
	if (!optns) optns = {};
	return new Promise(function(resolve,reject) {
	    var xhr = new XMLHttpRequest();
	    xhr.open(method,this.apiUrl + uri);
	    if (optns.abortFn) optns.abortFn(function() {
		return xhr.abort();
	    });
	    xhr.onreadystatechange = function() {
		switch(xhr.readyState) {
		    case 4:
			if (xhr.response && typeof(xhr.response) == 'object') {
			    if (xhr.response.errors) {
				var errs = xhr.response.errors.map(function(e) {
				    return new libVES.Error(e.type,e.message,e);
				});
				if (errs.length) {
				    if (optns && optns.onerror) try {
					resolve(optns.onerror(errs));
				    } catch (e) {
					reject(e);
				    }
				    else reject(errs[0]);
				}
			    }
			    else resolve(xhr.response.result);
			} else reject(new libVES.Error('BadResponse','Empty response'));
		}
	    };
	    if (body != null) xhr.setRequestHeader('Content-Type','application/json');
	    xhr.setRequestHeader('Accept','application/json');
	    if (this.user && optns.password) xhr.setRequestHeader('Authorization','Basic ' + btoa(this.user + ':' + optns.password));
	    else if (this.token) xhr.setRequestHeader('Authorization','Bearer ' + this.token);
	    xhr.responseType = 'json';
	    xhr.send(body);
	}.bind(this));
    },
    get: function(uri,fields,optns) {
	return this.request('GET',this.uriWithFields(uri,fields),null,optns);
    },
    post: function(uri,data,fields,optns) {
	return this.request('POST',this.uriWithFields(uri,fields),JSON.stringify(data),optns);
    },
    uriWithFields: function(uri,fields) {
	return fields ? uri + (uri.match(/\?/) ? '&' : '?') + 'fields=' + this.uriListFields(fields) : uri;
    },
    uriListFields: function(fields) {
	if (typeof(fields) == 'object') {
	    var rs = [];
	    if (fields[0]) rs = fields;
	    else for (var k in fields) {
		if (fields[k]) rs.push(k + (typeof(fields[k]) == 'object' ? '(' + this.uriListFields(fields[k]) + ')' : ''));
	    }
	    return rs.join(',');
	}
	return '';
    },
    login: function(passwd) {
	if (this.token) return this.me();
	var self = this;
	return this.userMe = Promise.resolve(passwd).then(function(passwd) {
	    return self.get('me',{sessionToken: true},{password: passwd}).then(function(data) {
		if (!data.sessionToken) throw new libVES.Error('InvalidValue','Session Token is not received');
		self.token = data.sessionToken;
		return new libVES.User(data,self);
	    });
	});
    },
    logout: function() {
	this.token = undefined;
	return this.lock();
    },
    delegate: function(optns) {
	var self = this;
	return libVES.getModule(libVES,'Delegate').then(function(dlg) {
	    return dlg.login(self,null,optns);
	});
    },
    me: function() {
	var self = this;
	if (!this.userMe) this.userMe = this.get('me').then((function(data) {
	    return new libVES.User(data,self);
	}).bind(this));
	return this.userMe;
    },
    unlock: function(veskey) {
	var self = this;
	return this.getVaultKey().then(function(vkey) {
	    return vkey.unlock(Promise.resolve(veskey)).then(function(cryptoKey) {
		if (!self.token && self.type == 'secondary') return vkey.getSessionToken().then(function(tkn) {
		    self.token = tkn;
		    return Promise.resolve(veskey).then(function(veskey) {
			if (veskey) return vkey.reshareVESkey(veskey).catch(function(){});
		    }).then(function() {
			return cryptoKey;
		    });
		});
		return cryptoKey;
	    });
	});
    },
    lock: function() {
	this.unlockedKeys = {};
	return Promise.resolve(true);
    },
    reset: function(val) {
	this.userMe = undefined;
	return this.lock().then(function() {
	    return val;
	});
    },
    getVaultKey: function() {
	var self = this;
	switch (this.type) {
	    case 'primary': return this.me().then(function(me) {
		return me.getCurrentVaultKey();
	    });
	    case 'secondary': return (this.vaultKey || (this.vaultKey = this.prepareExternals({externalId: self.externalId}).then(function(ext) {
		var vKey = new libVES.VaultKey({type: 'secondary', externals: ext},self);
		return vKey.getField('encSessionToken').then(function(tk) {
		    return vKey;
		});
	    })));
	    default: throw new libVES.Error('Internal','Invalid libVES.type: ' + this.type);
	}
    },
    getShadowKey: function() {
	return this.me().then(function(me) {
	    return me.getShadowVaultKey();
	});
    },
    getVaultKeysById: function() {
	return this.me().then(function(me) {
	    return me.getVaultKeys().then(function(vaultKeys) {
		return Promise.all(vaultKeys.map(function(e,i) {
		    return e.getId();
		})).then(function(ids) {
		    var rs = {};
		    for (var i = 0; i < ids.length; i++) rs[ids[i]] = vaultKeys[i];
		    return rs;
		});
	    });
	});
    },
    getItems: function() {
	var self = this;
	return this.getVaultKey().then(function(k) {
	    return k.getId().then(function(kid) {
		return k.getVaultEntries().then(function(ves) {
		    var vis = {};
		    var vlst = [];
		    for (var i = 0; i < ves.length; i++) {
			var viid = ves[i].vaultItem.id;
			if (!vis[viid]) {
			    var vi = vis[viid] = self.getItem(ves[i].vaultItem);
			    vlst.push(vi);
			    vi.vaultEntryByKey[kid] = ves[i];
			}
		    }
		    return vlst;
		});
	    });
	});
    },
    getItem: function(data) {
	return new libVES.VaultItem(data,this);
    },
    postItem: function(data) {
	var vi = new libVES.VaultItem(data,this);
	return vi.validate().then(function() {
	    return vi.post();
	});
    },
    usersToKeys: function(users) {
	var self = this;
	return Promise.all(users.map(function(u) {
	    if (typeof(u) == 'object') {
		if (u instanceof libVES.VaultKey) return [u];
		else if (u instanceof libVES.External) return [new libVES.VaultKey({externals:[u]},self)];
		else if (u instanceof libVES.User) return self.getUserKeys(u);
		else if (u instanceof Array || u.domain != null || u.externalId != null) return self._matchSecondaryKey(u,u.user).then(function(vkey) {
		    return [vkey];
		});
	    }
	    return self.getUserKeys(self._matchUser(u));
	})).then(function(ks) {
	    var rs = [];
	    for (var i = 0; i < ks.length; i++) for (var j = 0; j < ks[i].length; j++) rs.push(ks[i][j]);
	    return rs;
	});
    },
    _matchUser: function(u) {
	if (typeof(u) == 'object') {
	    if (u instanceof libVES.User) return u;
	    else return new libVES.User(u,this);
	} else if (typeof(u) == 'string' && u.match(/^\S+\@\S+$/)) return new libVES.User({email: u},this);
	throw new libVES.Error('BadUser',"Cannot match user: " + u,{value: u});
    },
    _matchSecondaryKey: function(ext,user) {
	var self = this;
	var m = function() {
	    return libVES.getModule(libVES.Domain,ext.domain);
	};
	return (ext.externalId ? self.prepareExternals(ext) : m().then(function(dom) {
	    return Promise.resolve(user || self.me()).then(function(u) {
		return dom.userToVaultRef(u);
	    }).then(function(ex) {
		return self.prepareExternals([ex]);
	    });
	}).catch(function(e) {
	    throw new libVES.Error('NotFound','Cannot match externalId for domain:' + ext.domain + ', user:' + user + '. Define libVES.Domain.' + ext.domain + '.userToVaultRef(user) to return a valid reference.',{error: e});
	})).then(function(exts) {
	    var vkey = new libVES.VaultKey({externals: exts, creator: self.me()},self);
	    return vkey.getId().then(function() {
		return vkey;
	    }).catch(function(e) {
		if (e.code != 'NotFound') throw e;
		return Promise.resolve(user || m().then(function(dom) {
		    return dom.vaultRefToUser(exts[0]);
		})).catch(function(e) {
		    throw new libVES.Error('NotFound','No matching secondary key (domain:' + ext.domain + ', externalId:' + ext.externalId + '). Supply "user" to create the temp key, or define libVES.Domain.' + ext.domain + '.vaultRefToUser(vaultRef) to return matching libVES.User',{error: e});
		}).then(function(u) {
		    return self.me().then(function(me) {
			return Promise.all([me.getId(),u.getId()]).then(function(ids) {
			    if (ids[0] == ids[1]) return self.getSecondaryKey(exts,true);
			}).catch(function(e) {
			    if (e != 'NotFound') throw e;
			}).then(function(rs) {
			    return rs || self.createTempKey(self._matchUser(u)).then(function(vkey) {
				return vkey.setField('externals',exts).then(function() {
				    return vkey;
				});
			    });
			});
		    });
		});
	    });
	});
    },
    getUserKeys: function(usr) {
	var self = this;
	return usr.getActiveVaultKeys().catch(function(e) {
	    if (e.code == 'NotFound') return [];
	    throw e;
	}).then(function(keys) {
	    return Promise.all(keys.map(function(k,i) {
		return k.getPublicCryptoKey().then(function() {
		    return k;
		}).catch(function() {});
	    })).then(function(keys) {
		var rs = [];
		for (var i = 0; i < keys.length; i++) if (keys[i]) rs.push(keys[i]);
		return rs;
	    });
	}).then(function(keys) {
	    if (!keys.length) return self.createTempKey(usr).then(function(k) {
		return [k];
	    });
	    return keys;
	});
    },
    createTempKey: function(usr,optns) {
	var self = this;
	var key = new libVES.VaultKey({type: 'temp', algo: this.keyAlgo, user: usr},self);
	var veskey = this.generateVESkey(usr);
	return key.generate(veskey,optns).then(function(k) {
	    if (self.e2e && self.e2e.length) usr.e2e = self.getVESkeyE2E(veskey,usr);
	    key.setField('vaultItems',veskey.then(function(v) {
		var vi = new libVES.VaultItem({type: 'password'},self);
		return self.me().then(function(me) {
		    return vi.shareWith([me],v,false).then(function() {
			return [vi];
		    });
		});
	    }));
	    key.setField('creator',self.me());
	    return key;
	});
    },
    generateVESkey: function(usr) {
	var buf = new Uint8Array(24);
	crypto.getRandomValues(buf);
	return Promise.resolve(libVES.Util.ByteArrayToB64(buf));
    },
    getVESkeyE2E: function(veskey,usr) {
	var self = this;
	return veskey.then(function(v) {
	    return libVES.getModule(libVES.E2E,['Dialog','TempKey']).then(function(cls) {
		return new cls({
		    user: usr,
		    e2e: self.e2e,
		    tempKey: v
		});
	    });
	});
    },
    setVESkey: function(veskey,lost,options) {
	var self = this;
	return this.me().then(function(me) {
	    return (new libVES.VaultKey({type: 'current', algo: self.keyAlgo, user: me},self)).generate(Promise.resolve(veskey),options).then(function(k) {
		return me.getVaultKeys().then(function(vkeys) {
		    var cur = null;
		    return Promise.all(vkeys.map(function(vkey,i) {
			return vkey.getType().then(function(t) {
			    switch (t) {
				case 'current':
				    cur = vkey;
				case 'lost':
				    return vkey.unlock().then(function() {
					return k.rekeyFrom(vkey);
				    }).catch(function(e) {});
			    }
			});
		    })).then(function(d) {
			var r;
			if (cur && lost) r = cur.setField('type','lost').then(function() {
			    k.user = undefined;
			    return me.setField('vaultKeys',[cur,k]).then(function() {
				return me;
			    });
			});
			else r = k;
			me.currentVaultKey = me.activeVaultKeys = undefined;
			if (!cur || !lost) me.vaultKeys = undefined;
			return r;
		    });
		}).then(function(r) {
		    return r.post(undefined,undefined,options);
		}).catch(function(e) {
		    self.reset();
		    throw e;
		}).then(function(post) {
		    return self.reset(post);
		}).then(function() {
		    return self.getVaultKey();
		});
	    });
	});
    },
    prepareExternals: function(ext) {
	var self = this;
	if (!ext) return Promise.reject(new libVES.Error('InvalidValue','External reference is required'));
	return Promise.resolve(ext).then(function(ext) {
	    if (!(ext instanceof Array)) ext = [ext];
	    if (ext.length < 1) throw new libVES.Error('InvalidValue','External reference is required');
	    var rs = [];
	    for (var i = 0; i < ext.length; i++) {
		rs[i] = (typeof(ext[i]) == 'object') ? {externalId: ext[i].externalId, domain: ext[i].domain} : {externalId: ext[i]};
		if (!rs[i].domain && !(rs[i].domain = self.domain)) throw new libVES.Error('InvalidValue','External reference: domain is required');
		if (!rs[i].externalId) throw new libVES.Error('InvalidValue','External reference: externalId is required');
	    }
	    return rs;
	});
    },
    getSecondaryKey: function(ext,force) {
	var self = this;
	return this.prepareExternals(Promise.resolve(ext).then(function(e) {
	    if (e.domain && !e.externalId) return libVES.getModule(libVES.Domain,e.domain).then(function(mod) {
		return self.me().then(function(me) {
		    return mod.userToVaultRef(me,self);
		});
	    });
	    return e;
	})).then(function(ext) {
	    var vkey = new libVES.VaultKey({externals: ext},self);
	    return vkey.getId().then(function(id) {
		return vkey;
	    }).catch(function(e) {
		if (!force) throw e;
		return self.setSecondaryKey(ext);
	    });
	});
    },
    setSecondaryKey: function(ext,veskey,optns) {
	var self = this;
	return this.prepareExternals(ext).then(function(ext) {
	    if (!veskey) veskey = self.generateVESkey();
	    return self.me().then(function(me) {
		return (new libVES.VaultKey({type: 'secondary', algo: self.keyAlgo, user: me, externals: ext},self)).generate(veskey,optns).then(function(k) {
		    var vi = new libVES.VaultItem({type: "password"},self);
		    k.setField('vaultItems',[vi]);
		    return Promise.resolve(veskey).then(function(v) {
			if (!v) throw new libVES.Error('InvalidValue','VESkey cannot be empty');
			return vi.shareWith([me],v,false).then(function() {
			    return k.post().then(function(post) {
				self.reset(post);
				return k;
			    });
			});
		    });
		});
	    });
	});
    },
    setShadow: function(usrs,optns) {
	if (!optns || !optns.n) return Promise.reject(new libVES.Error('InvalidValue','optns.n must be an integer'));
	var self = this;
	var rkey = new Uint8Array(32);
	window.crypto.getRandomValues(rkey);
	var algo = optns.v ? libVES.Scramble.algo[optns.v] : libVES.Scramble.RDX;
	if (!algo) return Promise.reject(new libVES.Error('InvalidValue','Unknown scramble algorithm: ' + optns.v));
	var s = new algo(optns.n);
	return s.explode(rkey,usrs.length,optns).then(function(tkns) {
	    return self.me().then(function(me) {
		me.activeVaultKeys = undefined;
		return me.setField('shadowVaultKey',new libVES.VaultKey({type: 'shadow', user: me, algo: self.keyAlgo},self).generate(rkey,optns),false).then(function(k) {
		    return me.getCurrentVaultKey().then(function(curr) {
			return k.rekeyFrom(curr).catch(function() {}).then(function() {
			    libVES.Object._refs = {"#/":k};
			    k.setField('vaultItems',Promise.all(tkns.map(function(tk,i) {
				var vi = new  libVES.VaultItem({type: 'secret'},self);
				return vi.shareWith([usrs[i]],tk,false).then(function() {
				    return vi;
				});
			    })).then(function(vis) {
				delete(libVES.Object._refs);
				return vis;
			    }));
			    return k.post();
			});
		    });
		}).catch(function(e) {
		    me.shadowVaultKey = undefined;
		    throw e;
		}).then(function() {
		    me.currentVaultKey = me.shadowVaultKey = me.activeVaultKeys = undefined;
		    return me.getShadowVaultKey();
		});
	    });
	});
    },
    getFile: function(fileRef) {
	var self = this;
	return self.prepareExternals(fileRef).then(function(ext) {
	    return new libVES.File({externals: ext},self);
	});
    },
    getFileItem: function(fileRef) {
	var self = this;
	return self.getFile(fileRef).then(function(file) {
	    return new libVES.VaultItem({file: file},self);
	});
    },
    getValue: function(fileRef) {
	return this.getFileItem(fileRef).then(function(vaultItem) {
	    return vaultItem.get();
	});
    },
    putValue: function(fileRef,value,shareWith) {
	var self = this;
	return this.getFileItem(fileRef).then(function(vaultItem) {
	    return vaultItem.setField('type',libVES.VaultItem.Type._detect(value)).then(function(type) {
		return vaultItem.getFile().then(function(file) {
		    return file.getExternals().then(function(exts) {
			return exts[0].getDomain().then(function(domain) {
			    var m = libVES.getModule(libVES.Domain,domain);
			    file.setField('path',m.then(function(mod) {
				return mod.defaultFilePath(file,exts[0]);
			    }).catch(function() {
				return '';
			    }));
			    file.setField('name',m.then(function(mod) {
				return mod.defaultFileName(file,exts[0]);
			    }).catch(function() {
				return null;
			    }));
			    return type;
			});
		    });
		});
	    }).then(function() {
	        return Promise.resolve(shareWith || self.getFileItem(fileRef).then(function(vi) {
	    	    return vi.getShareList();
	    	}).catch(function(e) {
		    return self.usersToKeys([{domain: fileRef.domain}]);
		})).then(function(shareWith) {
		    return vaultItem.shareWith(shareWith,value);
		});
	    });
	});
    },
    shareFile: function(fileRef,shareWith) {
	return this.getFileItem(fileRef).then(function(vaultItem) {
	    return vaultItem.shareWith(shareWith);
	});
    },
    fileExists: function(fileRef) {
	return this.getFileItem(fileRef).then(function(vaultItem) {
	    return vaultItem.getId().then(function(id) {
		return true;
	    }).catch(function(e) {
		if (e.code == 'NotFound') return false;
		throw e;
	    });
	});
    },
    deleteFile: function(fileRef) {
	return this.getFile(fileRef).then(function(file) {
	    return file.delete();
	});
    },
    newSecret: function(cls) {
	if (!cls) cls = this.textCipher;
	else cls = cls.split('.')[0];
	return libVES.getModule(libVES.Cipher,cls).then(function(ci) {
	    return (new ci()).getSecret().then(function(buf) {
		return cls + '.' + libVES.Util.ByteArrayToB64W(buf);
	    });
	});
    },
    secretToCipher: function(secret) {
	var ss = secret.split('.');
	return libVES.getModule(libVES.Cipher,ss[0]).then(function(cls) {
	    return new cls(libVES.Util.B64ToByteArray(ss[1]));
	});
    },
    encryptText: function(openText,secret) {
	return this.secretToCipher(secret).then(function(ci) {
	    return ci.encrypt(libVES.Util.StringToByteArray(openText),true).then(function(buf) {
		return libVES.Util.ByteArrayToB64W(buf);
	    });
	});
    },
    decryptText: function(cipherText,secret) {
	return this.secretToCipher(secret).then(function(ci) {
	    return ci.decrypt(libVES.Util.B64ToByteArray(cipherText),true).then(function(buf) {
		return libVES.Util.ByteArrayToString(buf);
	    });
	});
    },
    hashText: function(text,cls) {
	if (cls) cls = cls.split('.')[0];
	else cls = this.defaultHash;
	return libVES.getModule(libVES.Util,['Hash',cls]).then(function(fn) {
	    return fn(libVES.Util.StringToByteArray(text)).then(function(buf) {
		return cls + '.' + libVES.Util.ByteArrayToB64W(buf);
	    });
	});
    },
    found: function(veskeys,vaultKeys) {
	var self = this;
	return Promise.resolve(veskeys).then(function(veskeys) {
	    var chain = Promise.resolve(0);
	    if (veskeys && !(veskeys instanceof Array)) veskeys = [veskeys];
	    return (vaultKeys ? Promise.resolve(vaultKeys) : self.me().then(function(me) {
		var rs = [];
		return me.getVaultKeys().then(function(vaultKeys) {
		    return Promise.all(vaultKeys.map(function(vaultKey,i) {
			return vaultKey.getType().then(function(t) {
			    switch (t) {
				case 'temp': case 'lost': case 'recovery': rs.push(vaultKey);
			    }
			});
		    }));
		}).then(function() {
		    return rs;
		});
	    })).then(function(vaultKeys) {
		if (!(vaultKeys instanceof Array)) vaultKeys = [vaultKeys];
		return Promise.all(vaultKeys.map(function(vaultKey,i) {
		    return vaultKey.getRecovery().then(function(rcv) {
			return rcv.unlock();
		    }).catch(function(e) {
			var rs = vaultKey.unlock();
			if (veskeys) veskeys.map(function(veskey,i) {
			    rs = rs.catch(function() {
				return vaultKey.unlock(veskey);
			    });
			});
			return rs;
		    }).then(function() {
			chain = chain.then(function(ct) {
			    return vaultKey.rekey().then(function() {
				if (self.onRekey) return self.onRekey(vaultKey);
			    }).then(function() {
				return ct + 1;
			    });
			}).catch(function(e) {console.log(e);});;
		    }).catch(function() {});
		}));
	    }).then(function() {
		return chain;
	    });
	}).then(function(ct) {
	    if (ct) return ct + self.found();
	});
    },
    getMyRecoveries: function() {
	var self = this;
	return self.me().then(function(me) {
	    return me.getVaultKeys().then(function(vaultKeys) {
			return Promise.all(vaultKeys.map(function(e,i) {
				return e.getType();
			})).then(function(types) {
				var rs = [];
				for (var i = 0; i < types.length; i++) switch (types[i]) {
					case 'recovery': case 'shadow':
					rs.push(vaultKeys[i].getRecovery());
				}
				return Promise.all(rs);
			});
		});
	});
    },
    getFriendsRecoveries: function() {
	var self = this;
	return self.me().then(function(me) {
	    return me.getFriendsVaultKeys().then(function(vaultKeys) {
		return Promise.all(vaultKeys.map(function(e,i) {
		    return e.getType();
		})).then(function(types) {
		    var rs = [];
		    for (var i = 0; i < types.length; i++) switch (types[i]) {
			case 'recovery': case 'shadow':
			    rs.push(vaultKeys[i].getRecovery());
		    }
		    return Promise.all(rs);
		});
	    });
	});
    }
};

libVES.Error = function(code,msg,optns) {
    this.code = code;
    this.message = msg;
    if (optns) for (var k in optns) this[k] = optns[k];
};

libVES.Error.prototype.toString = function() {
    return this.message || this.code;
};

libVES.getModule = function(sectn,mods) {
    var mod;
    if (mods instanceof Array) mod = mods[0];
    else mods = [mod = mods];
    if (sectn[mod]) return mods.length > 1 ? libVES.getModule(sectn[mod],mods.slice(1)) : Promise.resolve(sectn[mod]);
    if (sectn.loadModule) {
	if (sectn.loadModule[mod]) return sectn.loadModule[mod];
    } else sectn.loadModule = {};
    return sectn.loadModule[mod] = libVES.loadModule(sectn,mod).then(function(m) {
	delete(sectn.loadModule[mod]);
	sectn[mod] = m;
	return ((mods instanceof Array) && mods.length > 1 ? libVES.getModule(m,mods.slice(1)) : m);
    });
};
libVES.getModuleFunc = function(sectn,mod,then) {
    return function() { var m = libVES.getModule(sectn,mod); return then ? m.then(then) : m; };
};
libVES.loadModule = function(sectn,mod) {
    return Promise.reject(new libVES.Error('Internal',"Cannot load " + sectn + '.' + mod));
};

if (!libVES.Domain) libVES.Domain = {};
