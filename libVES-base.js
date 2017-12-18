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
    if (this.domain && this.externalId != null) this.type = 'secondary';
    else if (this.user) this.type = 'primary';
    else throw new libVES.Error('InvalidValue','Required parameters: user || (domain && externalId)');
    this.unlockedKeys = {};
}

libVES.prototype = {
    apiUrl: 'https://api.ves.host/v1/',
//    e2e: ['signal'],
    keyAlgo: 'RSA',
    
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
	    if (this.user && optns.passwd) xhr.setRequestHeader('Authorization','Basic ' + btoa(this.user + ':' + optns.passwd));
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
	var self = this;
	return this.userMe = Promise.resolve(passwd).then(function(passwd) {
	    return self.get('me',{sessionToken: true},{passwd: passwd}).then(function(data) {
		if (!data.sessionToken) throw new libVES.Error('InvalidValue','Session Token is not received');
		self.token = data.sessionToken;
		return new libVES.User(data,self);
	    });
	});
    },
    logout: function() {
	this.token = undefined;
	return Promise.resolve(true);
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
		    return cryptoKey;
		});
		return cryptoKey;
	    });
	});
    },
    lock: function() {
	var pr = [];
	for (var i in this.unlockedKeys) pr.push(this.unlockedKeys[i].then(function(k) {
	    return k.lock();
	}));
	return Promise.all(pr);
    },
    reset: function(val) {
	if (this.userMe) return this.userMe.then(function(me) {
	    return me.reset().then(function() {
		return val;
	    });
	});
	return Promise.resolve(val);
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
	    var req;
	    if (typeof(u) == 'string' && u.match(/^\S+\@\S+$/)) req = {email: u};
	    else if (typeof(u) == 'object') {
		if (u instanceof libVES.User) return self.getUserKeys(u);
		req = u;
	    } else throw new libVES.Error('BadUser',"Cannot match user: " + u,{value: u});
	    var usr = new libVES.User(req,self);
	    return self.getUserKeys(usr);
	})).then(function(ks) {
	    var rs = [];
	    for (var i = 0; i < ks.length; i++) for (var j = 0; j < ks[i].length; j++) rs.push(ks[i][j]);
	    return rs;
	});
    },
    getUserKeys: function(usr) {
	console.log('getUserKeys',usr,usr.activeVaultKeys,usr.currentVaultKey,usr.shadowVaultKey);
	var self = this;
	return usr.getActiveVaultKeys().then(function(keys) {
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
	    key.getField('vaultItems').then(function(vis) { console.log(vis); });
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
		return self.getVaultKey().then(function(cur) {
		    var r = k.rekeyFrom(cur);
		    me.currentVaultKey = me.vaultKeys = me.activeVaultKeys = undefined;
		    return r;
		}).then(function(k) {
		    return k.post();
		}).then(function(post) {
		    return self.reset(post);
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
	    for (var i = 0; i < ext.length; i++) {
		if (typeof(ext[i]) != 'object') ext[i] = {externalId: ext[i]};
		if (!ext[i].domain && !(ext[i].domain = self.domain)) throw new libVES.Error('InvalidValue','External reference: domain is required');
		if (!ext[i].externalId) throw new libVES.Error('InvalidValue','External reference: externalId is required');
	    }
	    return ext;
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
				return self.reset(post);
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
	return this.usersToKeys(usrs).then(function(ks) {
	    var rkey = new Uint8Array(32);
	    window.crypto.getRandomValues(rkey);
	    var algo = optns.v ? libVES.Scramble.algo[optns.v] : libVES.Scramble.RDX;
	    if (!algo) throw 'Unknown scramble algorithm: ' + optns.v;
	    var s = new algo(optns.n);
	    return s.explode(rkey,usrs.length).then(function(tkns) {
		return self.me().then(function(me) {
		    me.activeVaultKeys = undefined;
		    return me.setField('shadowVaultKey',new libVES.VaultKey({type: 'shadow', user: me, algo: self.keyAlgo},self).generate(rkey,optns),false).then(function(k) {
			return me.getCurrentVaultKey().then(function(curr) {
			    return k.rekeyFrom(curr).catch(function() {}).then(function() {
				k.setField('vaultItems',Promise.all(tkns.map(function(tk,i) {
				    var vi = new  libVES.VaultItem({type: 'secret'},self);
				    return vi.shareWith([usrs[i]],tk,false).then(function() {
					return vi;
				    });
				})));
//				me.vaultEntries = undefined;
				return k.post();
			    });
			});
		    }).catch(function(e) {
			me.shadowVaultKey = undefined;
			throw e;
		    }).then(function() {
			return me.getShadowVaultKey();
		    });
		});
	    });
	});
    },
    getFile: function(fileRef) {
	var self = this;
	return self.prepareExternals(fileRef).then(function(ext) {
	    new libVES.File({externals: ext},self);
	});
    },
    getFileItem: function(fileRef) {
	var self = this;
	return new libVES.VaultItem({file: self.getFile(fileRef)},self);
    },
    getValue: function(fileRef) {
	return this.getFileItem(fileRef).then(function(vaultItem) {
	    return vaultItem.get();
	});
    },
    putValue: function(fileRef,value,shareWith) {
	return this.getFileItem(fileRef).then(function(vaultItem) {
	    
	});
    },
    deleteFile: function(fileRef) {
	return this.getFile(fileRef).then(function(file) {
	    return file.delete();
	});
    },
    shareTempKeys: function() {
	var self = this;
	return self.me().then(function(me) {
	    return me.getCreatedVaultKeys().then(function(vks) {
		return Promise.all(vks.map(function(vk,i) {
		    return vk.getUser().then(function(u) {
			return u.getCurrentVaultKey().then(function(curr) {
			    if (curr) return vk.getVaultItem().then(function(vi) {
				return vi.getVaultEntries().then(function() {
				    return curr.getId().then(function(id) {
					if (!vi.vaultEntryByKey[id]) return vi.shareWith([u]);
				    });
				});
			    });
			});
		    });
		}));
	    });
	});
    },
    rekeyTempKeys: function() {
	var self = this;
	return self.me().then(function(me) {
	    return me.getVaultKeys().then(function(vks) {
		return Promise.all(vks.map(function(vk,i) {
		    return vk.getType().then(function(t) {
			switch (t) {
			    case 'temp':
				return vk.unlock().then(function() {
				    return vk.getExternals().then(function(ex) {
					return (ex.length ? self.getSecondaryKey(ex) : self.getCurrentKey()).then(function(curr) {
					    return curr.rekeyTo(vk).then(function() {
					        return vk.delete();
					    });
					});
				    });
				}).catch(function() {
				});
			}
		    });
		}));
	    });
	});
    },
    getMyRecoveries: function() {
	return this.getVaultKeys().then(function(vaultKeys) {
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
    },
    watch: function() {
	var self = this;
	return this.me().then(function(me) {
	    return me.loadFields({
		vaultKeys: {
		    id: true,
		    type: true,
		    algo: true,
		    vaultItem: {
			vaultEntries: {
			    vaultKey: true,
			    encData: true
			}
		    }
		},
		createdVaultKeys: {
		    id: true,
		    type: true,
		    algo: true,
		    creator: {
			id: true,
			currentVaultKey: {
			    id: true,
			    type: true,
			    algo: true,
			    publicKey: true
			}
		    },
		    vaultItem: {
			vaultEntries: {
			    vaultKey: true,
			    encData: true
			}
		    }
		}
	    },true,{
		abortFn: function(callbk) {
		    self.watchAbortFn = callbk;
		},
		poll: 120
	    }).then(function() {
		return Promise.all([
		    self.shareTempKeys(),
		    self.rekeyTempKeys()
		]);
	    }).catch(function() {
	    }).then(function() {
		self.watchTmOut = window.setTimeout(self.watch.bind(self),1500);
	    });
	});
    },
    abort: function() {
	window.clearTimeout(this.watchTmOut);
	if (this.watchAbortFn) this.watchAbortFn();
	this.watchAbortFn = null;
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
