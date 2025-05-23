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
 * libVES-base.js             libVES: Main file
 *
 ***************************************************************************/

if (typeof(libVES) != 'function') function libVES(optns) {
    try {
	if (!crypto.subtle.digest) throw new libVES.Error('Init', 'crypto.subtle is unavailable or improperly implemented');
    } catch (e) {
	if (e instanceof libVES.Error) throw e;
	throw new libVES.Error('Init', 'crypto.subtle is not available');
    }
    for (var k in optns) this[k] = optns[k];
    if (this.domain) this.type = 'secondary';
    else if (this.user) this.type = 'primary';
    else throw new libVES.Error('InvalidValue','Required parameters: user || domain');
    this.unlockedKeys = {};
    this.pendingKeys = {};
}

libVES.prototype = {
    constructor: libVES,
    apiUrl: 'https://api.ves.host/v1/',
    pollUrl: 'https://poll.ves.host/v1/',
    wwwUrl: 'https://www.vesvault.com/',
    keyAlgo: 'ECDH',
    keyOptions: {namedCurve: 'P-521'},
    textCipher: 'AES256GCMp',
    defaultHash: 'SHA256',
    propagators: null,
    request: function(method,uri,body,optns) {
	var self = this;
	if (!optns) optns = {};
	return new Promise(function(resolve,reject) {
	    var xhr = new XMLHttpRequest();
	    xhr.open(method, (uri.match(/^https\:/) ? uri : this.apiUrl + uri));
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
				    var retry = function(o) { return self.request(method, uri, body, (o || optns)); };
				    if (optns && optns.onerror) try {
					resolve(optns.onerror(errs, optns, retry));
				    } catch (e) {
					reject(e);
				    } else if (self.onerror) try {
					resolve(self.onerror(errs, optns, retry));
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
	    else if (optns.token ?? this.token) xhr.setRequestHeader('Authorization','Bearer ' + (optns.token ? optns.token : this.token));
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
    mergeFieldList: function(flds, flds2) {
	for (var k in flds2) if (flds[k] instanceof Object) flds[k] = this.mergeFieldList(flds[k], flds2[k]); else flds[k] = flds2[k];
	return flds;
    },
    elevateAuth: function(optns) {
	var self = this;
	if (optns && (optns.password || optns.token)) return Promise.resolve(optns);
	return (optns && optns.authVaultKey ? Promise.resolve(optns.authVaultKey) : self.getVaultKey()).then(function(vkey) {
	    return vkey.getSessionToken().then(function(tkn) {
		if (!tkn) return optns;
		var o = {token: tkn};
		if (optns) for (var k in optns) o[k] = optns[k];
		return o;
	    });
	});
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
	this.token = this.userMe = this.vaultKey = undefined;
	return this.lock();
    },
    delegate: function(optns) {
	var self = this;
	return libVES.getModule(libVES,'Delegate').then(function(dlg) {
	    return dlg.login(self,null,optns).then(function() {
		return self;
	    });
	});
    },
    getVESflow: function() {
	var self = this;
	if (!this.VESflow) this.VESflow = libVES.getModule(libVES, 'Flow').then(function(fw) {
	    var flow = new fw('VES');
	    var authf = self.authorize.bind(self);
	    self.authorize = function(msg) {
		flow.setValue(msg);
		return authf(msg);
	    };
	    var outf = self.logout.bind(self);
	    self.logout = function() {
		flow.logout();
		return outf();
	    };
	    return flow;
	});
	return this.VESflow;
    },
    flow: function(start, optns) {
	var self = this;
	return self.getVESflow().then(function(flow) {
	    return flow.get().then(function(auth) {
		return self.authorize(auth);
	    }).catch(function(e) {
		if (!start || (e && e.code == 'Reload')) throw e;
		var url = self.wwwUrl + 'vv/unlock?url=' + encodeURIComponent(document.location.href) + '&domain=' + encodeURIComponent(self.domain);
		if (optns) for (var k in optns) if (optns[k] != null) url += '&' + encodeURIComponent(k) + '=' + encodeURIComponent(optns[k]);
		flow.url = undefined;
		return flow.setValue(undefined).then(function() {
		    return flow.addToken(url).then(function(url) {
			document.location.replace(url);
			throw new libVES.Error('Redirect', 'Starting VES Authorization...');
		    });
		});
	    });
	});
    },
    authorize: function(msg) {
	var self = this;
	return this.logout().then(function() {
	    if (msg.token) self.token = msg.token;
	    if (msg.domain) self.domain = msg.domain;
	    if (msg.externalId) self.externalId = msg.externalId;
	    return (msg.VESkey ? self.unlock(msg.VESkey) : self.me()).then(function() {
		return self;
	    });
	});
    },
    carry: function(optns) {
	var cr = {};
	if (this.externalId) cr.externalId = this.externalId;
	if (this.domain) cr.domain = this.domain;
	if (this.token) cr.token = this.token;
	if (this.VESkey) cr.VESkey = this.VESkey;
	try {
	    sessionStorage['libVES_carry'] = JSON.stringify(cr);
	} catch (e) {
	    return Promise.reject(e);
	}
	return Promise.resolve(true);
    },
    pick: function(optns) {
	try {
	    if (!sessionStorage['libVES_carry']) throw new libVES.Error('NotFound','No libVES_carry in sessionStorage');
	    var cr = JSON.parse(sessionStorage['libVES_carry']);
	    delete(sessionStorage['libVES_carry']);
	    return this.authorize(cr);
	} catch (e) {
	    return Promise.reject(e);
	}
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
	    return vkey.unlock(veskey).then(function(cryptoKey) {
		if (self.VESkey === null) self.VESkey = veskey;
		if (!self.token && self.type == 'secondary') return vkey.getSessionToken().then(function(tkn) {
		    self.token = tkn;
		    return cryptoKey;
		});
		return cryptoKey;
	    });
	}).then(function(ck) {
	    return self.handleAttn().catch(function() {}).then(function() {
		return ck;
	    });
	});
    },
    lock: function() {
	var lock = [];
	for (var kid in this.unlockedKeys) lock.push(this.unlockedKeys[kid].then(function(k) {
	    return k.lock();
	}).catch(function() {}));
        this.propagators = null;
	return Promise.all(lock).then(function() {
	    return true;
	});
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
    getItems: function(flds) {
	var self = this;
	return this.getVaultKey().then(function(k) {
	    return k.getId().then(function(kid) {
		return k.getVaultEntries(self.mergeFieldList({type: true, deleted: true, file: {creator: true, externals: true}, vaultKey: {type: true, user: true}}, flds)).then(function(ves) {
		    var vis = {};
		    var vlst = [];
		    for (var i = 0; i < ves.length; i++) {
			var viid = ves[i].vaultItem.id;
			if (!vis[viid]) {
			    var vi = ves[i].vaultItem;
			    if (!vi.file) vi.file = undefined;
			    if (!vi.vaultKey) vi.vaultKey = undefined;
			    vi = vis[viid] = self.getItem(vi);
			    vlst.push(vi);
			    if (!ves[i].vaultKey) ves[i].vaultKey = {id: kid};
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
		else if (u instanceof Array || u.domain != null || u.externalId != null) return self._matchSecondaryKey(u, u.user, u.appUrl).then(function(vkey) {
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
	    else return new libVES.User((u.id ? {id: u.id} : {email: u.email}), this);
	} else if (typeof(u) == 'string' && u.match(/^\S+\@\S+$/)) return new libVES.User({email: u},this);
	throw new libVES.Error('BadUser',"Cannot match user: " + u,{value: u});
    },
    _matchSecondaryKey: function(ext, user, appUrl) {
	var self = this;
	var m = function() {
	    return libVES.getModule(libVES.Domain,ext.domain).catch(function(e) {
		return {
		    userToVaultRef: function(u) {
			return u.getEmail().then(function(email) {
			    return email.toLowerCase();
			});
		    },
		    vaultRefToUser: function(ext) {
			var email = ext.externalId ? ext.externalId.replace(/\!.*/, '') : '';
			if (!email.match(/\@/)) throw new libVES.Error('NotFound', 'externalId is not an email for non-existing vault');
			return new libVES.User({email: email}, self);
		    }
		};
	    });
	};
	return (ext.externalId ? self.prepareExternals(ext) : m().then(function(dom) {
	    return Promise.resolve(user || self.me()).then(function(u) {
		return dom.userToVaultRef(u);
	    }).then(function(ex) {
		return self.prepareExternals([ex]);
	    });
	}).catch(function(e) {
	    throw new libVES.Error('NotFound', 'Cannot match externalId for domain:' + ext.domain + ', user:' + user + '. Define libVES.Domain.' + ext.domain + '.userToVaultRef(user) to return a valid reference.',{error: e});
	})).then(function(exts) {
            var keyref = {externals: exts};
            if (self.externalId && self.externalId[0] != '!') keyref.creator = self.me();
	    var vkey = new libVES.VaultKey(keyref, self);
	    return vkey.getId().then(function() {
		return vkey;
	    }).catch(function(e) {
		if (e.code != 'NotFound') throw e;
                if (!keyref.creator) throw new libVES.Error.InvalidKey('Anonymous vaults are not authorized to create temp keys');
		return Promise.resolve(user || m().then(function(dom) {
		    return dom.vaultRefToUser(exts[0]);
		})).catch(function(e) {
		    throw new libVES.Error('NotFound', 'No matching secondary vault key',{error: e});
		}).then(function(u) {
		    return self.me().then(function(me) {
			return Promise.all([me.getId(),u.getId()]).then(function(ids) {
			    if (ids[0] == ids[1]) return self.getSecondaryKey(exts,true);
			}).catch(function(e) {
			    if (e.code != 'NotFound') throw e;
			}).then(function(rs) {
			    return rs || self.createTempKey(self._matchUser(u)).then(function(vkey) {
				return vkey.setField('externals',exts).then(function() {
				    if (appUrl) vkey.setField('appUrl', appUrl);
				    return vkey;
				});
			    });
			});
		    });
		});
	    });
	});
    },
    getPropagators: function() {
        if (!this.propagators) {
            let xid = (this.externalId ?? this.email);
            this.propagators = (xid?.match(/^[^\!]+\@\w/) ? Promise.resolve(xid.replace(/\!.*/, '')) : this.me().then((me) => me.getEmail())).then((xid) => {
                if (!xid) return [];
                let prop = new libVES.VaultKey({externals: {domain: '.propagate', externalId: xid.toLowerCase()}}, this);
                return prop.getId().then(() => [prop]);
            }).catch((er) => {
                if (er?.code == 'NotFound' || er?.code == 'Unauthorized') return [];
                throw er;
            });
        }
        return Promise.resolve(this.propagators);
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
    createTempKey: function(usr, optns) {
	var self = this;
	var key = new libVES.VaultKey({type: 'temp', algo: this.keyAlgo, user: usr}, self);
	var veskey = this.generateVESkey(usr);
	return key.generate(veskey, optns).then(function(k) {
	    key.setField('vaultItems', veskey.then(function(v) {
		var vi = new libVES.VaultItem({type: 'password'}, self);
		return usr.getActiveVaultKeys().then(function(akeys) {
		    return [self.me(), self.getVaultKey()].concat(akeys);
		}).catch(function(e) {
		    if (e.code != 'NotFound') throw e;
		    var sh = self.type == 'secondary' ? [self.me(), self.getVaultKey()] : [self.me()];
                    return self.getPropagators().then((props) => sh.concat(props)).catch((er) => sh);
		}).then(function(sh) {
		    return Promise.all(sh);
		}).then(function(sh) {
		    return vi.shareWith(sh, v, false).then(function() {
			return [vi];
		    });
		});
	    }));
	    key.setField('creator', self.me());
	    return key;
	});
    },
    generateVESkey: function(usr) {
	var buf = new Uint8Array(24);
	crypto.getRandomValues(buf);
	return Promise.resolve(libVES.Util.ByteArrayToB64(buf));
    },
    setVESkey: function(veskey,lost,options) {
	var self = this;
	return this.me().then(function(me) {
	    return (new libVES.VaultKey({type: 'current', algo: self.keyAlgo, user: me},self)).generate(Promise.resolve(veskey),options).then(function(k) {
		return me.getCurrentVaultKey().then(function(cur) {
		    return (cur ? cur.unlock().then(function() {
			return k.rekeyFrom(cur);
		    }).catch(function(e) {
			if (!lost) throw e;
		    }) : Promise.resolve(null)).then(function() {
			var r;
			if (cur && lost) r = cur.setField('type','lost').then(function() {
			    k.user = undefined;
			    return me.setField('vaultKeys',[cur,k]).then(function() {
				return me;
			    });
			});
			else r = k;
			me.currentVaultKey = me.activeVaultKeys = me.shadowVaultKey = undefined;
			if (!cur || !lost) me.vaultKeys = undefined;
			return r;
		    });
		}).then(function(r) {
		    return self.elevateAuth(options).then(function(optns) {
			return r.post(undefined, undefined, optns);
		    });
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
    getSecondaryKey: function(ext, force) {
	var self = this;
	return this.prepareExternals(Promise.resolve(ext).then(function(e) {
	    if (e.domain && !e.externalId) return libVES.getModule(libVES.Domain, e.domain).then(function(mod) {
		return self.me().then(function(me) {
		    return mod.userToVaultRef(me, self);
		});
	    });
	    return e;
	})).then(function(ext) {
	    var vkey = new libVES.VaultKey({externals: ext}, self);
	    return vkey.getId().then(function(id) {
		return vkey;
	    }).catch(function(e) {
		if (!force || e.code != 'NotFound') throw e;
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
		    return self.getSecondaryKey(ext).then(function(k2) {
			return k.rekeyFrom(k2);
		    }).catch(function(e) {
			delete(k.vaultEntries);
			return k;
		    });
		}).then(function(k) {
		    var vi = new libVES.VaultItem({type: "password"},self);
		    k.setField('vaultItems',[vi]);
		    return Promise.resolve(veskey).then(function(v) {
			if (!v) throw new libVES.Error('InvalidValue','VESkey cannot be empty');
			return vi.shareWith([me],v,false).then(function() {
			    return self.elevateAuth(optns);
			}).then(function(optns) {
			    return k.post(undefined, undefined, optns).then(function(post) {
				return k.setField('id', post.id, false).then(function() {
				    k.fieldUpdate = {id: true};
				    return k;
				});
			    });
			});
		    });
		});
	    });
	});
    },
    setAnonymousKey: function(veskey, optns) {
	var self = this;
	return this.prepareExternals({externalId: self.externalId}).then(function(ext) {
	    if (!veskey) throw new libVES.Error('InvalidValue','VESkey cannot be empty');
	    return (new libVES.VaultKey({type: 'secondary', algo: (optns && optns.algo ? optns.algo : self.keyAlgo), externals: ext},self)).generate(veskey, optns).then(function(k) {
		return k.post(undefined, ['encSessionToken'], optns).then(function(post) {
		    return k.setField('id', post.id, false).then(function() {
			k.fieldUpdate = {id: true};
		    });
		}).catch(function(e) {
		    if (!e || e.code != 'Unauthorized') throw e;
		}).then(function() {
                    self.vaultKey = k.lock().then(function() {
                        return k;
                    });
		    return self.unlock(veskey);
		});
	    });
	});
    },
    setShadow: function(usrs,optns) {
	var self = this;
	if (!(usrs instanceof Array)) return Promise.reject(new libVES.Error('InvalidValue', 'usrs must be an array'));
	if (!usrs.length) {
	    return self.getShadowKey().then(function(sh) {
		return (sh ? sh.getId().then(function(id) {
		    return self.elevateAuth(optns).then(function(optns) {
			return self.post('vaultKeys/' + id, {'$op': 'delete'}, undefined, optns). then(function() {
			    return null;
			});
		    });
		}) : null);
	    });
	}
	if (!optns || !optns.n) return Promise.reject(new libVES.Error('InvalidValue','optns.n must be an integer'));
	var rkey = new Uint8Array(32);
	crypto.getRandomValues(rkey);
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
			    return self.elevateAuth(optns).then(function(optns) {
				return k.post(undefined, undefined, optns);
			    });
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
	    return vaultItem.setField('type',libVES.VaultItem.Type._detect(value)).then(function() {
	        return Promise.resolve(shareWith || self.getFileItem(fileRef).then(function(vi) {
		    return vi.getShareList();
		}).catch(function(e) {
		    return self.usersToKeys([{domain: VES.domain, externalId: VES.externalId}]);
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
	return this.getFileItem(fileRef).then(function(item) {
	    return item.delete();
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
	return libVES.getModule(libVES.Util,['Hash',cls]).then(function(mod) {
	    return mod.hash(libVES.Util.StringToByteArray(text)).then(function(buf) {
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
	    return me.getFriendsKeyItems().then(function(vaultItems) {
		var vaultKeys = [];
		return Promise.all(vaultItems.map(function(e,i) {
		    return e.getVaultKey().then(function(vk) {
			vaultKeys[i] = vk;
			if (vk) return vk.getType();
		    });
		})).then(function(types) {
		    var rs = [];
		    for (var i = 0; i < types.length; i++) switch (types[i]) {
			case 'recovery': case 'shadow':
			    rs.push(vaultKeys[i].getRecovery([vaultItems[i]]));
		    }
		    return Promise.all(rs);
		});
	    });
	});
    },
    getUnlockableKeys: function() {
	var self = this;
	return self.getVaultKey().then(function(vk) {
	    return vk.getField('unlockableVaultKeys').then(function(vks) {
		var rs = {};
		return Promise.all((vks || []).map(function(e, i) {
		    return e.getId().then(function(id) {
			rs[id] = e;
		    });
		})).then(function() {
		    return rs;
		});
	    });
	});
    },
    getAttn: function() {
	var self = this;
	var rs = {};
	return self.get('attn').then(function(attn) {
	    return attn ? Promise.all([(attn.vaultKeys ? Promise.all(attn.vaultKeys.map(function(vk, i) {
		return new libVES.VaultKey(vk, self);
	    })).then(function(vks) {
		rs.vaultKeys = vks;
	    }) : null)]) : null;
	}).then(function() {
	    return rs;
	});
    },
    handleAttn: function(attn) {
	var self = this;
	return (attn ? Promise.resolve(attn) : self.getAttn()).then(function(attn) {
	    if (attn) return Promise.all([(attn.vaultKeys ? self.attnVaultKeys(attn.vaultKeys) : null)]);
	});
    },
    attnVaultKeys: function(vkeys) {
	var self = this;
	return Promise.all(vkeys.map(function(vkey, i) {
	    console.log('attnVaultKeys:', vkey);
	    return vkey.getType().then(function(type) {
		switch (type) {
		    case 'temp':
		    case 'lost':
			return vkey.getUser().then(function(user) {
			    return self.me().then(function(me) {
				return Promise.all([user.getId(), me.getId()]).then(function(ids) {
				    if (ids[0] == ids[1]) return type == 'temp' ? vkey.rekey()
				    : self.elevateAuth({authVaultKey: vkey}).then(function(optns) {
					return vkey.rekey(optns);
				    });
				    else return vkey.getVaultItems().then(function(vis) {
                                        return Promise.all([user.getActiveVaultKeys(), vkey.getExternals().then((exts) => {
                                            let ckey = new libVES.VaultKey({externals: exts}, self);
                                            return ckey.getType().then(() => [ckey]).catch((er) => {
                                                if (er?.code != 'NotFound') throw er;
                                                return [];
                                            });
                                        })]).then((klists) => {
                                            let ks = (klists[0] ?? []).concat(klists[1]);
                                            return Promise.all(ks.map((k) => k.getType())).then((ktypes) => ks.filter((k, i) => ktypes[i] != 'temp'));
                                        }).then((ks) => self.elevateAuth().then(function(optns) {
                                            return Promise.all(vis.map(function(vi, i) {
                                                return vi.reshareWith(ks, undefined, optns);
                                            }));
                                        }));
				    });
				});
			    });
			});
		    case 'recovery':
			return vkey.getRecovery().then(function(rcv) {
			    return rcv.recover();
			});
		}
	    });
	}));
    },
    setKeyAlgo: function(optns) {
	if (typeof(optns) == 'string') {
	    this.keyOptions = null;
	    return this.keyAlgo = optns;
	}
	var algo = libVES.Algo.fromKeyOptions(optns);
	if (algo) {
	    this.keyOptions = optns;
	    return this.keyAlgo = algo;
	}
    }
};

libVES.Error = function(code, msg, optns) {
    if (libVES.Error[code] && (libVES.Error[code].prototype instanceof libVES.Error)) return new (libVES.Error[code])(msg, optns);
    this.code = code;
    this.init(msg, optns);
};

libVES.Error.prototype.init = function(msg, optns) {
    this.message = msg;
    if (optns) for (var k in optns) this[k] = optns[k];
};

libVES.Error.prototype.toString = function() {
    return this.message || this.code;
};

libVES.Error.NotFound = function(msg, optns) {
    this.init(msg, optns);
};
libVES.Error.NotFound.prototype = new libVES.Error('NotFound');

libVES.Error.InvalidValue = function(msg, optns) {
    this.init(msg, optns);
};
libVES.Error.InvalidValue.prototype = new libVES.Error('InvalidValue');

libVES.Error.InvalidKey = function(msg, optns) {
    this.init(msg, optns);
};
libVES.Error.InvalidKey.prototype = new libVES.Error('InvalidKey');

libVES.Error.Redirect = function(msg, optns) {
    this.init(msg, optns);
};
libVES.Error.Redirect.prototype = new libVES.Error('Redirect');

libVES.Error.Unauthorized = function(msg, optns) {
    this.init(msg, optns);
};
libVES.Error.Unauthorized.prototype = new libVES.Error('Unauthorized');

libVES.Error.Internal = function(msg, optns) {
    this.init(msg, optns);
};
libVES.Error.Internal.prototype = new libVES.Error('Internal');


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
libVES.maxKeyLen = 48896;
libVES.maxEncDataLen = 32768;


if (!libVES.Domain) libVES.Domain = {};
