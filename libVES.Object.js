/**
 * @title libVES.Object
 *
 * @author Jim Zubov <jz@vesvault.com> (VESvault)
 * GPL license, http://www.gnu.org/licenses/
 */
libVES.Object = function(data) {
    for (var k in data) this[k] = data[k];
    if (window.Trigger) this.trigger = Trigger.resolve(this);
};

libVES.Object.prototype = {
    fieldList: {id: true},
    fieldExtra: {},
    fieldClass: {},
    fieldSets: [],
    init: function(data,VES,refs) {
	this.VES = VES;
	this.fieldUpdate = data.id ? {id: true} : {};
	this.setFields(data,data.id == null);
	if (refs) for (var k in refs) this[k] = Promise.resolve(refs[k]);
    },
    setFields: function(data,up) {
	var self = this;
	var chg = false;
	for (var k in data) {
	    if (up === undefined || up) this.fieldUpdate[k] = true;
	    if (this[k] instanceof Promise) {
		this[k] = undefined;
		chg = true;
	    }
	    if (this[k] === undefined) this[k] = Promise.resolve(data[k]).then((function(k) {
		return function(v) {
		    var clsf;
		    if (self.fieldClass[k]) return (clsf = function(v) {
			if (v instanceof libVES.Object) return v;
			else if (v instanceof Array) return v.map(function(vv) { return clsf(vv); });
			else return new (self.fieldClass[k])(v,self.VES);
		    })(v);
		    return v;
		};
	    })(k));
	    else return Promise.reject(new libVES.Error('Internal',"Unknown field: " + k));
	}
	if (chg && self.trigger) self.trigger.resolve(self);
	return Promise.resolve(self);
    },
    setField: function(fld,val,upd) {
	var flds = {};
	flds[fld] = val;
	return this.setFields(flds,upd).then(function(self) {
	    return self[fld];
	});
    },
    getField: function(fld,fldlst,force) {
	var self = this;
	if (!this[fld] || force) {
	    var flds = {};
	    for (var i = 0; i < this.fieldSets.length; i++) if (this.fieldSets[i][fld]) {
		for (var k in this.fieldSets[i]) flds[k] = this.fieldSets[i][k];
		break;
	    }
	    if (fldlst) flds[fld] = fldlst;
	    if (!flds[fld]) {
		var cls = self.fieldClass[fld];
		flds[fld] = cls ? cls.prototype.fieldList : true;
	    }
	    this.loadFields(flds,force);
	}
	return this[fld];
    },
    loadFields: function(flds,force,optns) {
	var self = this;
	var req = this.id ? this.id.then(function(id) {  return self.VES.get(self.apiUri + '/' + id,flds,optns); }) : self.postData().then(function(data) {
	    data['$op'] = 'fetch';
	    return self.VES.post(self.apiUri,data,flds,optns);
	}).then(function(data) {
	    if (data.id) {
		self.id = Promise.resolve(data.id);
		self.fieldUpdate = {id: true};
	    }
	    return data;
	});
	for (var k in flds) if (force || this[k] === undefined) {
	    this[k] = req.then((function(fld) {
		var cls = self.fieldClass[fld];
		return function(data) {
		    if (cls && data[fld]) return ((data[fld] instanceof Array) ? data[fld].map(function(v) {
			return new cls(v,self.VES);
		    }) : new cls(data[fld],self.VES));
		    return data[fld];
		};
	    })(k));
	}
    },
    reset: function() {
	for (var k in this.fieldClass) delete(this[k]);
	return Promise.resolve();
    },
    getId: function() {
	return this.id ? Promise.resolve(this.id) : this.getField('id');
    },
    postData: function(fields,refs,parent) {
	if (refs && parent) for (var k in refs) if (refs[k] === this) return Promise.resolve({"$ref": k});
	var data = {};
	var prs = [];
	var self = this;
	var fmt = function(v,a) {
	    if (v instanceof libVES.Object) return v.postData(a,refs,self);
	    else if (v instanceof Array) return Promise.all(v.map(function(vv,i) {
		return fmt(vv,a);
	    }));
	    else return v;
	};
	var pf = function(k,pr,a) {
	    if (!(pr instanceof Promise)) pr = fmt(pr,a);
	    if (pr instanceof Promise) prs.push(pr.then(function(pr2) {
		return Promise.resolve(fmt(pr2,a)).then(function(v) {
		    data[k] = v;
		});
	    }));
	    else data[k] = pr;
	};
	if (!(fields instanceof Object)) fields = this.fieldUpdate;
	if (fields) for (var k in fields) if (this[k] !== undefined) pf(k,this[k],fields[k]);
	return Promise.all(prs).then(function() {
	    return data;
	});
    },
    post: function(fields,rfields,optns) {
	var self = this;
	if (!optns) optns = {};
	if (optns.retry == null) optns.retry = 3;
	return this.postData(fields,optns.refs).then(function(d) {
	    var op = {
		onerror: function(errors) {
		    if (optns.retry-- <= 0) throw new libVES.Error('RequestFailed',"Retry count exceeded",{errors: errors});
		    var rs = [];
		    for (var i = 0; i < errors.length; i++) {
			if (!errors[i].path) throw errors[i];
			rs.push(self.resolveErrorPath(errors[i]));
		    }
		    return Promise.all(rs).then(function() {
			return self.post(fields,rfields,optns);
		    });
		}
	    };
	    for (var k in optns) op[k] = optns[k];
	    return self.VES.post(self.apiUri,d,rfields,op);
	});
    },
    resolveErrorPath: function(e,idx) {
	var self = this;
	if (!e.path) throw e;
	if (!idx) idx = 0;
	if (e.path.length == idx) return this.resolveError(e,null);
	var f = e.path[idx++];
	if (this[f] === undefined) throw new libVES.Error('BadPath',"Path not found: " + f,{error: e});
	return Promise.resolve(this[f]).then(function(v) {
	    if (v instanceof libVES.Object) return v.resolveErrorPath(e,idx);
	    else if ((e.path.length > idx) && (v instanceof Array)) {
		var i = e.path[idx++];
		if (v[i] === undefined) throw new libVES.Error('BadPath',"Path not found: " + i,{error: e});
		else if (v[i] instanceof libVES.Object) return v[i].resolveErrorPath(e,idx);
		else throw e;
	    } else return self.resolveError(e,f);
	});
    },
    resolveError: function(e,field) {
	throw e;
    }
};


libVES.User = function(data,VES,refs) {
    this.init(data,VES,refs);
};

libVES.VaultKey = function(data,VES,refs) {
    this.init(data,VES,refs);
};

libVES.VaultItem = function(data,VES,refs) {
    this.vaultEntryByKey = {};
    this.init(data,VES,refs);
};

libVES.External = function(data,VES,refs) {
    this.init(data,VES,refs);
};

libVES.Lockbox = function(data,VES,refs) {
    this.init(data,VES,refs);
};

libVES.File = function(data,VES,refs) {
    this.init(data,VES,refs);
};

libVES.User.prototype = new libVES.Object({
    apiUri: 'users',
    fieldList: {id: true, email: true, type: true, firstName: true, lastName: true},
    fieldExtra: {vaultKeys: true, activeVaultKeys: true, currentVaultKey: true},
    fieldClass: {vaultKeys: libVES.VaultKey, activeVaultKeys: libVES.VaultKey, currentVaultKey: libVES.VaultKey, shadowVaultKey: libVES.VaultKey, friendsVaultKeys: libVES.VaultKey},
    getEmail: function() {
	return this.getField('email');
    },
    getFirstName: function() {
	return this.getField('firstName');
    },
    getLastName: function() {
	return this.getField('lastName');
    },
    getFullName: function() {
	var self = this;
	return this.getFirstName().then(function(f) {
	    return self.getLastName().then(function(l) {
		return f ? (l ? f + ' ' + l : f) : l;
	    });
	});
    },
    getVaultKeys: function() {
	return this.getField('vaultKeys');
    },
    getActiveVaultKeys: function() {
	var self = this;
	if (!this.activeVaultKeys && (this.currentVaultKey || this.shadowVaultKey)) return this.getCurrentVaultKey().then(function(curr) {
	    return curr ? self.getShadowVaultKey().then(function(sh) {
		return sh ? [curr,sh] : [curr];
	    }) : [];
	});
	return this.getField('activeVaultKeys');
    },
    getFriendsVaultKeys: function() {
	return this.getField('friendsVaultKeys');
    },
    getCurrentVaultKey: function() {
/*
	if (!this.currentVaultKey) {
	    if (this.vaultKeys) this.currentVaultKey = this.vaultKeys.then(function(vks) {
		for (var i = 0; i < vks.length; i++) if (vks[i].type == 'current') return vks[i];
		for (var i = 0; i < vks.length; i++) if (vks[i].type == 'temp' && vks[i].creatorUser && vks[i].creatorUser.id == self.id) return vks[i];
	    });
	    else if (this.activeVaultKeys) this.currentVaultKey = this.activeVaultKeys.then(function(vks) {
		return vks[0];
	    });
	}
*/
	return this.getField('currentVaultKey');
    },
    getShadowVaultKey: function() {
	return this.getField('shadowVaultKey');
    },
    getExternals: function() {
	return this.getField('externals');
    },
    getExternalsByDomain: function() {
	return this.getExternals().then(function(ex) {
	    var rs = {};
	    for (var i = 0; i < ex.length; i++) (rs[ex[i].domain] || (rs[ex[i].domain] = [])).push(ex[i]);
	    return rs;
	});
    },
    unlock: function(veskey) {
	return this.getCurrentVaultKey().then(function(k) {
	    return k.unlock(veskey);
	});
    },
    lock: function(veskey) {
	if (this.currentVaultKey) return this.currentVaultKey.then(function(k) {
	    return k.lock();
	});
    },
});


libVES.VaultKey.prototype = new libVES.Object({
    apiUri: 'vaultKeys',
    fieldList: {id: true, algo: true, type: true, publicKey: true, privateKey: true},
    fieldClass: {user: libVES.User, vaultItems: libVES.VaultItem, externals: libVES.External, sharedKeys: libVES.VaultKey},
    fieldExtra: {user: true, vaultItems: true},
    fieldSets: [{vaultEntries: {id: true, encData: true, vaultItem: {id: true}}},{type: true, algo: true, publicKey: true}],
    getAlgo: function() {
	return this.getField('algo');
    },
    getType: function() {
	return this.getField('type');
    },
    getPublicKey: function() {
	return this.getField('publicKey');
    },
    getPrivateKey: function() {
	return this.getField('privateKey');
    },
    getUnlockedPrivateKey: function() {
	var self = this;
	return this.unlock().then(function(k) {
	    return self.engine().then(function(e) {
		return e.export(k,{opentext:true});
	    });
	});
    },
    getVaultItems: function() {
	return this.getField('vaultItems');
    },
    getSharedKeys: function() {
	return this.getField('sharedKeys');
    },
    getExternals: function() {
	return this.getField('externals');
    },
    getUser: function() {
	return this.getField('user');
    },
    getVaultItems: function() {
	return this.getField('vaultItems');
    },
    resolveVESkey: function(veskey) {
	if (veskey) return Promise.resolve(veskey);
	var self = this;
	return self.getType().then(function(t) {
	    switch (t) {
	    case 'secondary':
	    case 'temp':
		return self.getVaultItems().then(function(vis) {
		    var f = function(vis) {
			if (!vis.length) throw new libVES.Error('InvalidKey','Cannot unlock the secondary key');
			return vis[0].getType().then(function(t) {
			    switch (t) {
				case 'password': return vis[0].get();
				default: return f(vis.slice(1));
			    }
			});
		    };
		    return f(vis);
		});
	    default: throw new libVES.Error('InvalidKey','Cannot unlock the key',{vaultKey: self});
	    }
	});
    },
    unlock: function(veskey) {
	var self = this;
	if (self.wcPriv) return self.wcPriv;
	return self.getId().then(function(id) {
	    if (!self.VES.unlockedKeys[id]) return self.VES.unlockedKeys[id] = self.engine().then(function(m) {
		return self.resolveVESkey(veskey).then(function(v) {
		    return self.getPrivateKey().then(function(prk) {
			return m.import(prk,{password: v});
		    }).catch(function(e) {
			if (e.code != 'Legacy' || !self.VES.unlockLegacyKey) throw e;
			delete(self.VES.unlockedKeys[id]);
			return self.VES.unlockLegacyKey(self,veskey);
		    });
		});
	    });
	    else return self.VES.unlockedKeys[id].catch(function(e) {
		self.VES.unlockedKeys[id] = null;
		return self.unlock(veskey);
	    });
	});
    },
    lock: function() {
	var self = this;
	return this.getId().then(function(id) {
	    delete(self.wcPriv);
	    delete(self.VES.unlockedKeys[id]);
	    return true;
	});
    },
    getPublicCryptoKey: function() {
	if (!this.wcPub) {
	    var self = this;
	    self.wcPub = this.engine().then(function(e) {
		return self.getPublicKey().then(function(pubk) {
		    return e.import(pubk);
		});
	    });
	}
	return this.wcPub;
    },
    engine: function() {
	return this.getAlgo().then(function(algo) {
	    return libVES.getModule(libVES.Algo,algo);
	});
    },
    generate: function(veskey,optns) {
	var self = this;
	var wc = optns && optns.privateKey ? libVES.Algo.acquire(optns.privateKey).then(function(wc) {
	    self.setField('algo',wc.engine.tag);
	    if (!wc.privateKey) throw new libVES.Error('InvalidValue','Private key expected');
	    return wc;
	}) : (optns && optns.algo ? self.setField('algo',optns.algo) : Promise.resolve()).then(function() {
	    return self.engine().then(function(e) {
		return e.generate(optns).then(function(ks) {
		    ks.engine = e;
		    return ks;
		});
	    });
	});
	return Promise.resolve(veskey).then(function(v) {
	    self.wcPub = wc.then(function(ks) {
		return ks.publicKey;
	    });
	    self.setField('publicKey',wc.then(function(ks) {
		return ks.engine.export(ks.publicKey);
	    }));
	    self.wcPriv = wc.then(function(ks) {
		return ks.privateKey;
	    });
	    self.setField('privateKey',wc.then(function(ks) {
		return ks.engine.export(ks.privateKey,{password:v});
	    }));
	    return self;
	});
    },
    encrypt: function(ptxt) {
	var self = this;
	return self.engine().then(function(e) {
	    return self.getPublicCryptoKey().then(function(k) {
		return e.encrypt(k,ptxt).then(function(ctxt) {
		    return libVES.Util.ByteArrayToB64(ctxt);
		});
	    });
	});
    },
    decrypt: function(ctxt) {
	var self = this;
	return self.engine().then(function(e) {
	    return self.unlock().then(function(k) {
		return e.decrypt(k,libVES.Util.B64ToByteArray(ctxt));
	    });
	});
    },
    getVaultEntries: function(details) {
	return this.getField('vaultEntries',{id: true, encData: true, vaultItem: (typeof(details) == 'object' ? details : ((details != null && !details) ? true : {id: true, type: true, meta: true}))});
    },
    rekeyFrom: function(key,veskey) {
	var self = this;
	var old_vis = {};
	return (self.vaultEntries ? self.vaultEntries.then(function(old_ves) {
	    return old_ves.map(function(ve,i) {
		old_vis[ve.vaultItem.id] = true;
	    });
	}) : Promise.resolve(null)).then(function() {
	    return self.setField('vaultEntries',key.unlock(veskey).then(function() {
		return key.getVaultEntries().then(function(ves) {
		    return Promise.all(ves.map(function(ve) {
			return old_vis[ve.vaultItem.id] ? Promise.resolve({
			    vaultItem: {id: ve.vaultItem.id}
			}) : key.decrypt(ve.encData).then(function(ptxt) {
			    return self.encrypt(ptxt).then(function(ctxt) {
				return {
				    vaultItem: {id: ve.vaultItem.id},
				    encData: ctxt
				};
			    });
			}).catch(function(e) {
			    return {
				vaultItem: {id: ve.vaultItem.id},
				"$op": "ignore"
			    };
			});
		    }));
		});
	    }));
	}).then(function() {
	    return self;
	});
    },
    rekey: function() {
	var self = this;
	return self.getUser().then(function(user) {
	    return self.getExternals().then(function(exts) {
		return (exts && exts.length ? exts[0].toRef().then(function(ext) {
		    ext.user = user;
		    return ext;
		}) : Promise.resolve(user)).then(function(ref) {
		    return self.VES.usersToKeys([ref]);
		});
	    }).then(function(keys) {
		return Promise.all(keys.map(function(key,i) {
		    return key.getVaultEntries().catch(function(e) {
			if (e.code != 'NotFound') throw e;
			key.vaultEntries = undefined;
		    }).then(function() {
			return key.rekeyFrom(self);
		    });
		}));
	    }).then(function(keys) {
		return user.setField('vaultKeys',keys).then(function() {
		    return user.post(null,{vaultEntries: true},{refs: {'#/': user}}).then(function(data) {
			self.setFields(data,false);
			return self;
		    });
		});
	    });
	});
    },
    getRecovery: function() {
	var self = this;
	return self.getType().then(function(t) {
	    switch (t) {
		case 'shadow': case 'recovery':
		    return new libVES.Recovery(self);
		default: throw new libVES.Error('InvalidValue','Recovery is not applicable for VaultKey type ' + t);
	    }
	});
    },
    getSessionToken: function() {
	var self = this;
	return this.getField('encSessionToken').then(function(tk) {
	    return self.decrypt(tk).then(function(b) {
		return libVES.Util.ByteArrayToString(b);
	    });
	});
    },
    reshareVESkey: function(veskey) {
	var self = this;
	return self.getVaultItems().then(function(vaultItems) {
	    return self.getUser().then(function(user) {
		return Promise.all(vaultItems.map(function(vaultItem,i) {
		    return vaultItem.getType().then(function(t) {
			if (t == 'password') return vaultItem.reshareWith([user],veskey);
		    });
		}));
	    });
	});
    },
    matchVaults: function(vaultKeys) {
	return Promise.resolve(false);
    }
});

libVES.VaultItem.prototype = new libVES.Object({
    apiUri: 'vaultItems',
    fieldList: {id: true},
    fieldClass: {vaultKey: libVES.VaultKey, file: libVES.File},
    fieldSets: [{type: true, meta: true},{vaultEntries: {id: true, encData: true, vaultKey: {id: true}}},{vaultKey: true, file: true, lockbox: true}],
    defaultCipher: 'AES256GCM',
    getRaw: function() {
	var self = this;
	return self.VES.getVaultKeysById().then(function(vaultKeys) {
	    var f = function(vaultEntries) {
	        var i = 0;
		var fn = function() {
		    for (; i < vaultEntries.length; i++) {
			var k,d;
			if ((d = vaultEntries[i].encData) != null && (k = vaultKeys[vaultEntries[i].vaultKey.id])) {
			    i++;
			    return k.decrypt(d).catch(fn);
			}
		    }
		    return Promise.reject(new libVES.Error('Invalid Key',"No unlocked key to decrypt the item",{vaultItem: self}));
		};
		return fn();
	    };
	    var vaultEntries = [];
	    if (self.vaultEntryByKey) for (var k in self.vaultEntryByKey) vaultEntries.push(self.vaultEntryByKey[k]);
	    return f(vaultEntries).catch(function() {
		return self.getVaultEntries().then(f);
	    });
	});
    },
    get: function() {
	var self = this;
	return this.getRaw().then(function(buf) {
	    return self.parse(buf);
	});
    },
    getType: function() {
	return this.getField('type');
    },
    getMeta: function() {
	return this.getField('meta');
    },
    getVaultEntries: function() {
	var self = this;
	return this.getField('vaultEntries').then(function(ves) {
	    for (var i = 0; i < ves.length; i++) self.vaultEntryByKey[ves[i].vaultKey.id] = ves[i];
	    return ves;
	});
    },
    getVaultKey: function() {
	return this.getField('vaultKey');
    },
    getFile: function() {
	return this.getField('file');
    },
    getLockbox: function() {
	return this.getField('lockbox');
    },
    parse: function(buf) {
	var self = this;
	return this.getType().then(function(type) {
	    return libVES.getModule(libVES.VaultItem.Type,type).then(function(m) {
		return m.parse.call(self,buf);
	    }).catch(function(e) {
		return new Uint8Array(buf);
	    });
	});
    },
    build: function(data) {
	var self = this;
	return this.getType().then(function(type) {
	    return libVES.getModule(libVES.VaultItem.Type,type).then(function(m) {
		return m.build.call(self,data);
	    });
	});
    },
    shareWith: function(usrs,val,save) {
	var self = this;
	return (val == null ? self.getRaw() : self.build(val)).then(function(v) {
	    return self.VES.usersToKeys(usrs).then(function(ks) {
		return (val == null ? self.getVaultEntries().then(function(ves) {
		    var k_ves = {};
		    var k_used = {};
		    for (var j = 0; j < ves.length; j++) k_ves[ves[j].vaultKey.id] = ves[j];
		    return Promise.all(ks.map(function(k,j) {
			return k.getId().then(function(k_id) {
			    k_used[k_id] = true;
			    return k_ves[k_id];
			}).catch(function(){});
		    })).then(function(old_ves) {
			for (var k_id in k_ves) if (!k_used[k_id]) old_ves.push(k_ves[k_id]);
			return old_ves;
		    });
		}) : Promise.resolve([])).then(function(old_ves) {
		    var new_ves = [];
		    var set_ves = [];
		    return Promise.all(ks.map(function(k,j) {
			return new_ves[j] = (old_ves[j] || k.encrypt(v).then(function(ctext) {
			    return (function(refs) {
				if (refs) for (var i in refs) if (refs[i] === k) return Promise.resolve({'$ref':i});
				return k.postData(null,refs);
			    })(libVES.Object._refs).then(function(pd) {
				return set_ves.push({vaultKey: pd, encData: ctext});
			    });
			}));
		    })).then(function() {
			return Promise.all(old_ves.slice(ks.length).map(function(ve,j) {
			    return (new libVES.VaultKey(ve.vaultKey,self.VES)).matchVaults(ks).then(function(f) {
				if (f === false) set_ves.push({vaultKey: ve.vaultKey, '$op': 'delete'});
			    });
			}));
		    }).then(function() {
			if (!set_ves.length) return save = false;
			return self.setField('vaultEntries',set_ves);
		    });
		});
	    });
	}).then(function() {
	    if (save || save === undefined) return self.post().then(function() {
		return self;
	    });
	    return self;
	});
    },
    reshareWith: function(share,val,save) {
	var self = this;
	return self.VES.usersToKeys(share).then(function(new_ks) {
	    return self.getShareVaultKeys().then(function(curr_ks) {
		return Promise.all(curr_ks.map(function(k,i) {
		    return k.getId();
		})).then(function(curr_ids) {
		    var m_curr_ks = {};
		    for (var i = 0; i < curr_ks.length; i++) m_curr_ks[curr_ids[i]] = curr_ks[i];
		    return Promise.all(new_ks.map(function(k,i) {
			return k.getId();
		    })).then(function(new_ids) {
			for (var i = 0; i < new_ks.length; i++) if (!m_curr_ks[new_ids[i]]) curr_ks.push(m_curr_ks[new_ids[i]] = new_ks[i]);
			return self.shareWith(curr_ks,val,save);
		    });
		});
	    });
	});
    },
    getShareVaultKeys: function() {
	var self = this;
	return this.getVaultEntries().then(function(vaultEntries) {
	    return vaultEntries.map(function(e,i) {
		return new libVES.VaultKey(e.vaultKey,self.VES);
	    });
	});
    },
    getShareList: function() {
	var self = this;
	return this.getShareVaultKeys().then(function(vaultKeys) {
	    var uids = {};
	    return Promise.all(vaultKeys.map(function(e,i) {
		return e.getExternals().then(function(exts) {
		    if (exts && exts.length) return exts[0];
		    return e.getUser().then(function(u) {
			return u.getId().then(function(uid) {
			    if (uids[uid]) return null;
			    uids[uid] = true;
			    return u;
			});
		    });
		});
	    })).then(function(lst) {
		var rs = [];
		for (var i = 0; i < lst.length; i++) if (lst[i]) rs.push(lst[i]);
		return rs;
	    });
	});
    }
});
libVES.VaultItem.Type = {
    _detect: function(data) {
	if (typeof(data) == 'object') {
	    if (data instanceof libVES.Cipher) return 'file';
	    throw new libVES.Error('Internal','Unknown vault item data type');
	} else return 'string';
    },
    string: {
	parse: function(buf) {
	    return libVES.Util.ByteArrayToString(buf);
	},
	build: function(data) {
	    return libVES.Util.StringToByteArray(String(data));
	}
    },
    file: {
	parse: function(buf) {
	    var self = this;
	    return this.getMeta().then(function(meta) {
		var ci = libVES.Cipher[meta.a || self.defaultCipher];
		return new ci(new Uint8Array(buf));
	    });
	},
	build: function(data) {
	    if (!(data instanceof libVES.Cipher)) throw new libVES.Error('InvalidData',"Content of a VaultItem type 'file' must be libVES.Cipher");
	    return data.getSecret();
	}
    },
    secret: {
	parse: function(buf) {
	    var self = this;
	    return this.getMeta().then(function(meta) {
		return {value: buf, meta: meta};
	    });
	},
	build: function(data) {
	    this.setField('meta',data.meta);
	    return data.value;
	}
    }
};
libVES.VaultItem.Type.password = libVES.VaultItem.Type.string;

libVES.File.prototype = new libVES.Object({
    apiUri: 'files',
    fieldList: {id: true},
    fieldClass: {externals: libVES.External},
    getExternals: function() {
	return this.getField('externals');
    }
});

libVES.External.prototype = new libVES.Object({
    apiUri: 'externals',
    fieldList: {id: true},
    getDomain: function() {
	return this.getField('domain');
    },
    getExternalId: function() {
	return this.getField('externalId');
    },
    toRef: function() {
	return Promise.all([this.getDomain(),this.getExternalId()]).then(function(r) {
	    return {domain: r[0], externalId: r[1]};
	});
    }
});
