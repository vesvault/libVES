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
 * libVES.Object.js           libVES: API objects: VaultKey, VaultItem,
 *                                    User, File, External
 *
 ***************************************************************************/
libVES.Object = function(data) {
    for (var k in data) this[k] = data[k];
    if (typeof(Trigger) != 'undefined') this.trigger = Trigger.resolve(this);
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
    setFields: function(flds, up) {
        var res = Promise.resolve(null);
        for (var fld in flds) ((fld) => {
            if (up === undefined || up) this.fieldUpdate[fld] = true;
            var cls = this.fieldClass[fld];
            var cur = this[fld];
            res = this[fld] = res.then(() => Promise.resolve(flds[fld]).then((val) => Promise.resolve(cur).catch((er) => undefined).then((cur) => {
                if (!cls || !val) return val;
                else if (val instanceof Array) return val.map((v) => ((v instanceof libVES.Object) ? v : new cls(v, this.VES)));
                else if (cur instanceof cls) return cur.setFields(val, up);
                else return (val instanceof libVES.Object) ? val : new cls(val, this.VES);
            })));
        })(fld);
        return res.then(() => this);
    },
    setField: function(fld,val,upd) {
	var flds = {};
	flds[fld] = val;
	return this.setFields(flds,upd).then(function(self) {
	    return self[fld];
	});
    },
    unsetField: function(fld) {
	delete(this[fld]);
    },
    _fieldsToLoad: function(fldlst, force, ld) {
        var flds = {};
        for (var k in fldlst) flds[k] ||= fldlst[k];
        for (var i = 0; i < this.fieldSets.length; i++) {
            for (var k in this.fieldSets[i]) if (fldlst[k]) {
                for (var k in this.fieldSets[i]) if ((force || !this[k]) && !(flds[k] instanceof Object)) (flds ||= {})[k] = this.fieldSets[i][k];
                break;
            }
        }
        var res = Promise.resolve(null);
        for (var fld in flds) ((fld) => {
            var cur = this[fld];
            var na = (cur === undefined);
            var cls = this.fieldClass[fld];
            res = res.then((res) => Promise.resolve(cur).catch((er) => null).then((cur) => {
                var lst = null;
                if (force || na) lst = flds[fld];
                else if (cls) {
                    if (cur instanceof Array) lst = ((cur[0] instanceof cls) ? cur[0]._fieldsToLoad(flds[fld], force, ld.then((vals) => vals[fld])) : Promise.resolve(null)).then((lst) => (lst && flds[fld]));
                    else if (cur instanceof cls) lst = cur._fieldsToLoad(flds[fld], force, ld.then((vals) => vals[fld]));
                }
                return Promise.resolve(lst).then((lst) => {
                    if (lst) (res ||= {})[fld] = lst;
                    return res;
                });
            }));
            if (na || (!cls && force)) (this[fld] = ld.then((vals) => (vals?.hasOwnProperty(fld) ? (cls && vals[fld] ? ((vals[fld] instanceof Array) ? vals[fld].map((e) => new cls(e, this.VES)) : new cls(vals[fld], this.VES)) : vals[fld]) : cur))).catch(() => null);
        })(fld);
        ld.then((vals) => {
            for (var fld in vals) if (!flds[fld] && !this[fld]) this.setField(fld, vals[fld], false);
        }).catch((er) => null);
        return res.then((res) => {
            if (res) for (var k in fldlst) if (res[k]) return res;
            return null;
        });
    },
    getFields: function(fldlst, force) {
        var ldf;
        var ld = new Promise((resolve, reject) => ldf = [resolve, reject]);
        this._fieldsToLoad(fldlst, force, ld).then((flds) => this.loadFields(flds, force)).then((vals) => ldf[0](vals)).catch((er) => ldf[1](er));
	var plst = [];
	for (var k in fldlst) ((k) => {
	    plst.push(ld.then(() => this[k]).then(function rslv(v) {
		if (v instanceof Array) return Promise.all(v.map(function(e, i) {
		    return rslv(e);
		}));
		if (!(v instanceof libVES.Object)) return v;
		return v.getFields(fldlst[k]);
	    }));
	})(k);
	var rs = {};
	return Promise.all(plst).then((lst) => {
	    var i = 0;
	    for (var k in fldlst) rs[k] = lst[i++];
	    return rs;
	});
    },
    getField: function(fld,fldlst,force) {
	if (!this[fld] || force) {
	    var flds = {};
            flds[fld] = fldlst || true;
	    this.getFields(flds, force).catch(() => null);
	}
	return this[fld];
    },
    loadFields: function(flds,force,optns) {
        if (!flds) return Promise.resolve({});
	var self = this;
	return (this.id && !flds.id ? this.id.then(function(id) {  return self.VES.get(self.apiUri + '/' + id,flds,optns); }) : self.postData().then(function(data) {
	    data['$op'] = 'fetch';
	    return self.VES.post(self.apiUri,data,flds,optns);
	}).then(function(data) {
	    if (data.id) {
		self.id = Promise.resolve(data.id);
		self.fieldUpdate = {id: true};
	    }
	    return data;
	})).then((data) => libVES.Util.fillUndefs(data, flds));
    },
    reset: function() {
	for (var k in this.fieldClass) this.unsetField(k);
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
    },
    setUpdate: function(flds) {
	var rs = [];
	for (var k in flds) {
	    if (flds[k]) this.fieldUpdate[k] = true;
	    else delete(this.fieldUpdate[k]);
	    if (this[k] && (flds[k] instanceof Object)) (function(p, k) {
		rs.push(p.then(function rslv(obj) {
		    if (obj instanceof Array) return Promise.all(obj.map(rslv));
		    if (obj instanceof libVES.Object) return obj.setUpdate(flds[k]);
		}));
	    })(this[k], k);
	}
	return Promise.all(rs);
    },
    toJSON: function() {
        return String(this);
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

libVES.File = function(data,VES,refs) {
    this.init(data,VES,refs);
};

libVES.Event = function(data, VES, refs) {
    this.init(data, VES, refs);
};

libVES.Session = function(data, VES, refs) {
    this.init(data, VES, refs);
};

libVES.oldDomain = libVES.Domain;
libVES.Domain = function(dom, VES) {
    this.init({id: (dom ? dom : VES.domain)}, VES);
};
(function(old) {
    if (old) for (var k in old) libVES.Domain[k] = old[k];
})(libVES.oldDomain);

libVES.User.prototype = new libVES.Object({
    apiUri: 'users',
    fieldList: {id: true, email: true, type: true, firstName: true, lastName: true},
    fieldExtra: {vaultKeys: true, activeVaultKeys: true, currentVaultKey: true},
    fieldClass: {vaultKeys: libVES.VaultKey, activeVaultKeys: libVES.VaultKey, currentVaultKey: libVES.VaultKey, shadowVaultKey: libVES.VaultKey, friendsKeyItems: libVES.VaultItem},
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
    getFriendsKeyItems: function() {
	return this.getField('friendsKeyItems');
    },
    getCurrentVaultKey: function() {
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
    fieldClass: {user: libVES.User, vaultItems: libVES.VaultItem, externals: libVES.External, unlockableVaultKeys: libVES.VaultKey, creator: libVES.User},
    fieldExtra: {user: true, vaultItems: true},
    fieldSets: [{vaultEntries: {id: true, encData: true, vaultItem: {id: true}}},{type: true, algo: true, publicKey: true}, {unlockableVaultKeys: {id: true, type: true}}],
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
    getExternals: function() {
	return this.getField('externals');
    },
    getUser: function() {
	return this.getField('user');
    },
    resolveVESkey: function(veskey) {
	if (veskey) return Promise.resolve(veskey);
	var self = this;
	return self.getType().then(function(t) {
	    switch (t) {
	    case 'secondary':
	    case 'temp':
	    case 'lost':
		return self.getVaultItems().then(function(vis) {
		    var f = function(vis) {
			if (!vis || !vis.length) throw new libVES.Error('InvalidKey','Cannot unlock the secondary key');
			return vis[0].getType().then(function(t) {
			    switch (t) {
				case 'password': return self.getId().then(function(kid) {
                                    if (!self.VES.pendingKeys) self.VES.pendingKeys = {};
                                    if (kid) self.VES.pendingKeys[kid] = true;
                                    return vis[0].get().finally(function() {
                                        self.VES.pendingKeys[kid] = false;
                                    });
                                });
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
    invalidVESkey: function() {
	var self = this;
	return self.getVaultItems().then(function(vis) {
            return Promise.all(vis.map(function(vi) {
                return vi.getVaultEntries().then(function(entries) {
                    if (entries) for (let i = 0; i < entries.length; i++) if (self.VES.unlockedKeys[entries[i].vaultKey.id]) return Promise.resolve(self.VES.unlockedKeys[entries[i].vaultKey.id]).then(function(key) {
                        return key.getFields({user: {email: true}, extrenals: {domain: true, externalId: true}}).then(function(flds) {
                            return vi.unshareWith([flds.externals && flds.externals[0] ? flds.externals[0] : flds.user.email]);
                        });
                    });
                });
            }));
        });
    },
    unlock: function(veskey) {
	var self = this;
	if (!self.wcPriv) self.wcPriv = self.getId().then(function(id) {
	    return Promise.resolve(self.VES.unlockedKeys[id]).then(function(k) {
		return k.wcPriv;
	    }).catch(function(e) {
		let un = self.engine().then(function(m) {
		    return self.resolveVESkey(veskey).then(function(v) {
			return self.getPrivateKey().then(function(prk) {
			    return m.import(prk, {password: v}).catch(function(e) {
                                if (e && e.code == 'InvalidKey' && !veskey) {
                                    console.log('Bad key propagated for ' + id + ', unsharing...');
                                    return self.invalidVESkey().catch(function(e2) {
                                        console.log(e2);
                                    }).then(function(r) {
                                        console.log(r);
                                        throw e;
                                    });
                                }
                                throw e;
                            });
			});
		    });
		});
                let vk = self.VES.unlockedKeys[id] = un.then(function() {
		    return self;
		}).catch(function(e) {
		    if (self.VES.unlockedKeys[id] === vk) delete(self.VES.unlockedKeys[id]);
		});
		return un;
	    });
	});
        else if (veskey) self.wcPriv = self.wcPriv.catch(function(e) {
            delete(self.wcPriv);
            return self.unlock(veskey);
        });
	return self.wcPriv;
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
	if (!optns) optns = this.VES.keyOptions;
	var self = this;
	var a;
	var wc = optns && optns.privateKey ? libVES.Algo.acquire(optns.privateKey).then(function(wc) {
	    self.setField('algo',wc.engine.tag);
	    if (!wc.privateKey) throw new libVES.Error('InvalidValue','Private key expected');
	    return wc;
	}) : (optns && (a = libVES.Algo.fromKeyOptions(optns)) ? self.setField('algo', a) : Promise.resolve()).then(function() {
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
	    if (old_ves) return old_ves.map(function(ve,i) {
		old_vis[ve.vaultItem.id] = true;
	    });
	}) : Promise.resolve(null)).then(function() {
	    return self.setField('vaultEntries',key.unlock(veskey).then(function() {
		return key.getVaultEntries().then(function(ves) {
		    return Promise.all(ves.map(function(ve) {
			return old_vis[ve.vaultItem.id] ? null : key.decrypt(ve.encData).then(function(ptxt) {
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
		    }).filter(function(e, i) {
			return !!e;
		    }));
		});
	    }));
	}).then(function() {
	    return self;
	});
    },
    rekey: function(optns) {
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
		    if (!optns) optns = {};
		    optns.refs = {'#/': user};
		    return user.post(null,{vaultEntries: true}, optns).then(function(data) {
			self.setFields(data,false);
			return self.VES.onRekey ? self.VES.onRekey(self).catch(function() {}).then(function() {
			    return self;
			}) : self;
		    });
		});
	    });
	});
    },
    getRecovery: function(myItems) {
	var self = this;
	return self.getType().then(function(t) {
	    switch (t) {
		case 'shadow': case 'recovery':
		    return new libVES.Recovery(self, myItems);
		default: throw new libVES.Error('InvalidValue','Recovery is not applicable for VaultKey type ' + t);
	    }
	});
    },
    getSessionToken: function() {
	var self = this;
	return this.getField('encSessionToken').then(function(tk) {
	    if (!tk) return null;
	    return self.decrypt(tk).then(function(b) {
		return libVES.Util.ByteArrayToString(b);
	    });
	});
    },
    reshareVESkey: function(veskey, optns) {
	var self = this;
	return self.getVaultItems().then(function(vaultItems) {
	    return self.getUser().then(function(user) {
		return Promise.all(vaultItems.map(function(vaultItem,i) {
		    return vaultItem.getType().then(function(t) {
			if (t == 'password') return vaultItem.reshareWith([user], veskey, false).then(function(vi) {
			    return vi.post(undefined, undefined, optns);
			});
		    });
		}));
	    });
	});
    },
    matchVaults: function(shares) {
        return this.getFields({id: true, externals: {domain: true, externalId: true}, user: {email: true}}).then((flds) => (shares || []).reduce((res, sh) => res.then((res) => Promise.resolve(sh).then((sh) => {
            if (res) return res;
            var ext = flds.externals?.[0];
            if (sh instanceof libVES.Object) {
                if (sh instanceof libVES.VaultKey) return sh.getId().then((id) => (id == flds.id ? sh : res));
                else if ((sh instanceof libVES.External) && ext) return sh.getFields({domain: true, externalId: true}).then((xflds) => (xflds.domain == ext.domain && xflds.externalId == ext.externalId ? sh : res));
                else if ((sh instanceof libVES.User) && flds.user && !ext) return sh.getEmail().then((email) => (email == flds.user.email ? sh : res));
            } else if (sh instanceof Object) {
                if (sh.externalId && sh.externalId == ext?.externalId && (sh.domain || this.VES.domain) == ext.domain) return sh;
                else if (sh.email && sh.email == flds.user?.email && !ext) return sh;
            } else if (sh && flds.user?.email == sh && !ext) return sh;
            return res;
        })), Promise.resolve(false)));
    },
    getKeyOptions: function() {
	var self = this;
	return self.engine().then(function(e) {
	    return self.getPublicCryptoKey().then(function(pub) {
		return e.getKeyOptions(pub);
	    });
	});
    }
});

libVES.VaultItem.prototype = new libVES.Object({
    apiUri: 'vaultItems',
    fieldList: {id: true, deleted: true, file: true},
    fieldClass: {vaultKey: libVES.VaultKey, file: libVES.File},
    fieldSets: [{type: true, meta: true},{vaultEntries: {id: true, encData: true, vaultKey: {id: true, type: true, user: {id: true, email: true}, algo: true, externals: {id: true, domain: true, externalId: true}}}},{vaultKey: true, file: true}],
    defaultCipher: 'AES256GCM',
    getRaw: function() {
	var self = this;
	var f = function(vaultEntries, vaultKeys) {
	    var i = 0;
	    var fn = function() {
		if (vaultEntries) for (; i < vaultEntries.length; i++) {
		    var k, d;
		    if ((d = vaultEntries[i].encData) != null && (k = vaultKeys[vaultEntries[i].vaultKey.id]) && (!self.VES.pendingKeys || !self.VES.pendingKeys[vaultEntries[i].vaultKey.id])) {
			i++;
			return Promise.resolve(k).then(function(k) {
			    return k.decrypt(d).catch(fn);
			});
		    }
		}
		return Promise.reject(new libVES.Error('InvalidKey',"No unlocked key to decrypt the item",{vaultItem: self}));
	    };
	    return fn();
	};
	var vaultEntries = [];
	if (self.vaultEntryByKey) for (var k in self.vaultEntryByKey) vaultEntries.push(self.vaultEntryByKey[k]);
	return f(vaultEntries, self.VES.unlockedKeys).catch(function() {
	    return self.getVaultEntries().then(function(vaultEntries) {
		return f(vaultEntries, self.VES.unlockedKeys).catch(function() {
		    return self.VES.getUnlockableKeys().then(function(vks) {
			return f(vaultEntries, vks);
		    });
		});
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
	    if (ves) for (var i = 0; i < ves.length; i++) self.vaultEntryByKey[ves[i].vaultKey.id] = ves[i];
	    return ves;
	});
    },
    getVaultKey: function() {
	return this.getField('vaultKey');
    },
    getFile: function() {
	return this.getField('file');
    },
    getDeleted: function() {
	return this.getField('deleted');
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
	return this.getType().catch(function(e) {
            if (e && e.code == 'NotFound') return self.setField('type', libVES.VaultItem.Type._detect(data));
            throw e;
        }).then(function(type) {
	    return libVES.getModule(libVES.VaultItem.Type,type).then(function(m) {
		return m.build.call(self,data);
	    });
	});
    },
    resolveRaw: function(val) {
	return (val == null ? this.getRaw() : this.build(val));
    },
    shareWith: function(usrs,val,save) {
	var self = this;
	return self.VES.usersToKeys(usrs).then(function(ks) {
	    return (val == null ? self.getVaultEntries().then(function(ves) {
		var k_ves = {};
		var k_used = {};
		for (var j = 0; j < ves.length; j++) k_ves[ves[j].vaultKey.id] = ves[j];
		return Promise.all(ks.map(function(k,j) {
		    if (!k.fieldUpdate.privateKey) return k.getId().then(function(k_id) {
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
		var valr = null;
		var key_ids = {};
		return Promise.all(ks.map(function(k,j) {
		    return new_ves[j] = (old_ves[j] || (valr != null ? valr : valr = self.resolveRaw(val)).then(function(v) {
			return (function(refs) {
			    if (refs) for (var i in refs) if (refs[i] === k) return Promise.resolve({'$ref':i});
			    return k.postData(null,refs);
			})(libVES.Object._refs).then(function(pd) {
			    if (pd.id) {
				if (key_ids[pd.id]) return;
				key_ids[pd.id] = true;
			    }
			    return k.encrypt(v).then(function(ctext) {
				return set_ves.push({vaultKey: pd, encData: ctext});
			    });
			});
		    }));
		})).then(function() {
		    return Promise.all(old_ves.slice(ks.length).map(function(ve,j) {
			return (new libVES.VaultKey(ve.vaultKey,self.VES)).matchVaults(usrs).then(function(f) {
			    if (!f) set_ves.push({vaultKey: {id: ve.vaultKey.id}, '$op': 'delete'});
			});
		    }));
		}).then(function() {
		    if (!set_ves.length) return save = false;
		    return self.setField('vaultEntries',set_ves);
		});
	    });
	}).then(function() {
	    if (self.id && val != null) return self.setUpdate({id: false, type: true, file: {id: false, externals: {id: false, domain: true, externalId: true}}});
	}).then(function() {
	    if (save || save === undefined) return self.post(undefined, undefined, ((save instanceof Object) ? save : undefined)).then(function(flds) {
                self.vaultEntryByKey = {};
                self.setFields(flds, false);
		return self;
	    }).finally(function() {
		delete(self.vaultEntries);
	    });
	    return self;
	}).catch(function(er) {
	    delete(self.vaultEntries);
	    throw er;
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
			return k.getId().catch(function(e) {
			    if (e.code != 'NotFound') throw e;
			});
		    })).then(function(new_ids) {
			for (var i = 0; i < new_ks.length; i++) if (!m_curr_ks[new_ids[i]]) curr_ks.push(m_curr_ks[new_ids[i]] = new_ks[i]);
			return self.shareWith(curr_ks,val,save);
		    });
		});
	    });
	});
    },
    unshareWith: function(share, save) {
        return this.getShareVaultKeys().then((vkeys) => Promise.all(vkeys.map((vkey) => vkey.matchVaults(share))).then((del) => this.shareWith(vkeys.filter((vkey, i) => !del[i]), undefined, save)));
    },
    set: function(val, save) {
	var self = this;
	return self.getShareList().then(function(sh) {
	    return self.shareWith(sh, val, save);
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
	    var xids = {};
	    return Promise.all(vaultKeys.map(function(e,i) {
		return e.getExternals().then(function(exts) {
		    if (exts && exts.length) return exts[0].getId().then(function(xid) {
			if (!xid || xids[xid]) return null;
			xids[xid] = true;
			return exts[0];
		    });
		    return e.getUser().then(function(u) {
			return u.getId().then(function(uid) {
			    if (!uid || uids[uid]) return null;
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
    },
    delete: function() {
	var self = this;
	return self.getId().then(function(id) {
	    return self.VES.post(self.apiUri + '/' + id, {'$op': 'delete'});
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
	    this.setField('meta', data.getMeta());
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
    fieldList: {id: true, externals: true},
    fieldClass: {externals: libVES.External, creator: libVES.User},
    getExternals: function() {
	return this.getField('externals');
    },
    getCreator: function() {
	return this.getField('creator');
    },
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


libVES.Event.prototype = new libVES.Object({
    apiUri: 'events',
    fieldList: {id: true, recordedAt: true, vaultKey: true, vaultItem: true, user: true},
    fieldClass: {vaultKey: libVES.VaultKey, vaultItem: libVES.VaultItem, user: libVES.User, creator: libVES.User, session: libVES.Session},
    getType: function() {
	return this.getField('type');
    },
    getVaultKey: function() {
	return this.getField('vaultKey');
    },
    getVaultItem: function() {
	return this.getField('vaultItem');
    },
    getUser: function() {
	return this.getField('user');
    },
    getCreator: function() {
	return this.getField('creator');
    },
    getSession: function() {
	return this.getField('session');
    }
});

libVES.Session.prototype = new libVES.Object({
    apiUri: 'sessions',
    fieldList: {id: true, createdAt: true, expiresAt: true, vaultKey: true, user: true},
    fieldClass: {vaultKey: libVES.VaultKey, user: libVES.User},
    getVaultKey: function() {
	return this.getField('vaultKey');
    },
    getUser: function() {
	return this.getField('user');
    },
    getRemote: function() {
	return this.getField('remote');
    },
    getUserAgent: function() {
	return this.getField('userAgent');
    }
});

libVES.Domain.prototype = new libVES.Object({
    apiUri: 'domains',
    fieldList: {id: true},
    fieldClass: {vaultKeys: libVES.VaultKey, vaultItems: libVES.VaultItem, creator: libVES.User},
    fieldSets: [{vaultItems: {id: true, type: true, file: {creator: true, externals: true}, deleted: true}, vaultKeys: {id: true, type: true, user: {id: true}, algo: true, externals: {id: true}}}],
    getCreator: function() {
	return this.getField('creator');
    },
    getVaultKeys: function() {
	return this.getField('vaultKeys');
    },
    getVaultItems: function() {
	return this.getField('vaultItems');
    }
});

