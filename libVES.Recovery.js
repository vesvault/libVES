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
 * libVES.Recovery.js         libVES: VESrecovery interface
 *
 ***************************************************************************/
libVES.Recovery = function(vaultKey, myItems) {
    this.vaultKey = vaultKey;
    if (myItems) this.myItems = Promise.resolve(myItems);
};

libVES.Recovery.prototype = {
    getTokens: function() {
	if (this.tokens) return this.tokens;
	var self = this;
	return this.tokens = self.vaultKey.getType().then(function(t) {
	    switch (t) {
		case 'shadow': case 'recovery': return (self.myItems ? self.myItems : self.vaultKey.getField('vaultItems',{
		    id: true,
		    meta: true,
		    type: true,
		    vaultEntries: {
			encData: true,
			vaultKey: {
			    user: true,
			    type: true
			}
		    }
		},true)).then(function(vis) {
		    var frnds = {};
		    var fn = function() {
			return self.vaultKey.getUser().then(function(my_u) {
			    return my_u.getId().then(function(my_uid) {
				return Promise.all(vis.map(function(vi) {
				    var frnd = {vaultItem: vi};
				    return Promise.all([
					vi.getVaultEntries().then(function(ves) {
					    return Promise.all(ves.map(function(ve) {
						var vk = new libVES.VaultKey(ve.vaultKey,self.vaultKey.VES);
						return vk.getUser().then(function(u) {
						    return u.getId().then(function(uid) {
							if (uid == my_uid) {
							    frnd.assisted = true;
							    return vk.getType().then(function(type) {
								if (type == 'current') frnd.current = true;
							    });
							} else {
							    frnd.user = u;
							    frnds[uid] = frnd;
							}
						    });
						});
					    }));
					}),
					vi.get().then(function(data) {
					    frnd.meta = data.meta;
					    frnd.value = data.value;
					}).catch(function(e) {
					    return vi.getMeta().then(function(meta) {
						frnd.meta = meta;
					    });
					})
				    ]);
				}));
			    });
			}).then(function() {
			    var rs = [];
			    for (var id in frnds) rs.push(frnds[id]);
			    return rs;
			});
		    };
		    return self.vaultKey.trigger ? self.vaultKey.trigger.then(fn) : fn();
		});
		default: throw new libVES.Error('InvalidValue','Recovery info is applicable for key type shadow or recovery');
	    }
	});
    },
    requireOwner: function() {
	return Promise.all([this.vaultKey.getUser(),this.vaultKey.VES.me()]).then(function(usrs) {
	    return Promise.all(usrs.map(function(v,i) {
		return v.getId();
	    })).then(function(uids) {
		if (uids[0] == uids[1]) return true;
		throw new libVES.Error('InvalidValue','Not an owner of the VESrecovery');
	    });
	});
    },
    getFriends: function() {
	return this.getTokens().then(function(tkns) {
	    return tkns.map(function(v,i) {
		return v.user;
	    });
	});
    },
    getOptions: function() {
	return this.getTokens().then(function(tkns) {
	    return tkns.length ? tkns[0].meta : null;
	});
    },
    getFriendInfo: function(user) {
	var self = this;
	return this.getTokens().then(function(tkns) {
	    return Promise.all(tkns.map(function(v,i) {
		return v.user.getId();
	    })).then(function(uids) {
		return user.getId().then(function(uid) {
		    for (var i = 0; i < uids.length; i++) if (uids[i] == uid) return tkns[i];
		    throw new libVES.Error('InvalidValue','Not a friend: ' + uid);
		});
	    });
	});
    },
    getMyToken: function() {
	var self = this;
	return self.vaultKey.VES.me().then(function(me) {
	    return self.getFriendInfo(me);
	});
    },
    getFriendsTotal: function() {
	return this.getTokens().then(function(tkns) {
	    return tkns.length;
	});
    },
    getFriendsRequired: function() {
	return this.getTokens().then(function(tkns) {
	    return tkns[0].meta.n;
	});
    },
    getFriendsAssisted: function() {
	var self = this;
	return this.getTokens().then(function(tkns) {
	    var a = 0;
	    tkns.map(function(t, i) {
		if (t.assisted) a++;
	    });
	    return a;
	});
    },
    getFriendsToGo: function() {
	var self = this;
	return self.getFriendsRequired().then(function(n) {
	    return self.getFriendsAssisted().then(function(a) {
		return a < n ? n - a : 0;
	    });
	});
    },
    _assist: function(assist) {
	var self = this;
	return this.getMyToken().then(function(tkn) {
	    if (!tkn) throw new libVES.Error('InvalidValue','No assistance available');
	    return self.vaultKey.getUser().then(function(user) {
		return self.vaultKey.VES.elevateAuth().catch(function(e) {
		    return undefined;
		}).then(function(optns) {
		    return tkn.vaultItem.shareWith((assist ? [tkn.user,user] : [tkn.user]), undefined, optns).then(function() {
			self.tokens = undefined;
			self.vaultKey.vaultItems = undefined;
			return true;
		    });
		});
	    });
	});
    },
    assist: function() {
	var self = this;
	return self.vaultKey.getType().then(function(t) {
	    return t == 'recovery' ? self._assist(true) : null;
	});
    },
    revoke: function() {
	return this._assist(false);
    },
    unlock: function() {
	var self = this;
	return self.getTokens().then(function(tkns) {
	    var vtkns = [];
	    for (var i = 0; i < tkns.length; i++) if (tkns[i].value != null) vtkns.push(tkns[i]);
	    if (vtkns.length) return libVES.getModule(libVES,['Scramble','algo',vtkns[0].meta.v]).then(function(sc) {
		return new sc(vtkns[0].meta.n).implode(vtkns,function(secret) {
		    return self.vaultKey.unlock(secret);
		});
	    });
	});
    },
    _recover: function() {
	var self = this;
	return self.unlock().then(function() {
	    return self.vaultKey.VES.elevateAuth({authVaultKey: self.vaultKey}).then(function(optns) {
		return self.vaultKey.rekey(optns);
	    });
	});
    },
    recover: function() {
	var self = this;
	if (!this.recovery) this.recovery = this.requireOwner().then(function() {
	    return self._recover();
	});
	return this.recovery;
    }
};
