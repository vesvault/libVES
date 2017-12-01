/**
 * @title libVES.Recovery
 *
 * @author Jim Zubov <jz@vesvault.com> (VESvault)
 * GPL license, http://www.gnu.org/licenses/
 */
libVES.Recovery = function(vaultKey) {
    this.vaultKey = vaultKey;
};

libVES.Recovery.prototype = {
    getTokens: function() {
	if (this.tokens) return this.tokens;
	var self = this;
	return this.tokens = self.vaultKey.getType().then(function(t) {
	    switch (t) {
		case 'shadow': case 'recovery': return self.getVaultItems().then(function(vis) {
		    var frnds = {};
		    var fn = function() {
			return self.vaultKey.getUser().then(function(my_u) {
			    return my_u.getId().then(function(my_uid) {
				return Promise.all(vis.map(function(vi) {
				    var frnd = {vaultItem: vi};
				    return Promise.all([
					vi.getVaultEntries().then(function(ves) {
					    return Promise.all(ves.map(function(ve) {
						return new libVES.VaultKey(ve.vaultKey,self.VES).getUser().then(function(u) {
						    return u.getId().then(function(uid) {
							if (uid == my_uid) frnd.assisted = true;
							else {
							    frnd.user = u;
							    frnds[uid] = frnd;
							}
						    });
						});
					    }));
					}),
					vi.getMeta().then(function(meta) {
					    frnd.meta = meta;
					}),
					vi.get().then(function(data) {
					    frnd.value = data;
					}).catch(function(){})
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
	return Promise.all(this.vaultKey.getUser(),this.vaultKey.libVES.me()).then(function(usrs) {
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
    getFriendInfo: function(user) {
	var self = this;
	return this.getTokens().then(function(tkns) {
	    return Promise.resolve(tkns.map(function(v,i) {
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
	return self.vaultKey.libVES.me().then(function(me) {
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
	    return Promise.all(tkns.map(function(v,i) {
		return v.getVaultEntries().then(function() {
		    return v.vaultEntryByKey;
		});
	    })).then(function(ves) {
		return self.vaultKey.getUser().then(function(user) {
		    return user.getCurrentVaultKey().then(function(vk) {
			return vk.getId().then(function(vkid) {
			    var rs = 0;
			    for (var i = 0; i < ves.length; i++) if (ves[i][vkid]) rs++;
			    return rs;
			});
		    });
		});
	    });
	    return tkns[0].meta.n;
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
	this.getMyToken().then(function(tkn) {
	    if (!tkn) throw new libVES.Error('InvalidValue','No assistance available');
	    return self.vaultKey.getUser().then(function(user) {
		return tkn.vaultItem.shareWith(assist ? [tkn.user,user] : [tkn.user]).then(function() {
		    return true;
		});
	    });
	});
    },
    assist: function() {
	return this._assist(true);
    },
    revoke: function() {
	return this._assist(false);
    },
    _recover: function() {
	var self = this;
	self.getTokens().then(function(tkns) {
	    var vtkns = [];
	    for (var i = 0; i < tkns.length; i++) if (tkns[i].value != null) vtkns.push(tkns[i]);
	    if (vtkns.length) return libVES.getModule(libVES,['Scramble','algo',vtkns[0].meta.v]).then(function(sc) {
		return sc.implode(vtkns,function(secret) {
		    return self.vaultKey.unlock(secret).then(function() {
			return self.vaultKey.getUser().then(function(user) {
			    return user.getCurrentVaultKey().then(function(curr) {
				return curr.rekeyFrom(self.vaultKey);
			    });
			});
		    });
		});
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