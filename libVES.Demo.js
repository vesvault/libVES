libVES.Demo = function(optns) {
    if (optns) for (var k in optns) this[k] = optns[k];
    this.current = {};
    this.loginForm();
};

libVES.Demo.prototype = {
    loadElement: function(e,val) {
	var self = this;
	if (val != null) {
	    e.className = self.setClass(e,['loading','error'],['loading']);
	    e.innerHTML = 'loading...';
	    Promise.resolve(val).then(function(v) {
		e.className = self.setClass(e,['loading','error'],[]);
		if (typeof(v) == 'function') {
		    e.innerHTML = '';
		    return v(e);
		} else return e.innerHTML = v;
	    }).catch(function(v) {
		e.className = self.setClass(e,['loading','error'],['error']);
		e.innerHTML = v;
	    });;
	}
    },
    setClass: function(e,del,add) {
	return e.className = (e.className || '').split(/\s+/).filter(function(c) {
	    return !del || del.indexOf(c) < 0;
	}).join(' ') + (add ? ' ' + add.join(' ') : '');
    },
    addElement: function(cnt,tag,cls,val) {
	var e = document.createElement(tag);
	if (cls) e.className = cls;
	this.loadElement(e,val);
	cnt.appendChild(e);
	return e;
    },
    addMenu: function(cnt,cls,items) {
	var self = this;
	var selected = null;
	this.addElement(cnt,'div',cls,function(cnt2) {
	    for (var i = 0; i < items.length; i++) (function(item) {
		item.dom = self.addElement(cnt2,'a','menu-link',item.text);
		item.dom.href = '#';
		item.dom.onclick = function() {
		    if (item != selected) {
			if (selected) {
			    if (selected.unload) selected.unload(selected.dom,selected);
			    selected.dom.className = 'menu-link';
			}
			item.dom.className = 'menu-link selected';
			(selected = item).load(item.dom,item);
		    }
		    return false;
		}
	    })(items[i]);
	    if (!selected) console.log(items[0].dom.onclick());
	});
    },
    addSelector: function(cnt,cls,items,cur) {
	var self = this;
	var selected = null;
	self.addElement(cnt,'label',cls,function(lbl) {
	    self.addElement(lbl,'select',null,Promise.resolve(items).then(function(items) {
		return Promise.resolve(cur ? cur(items) : null).then(function(c) {
		    return function(sel) {
			for (var i = 0; i < items.length; i++) {
			    var op = self.addElement(sel,'option','',items[i].text);
			    op.value = i;
			    if (c == items[i]) {
				op.selected = true;
				selected = c;
			    }
			}
			sel.onchange = function() {
			    var item = items[this.value];
			    if (selected && selected.unload) selected.unload(selected);
			    selected = item;
			    if (item.load) item.load(item);
			    return true;
			};
			if (!selected && items[0]) selected = items[0];
			if (selected && selected.load) selected.load(selected);
		    };
		});
	    }));
	});
    },

    loginForm: function() {
	var self = this;
	this.container.innerHTML = '';
	var menu = this.addElement(this.container,'div');
	var frmdiv = this.addElement(this.container,'div')
	var cont = this.addElement(this.container,'div')
	this.addMenu(menu,'login-menu',[
	    {
		text: 'Primary',
		load: function() {
		    self.addElement(frmdiv,'form','login-form',function(frm) {
			var user = self.addElement(frm,'input','login-form-user');
			var passwd = self.addElement(frm,'input','login-form-passwd',function(e) { e.type = 'password'; });
			self.addElement(frm,'button','login-form-login','Login').onclick = function() {
			    user.disabled = true;
			    passwd.disabled = true;
			    self.VES = new libVES({user: user.value, passwd: passwd.value});
			    self.veskeyForm(cont);
			};
			self.addElement(frm,'button','login-form-logout','Logout').onclick = function() {
			    user.disabled = false;
			    passwd.disabled = false;
			    self.VES = null;
			    self.veskeyForm(cont);
			};
			if (self.VES) {
			    user.value = self.VES.user;
			    user.disabled = true;
			    passwd.value = self.VES.passwd;
			    passwd.disabled = true;
			}
			self.veskeyForm(cont);
		    });
		},
		unload: function() {
		    frmdiv.innerHTML = '';
		}
	    },
	    {
		text: 'Secondary',
		load: function() {
		},
		unload: function() {
		    cont.innerHTML = '';
		}
	    }
	]);
    },
    veskeyForm: function(c) {
	var self = this;
	c.innerHTML = '';
	var frmdiv = self.addElement(c,'div');
	var cont = self.addElement(c,'div');
	self.addElement(frmdiv,'form','veskey-form',function(frm) {
	    if (self.VES) return self.VES.getVaultKey().then(function(k) {
		return k.getId().then(function(id) {
		    return k.getType().then(function(t) {
			return self.VES.me().then(function(me) {
			    return me.getEmail().then(function(email) {
				return me.getId().then(function(uid) {
				    self.addElement(frm,'div','','Logged in: user id=' + uid + ' (' + email + ')');
				    self.addElement(frm,'div','','vaultKey id=' + id + ' (' + t +')');
				    var inpt = self.addElement(frm,'input','veskey-field');
				    self.addElement(frm,'button','veskey-unlock','Unlock').onclick = function() {
					self.VES.unlock(inpt.value).then(function() {
					    self.vaultView(cont);
					}).catch(function(e) {
					    window.alert(e);
					});
					return false;
				    };
				    self.addElement(frm,'button','veskey-lock','Lock').onclick = function() {
					self.VES.lock().then(function() {
					    self.vaultView(cont);
					}).catch(function(e) {
					    window.alert(e);
					});
					return false;
				    };
				    self.vaultView(cont);
				});
			    });
			});
		    });
		});
	    });
	});
    },

    vaultView: function(c) {
	var self = this;
	c.innerHTML = '';
	var menu = this.addElement(c,'div','vault-view-menu');
	var cont = this.addElement(c,'div','vault-view-content');
	var current = this.current;
	var loadf = {};
	var unloadf = function() {
	    cont.innerHTML = '';
	};
	this.addMenu(menu,'vault-view-menu',[
	    {
		text: 'Keys',
		load: loadf.key = function(dom,item) {
		    var view = null;
		    self.addSelector(cont,'vault-key',self.VES.getVaultKey().then(function(k) {
			var f = function(k,prf) {
			    var prs = [k.getId().then(function(id) {
				return k.getType().then(function(t) {
				    return k.getExternals().then(function(exts) {
					return Promise.all(exts.map(function(ext) {
					    return ext.getDomain().then(function(d) {
						return ext.getExternalId().then(function(xid) {
						    return d + ': ' + xid;
						});
					    });
					})).then(function(exts) {
					    var txt = prf + id + ': ' + t;
					    if (exts.length) txt += ' (' + exts.join(', ') + ')';
					    return [{
						text: txt,
						object: k,
						load: function() {
						    current.key = k;
						    if (!view) view = self.addElement(cont,'div','vault-key-view');
						    view.innerHTML = '';
						    self.addElement(view,'div','',k.unlock().catch(function(er) {
							return null;
						    }).then(function(wc) {
							return function(e) {
							    self.addElement(e,'div','vault-key-view-hdr',k.getId().then(function(id) {
								return k.getType().then(function(t) {
								    return 'vaultKey ' + id + ' (' + t + ')';
								});
							    }));
							    self.addElement(e,'div','vault-key-view-user',k.getUser().then(function(u) {
								return u.getId().then(function(id) {
								    return u.getEmail().then(function(email) {
									return 'owner: ' + email + ' (id=' + id + ')';
								    });
								});
							    }));
							    self.addElement(e,'div','vault-key-view-status',(wc ? k.getVaultItems().then(function(vis) {
								return (vis && vis[0] ? vis[0].get() : Promise.resolve(null)).then(function(v) {
								    return function(e) {
									self.addElement(e,'span','','unlocked');
									if (v != null) self.addElement(e,'input','vault-key-view-veskey',function(inpt) {
									    inpt.value = v;
									    inpt.setAttribute('readonly',true);
									});
								    };
								});
							    }) : 'locked'));
							    self.addElement(e,'textarea','vault-key-view-pub',k.getPublicKey()).setAttribute('readonly',true);
							    self.addElement(e,'textarea','vault-key-view-priv',(wc ? k.getUnlockedPrivateKey() : k.getPrivateKey())).setAttribute('readonly',true);
							    var msgdiv;
							    var addf = function(flds) {
								unloadf();
								self.addElement(cont,'form','vault-key-add-form',function(e) {
								    var inputs = {
									domain: self.addElement(e,'input','vault-key-input-domain'),
									externalId: self.addElement(e,'input','vault-key-input-extid'),
									veskey: self.addElement(e,'input','vault-key-input-veskey'),
									priv: self.addElement(e,'textarea','vault-key-input-priv')
								    };
								    if (flds) for (var k in flds) if (inputs[k]) inputs[k].value = flds[k];
								    var msg;
								    self.addElement(e,'button','vault-key-add-submit','Submit').onclick = function() {
									self.loadElement(msg,self.VES.setSecondaryKey([{domain: inputs.domain.value, externalId: inputs.externalId.value}],inputs.veskey.value,{privateKey: inputs.priv.value}).then(function(k) {
									    current.key = k;
									    unloadf();
									    loadf.key();
									}));
									return false;
								    };
								    self.addElement(e,'button','vault-key-add-cancel','Cancel').onclick = function() {
									unloadf();
									loadf.key();
									return false;
								    };
								    msg = self.addElement(e,'div','message');
								});
							    };
							    self.addElement(e,'button','vault-key-view-rekey','Rekey').onclick = function() {
								addf();
							    };
							    self.addElement(e,'button','vault-key-view-delete','Delete').onclick = function() {
								self.loadElement(msgdiv,k.getId().then(function(id) {
								    if (window.confirm('Delete vaultKey ' + id + '?')) return k.delete().then(function() {
									unloadf();
									loadf.key();
								    });
								    else return '';
								}));
								return false;
							    };
							    self.addElement(e,'button','vault-key-view-new','New Key').onclick = function() {
								addf();
							    };
							    msgdiv = self.addElement(e,'div','message');
							};
						    }));
						}
					    }];
					});
				    });
				});
			    })];
			    return k.getSharedKeys().then(function(sk) {
				for (var i = 0; i < sk.length; i++) prs[i + 1] = f(sk[i],'&raquo; ' + prf)
				return Promise.all(prs).then(function(lst) {
				    var rs = [];
				    for (var i = 0; i < lst.length; i++) for (var j = 0; j < lst[i].length; j++) rs.push(lst[i][j]);
				    return rs;
				});
			    });
			};
			return f(k,'');
		    }),function(items) {
			for (var i = 0; i < items.length; i++) if (items[i].object == current.key) return items[i];
		    });
		},
		unload: unloadf
	    },
	    {
		text: 'VESrecovery',
		load: loadf.recovery = function(dom,item) {
		    self.VES.getShadowKey().then(function(sh) {
			if (sh) self.addElement(cont,'div','ves-recovery-view',sh.getRecovery().then(function(rc) {
			    return function(dom) {
				return self.vaultShadow(dom,rc);
			    };
			}));
			else self.addElement(cont,'div','ves-recovery-not-set');
		    });
		},
		unload: unloadf
	    },
	    {
		text: 'Lockboxes',
		load: function(dom,item) {
		}
	    },
	    {
		text: 'Files',
		load: function(dom,item) {
		}
	    },
	]);
    },
    vaultShadow: function(dom,rc,edit) {
	var self = this;
	don.innerHTML = '';
	for (var i = 0; i < rc.tokens.length; i++) self.addElement(dom,'div','ves-recovery-friend',(function(r,i) {
	    return function(e) {
		self.addElement(e,'div','ves-recovery-friend-id',r.user.getId());
		self.addElement(e,'div','ves-recovery-friend-email',r.user.getEmail());
		self.addElement(e,'div','ves-recovery-friend-name',r.user.getFullName());
		if (edit) self.addElement(e,'button','ves-recovery-friend-remove','x').onclick = function() {
		    dom.removeChild(e);
		    rc.tokens.splice(i,1);
		    return false;
		};
	    };
	})(rc.tokens[i],i));
	if (edit) {
	    self.addElement(dom,'form','ves-recovery-friend-add',function(frm) {
	    });
	}
    }
};
