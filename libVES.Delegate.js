/**
 * @title libVES.Delegate
 *
 * @author Jim Zubov <jz@vesvault.com> (VESvault)
 * GPL license, http://www.gnu.org/licenses/
 */
libVES.Delegate = {
    html: '<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);display:table;z-index:2;">'
	+ '<div style="width: 500px; height: 120px;background-color:white;margin: 20% auto auto auto;padding: 30px 0px 30px 30px;">'
	+ '<div style="display:table-row;"><div style="display:table-cell;vertical-align:middle;text-align:center;">'
	+ '<p>Use VESvault popup window to grant the App Vault permission</p>'
	+ '<p><a href="#" onclick="libVES.Delegate.cancel(); return false;">Cancel</a></p>'
	+ '</div></div></div></div>',
    name: 'VESvaultDelegate',
    login: function(VES,challenge,optns) {
	if (this.popup) return this.response || Promise.reject(new libVES.Error('InvalidValue','The delegate popup is already open'));
	if (!challenge) {
	} else try {
	    var info = document.location.search.match(/[\?\&]VESvaultDelegate=([^\&]+)/)[0];
	} catch(e) {}
	this.VES = VES;
	var self = this;
	return this.response = new Promise(function(resolve,reject) {
	    self.reject = reject;
	    self.resolve = resolve;
	    self.popup = document.createElement('DIV');
	    self.popup.innerHTML = self.html;
	    document.getElementsByTagName('BODY')[0].appendChild(self.popup);
	    var url = VES.wwwUrl + 'session/delegate/' + escape(VES.app) + '/' + escape(VES.domain);
	    self.popupWindow = window.open(url,self.name,"width=500,height=500,top=100,left=100");
	    if (self.popupWindow) self.popupWindow.onblur = function() {
		window.setTimeout(function() {console.log(self.popupWindow.closed);},0);
//		self.cancel.bind(self);
	    };
	    window.addEventListener('message',self.listener.bind(self));
	    window.addEventListener('focus',self.chkCancel.bind(self));
	    window.clearInterval(self.popupInterval);
	    this.popupInterval = window.setInterval(self.chkCancel.bind(self),1000);
	});
    },
    listener: function(evnt) {
	if (evnt.source == this.popupWindow) {
	    var msg = JSON.parse(evnt.data);
	    var VES = this.VES;
	    if (msg.externalId) {
		VES.externalId = msg.externalId;
		this.resolve(VES.unlock(msg.VESkey).then(function() {
		    return VES;
		}));
		this.close();
	    } else if (msg.token) {
		VES.token = msg.token;
		this.resolve(VES.getSecondaryKey({domain:VES.domain},true).then(function(vaultKey) {
		    return vaultKey.getExternals().then(function(externals) {
			return Promise.all(externals.map(function(ext,i) {
			    return ext.getDomain();
			})).then(function(domains) {
			    for (var i = 0; i < domains.length; i++) if (domains[i] == VES.domain) return externals[i].getExternalId();
			    throw new libVES.Error('Internal','No external id found for newly created secondary key');
			}).then(function(extId) {
			    VES.externalId = extId;
			    return VES;
			});
		    });
		}));
		this.close();
	    }
	}
    },
    close: function() {
	if (this.popup) {
	    if (this.popupWindow) {
		try {
		    this.popupWindow.close();
		} catch (e) {}
		this.popupWindow = null;
	    }
	    window.clearInterval(this.popupInterval);
	    this.popupInterval = null;
	    this.popup.parentNode.removeChild(this.popup);
	    this.popup = null;
	    return self.response;
	}
    },
    cancel: function() {
	var rs = this.close();
	if (this.response && this.reject) this.reject(new libVES.Error('Aborted','VESvault login is cancelled'));
	return rs;
    },
    chkCancel: function() {
	if (this.popupWindow && this.popupWindow.closed) this.cancel();
    }
};
