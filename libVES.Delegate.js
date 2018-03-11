/**
 * @title libVES.Delegate
 *
 * @author Jim Zubov <jz@vesvault.com> (VESvault)
 * GPL license, http://www.gnu.org/licenses/
 */
libVES.Delegate = {
    html: '<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);display:table;z-index:200000;">'
	+ '<div style="display:table-row;"><div style="display:table-cell;vertical-align:middle;text-align:center;">'
	+ '<div style="min-width:320px;max-width:640px;;background-color:white;margin: auto;padding: 30px;">'
	+ '<p>Use the VESvault popup window to grant access to the App Vault</p>'
	+ '<p class="VESvaultDelegateBlockerMsg" style="color: #bf7f00; font-style:italic;">&nbsp;</p>'
	+ '<p><a class="VESvaultDelegateRetryLnk" href="{$url}" target="VESvaultDelegate" onclick="return !libVES.Delegate.retryPopup(this.href,this)">Click here</a> if you can\'t see VESvault popup window</p>'
	+ '<p><a class="VESvaultDelegateCancelLnk" href="#" onclick="libVES.Delegate.cancel(); return false;">Cancel</a></p>'
	+ '</div></div></div></div>',
    htmlBlockerMsg: 'Looks like your browser is using a popup blocker...',
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
	    var url = VES.wwwUrl + 'session/delegate/' + escape(VES.app) + '/' + escape(VES.domain);
	    self.matchOrigin = (function(m) { return m ? m[0] : document.location.protocol + '//' + document.location.host; })(url.match(/^(https\:\/\/[^\/\?\#]+)/));
	    self.popup = document.createElement('DIV');
	    self.popup.innerHTML = self.html.replace('{$url}',url);
	    document.getElementsByTagName('BODY')[0].appendChild(self.popup);
	    self.retryPopupCalled = 0;
	    try {
		document.getElementsByClassName('VESvaultDelegateRetryLnk')[0].onclick = function() {
		    return !libVES.Delegate.retryPopup(this.href,this);
		};
		document.getElementsByClassName('VESvaultDelegateCancelLnk')[0].onclick = function() {
		    libVES.Delegate.cancel();
		    return false;
		};
	    } catch(e) {}
	    if (!self.openPopup(url)) try {
		document.getElementsByClassName('VESvaultDelegateBlockerMsg')[0].innerHTML = self.htmlBlockerMsg;
	    } catch(e) {
		window.alert(self.htmlBlockerMsg);
	    }
	    window.addEventListener('message',self.listener.bind(self));
	    window.addEventListener('focus',self.chkCancel.bind(self));
	    window.addEventListener('beforeunload',self.cancel.bind(self));
	    window.clearInterval(self.popupInterval);
	    self.popupInterval = window.setInterval(self.chkCancel.bind(self),1000);
	});
    },
    openPopup: function(url) {
	return this.popupWindow = window.open(url,this.name,"width=600,height=600,top=100,left=100");
    },
    retryPopup: function(url,href) {
	var f = this.retryPopupCalled;
	this.retryPopupCalled++;
	if (href && f > 1) href.target = '_blank';
	else if (this.popupWindow) try {
	    this.popupWindow.focus();
	} catch(e) {}
	return !f && this.openPopup(url);
    },
    listener: function(evnt) {
	if (this.popupWindow && evnt.origin == this.matchOrigin) try {
	    var msg = JSON.parse(evnt.data);
	    var VES = this.VES;
	    if (msg.externalId) {
		VES.externalId = msg.externalId;
		this.resolve(VES.unlock(msg.VESkey).then(function() {
		    return VES;
		}));
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
	    } else return;
	    this.close();
	    if (!evnt.source.closed) evnt.source.close();
	} catch(e) {}
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
