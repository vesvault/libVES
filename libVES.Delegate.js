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
 * libVES.Delegate.js         libVES: Delegate login via VESvault
 *
 ***************************************************************************/
libVES.Delegate = {
    html: '<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);display:table;z-index:200000;">'
	+ '<div style="display:table-row;"><div style="display:table-cell;vertical-align:middle;text-align:center;">'
	+ '<div style="min-width:320px;max-width:640px;;background-color:white;margin: auto;padding: 30px;">'
	+ '{$content}'
	+ '</div></div></div></div>',
    htmlDlg: '<p>Use the VESvault popup window to grant access to the App Vault</p>'
	   + '<p class="VESvaultDelegateBlockerMsg" style="color: #bf7f00; font-style:italic;">&nbsp;</p>'
	   + '<p><a class="VESvaultDelegateRetryLnk" href="{$url}" target="VESvaultDelegate" onclick="return !libVES.Delegate.retryPopup(this.href,this)">Click here</a> if you can\'t see VESvault popup window</p>'
	   + '<p><a class="VESvaultDelegateCancelLnk" href="#" onclick="libVES.Delegate.cancel(); return false;">Cancel</a></p>',
    htmlFlw: '<p>Authorizing VES Access</p>'
	   + '<iframe style="width: 100%; height: 48px; border: none;" src="{$url}"></iframe>',
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
	    var url = VES.wwwUrl + 'vv/unlock?via=delegate&url=' + encodeURIComponent(document.location.href) + '&domain=' + encodeURIComponent(VES.domain);
	    if (optns) for (var k in optns) if (optns[k] != null) url += '&' + encodeURIComponent(k) + '=' + encodeURIComponent(optns[k]);
	    self.setOrigin(url);
	    self.showOverlay(self.htmlDlg.replace('{$url}',url));
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
    flow: function(VES, start, optns) {
	if (this.response) return this.response;
	this.VES = VES;
	var self = this;
	var unlk = VES.wwwUrl + 'vv/unlock';
	if (start || (!sessionStorage['libVES.flowStarted'] && document.referrer.substr(0, unlk.length).toLowerCase() == unlk.toLowerCase())) {
	    return self.response = new Promise(function(resolve, reject) {
		self.reject = reject;
		self.resolve = resolve;
		var ifrm = VES.wwwUrl + 'vv/flowin?url=' + encodeURIComponent(document.location.href) + '&domain=' + encodeURIComponent(VES.domain);
		if (optns) for (var k in optns) if (optns[k] != null) ifrm += '&' + encodeURIComponent(k) + '=' + encodeURIComponent(optns[k]);
		self.setOrigin(ifrm);
		window.addEventListener('message',self.listener.bind(self));
		self.showOverlay(self.htmlFlw.replace('{$url}', ifrm));
		if (start) delete(sessionStorage['libVES.flowStarted'])
		else sessionStorage['libVES.flowStarted'] = true;
	    });
	} else {
	    return new Promise(function(){});
	}
    },
    showOverlay: function(cont) {
	this.popup = document.createElement('DIV');
	this.popup.innerHTML = this.html.replace('{$content}', cont);
	document.getElementsByTagName('BODY')[0].appendChild(this.popup);
    },
    setOrigin: function(url) {
	this.matchOrigin = (function(m) { return m ? m[0] : document.location.protocol + '//' + document.location.host; })(url.match(/^(https\:\/\/[^\/\?\#]+)/));
    },
    openPopup: function(url) {
	return this.popupWindow = window.open(url,this.name,"width=600,height=600,top=100,left=100");
    },
    retryPopup: function(url,href) {
	this.retryPopupCalled++;
	if (this.popupWindow) try {
	    this.popupWindow.focus();
	    return true;
	} catch(e) {}
	this.openPopup(url);
	return true;
    },
    listener: function(evnt) {
	if (this.popup && evnt.origin == this.matchOrigin) try {
	    var msg = JSON.parse(evnt.data);
	    if (msg.redirect) {
		document.location.replace(msg.redirect);
	    } else {
		this.resolve(this.VES.authorize(msg));
	    }
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
	    return this.response;
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
