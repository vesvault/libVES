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
 * (c) 2018 - 2026 VESvault Corp
 * Jim Zubov <jz@vesvault.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License in the accompanying LICENSE
 * file, or at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.  See the License for the specific language governing
 * permissions and limitations under the License.
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
    // Two delivery channels from V back to O:
    //   - Browser path: V has window.opener and postMessages O directly.
    //   - App path: V is App-Link-intercepted into the native app, has no
    //     opener. V Flow-encrypts the auth payload to O's pub and redirects
    //     to a partner-hosted hook page at O's origin (path from
    //     app.delegate.hook in O's /ves.json manifest). The hook calls
    //     libVES.Delegate.hook() which BC-relays the still-encrypted token
    //     back to O over libVES.Flow's BroadcastChannel, scoped by a random
    //     `chan` nonce O passed through V to the hook URL.
    login: function(VES,challenge,optns) {
	if (this.popup) return this.response || Promise.reject(new libVES.Error('InvalidValue','The delegate popup is already open'));
	if (!challenge) {
	} else try {
	    var info = document.location.search.match(/[\?\&]VESvaultDelegate=([^\&]+)/)[0];
	} catch(e) {}
	this.VES = VES;
	var self = this;
	self._handled = false;
	self.chan = libVES.Util.ByteArrayToB64W((function() {
	    var b = new Uint8Array(12);
	    crypto.getRandomValues(b);
	    return b;
	})());
	return this.response = new Promise(function(resolve,reject) {
	    self.reject = reject;
	    self.resolve = resolve;
	    var baseUrl = VES.wwwUrl + (VES.wwwUrl.match(/\/$/) ? '' : '/') + 'vv/unlock?via=delegate'
		+ '&url=' + encodeURIComponent(document.location.href)
		+ '&domain=' + encodeURIComponent(VES.domain)
		+ '&chan=' + encodeURIComponent(self.chan);
	    if (optns) for (var k in optns) if (optns[k] != null) baseUrl += '&' + encodeURIComponent(k) + '=' + encodeURIComponent(optns[k]);
	    self.setOrigin(baseUrl);
	    // Drain any matching stale localStorage entry from a prior tab,
	    // then listen for late writes (storage event) as a fallback to BC
	    // for the subscribe-before-open race.
	    try {
		var lsKey = 'libVES.Delegate.' + self.chan;
		localStorage.removeItem(lsKey);
		self._storageHandler = function(ev) {
		    if (ev.key != lsKey || !ev.newValue) return;
		    try {
			var d = JSON.parse(ev.newValue);
			if (d && d.type == 'VESflow.delegate.relay') self.onBC({type: 'VESflow.delegate.relay', chan: self.chan, token: d.token});
		    } catch (_) {}
		};
		window.addEventListener('storage', self._storageHandler);
	    } catch (_) {}
	    // Create Flow instance and subscribe to BC BEFORE opening V so the
	    // hook's relay can't beat us to it.
	    self.flow = new libVES.Flow('VES');
	    if (libVES.Flow.bc) {
		libVES.Flow.bc();
		libVES.Flow.subscribe(self.onBC.bind(self));
	    }
	    // Plant our pub in the V URL fragment as a Flow intro token so V's
	    // recvToken stores it under O's origin; V can then Flow-encrypt
	    // the auth payload back to us on the no-opener path.
	    self.flow.privKey().catch(function() {}).then(function() {
		return self.flow.addToken(baseUrl).catch(function() { return baseUrl; });
	    }).then(function(url) {
		if (self._handled) return;
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
		if (!self.listening) {
		    window.addEventListener('message',self.listener.bind(self));
		    window.addEventListener('beforeunload',self.cancel.bind(self));
		    self.listening = true;
		}
		// popup.closed is intentionally NOT polled here. Cancellation
		// signals are explicit: a {cancelled: true} postMessage from
		// the popup's beforeunload handler, or the user clicking the
		// Cancel link in the overlay. If neither arrives the overlay
		// stays.
	    });
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
    acceptOrigin: function(org) {
	return org == this.matchOrigin;
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
	if (this.popup && this.acceptOrigin(evnt.origin)) try {
	    var msg = JSON.parse(evnt.data);
	    if (msg.redirect) {
		document.location.replace(msg.redirect);
		return;
	    }
	    if (msg.cancelled) {
		this.cancel();
		return;
	    }
	    this._handled = true;
	    this.resolve(this.VES.authorize(msg));
	    this.close();
	    if (!evnt.source.closed) evnt.source.close();
	} catch(e) {}
    },
    onBC: function(d) {
	if (!this.popup || this._handled) return;
	if (!d || d.type != 'VESflow.delegate.relay' || d.chan != this.chan || !d.token) return;
	this._handled = true;
	var self = this;
	this.flow.recvToken(d.token).then(function(msg) {
	    self.resolve(self.VES.authorize(msg));
	    self.close();
	}).catch(function(e) {
	    self.reject(e);
	    self.close();
	});
    },
    close: function() {
	if (this._storageHandler) {
	    try { window.removeEventListener('storage', this._storageHandler); } catch (e) {}
	    this._storageHandler = null;
	}
	if (this.popup) {
	    if (this.popupWindow) {
		try {
		    this.popupWindow.close();
		} catch (e) {}
		this.popupWindow = null;
	    }
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
    // Partner-hosted relay page entry point. The hook page at O's origin is
    // a ~3-line file that loads libVES and calls this. We parse the
    // encrypted Flow token from the URL fragment, BC-publish it (keyed by
    // the chan nonce from the query string) so the original O tab can
    // decrypt + authorize, mirror to localStorage as a belt-and-braces
    // fallback, and try to self-close.
    hook: function() {
	var qp = new URLSearchParams(location.search);
	var chan = qp.get('chan') || '';
	var tk = null;
	libVES.Flow.parseToken(location.hash, function(k, t) {
	    if (k != 'VES') return false;
	    tk = t;
	    return true;
	});
	if (!tk) return libVES.Delegate.hookMessage('Authorization payload missing.');
	var bc = libVES.Flow.bc();
	if (bc) try { bc.postMessage({type: 'VESflow.delegate.relay', chan: chan, token: tk}); } catch (e) {}
	try {
	    var lsKey = 'libVES.Delegate.' + chan;
	    localStorage.setItem(lsKey, JSON.stringify({type: 'VESflow.delegate.relay', token: tk, ts: Date.now()}));
	    setTimeout(function() { try { localStorage.removeItem(lsKey); } catch (e) {} }, 30000);
	} catch (e) {}
	try { window.close(); } catch (e) {}
	setTimeout(function() { libVES.Delegate.hookMessage('Authorization delivered. You can close this window.'); }, 300);
    },
    hookMessage: function(text) {
	try {
	    document.body.innerHTML = '<div style="font-family:arial,sans-serif;text-align:center;padding:48px 16px;color:#444;max-width:480px;margin:0 auto;">' + text + '</div>';
	} catch (e) {}
    }
};
