/***************************************************************************
 *          ___       ___
 *         /   \     /   \    VESvault
 *         \__ /     \ __/    Encrypt Everything without fear of losing the Key
 *            \\     //                   https://vesvault.com https://ves.host
 *             \\   //
 *     ___      \\_//
 *    /   \     /   \         libVES.Flow: Cross-origin private context manager
 *    \__ /     \ __/
 *       \\     //
 *        \\   //
 *         \\_//
 *         /   \
 *         \___/
 *
 *
 * (c) 2022 VESvault Corp
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
 * @title libVES.Flow
 * @ Securely maintain private session data across multiple https origins
 * @version 0.1a
 *
 * @author Jim Zubov <jz@vesvault.com> (VESvault Corp)
 *
 ***************************************************************************/

libVES.Flow = function(name, optns) {
    this.name = name;
    this.origin = document.location.origin;
    this.url = this.origin + '/VESflow';
    if (optns) for (var k in optns) this[k] = optns[k];
    return this;
};

libVES.Flow.algo = {name: 'ECDH', namedCurve: 'P-256'};

libVES.Flow.keyAlgo = function(jwk) {
    if (jwk && jwk.kty == 'EC') return {name: 'ECDH', namedCurve: jwk.crv};
    return null;
};

libVES.Flow.toOrigin = function(url) {
    var a = document.createElement('a');
    a.href = url;
    return a.origin;
};

libVES.Flow.jwkPub = function(jwk) {
    delete(jwk.d);
    delete(jwk.key_ops);
    delete(jwk.ext);
    return jwk;
};

libVES.Flow.parseToken = function(src, callbk) {
    src = src.replace(/\#VESflow\.(\w+)=([^\#\&\=]+)/g, function(s, k, v) {
	var tk;
	try {
	    tk = JSON.parse(decodeURIComponent(v));
	    if (callbk(decodeURIComponent(k), tk)) return '';
	} catch(e) {
	    console.log(e);
	}
	return s;
    });
    return src;
};

libVES.Flow.logout = function() {
    for (var k in sessionStorage) if (k.match(/^VESflow\b/)) delete(sessionStorage[k]);
};

// Cross-tab handoff channel. Same-origin tabs use this to:
//   - share the ECDH privKey from sessionStorage when a sibling tab needs it
//     (e.g. after an App Link bounce lands in a fresh tab without sessionStorage)
//   - notify peers when auth completes so they can self-close
// Set to null to disable BC entirely; consumers can override before any Flow
// instance is constructed.
libVES.Flow.bcName = 'ves-flow-handoff';
libVES.Flow.bcPrivKeyTimeoutMs = 250;

libVES.Flow._bc = undefined;
libVES.Flow._handlers = [];

libVES.Flow.bc = function() {
    if (libVES.Flow._bc !== undefined) return libVES.Flow._bc;
    if (!libVES.Flow.bcName || typeof BroadcastChannel === 'undefined') return libVES.Flow._bc = null;
    var bc = new BroadcastChannel(libVES.Flow.bcName);
    bc.addEventListener('message', function(ev) {
	var d = ev.data || {};
	if (d.type == 'VESflow.privKey.req') {
	    var jwk = sessionStorage['VESflow' + d.algo];
	    if (jwk) bc.postMessage({type: 'VESflow.privKey.rep', algo: d.algo, jwk: jwk, reqId: d.reqId});
	    return;
	}
	for (var i = 0; i < libVES.Flow._handlers.length; i++) {
	    try { libVES.Flow._handlers[i](d, ev); } catch (e) { console.log(e); }
	}
    });
    return libVES.Flow._bc = bc;
};

libVES.Flow.subscribe = function(fn) {
    libVES.Flow._handlers.push(fn);
    return fn;
};

libVES.Flow.unsubscribe = function(fn) {
    var i = libVES.Flow._handlers.indexOf(fn);
    if (i >= 0) libVES.Flow._handlers.splice(i, 1);
};

libVES.Flow.requestPrivKeyJWK = function(algoStr, timeoutMs) {
    var bc = libVES.Flow.bc();
    if (!bc) return Promise.reject(null);
    return new Promise(function(resolve, reject) {
	var reqId = Math.random().toString(36).slice(2);
	var h = function(d) {
	    if (d.type != 'VESflow.privKey.rep' || d.reqId != reqId) return;
	    clearTimeout(t);
	    libVES.Flow.unsubscribe(h);
	    resolve(typeof d.jwk == 'string' ? JSON.parse(d.jwk) : d.jwk);
	};
	var t = setTimeout(function() {
	    libVES.Flow.unsubscribe(h);
	    reject(null);
	}, timeoutMs || libVES.Flow.bcPrivKeyTimeoutMs);
	libVES.Flow.subscribe(h);
	bc.postMessage({type: 'VESflow.privKey.req', algo: algoStr, reqId: reqId});
    });
};

libVES.Flow.prototype.source = function(src) {
    if (src != null) history.replaceState(null, '', src);
    return document.location.href;
};

libVES.Flow.prototype.privKey = function(algo) {
    if (!algo) algo = libVES.Flow.algo;
    var a = JSON.stringify(algo);
    var k = sessionStorage['VESflow' + a];
    var src = k ? Promise.resolve(JSON.parse(k))
	: libVES.Flow.requestPrivKeyJWK(a).then(function(jwk) {
	    if (jwk) sessionStorage['VESflow' + a] = JSON.stringify(jwk);
	    return jwk;
	}, function() { return null; });
    return src.then(function(jwk) {
	if (jwk) return crypto.subtle.importKey('jwk', jwk, algo, true, ['deriveBits', 'deriveKey']);
	return crypto.subtle.generateKey(algo, true, ['deriveBits', 'deriveKey']).then(function(pair) {
	    return crypto.subtle.exportKey('jwk', pair.privateKey).then(function(jwk) {
		sessionStorage['VESflow' + a] = JSON.stringify(jwk);
		return pair.privateKey;
	    });
	});
    });
};

libVES.Flow.prototype.pubJWK = function(org) {
    return ((!org || org == this.origin) ? this.privKey().then(function(priv) {
	return crypto.subtle.exportKey('jwk', priv).then(function(jwk) {
	    return libVES.Flow.jwkPub(jwk);
	});
    }) : Promise.resolve(sessionStorage['VESflow|' + org]).then(function(k) {
	if (!k) throw new libVES.Error('NotFound', 'No public key stored for ' + org);
	return JSON.parse(k);
    }));
};

libVES.Flow.prototype.pubKey = function(org) {
    return this.pubJWK(org).then(function(jwk) {
	return crypto.subtle.importKey('jwk', jwk, libVES.Flow.keyAlgo(jwk), true, []);
    });
};

libVES.Flow.prototype.cipher = function(url) {
    var self = this;
    return self.pubKey(libVES.Flow.toOrigin(url)).then(function(pub) {
	return self.privKey(pub.algorithm).then(function(priv) {
	    return crypto.subtle.deriveBits({name: 'ECDH', public: pub}, priv, 8 * libVES.Algo.ECDH.curveBytes[pub.algorithm.namedCurve]);
	});
    }).then(function(raw) {
	return crypto.subtle.digest({name: 'SHA-256'}, raw).then(function(buf) {
	    return crypto.subtle.importKey('raw', buf, 'AES-GCM', false, ['encrypt', 'decrypt']);
	});
    });
};

libVES.Flow.prototype.encrypt = function(url, val) {
    var self = this;
    return Promise.resolve(val || this.value()).then(function(val) {
	if (val == null) throw new libVES.Error('NoData', 'Empty value');
	return self.cipher(url).then(function(ci) {
	    var iv = new Uint8Array(12);
	    crypto.getRandomValues(iv);
	    return crypto.subtle.encrypt({name: 'AES-GCM', iv: iv.buffer}, ci, libVES.Util.StringToByteArray(JSON.stringify(val))).then(function(ctext) {
		return libVES.Util.ByteArrayToB64W(iv) + '.' + libVES.Util.ByteArrayToB64W(ctext);
	    });
	});
    });
};

libVES.Flow.prototype.token = function(url) {
    var self = this;
    return this.pubJWK().then(function(jwk) {
	return {url: self.url, key: jwk};
    }).then(function(tk) {
	return self.encrypt(url).then(function(ctext) {
	    tk.enc = ctext;
	    self.erase(url);
	    self.sent = true;
	    return tk;
	}).catch(function(e) {
	    self.store(url).catch(function(e) {});
	    return tk;
	});
    });
};

libVES.Flow.prototype.addToken = function(url) {
    var self = this;
    return self.token(url).then(function(tk) {
	return url + '#VESflow.' + self.name + '=' + encodeURIComponent(JSON.stringify(tk));
    });
};

libVES.Flow.prototype.decrypt = function(ctext, url) {
    var self = this;
    var c = ctext.split('.');
    return self.cipher(url).then(function(ci) {
	return crypto.subtle.decrypt({name: 'AES-GCM', iv: libVES.Util.B64ToByteArray(c[0])}, ci, libVES.Util.B64ToByteArray(c[1])).then(function(ptext) {
	    return JSON.parse(libVES.Util.ByteArrayToString(ptext));
	});
    });
};

libVES.Flow.prototype.value = function() {
    var self = this;
    return Promise.resolve(history.state && history.state['VESflow.' + self.name]).then(function(ctext) {
	return self.decrypt(ctext);
    });
};

libVES.Flow.prototype.setValue = function(val) {
    var self = this;
    return Promise.resolve(val? self.encrypt(null, val) : null).then(function(ctext) {
	var s = {};
	if (history.state) for (var k in history.state) s[k] = history.state[k];
	if (ctext) s['VESflow.' + self.name] = ctext;
	else delete(s['VESflow.' + self.name]);
	history.replaceState(s, '');
	return val;
    });
};

libVES.Flow.prototype.click = function(a) {
    var self = this;
    (a.origin == this.origin ? self.store() : self.addToken(a.href).then(function(url) {
	a.href = url;
    })).catch(function(e) {
	if (!e || e.code != 'NotFound') throw e;
    }).then(function() {
	document.location.href = a.href;
    }).catch(function(e) {
	console.log(e);
    });
    return false;
};

libVES.Flow.prototype.reload = function(e) {
    if (!this.sent) this.store().catch(function(e) {});
};

libVES.Flow.prototype.recv = function(dval) {
    var self = this;
    return Promise.resolve(self.source()).then(function(src) {
	var tk = null;
	src = libVES.Flow.parseToken(src, function(k, t) {
	    if (k != self.name) return false;
	    tk = t;
	    return true;
	});
	if (tk == null) throw new libVES.Error('NotFound', 'No valid token in the source url');
	return Promise.resolve(self.source(src)).then(function() {
	    if (dval) for (var k in dval) if (tk[k] === undefined) tk[k] = dval[k];
	    return self.recvToken(tk);
	});
    });
};

libVES.Flow.prototype.recvToken = function(tk) {
    var org = libVES.Flow.toOrigin(tk.url);
    if (org != this.origin && tk.key) sessionStorage['VESflow|' + org] = JSON.stringify(tk.key);
    if (!tk.enc) return Promise.reject(new libVES.Error('Incomplete', 'Missing encrypted data', {url: tk.url}));
    return this.decrypt(tk.enc, org);
};

libVES.Flow.prototype.get = function() {
    var self = this;
    return self.fetch().catch(function(e) {
	if (!e || e.code != 'NotFound') console.log(e);
	return null;
    }).then(function(data) {
	return self.recv().catch(function(e) {
	    if (e && e.code == 'Incomplete') {
		self.url = document.location.href;
		return self.addToken(e.url).then(function(url) {
		    document.location.replace(url);
		    throw new libVES.Error('Redirect', 'Completing the key exchange');
		});
	    }
	    if (!data) throw e;
	    return data;
	});
    });
};

libVES.Flow.prototype.store = function(url) {
    if (history.state && history.state['VESflow.' + this.name]) {
	this.sent = 1;
	return Promise.resolve(sessionStorage['VESflow.' + this.name + '>' + libVES.Flow.toOrigin(url)] = history.state['VESflow.' + this.name]);
    }
    return Promise.reject(new libVES.Error('NotFound', 'Value is not set'));
};

libVES.Flow.prototype.fetch = function(url) {
    var self = this;
    return Promise.resolve(sessionStorage['VESflow.' + self.name + '>' + libVES.Flow.toOrigin(url)]).then(function(ctext) {
	if (!ctext) throw new libVES.Error('NotFound', 'Not in the session storage');
	return self.decrypt(ctext).then(function(data) {
	    self.erase(url);
	    return data;
	});
    });
};

libVES.Flow.prototype.erase = function(url) {
    delete(sessionStorage['VESflow.' + this.name + '>' + libVES.Flow.toOrigin(url)]);
};

libVES.Flow.prototype.logout = function() {
    this.setValue(undefined);
    return libVES.Flow.logout();
};


// libVES.Flow.Handoff
//
// Choreographs a cross-tab unlock handoff for flows that bounce through a
// native app or another origin. Responsibilities:
//   - Render an "authorization in progress" overlay while waiting.
//   - Listen on the Flow BroadcastChannel for an auth payload posted by a
//     sibling tab that completed unlock, and self-close when that happens.
//   - Treat the tab becoming visible again without an auth landing within a
//     short grace window as a user cancellation.
//
// Construction options (all optional):
//   bcName:        BroadcastChannel name; defaults to libVES.Flow.bcName.
//   tabId:         identifier broadcast with auth/ack messages; auto-generated.
//   cancelGraceMs: ms to wait after the tab becomes visible before declaring
//                  a cancellation; default 1500. Pass 0 to disable.
//   overlay:       true (default) renders the built-in overlay; pass false to
//                  suppress it and render your own from the callbacks.
//   onAuth:        function(auth, source) - local unlock succeeded.
//   onSibling:     function(payload) - a sibling tab completed unlock.
//   onCancel:      function() - cancellation detected.
//   diag:          function(label, val) - optional diagnostic sink.

libVES.Flow.Handoff = function(opts) {
    opts = opts || {};
    this.bcName = opts.bcName || libVES.Flow.bcName;
    this.tabId = opts.tabId || Math.random().toString(36).slice(2, 10);
    this.cancelGraceMs = opts.cancelGraceMs != null ? opts.cancelGraceMs : 1500;
    this.overlay = opts.overlay !== false;
    this.onAuth = opts.onAuth || null;
    this.onSibling = opts.onSibling || null;
    this.onCancel = opts.onCancel || null;
    this.diag = opts.diag || function() {};
    this._handled = false;
    this._waiting = false;
};

libVES.Flow.Handoff.overlayId = 'ves-flow-handoff-overlay';

libVES.Flow.Handoff.prototype.start = function() {
    var self = this;
    libVES.Flow.bc();
    // Reset for a fresh cycle: a long-lived Handoff is re-armed every time
    // the user kicks off a new unlock attempt.
    if (self._bcHandler) libVES.Flow.unsubscribe(self._bcHandler);
    if (self._visHandler) document.removeEventListener('visibilitychange', self._visHandler);
    self._handled = false;
    self._waiting = true;
    self.showOverlay('in-progress');
    self._bcHandler = libVES.Flow.subscribe(function(d) {
	if (d.type != 'VESflow.auth' || self._handled || d.from == self.tabId) return;
	self._handled = true;
	self._waiting = false;
	self.diag('BC recv', 'auth from ' + d.from);
	if (libVES.Flow._bc) libVES.Flow._bc.postMessage({type: 'VESflow.ack', tabId: self.tabId});
	try { window.close(); } catch (e) { self.diag('self-close threw', String(e)); }
	setTimeout(function() {
	    self.showOverlay('completed');
	    if (self.onSibling) self.onSibling(d.payload);
	}, 200);
    });
    self._visHandler = function() {
	if (document.hidden || !self._waiting || self._handled) return;
	self.diag('tab visible while flow in progress', 'grace ' + self.cancelGraceMs + 'ms');
	if (!self.cancelGraceMs) return;
	setTimeout(function() {
	    if (!self._waiting || self._handled) return;
	    self.diag('cancellation assumed', 'no auth within grace period');
	    self.cancel();
	}, self.cancelGraceMs);
    };
    document.addEventListener('visibilitychange', self._visHandler);
    return self;
};

// Mark a locally completed auth and notify peers.
libVES.Flow.Handoff.prototype.deliver = function(auth) {
    if (this._handled) return;
    this._handled = true;
    this._waiting = false;
    if (libVES.Flow._bc) libVES.Flow._bc.postMessage({type: 'VESflow.auth', payload: auth, from: this.tabId});
    this.hideOverlay();
    if (this.onAuth) this.onAuth(auth, 'local');
    // Listen briefly for a closeReceiver ack from a sibling consumer
    // (e.g. libVES.Delegate) asking this tab to self-close because the
    // opener is the canonical context to keep. Flow mode's ack omits the
    // closeReceiver flag so this no-ops there; the Flow opener self-closes
    // instead.
    var self = this;
    var ackFn = libVES.Flow.subscribe(function(d) {
	if (!d || d.type != 'VESflow.ack' || !d.closeReceiver) return;
	if (d.target && d.target != self.tabId) return;
	libVES.Flow.unsubscribe(ackFn);
	try { window.close(); } catch (e) {}
	setTimeout(function() { self.showOverlay('completed'); }, 200);
    });
    setTimeout(function() { libVES.Flow.unsubscribe(ackFn); }, 1500);
};

// Mark a local unlock done without broadcasting (e.g. delegate path, or a
// flow path where the auth payload isn't available).
libVES.Flow.Handoff.prototype.complete = function() {
    this._handled = true;
    this._waiting = false;
    this.hideOverlay();
};

libVES.Flow.Handoff.prototype.cancel = function() {
    if (this._handled) return;
    this._waiting = false;
    this.showOverlay('cancelled');
    if (this.onCancel) this.onCancel();
};

libVES.Flow.Handoff.prototype.dispose = function() {
    this._waiting = false;
    if (this._bcHandler) {
	libVES.Flow.unsubscribe(this._bcHandler);
	this._bcHandler = null;
    }
    if (this._visHandler) {
	document.removeEventListener('visibilitychange', this._visHandler);
	this._visHandler = null;
    }
    this.hideOverlay();
};

libVES.Flow.Handoff.prototype.hideOverlay = function() {
    var ov = document.getElementById(libVES.Flow.Handoff.overlayId);
    if (ov) ov.remove();
};

libVES.Flow.Handoff.prototype.showOverlay = function(state) {
    if (!this.overlay) return;
    this.hideOverlay();
    var self = this;
    var ov = document.createElement('div');
    ov.id = libVES.Flow.Handoff.overlayId;
    ov.dataset.state = state;
    ov.style.cssText = 'position:fixed;inset:0;background:rgba(20,20,28,0.78);display:flex;align-items:center;justify-content:center;z-index:200000;font-family:arial,sans-serif;';
    var box = '<div style="background:#fff;padding:32px 36px;border-radius:10px;max-width:420px;text-align:center;box-shadow:0 12px 40px rgba(0,0,0,0.35);">';
    if (state == 'in-progress') {
	ov.innerHTML = box
	    + '<div style="width:46px;height:46px;border:4px solid #e0e8f5;border-top-color:#66a0fd;border-radius:50%;margin:0 auto 20px;animation:vesFlowSpin 1s linear infinite;"></div>'
	    + '<h2 style="margin:0 0 12px;color:#66a0fd;font-weight:300;">VES authorization in progress</h2>'
	    + '<p style="margin:8px 0;color:#333;">Complete sign-in in the VES app.</p>'
	    + '<a href="#" data-handoff-action="cancel" style="display:inline-block;margin-top:12px;color:#888;font-size:13px;">Cancel</a>'
	    + '</div><style>@keyframes vesFlowSpin{to{transform:rotate(360deg);}}</style>';
    } else if (state == 'cancelled') {
	ov.innerHTML = box
	    + '<h2 style="margin:0 0 12px;color:#a04444;font-weight:300;">Authorization not completed</h2>'
	    + '<p style="margin:8px 0;color:#333;">The VES app was closed before authorization could complete.</p>'
	    + '<button data-handoff-action="dismiss" style="margin-top:16px;padding:8px 20px;font-size:14px;border:1px solid #ccc;background:#fff;border-radius:4px;cursor:pointer;">Dismiss</button>'
	    + '</div>';
    } else if (state == 'completed') {
	ov.innerHTML = box
	    + '<h2 style="margin:0 0 12px;color:#66a0fd;font-weight:300;">VES authorization complete</h2>'
	    + '<p style="margin:8px 0;color:#333;">Authorization was completed in another window.</p>'
	    + '<p style="margin:8px 0;color:#888;font-size:13px;">You can close this tab.</p>'
	    + '</div>';
    }
    ov.addEventListener('click', function(ev) {
	var a = ev.target && ev.target.getAttribute && ev.target.getAttribute('data-handoff-action');
	if (!a) return;
	ev.preventDefault();
	if (a == 'cancel') { self._waiting = false; self.hideOverlay(); }
	else if (a == 'dismiss') self.hideOverlay();
    });
    document.body.appendChild(ov);
};
