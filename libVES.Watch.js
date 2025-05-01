/***************************************************************************
 *          ___       ___
 *         /   \     /   \    VESvault
 *         \__ /     \ __/    Encrypt Everything without fear of losing the Key
 *            \\     //                   https://vesvault.com https://ves.host
 *             \\   //
 *     ___      \\_//
 *    /   \     /   \         libVES.Watch: Event Observer
 *    \__ /     \ __/
 *       \\     //
 *        \\   //
 *         \\_//
 *         /   \
 *         \___/
 *
 *
 * (c) 2023 VESvault Corp
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
 * @author Jim Zubov <jz@vesvault.com> (VESvault Corp)
 *
 ***************************************************************************/


libVES.Watch = function(obj, optns) {
    if (obj instanceof libVES) obj = obj.domain ? (obj.externalId ? obj.getVaultKey() : new libVES.Domain(null, obj)) : obj.me();
    var self = this;
    this.object = Promise.resolve(obj).then(function(o) {
	if (o instanceof libVES.VaultKey) {
	    self.uri = 'vaultKeys/';
	} else if (o instanceof libVES.VaultItem) {
	    self.uri = 'vaultItems/';
	} else if (o instanceof libVES.User) {
	    self.uri = 'users/';
	} else if (o instanceof libVES.Domain) {
	    self.uri = 'domains/';
	} else {
	    throw new libVES.Error('Internal', 'Watchable object expected');
	}
	self.VES = o.VES;
	return o;
    });
    if (optns) for (var k in optns) this[k] = optns[k];
};

libVES.Watch.prototype = {
    fields: {vaultKey: {id: true, user: true, externals: true, creator: true}, vaultItem: {id: true, vaultKey: true, file: {externals: true, creator: true}}, session: {id: true, userAgent: true, remote: true, createdAt: true, expiresAt: true}},
    state: 'idle',
    timeout: 900,
    getEvents: function(start, ct, poll) {
	var self = this;
	return self.object.then(function(o) {
	    return o.getId().then(function(id) {
		return (poll ? self.VES.pollUrl : '') + self.uri + id
		    + '?fields=events(' + self.VES.uriListFields(self.fields) + ')%5B' + start + (ct >= 0 ? '%2B' : '') + ct + '%5D'
		    + (poll ? '&poll=' + self.timeout : '');
	    });
	}).then(function(url) {
	    return self.VES.get(url);
	}).then(function(res) {
	    if (!res.events) return null;
	    return res.events.map(function(e, i) {
		return new libVES.Event(libVES.Util.fillUndefs(e, self.fields), self.VES);
	    });
	});
    },
    setState: function(st) {
	if (this.statefn) try {
	    this.statefn(st, this);
	} catch(e) {}
	this.state = st;
    },
    setBusy: function(busy) {
	this.busy = busy;
	if (!busy && this.state == 'stop') this.setState('idle');
    },
    start: function(pos) {
	if (!this.eventfn) return Promise.reject(new libVES.Error('InvalidValue', 'eventfn is not set'));
	if (this.busy) return Promise.reject(new libVES.Error('Internal', 'Watch instance is busy'));
	var self = this;
	self.setBusy(true);
	this.setState('read');
	if (pos < 0) {
	    this.next = 0;
	    return this.getEvents(0, pos).then(function(evs) {
		self.setBusy(false);
		return self.received(evs ? evs.reverse() : null);
	    }).finally(function() {
		self.setBusy(false);
            });
	} else {
	    this.next = pos;
	    return this.getEvents(pos, 0).then(function(evs) {
		self.setBusy(false);
		return self.received(evs);
	    }).finally(function() {
		self.setBusy(false);
	    });
	}
    },
    active: function() {
	return this.state == 'read' || this.state == 'poll';
    },
    received: function(evs) {
	var self = this;
	var p;
        if (!evs) return null;
	if (evs.length) return evs.reduce(function(v, ev) {
	    if (self.active()) try {
		self.eventfn(ev, self);
	    } catch(e) {
		console.log(e);
	    }
	    return ev;
	}, null).getId().then(function(id) {
	    self.next = id + 1;
            return self.request();
	});
	else {
	    if (this.state == 'read') this.setState('poll');
	    return self.request(), true;
	}
    },
    request: function() {
	if (this.busy || !this.active()) return true;
	var self = this;
	self.setBusy(true);
	return self.getEvents(self.next, 0, (self.state == 'poll')).then(function(evs) {
	    self.setBusy(false);
	    return self.received(evs);
	}).catch(function(e) {
	    self.setBusy(false);
	    if (self.errorfn) try {
		self.errorfn(e, self);
	    } catch(e) {
		console.log(e);
	    }
	    return self.retry();
	});
    },
    retry: function() {
	var self = this;
	return new Promise(function(resolve, reject) {
	    window.setTimeout(function() {
		resolve(self.request());
	    }, 1000);
	});
    },
    stop: function() {
	this.setState(this.busy ? 'stop' : 'idle');
    }
};
