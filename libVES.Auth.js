/***************************************************************************
 *          ___       ___
 *         /   \     /   \    VESvault
 *         \__ /     \ __/    Encrypt Everything without fear of losing the Key
 *            \\     //                   https://vesvault.com https://ves.host
 *             \\   //
 *     ___      \\_//
 *    /   \     /   \         VESauth:         HTTP X-VES Authentication client
 *    \__ /     \ __/
 *       \\     //
 *        \\   //
 *         \\_//
 *         /   \
 *         \___/
 *
 *
 * (c) 2021 VESvault Corp
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
 * @title libVES
 * @dev Send X-VES-Authorization: header to the external HTTPS server as a
 * @dev proof of ownership of a particulat vaultItem
 * @version 0.1a
 *
 * @author Jim Zubov <jz@vesvault.com> (VESvault Corp)
 *
 ***************************************************************************/

libVES.Auth = function(optns) {
    for (var k in optns) this[k] = optns[k];
    return this;
};

libVES.Auth.prototype.getToken = function() {
    if (this.vaultItem) return Promise.all([this.vaultItem.getId(), this.vaultItem.getField('verifyToken')]).then(function(flds) {
	return 'vaultItem.' + flds[0] + '.' + flds[1];
    });
    else if (this.vaultKey) return Promise.all([this.vaultKey.getId(), this.vaultItem.getSessionToken()]).then(function(flds) {
	return 'vaultKey.' + flds[0] + '.' + flds[1];
    });
    else if ((VES = this.VES) && VES.token) return this.VES.getVaultKey().then(function(vkey) {
	return vkey.getId().then(function(id) {
	    return 'vaultKey.' + id + '.' + VES.token;
	});
    });
    return Promise.reject({code: 'VESauth', message: 'No object to generate a VESauth token for'});
};

libVES.Auth.prototype.getData = function(url, type) {
    return this.getToken().then(function(tkn) {
	return new Promise(function(resolve, reject) {
	    var xhr = new XMLHttpRequest();
	    xhr.open('GET', url);
	    if (type) xhr.responseType = type;
	    xhr.onreadystatechange = function() {
		switch(xhr.readyState) {
		    case 4:
			if (xhr.status == 200) resolve(xhr.response);
			else reject({code: xhr.status, message: xhr.statusText});
		}
	    };
	    xhr.setRequestHeader('X-VES-Authorization', tkn);
	    xhr.send();
	});
    });
};

libVES.Auth.prototype.getJSON = function(url) {
    return this.getData(url, 'json').then(function(json) {
	var a = document.createElement('a');
	a.href = url;
	if (!a.hash) return json;
	var path = a.hash.split(/\//);
	for (var i = 1; i < path.length; i++) if (path[i]) {
	    if (json instanceof Array) json = json[Number(path[i])];
	    else if (json instanceof Object) json = json[path[i]];
	    else return null;
	}
	return json;
    });
};

libVES.Auth.prototype.auth = function(token) {
    return this.verify(token, true);
};

libVES.Auth.prototype.verify = function(token, auth) {
    var tk = token.match(/^(\w*)\.(\d*)\.(.*)$/);
    if (!tk) return Promise.reject(new libVES.Error('VESauth', 'Invalid VESauth token'));
    var ves = new libVES({domain: (this.domain || '*'), token: tk[3]});
    if (tk[1] == 'vaultItem') {
	if (auth) return Promise.reject(new libVES.Error('VESauth', 'Verify token cannot be used for authentication'));
	return Promise.resolve(this.vaultItem ? this.vaultItem.getId() : tk[2]).then(function(id) {
	    var vi = new libVES.VaultItem({id: id}, ves);
	    return vi.getFile().then(function(file) {
		return vi.getField('deleted').then(function(f) {
		    if (f) throw new libVES.Error('VESauth', 'Verify token expired');
		    return file.getCreator();
		});
	    });
	});
    }
    if (tk[1] != 'vaultKey') return Promise.reject(new libVES.Error('VESauth', 'Unknown token type'));
    if (this.vaultItem) return this.vaultItem.getId().then(function(id) {
	var vi = new libVES.VaultItem({id: id}, ves);
	return vi.getVaultEntries().then(function(vents) {
	    if (!auth && vents && vents.length) return ves.me();
	    if (vents && tk[2]) for (var i = 0; i < vents.length; i++) if (vents[i].vaultKey && Number(vents[i].vaultKey.id) == Number(tk[2])) return ves.me();
	    throw new libVES.Error('VESauth', 'ACL not authorized');
	});
    });
    if (!auth) return ves.me();
    return Promise.resolve(this.vaultKey ? this.vaultKey.getId() : tk[2]).then(function(id) {
	return (new libVES.VaultKey({id: id}, ves)).getExternals().then(function(ext) {
	    if (!ext || !ext[0]) throw new libVES.Error('VESauth', 'Bad vaultKey for VESauth');
	    return ext[0].getDomain().then(function(dom) {
		return ext[0].getExternalId().then(function(extid) {
		    if (!extid || !extid.match(/^[^\!\@]+\@[^\!\@]+$/)) throw new libVES.Error('VESauth', 'Bad vaultKey for VESauth');
		    if (dom && dom.toLowerCase() == ves.domain.toLowerCase()) return ves.me();
		    throw new libVES.Error('VESuath', 'VES domain does not match');
		});
	    });
	});
    });
};
