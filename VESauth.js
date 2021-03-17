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

function VESauth(optns) {
    for (var k in optns) this[k]=optns[k];
    return this;
};

VESauth.prototype.getAuth = function() {
    if (this.vaultItem) return Promise.all([this.vaultItem.getId(), this.vaultItem.getField('verifyToken')]).then(function(flds) {
	return 'vaultItem.' + flds[0] + '.' + flds[1];
    });
    return Promise.reject({code: 'VESauth', message: 'vaultItem required'});
};

VESauth.prototype.getData = function(url, type) {
    return this.getAuth().then(function(tkn) {
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

VESauth.prototype.getJSON = function(url) {
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
