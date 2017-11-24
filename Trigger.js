/**
 * @title Trigger
 *
 * Dependency Driven Interface, compatible with Promise
 *
 * @version 0.5 alpha
 * @author Jim Zubov <jz@vesvault.com> (VESvault)
 * GPL license, http://www.gnu.org/licenses/
 */
Trigger = function(evalfn) {
    this.id = Trigger.nextId++;
//    console.log('id = '+ this.id);
    Trigger._all[this.id] = this;
    this._deps = {};
    this._follow = [];
    if (typeof(evalfn) == 'function') window.setTimeout((function() {
	evalfn(this.resolve.bind(this),this.reject.bind(this));
    }).bind(this),0);
    this.nextIdx = 0;
};
Trigger._all = [];

Trigger.all = function(list) {
    var rs = Trigger.resolve([]);
    for (var i = 0; i < list.length; i++) rs = (function(val) {
	return rs.then(function(r) {
	    return Trigger.resolve(val).then(function(v) {
		r.push(v);
		return r;
	    });
	});
    })(list[i]);
    return rs;
	
    return new Trigger(function(resolve,reject) {
	var rslvd = [];
	var rslvc = 0;
	var vals = [];
	var rslv = function(v,i) {
	    if (!rslvd[i]) {
		rslvc++;
		rslvd[i] = true;
		vals[i] = v;
		if (rslvc >= list.length) resolve(vals);
	    }
	};
	var rjct = function(v,i) {
	    if (rslvd[i]) {
		rslvc--;
		rslvd[i] = false;
	    }
	    reject(v);
	};
	list.map(function(e,i) {
	    if (e instanceof Trigger) e.then(function(v) {
		rslv(v,i);
	    }).catch(function(v) {
		rjct(v,i);
	    });
	    else rslv(e,i);
	});
    });
};
Trigger.resolve = function(value) {
    return new Trigger(function(resolve,reject) {
	resolve(value);
    });
};
Trigger.reject = function(value) {
    return new Trigger(function(resolve,reject) {
	reject(value);
    });
};
Trigger.nextId = 1;

Trigger.prototype = {
    value: undefined,
    status: 'pending',
    _set: function(value,status,depth) {
	if (depth != null) {
	    for (var i = depth; i < this._follow.length; i++) this._follow[i].then(null,'#' + this.id);
	    this._follow.length = depth;
	    if (value instanceof Trigger) {
		var self = this;
		this._follow.push(value);
		return value.then(function(val) {
		    self._set(val,'resolved',depth + 1);
		    return val;
		},'#' + self.id).catch(function(err) {
		    self.reject(err);
		    throw err;
		},'#' + self.id);
	    }
	}
	if (this.status != status || this.value !== value) {
	    this.status = status;
	    this.value = value;
	    window.clearTimeout(this._tmout);
	    this._tmout = window.setTimeout((function() {
		for (var i in this._deps) this._deps[i](value,status == 'rejected');
	    }).bind(this),0);
	}
	return this;
    },
    resolve: function(value) {
	return this._set(value,'resolved',0);
    },
    reject: function(value) {
	return this._set(value,'rejected');
    },
    _register: function(callbk,label,rj) {
	if (typeof(callbk) != 'function') {
	    if (label != null) delete(this._deps[label]);
	    return this;
	}
	if (label == null) label = '__' + this.nextIdx++;
	var t = new Trigger();
	var fn = this._deps[label] = function(val,error) {
	    try {
		if (rj) {
		    if (error) val = callbk(val);
		} else {
		    if (error) throw val;
		    val = callbk(val);
		}
		t.resolve(val);
	    } catch (e) {
		t.reject(e);
	    }
	};
	switch (this.status) {
	    case 'resolved':
		fn(this.value);
		break;
	    case 'rejected':
		fn(this.value,true);
		break;
	}
	return t;
    },
    then: function(callbk,label) {
	return this._register(callbk,label);
    },
    catch: function(callbk,label) {
	return this._register(callbk,label,true);
    }
};
