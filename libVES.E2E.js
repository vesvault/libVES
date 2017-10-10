libVES.E2E = function(optns) {
    for (var k in optns) this[k] = optns[k];
};

libVES.E2E.prototype = new libVES.Object({
    postData: function() {
	var self = this;
	var rs = {engine: this.engineTag};
	return this.getRecipients().then(function(rcpts) {
	    var rdata = [];
	    for (var i = 0; i < rcpts.length; i++) rdata.push(rcpts[i].postData());
	    return Promise.all(rdata).then(function(rd) {
		rs.recipients = rd;
		return self.getCtext().then(function(ctxt) {
		    rs.encData = libVES.Util.ByteArrayToB64(ctxt);
		    return self.getExtra().then(function(ex) {
			if (ex) for (var k in ex) rs[k] = ex[k];
			return rs;
		    });
		});
	    });
	});
    },
    resolveError: function(e) {
	throw new libVES.Error('BadRequest',"libVES.E2E.resolveError");
    },
    getCtext: function() {
	return this.engine.getCtext.call(this);
    },
    getExtra: function() {
	if (!this.engine.getExtra) return Promise.resolve();
	return this.engine.getExtra.call(this);
    },
});

