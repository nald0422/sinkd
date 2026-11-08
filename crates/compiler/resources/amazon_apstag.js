(function () {
    'use strict';
    var noop = function () {};
    var w = window;
    var queued = w.apstag && w.apstag._Q && w.apstag._Q.length ? Array.prototype.slice.call(w.apstag._Q) : [];
    var apstag = {
        _Q: [],
        init: noop,
        fetchBids: function (config, callback) {
            if (typeof callback === 'function') {
                setTimeout(function () { try { callback([]); } catch (e) {} }, 1);
            }
        },
        setDisplayBids: noop,
        targetingKeys: function () { return []; },
        renderImp: noop,
        dpa: noop,
        rpa: noop,
        upa: noop
    };
    w.apstag = apstag;
    for (var i = 0; i < queued.length; i++) {
        var entry = queued[i];
        if (entry && entry[0] === 'f') { apstag.fetchBids.apply(null, entry[1]); }
    }
})();
