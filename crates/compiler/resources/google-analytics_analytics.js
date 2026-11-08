(function () {
    'use strict';
    var noop = function () {};
    var w = window;
    var name = w.GoogleAnalyticsObject || 'ga';
    var queued = w[name] && w[name].q && w[name].q.length ? Array.prototype.slice.call(w[name].q) : [];
    var Tracker = function () {};
    Tracker.prototype.get = noop;
    Tracker.prototype.set = noop;
    Tracker.prototype.send = function () { ga.apply(null, ['send'].concat(Array.prototype.slice.call(arguments))); };
    var tracker = new Tracker();
    var later = function (fn) {
        setTimeout(function () { try { fn(); } catch (e) {} }, 1);
    };
    var ga = function () {
        var n = arguments.length;
        if (n === 0) { return; }
        if (typeof arguments[0] === 'function') {
            try { arguments[0](tracker); } catch (e) {}
            return;
        }
        var last = arguments[n - 1];
        if (last && typeof last === 'object' && typeof last.hitCallback === 'function') {
            later(last.hitCallback);
        }
    };
    ga.create = function () { return tracker; };
    ga.getByName = function () { return tracker; };
    ga.getAll = function () { return [tracker]; };
    ga.remove = noop;
    ga.loaded = true;
    ga.l = Date.now();
    w[name] = ga;
    var dl = w.dataLayer;
    if (dl && dl.hide && typeof dl.hide.end === 'function') {
        dl.hide.end();
        dl.hide.end = noop;
    }
    for (var i = 0; i < queued.length; i++) { ga.apply(null, queued[i]); }
})();
