(function () {
    'use strict';
    var noop = function () {};
    var w = window;
    var dl = w.dataLayer = w.dataLayer || [];
    var later = function (fn) {
        setTimeout(function () { try { fn(); } catch (e) {} }, 1);
    };
    var handle = function (item) {
        if (!item || typeof item !== 'object') { return; }
        if (typeof item.eventCallback === 'function') { later(item.eventCallback); }
        if (item[0] === 'event' && item[2] && typeof item[2].event_callback === 'function') {
            later(item[2].event_callback);
        }
    };
    for (var i = 0; i < dl.length; i++) { handle(dl[i]); }
    var push = dl.push;
    dl.push = function () {
        var n = push.apply(dl, arguments);
        for (var i = 0; i < arguments.length; i++) { handle(arguments[i]); }
        return n;
    };
    w.google_tag_manager = w.google_tag_manager || {};
    if (dl.hide && typeof dl.hide.end === 'function') {
        dl.hide.end();
        dl.hide.end = noop;
    }
})();
