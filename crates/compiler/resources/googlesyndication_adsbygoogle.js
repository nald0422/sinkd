(function () {
    'use strict';
    var w = window;
    var queued = w.adsbygoogle && w.adsbygoogle.length ? Array.prototype.slice.call(w.adsbygoogle) : [];
    var settle = function () {
        var slots = document.querySelectorAll('ins.adsbygoogle:not([data-adsbygoogle-status])');
        for (var i = 0; i < slots.length; i++) {
            slots[i].setAttribute('data-adsbygoogle-status', 'done');
            slots[i].setAttribute('data-ad-status', 'unfilled');
        }
    };
    var ads = [];
    ads.loaded = true;
    ads.push = function () {
        settle();
        return ads.length;
    };
    w.adsbygoogle = ads;
    if (queued.length) { ads.push.apply(ads, queued); }
})();
