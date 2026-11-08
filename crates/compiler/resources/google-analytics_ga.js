(function () {
    'use strict';
    var noop = function () {};
    var w = window;
    var tracker = {};
    var names = ['_addIgnoredOrganic', '_addIgnoredRef', '_addItem', '_addOrganic',
        '_addTrans', '_clearIgnoredOrganic', '_clearIgnoredRef', '_clearOrganic',
        '_cookiePathCopy', '_deleteCustomVar', '_link', '_linkByPost',
        '_setAccount', '_setAllowAnchor', '_setAllowHash', '_setAllowLinker',
        '_setCampContentKey', '_setCampMediumKey', '_setCampNameKey',
        '_setCampNOKey', '_setCampSourceKey', '_setCampTermKey', '_setCampaignCookieTimeout',
        '_setCampaignTrack', '_setClientInfo', '_setCookiePath', '_setCookiePersistence',
        '_setCookieTimeout', '_setCustomVar', '_setDetectFlash', '_setDetectTitle',
        '_setDomainName', '_setLocalGifPath', '_setLocalRemoteServerMode',
        '_setLocalServerMode', '_setReferrerOverride', '_setRemoteServerMode',
        '_setSampleRate', '_setSessionTimeout', '_setSiteSpeedSampleRate',
        '_setTrans', '_setTrustedDomainName', '_setVar', '_setVisitorCookieTimeout',
        '_trackEvent', '_trackPageLoadTime', '_trackPageview', '_trackSocial',
        '_trackTiming', '_trackTrans'];
    for (var i = 0; i < names.length; i++) { tracker[names[i]] = noop; }
    tracker._getName = function () { return ''; };
    tracker._getAccount = function () { return ''; };
    tracker._getVersion = function () { return ''; };
    tracker._getVisitorCustomVar = noop;
    tracker._getLinkerUrl = function (url) { return url; };
    var gat = {
        _anonymizeIp: noop, _forceSSL: noop,
        _createTracker: function () { return tracker; },
        _getTracker: function () { return tracker; },
        _getTrackerByName: function () { return tracker; }
    };
    var queued = w._gaq && w._gaq.length ? Array.prototype.slice.call(w._gaq) : [];
    var gaq = {
        _createAsyncTracker: function () { return tracker; },
        _getAsyncTracker: function () { return tracker; },
        push: function () {
            for (var i = 0; i < arguments.length; i++) {
                if (typeof arguments[i] === 'function') {
                    try { arguments[i](); } catch (e) {}
                }
            }
            return 0;
        }
    };
    w._gat = gat;
    w._gaq = gaq;
    if (queued.length) { gaq.push.apply(gaq, queued); }
})();
