(function () {
    'use strict';
    var noop = function () {};
    var self = function () { return this; };
    var nothing = function () { return null; };
    var none = function () { return []; };
    var yes = function () { return true; };
    var no = function () { return false; };
    var w = window;
    var g = w.googletag || {};
    var listeners = {};
    var slots = [];
    var Slot = function (path, id) {
        this.path = path || '';
        this.id = id || '';
    };
    var slotMethods = {
        addService: self, clearCategoryExclusions: self, clearTargeting: self,
        defineSizeMapping: self, get: nothing, getAttributeKeys: none,
        getCategoryExclusions: none, getResponseInformation: nothing,
        getSlotId: self, getTargeting: none, getTargetingKeys: none, set: self,
        setCategoryExclusion: self, setClickUrl: self, setCollapseEmptyDiv: self,
        setConfig: noop, setForceSafeFrame: self, setSafeFrameConfig: self,
        setTargeting: self, updateTargetingFromMap: self,
        getAdUnitPath: function () { return this.path; },
        getDomId: function () { return this.id; },
        getSlotElementId: function () { return this.id; }
    };
    for (var m in slotMethods) { Slot.prototype[m] = slotMethods[m]; }
    var define = function (path, a, b) {
        var slot = new Slot(path, typeof b === 'string' ? b : a);
        slots.push(slot);
        return slot;
    };
    var emit = function (type, slot) {
        var fns = listeners[type] || [];
        for (var i = 0; i < fns.length; i++) {
            try {
                fns[i]({ isEmpty: true, size: null, slot: slot, serviceName: 'publisher_ads' });
            } catch (e) {}
        }
    };
    var display = function (id) {
        for (var i = 0; i < slots.length; i++) {
            if (id === undefined || slots[i].id === id || slots[i] === id) {
                emit('slotRequested', slots[i]);
                emit('slotRenderEnded', slots[i]);
            }
        }
    };
    var pubads = {
        addEventListener: function (type, fn) {
            if (typeof fn === 'function') { (listeners[type] = listeners[type] || []).push(fn); }
            return this;
        },
        removeEventListener: yes, clear: yes, clearCategoryExclusions: self,
        clearTagForChildDirectedTreatment: self, clearTargeting: self,
        collapseEmptyDivs: self, disableInitialLoad: noop, display: noop,
        enableAsyncRendering: yes, enableLazyLoad: noop, enableSingleRequest: yes,
        enableSyncRendering: yes, enableVideoAds: noop, get: nothing,
        getAttributeKeys: none, getTargeting: none, getTargetingKeys: none,
        getSlots: function () { return slots.slice(); },
        isInitialLoadDisabled: no, refresh: noop, set: self,
        setCategoryExclusion: self, setCentering: noop, setCookieOptions: self,
        setForceSafeFrame: self, setLocation: self, setPrivacySettings: self,
        setPublisherProvidedId: self, setRequestNonPersonalizedAds: self,
        setSafeFrameConfig: self, setTagForChildDirectedTreatment: self,
        setTargeting: self, setVideoContent: self, updateCorrelator: noop,
        defineOutOfPagePassback: function (path) { return define(path); },
        definePassback: function (path) { return define(path); }
    };
    var service = { addEventListener: self, enableSyncLoading: noop, setRefreshUnfilledSlots: noop, setVideoSession: noop };
    g.apiReady = true;
    g.pubadsReady = true;
    g.pubads = function () { return pubads; };
    g.companionAds = function () { return service; };
    g.content = function () { return service; };
    g.defineSlot = define;
    g.defineOutOfPageSlot = function (path, id) { return define(path, id); };
    g.destroySlots = function () { slots.length = 0; return true; };
    g.disablePublisherConsole = noop;
    g.display = display;
    g.enableServices = noop;
    g.getVersion = function () { return ''; };
    g.openConsole = noop;
    g.setAdIframeTitle = noop;
    g.setConfig = noop;
    g.sizeMapping = function () {
        var b = { addSize: function () { return b; }, build: nothing };
        return b;
    };
    var queued = g.cmd && g.cmd.length ? Array.prototype.slice.call(g.cmd) : [];
    var cmd = [];
    cmd.push = function () {
        for (var i = 0; i < arguments.length; i++) {
            if (typeof arguments[i] === 'function') {
                try { arguments[i](); } catch (e) {}
            }
        }
        return 1;
    };
    g.cmd = cmd;
    w.googletag = g;
    cmd.push.apply(cmd, queued);
})();
