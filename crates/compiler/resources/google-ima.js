(function () {
    'use strict';
    var w = window;
    var google = w.google = w.google || {};
    if (google.ima && typeof google.ima.AdsLoader === 'function') { return; }
    var noop = function () {};
    var nothing = function () { return null; };
    var none = function () { return []; };
    var no = function () { return false; };
    var zero = function () { return 0; };
    var blank = function () { return ''; };
    var minusOne = function () { return -1; };
    var give = function (value) { return function () { return value; }; };
    var later = function (fn) { setTimeout(fn, 0); };
    var define = function (C, table) {
        for (var k in table) { C.prototype[k] = table[k]; }
        return C;
    };
    var events = {
        addEventListener: function (type, fn, capture, scope) {
            if (typeof fn !== 'function') { return; }
            var types = Array.isArray(type) ? type : [type];
            var map = this._handlers || (this._handlers = {});
            for (var i = 0; i < types.length; i++) {
                (map[types[i]] = map[types[i]] || []).push({ fn: fn, scope: scope });
            }
        },
        removeEventListener: function (type, fn) {
            var types = Array.isArray(type) ? type : [type];
            var map = this._handlers || {};
            for (var i = 0; i < types.length; i++) {
                var list = map[types[i]] || [];
                for (var j = list.length - 1; j >= 0; j--) {
                    if (list[j].fn === fn) { list.splice(j, 1); }
                }
            }
        }
    };
    var fire = function (target, event) {
        var list = ((target._handlers || {})[event.type] || []).slice();
        for (var i = 0; i < list.length; i++) {
            try { list[i].fn.call(list[i].scope || null, event); } catch (e) {}
        }
    };

    var ErrorCode = {
        VAST_MALFORMED_RESPONSE: 100, VAST_SCHEMA_VALIDATION_ERROR: 101,
        VAST_UNSUPPORTED_VERSION: 102, VAST_TRAFFICKING_ERROR: 200,
        VAST_UNEXPECTED_LINEARITY: 201, VAST_UNEXPECTED_DURATION_ERROR: 202,
        VAST_WRAPPER_ERROR: 300, VAST_LOAD_TIMEOUT: 301, VAST_TOO_MANY_REDIRECTS: 302,
        VAST_NO_ADS_AFTER_WRAPPER: 303, VIDEO_PLAY_ERROR: 400, VAST_MEDIA_LOAD_TIMEOUT: 402,
        VAST_LINEAR_ASSET_MISMATCH: 403, VAST_PROBLEM_DISPLAYING_MEDIA_FILE: 405,
        OVERLAY_AD_PLAYING_FAILED: 500, NONLINEAR_DIMENSIONS_ERROR: 501,
        OVERLAY_AD_LOADING_FAILED: 502, VAST_NONLINEAR_ASSET_MISMATCH: 503,
        COMPANION_REQUIRED_ERROR: 602, UNKNOWN_ERROR: 900, VPAID_ERROR: 901,
        FAILED_TO_REQUEST_ADS: 1005, VAST_ASSET_NOT_FOUND: 1007, VAST_EMPTY_RESPONSE: 1009,
        UNKNOWN_AD_RESPONSE: 1010, UNSUPPORTED_LOCALE: 1011, ADS_REQUEST_NETWORK_ERROR: 1012,
        INVALID_AD_TAG: 1013, STREAM_INITIALIZATION_FAILED: 1020, ASSET_FALLBACK_FAILED: 1021,
        INVALID_ARGUMENTS: 1101, AUTOPLAY_DISALLOWED: 1205
    };
    var AdError = define(function (type, code, vastCode, message) {
        this.type = type;
        this.errorCode = code;
        this.vastErrorCode = vastCode;
        this.message = message;
    }, {
        getErrorCode: function () { return this.errorCode; },
        getInnerError: nothing,
        getMessage: function () { return this.message; },
        getType: function () { return this.type; },
        getVastErrorCode: function () { return this.vastErrorCode; },
        toString: function () { return 'AdError ' + this.errorCode + ': ' + this.message; }
    });
    AdError.ErrorCode = ErrorCode;
    AdError.Type = { AD_LOAD: 'adLoadError', AD_PLAY: 'adPlayError' };

    var AdErrorEvent = define(function (error, context) {
        this.type = 'adError';
        this.error = error;
        this.context = context;
    }, {
        getError: function () { return this.error; },
        getUserRequestContext: function () { return this.context; }
    });
    AdErrorEvent.Type = { AD_ERROR: 'adError' };

    var AdPodInfo = define(function () {}, {
        getAdPosition: give(1), getIsBumper: no, getMaxDuration: minusOne,
        getPodIndex: zero, getTimeOffset: zero, getTotalAds: give(1)
    });
    var Ad = define(function () {}, {
        getAdId: blank, getAdPodInfo: function () { return new AdPodInfo(); },
        getAdSystem: blank, getAdvertiserName: blank, getApiFramework: nothing,
        getCompanionAds: none, getContentType: blank, getCreativeAdId: blank,
        getCreativeId: blank, getDealId: blank, getDescription: blank, getDuration: zero,
        getHeight: zero, getMediaUrl: nothing, getMinSuggestedDuration: zero,
        getSkipTimeOffset: minusOne, getSurveyUrl: nothing, getTitle: blank,
        getTraffickingParameters: function () { return {}; },
        getTraffickingParametersString: blank, getUiElements: none,
        getUniversalAdIdRegistry: blank, getUniversalAdIdValue: blank,
        getUniversalAdIds: none, getVastMediaBitrate: zero, getVastMediaHeight: zero,
        getVastMediaWidth: zero, getWidth: zero, getWrapperAdIds: none,
        getWrapperAdSystems: none, getWrapperCreativeIds: none, isLinear: no
    });
    var CompanionAd = define(function () {}, {
        getAdSlotId: blank, getContent: blank, getContentType: blank,
        getHeight: zero, getWidth: zero
    });

    var AdEvent = define(function (type, ad, data) {
        this.type = type;
        this.ad = ad || null;
        this.data = data || null;
    }, {
        getAd: function () { return this.ad; },
        getAdData: function () { return this.data; }
    });
    AdEvent.Type = {
        AD_BREAK_READY: 'adBreakReady', AD_BUFFERING: 'adBuffering', AD_CAN_PLAY: 'adCanPlay',
        AD_METADATA: 'adMetadata', AD_PROGRESS: 'adProgress',
        ALL_ADS_COMPLETED: 'allAdsCompleted', CLICK: 'click', COMPLETE: 'complete',
        CONTENT_PAUSE_REQUESTED: 'contentPauseRequested',
        CONTENT_RESUME_REQUESTED: 'contentResumeRequested', DURATION_CHANGE: 'durationChange',
        FIRST_QUARTILE: 'firstQuartile', IMPRESSION: 'impression', INTERACTION: 'interaction',
        LINEAR_CHANGED: 'linearChanged', LOADED: 'loaded', LOG: 'log', MIDPOINT: 'midpoint',
        PAUSED: 'pause', RESUMED: 'resume', SKIPPABLE_STATE_CHANGED: 'skippableStateChanged',
        SKIPPED: 'skip', STARTED: 'start', THIRD_QUARTILE: 'thirdQuartile',
        USER_CLOSE: 'userClose', VIDEO_CLICKED: 'videoClicked',
        VIDEO_ICON_CLICKED: 'videoIconClicked', VIEWABLE_IMPRESSION: 'viewable_impression',
        VOLUME_CHANGED: 'volumeChange', VOLUME_MUTED: 'mute'
    };

    var AdsManager = define(function () { this.volume = 1; }, {
        addEventListener: events.addEventListener,
        removeEventListener: events.removeEventListener,
        clicked: noop, collapse: noop, configureAdsManager: noop, discardAdBreak: noop,
        expand: noop, focus: noop, init: noop, pause: noop, requestNextAdBreak: noop,
        resize: noop, resume: noop, setAutoPlayAdBreaks: noop, skip: noop, start: noop,
        stop: noop, updateAdsRenderingSettings: noop,
        destroy: function () { this._handlers = {}; },
        getAdSkippableState: no, getCuePoints: none, getCurrentAd: nothing,
        getRemainingTime: minusOne,
        getVolume: function () { return this.volume; },
        setVolume: function (v) { this.volume = v; },
        isCustomClickTrackingUsed: no, isCustomPlaybackUsed: no
    });
    var AdsManagerLoadedEvent = define(function (manager, context) {
        this.type = 'adsManagerLoaded';
        this.manager = manager;
        this.context = context;
    }, {
        getAdsManager: function () { return this.manager; },
        getUserRequestContext: function () { return this.context; }
    });
    AdsManagerLoadedEvent.Type = { ADS_MANAGER_LOADED: 'adsManagerLoaded' };

    var AdDisplayContainer = define(function (container, video, click) {
        this.container = container || null;
        this.video = video || null;
        this.click = click || null;
    }, { initialize: noop, destroy: noop });

    var AdsRequest = define(function () {
        this.adTagUrl = '';
        this.adsResponse = null;
        this.contentDuration = -1;
        this.contentKeywords = null;
        this.contentTitle = null;
        this.forceNonLinearFullSlot = false;
        this.linearAdSlotHeight = 0;
        this.linearAdSlotWidth = 0;
        this.liveStreamPrefetchSeconds = 0;
        this.nonLinearAdSlotHeight = 0;
        this.nonLinearAdSlotWidth = 0;
        this.omidAccessModeRules = {};
        this.vastLoadTimeout = 5000;
    }, { setAdWillAutoPlay: noop, setAdWillPlayMuted: noop, setContinuousPlayback: noop });

    var AdsRenderingSettings = function () {
        this.autoAlign = true;
        this.bitrate = -1;
        this.enablePreloading = false;
        this.loadVideoTimeout = 8000;
        this.mimeTypes = null;
        this.playAdsAfterTime = -1;
        this.restoreCustomPlaybackStateOnAdBreakComplete = false;
        this.uiElements = null;
        this.useStyledLinearAds = false;
        this.useStyledNonLinearAds = false;
    };

    var CompanionAdSelectionSettings = function () {
        this.creativeType = 'All';
        this.resourceType = 'All';
        this.sizeCriteria = 'SelectExactMatch';
    };
    CompanionAdSelectionSettings.CreativeType = { ALL: 'All', FLASH: 'Flash', IMAGE: 'Image' };
    CompanionAdSelectionSettings.ResourceType = {
        ALL: 'All', HTML: 'Html', IFRAME: 'IFrame', STATIC: 'Static'
    };
    CompanionAdSelectionSettings.SizeCriteria = {
        IGNORE: 'IgnoreSize', SELECT_EXACT_MATCH: 'SelectExactMatch',
        SELECT_NEAR_MATCH: 'SelectNearMatch'
    };

    var ImaSdkSettings = define(function () {
        this.values = {
            autoPlayAdBreaks: true, companionBackfill: 'always', cookies: true,
            customPlaybackForIOS10Plus: false, featureFlags: {}, locale: '',
            redirects: 4, playerType: '', playerVersion: '', ppid: '', sessionId: '',
            vpaidAllowed: true, vpaidMode: 0
        };
    }, {
        getCompanionBackfill: function () { return this.values.companionBackfill; },
        getDisableCustomPlaybackForIOS10Plus: function () {
            return this.values.customPlaybackForIOS10Plus;
        },
        getFeatureFlags: function () { return this.values.featureFlags; },
        getLocale: function () { return this.values.locale; },
        getNumRedirects: function () { return this.values.redirects; },
        getPlayerType: function () { return this.values.playerType; },
        getPlayerVersion: function () { return this.values.playerVersion; },
        getPpid: function () { return this.values.ppid; },
        getSessionId: function () { return this.values.sessionId; },
        getVpaidMode: function () { return this.values.vpaidMode; },
        isCookiesEnabled: function () { return this.values.cookies; },
        isVpaidAdapter: no,
        setAutoPlayAdBreaks: function (v) { this.values.autoPlayAdBreaks = v; },
        setCompanionBackfill: function (v) { this.values.companionBackfill = v; },
        setCookiesEnabled: function (v) { this.values.cookies = v; },
        setDisableCustomPlaybackForIOS10Plus: function (v) {
            this.values.customPlaybackForIOS10Plus = v;
        },
        setFeatureFlags: function (v) { this.values.featureFlags = v || {}; },
        setLocale: function (v) { this.values.locale = v; },
        setNumRedirects: function (v) { this.values.redirects = v; },
        setPlayerType: function (v) { this.values.playerType = v; },
        setPlayerVersion: function (v) { this.values.playerVersion = v; },
        setPpid: function (v) { this.values.ppid = v; },
        setSessionId: function (v) { this.values.sessionId = v; },
        setVpaidAllowed: function (v) { this.values.vpaidAllowed = v; },
        setVpaidMode: function (v) { this.values.vpaidMode = v; }
    });
    ImaSdkSettings.CompanionBackfillMode = { ALWAYS: 'always', ON_MASTER_AD: 'on_master_ad' };
    ImaSdkSettings.VpaidMode = { DISABLED: 0, ENABLED: 1, INSECURE: 2 };
    var settings = new ImaSdkSettings();

    var VERSION = '3.0.0';
    var AdsLoader = define(function (container) {
        this.container = container || null;
        this.destroyed = false;
    }, {
        addEventListener: events.addEventListener,
        removeEventListener: events.removeEventListener,
        contentComplete: noop,
        destroy: function () { this.destroyed = true; this._handlers = {}; },
        getSettings: function () { return settings; },
        getVersion: function () { return VERSION; },
        requestAds: function (request, context) {
            var loader = this;
            later(function () {
                if (loader.destroyed) { return; }
                var error = new AdError(
                    AdError.Type.AD_LOAD,
                    ErrorCode.VAST_EMPTY_RESPONSE,
                    ErrorCode.VAST_NO_ADS_AFTER_WRAPPER,
                    'The VAST response document is empty.'
                );
                fire(loader, new AdErrorEvent(error, context));
            });
        }
    });

    google.ima = {
        Ad: Ad,
        AdCuePoints: define(function () {}, { getCuePoints: none }),
        AdDisplayContainer: AdDisplayContainer,
        AdError: AdError,
        AdErrorEvent: AdErrorEvent,
        AdEvent: AdEvent,
        AdPodInfo: AdPodInfo,
        AdsLoader: AdsLoader,
        AdsManager: AdsManager,
        AdsManagerLoadedEvent: AdsManagerLoadedEvent,
        AdsRenderingSettings: AdsRenderingSettings,
        AdsRequest: AdsRequest,
        CompanionAd: CompanionAd,
        CompanionAdSelectionSettings: CompanionAdSelectionSettings,
        ImaSdkSettings: ImaSdkSettings,
        OmidAccessMode: { DOMAIN: 'domain', FULL: 'full', LIMITED: 'limited' },
        OmidVerificationVendor: {
            COMSCORE: 7, DOUBLEVERIFY: 3, GOOGLE: 9, INTEGRAL_AD_SCIENCE: 4, MEETRICS: 8,
            MOAT: 2, NIELSEN: 5, OTHER: 1, PIXELATE: 6
        },
        UiElements: { AD_ATTRIBUTION: 'adAttribution', COUNTDOWN: 'countdown' },
        UniversalAdIdInfo: define(function () {}, {
            getAdIdRegistry: blank, getAdIdValue: blank
        }),
        ViewMode: { FULLSCREEN: 'fullscreen', NORMAL: 'normal' },
        VERSION: VERSION,
        settings: settings
    };
})();
