import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { createContext, runInContext } from "node:vm";

// The surrogates as the compiler bundles them (crates/compiler/resources),
// run in a bare window: what a page's own player code would see.
const resources = new URL("../../../crates/compiler/resources/", import.meta.url);

function page(globals: Record<string, unknown> = {}) {
  const context = createContext({ setTimeout, ...globals });
  runInContext("var window = this;", context);
  return {
    load: (name: string) => runInContext(readFileSync(new URL(name, resources), "utf8"), context),
    // Results are copied out of the page's realm, whose Object and Array
    // are not this one's.
    run: async <T>(code: string): Promise<T> => {
      const value = await runInContext(code, context);
      return value === undefined ? value : JSON.parse(JSON.stringify(value));
    },
  };
}

// The usual player flow: container, loader, listeners, request.
const REQUEST = `new Promise(function (resolve) {
  var ima = google.ima;
  var container = new ima.AdDisplayContainer({}, {});
  container.initialize();
  var loader = new ima.AdsLoader(container);
  var seen = { managerLoaded: false };
  loader.addEventListener(ima.AdsManagerLoadedEvent.Type.ADS_MANAGER_LOADED, function () {
    seen.managerLoaded = true;
  }, false);
  loader.addEventListener(ima.AdErrorEvent.Type.AD_ERROR, function (e) {
    var error = e.getError();
    seen.code = error.getErrorCode();
    seen.type = error.getType();
    seen.message = error.getMessage();
    seen.context = e.getUserRequestContext();
    seen.isNoAds = seen.code === ima.AdError.ErrorCode.VAST_EMPTY_RESPONSE;
    setTimeout(function () { resolve(seen); }, 10);
  }, false);
  var request = new ima.AdsRequest();
  request.adTagUrl = "https://pubads.g.doubleclick.net/gampad/ads?iu=/1/x";
  request.setAdWillAutoPlay(true);
  loader.requestAds(request, { id: 7 });
})`;

test("google-ima.js answers an ad request with no ads", async () => {
  const p = page();
  p.load("google-ima.js");
  const seen = await p.run<Record<string, unknown>>(REQUEST);
  assert.equal(seen.managerLoaded, false, "never loads an ads manager");
  assert.equal(seen.isNoAds, true, JSON.stringify(seen));
  assert.equal(seen.code, 1009);
  assert.equal(seen.type, "adLoadError");
  assert.equal(typeof seen.message, "string");
  assert.deepEqual(seen.context, { id: 7 }, "hands back the request context");
});

test("google-ima.js stays silent for removed listeners and destroyed loaders", async () => {
  const p = page();
  p.load("google-ima.js");
  const calls = await p.run<number[]>(`new Promise(function (resolve) {
    var ima = google.ima;
    var calls = [0, 0, 0];
    var a = new ima.AdsLoader(new ima.AdDisplayContainer({}));
    var gone = function () { calls[0] += 1; };
    a.addEventListener(ima.AdErrorEvent.Type.AD_ERROR, gone);
    a.removeEventListener(ima.AdErrorEvent.Type.AD_ERROR, gone);
    a.addEventListener([ima.AdErrorEvent.Type.AD_ERROR, "other"], function () { calls[1] += 1; });
    a.requestAds(new ima.AdsRequest());
    var b = new ima.AdsLoader(new ima.AdDisplayContainer({}));
    b.addEventListener(ima.AdErrorEvent.Type.AD_ERROR, function () { calls[2] += 1; });
    b.requestAds(new ima.AdsRequest());
    b.destroy();
    setTimeout(function () { resolve(calls); }, 20);
  })`);
  assert.deepEqual(calls, [0, 1, 0]);
});

test("google-ima.js has the namespace players configure", async () => {
  const p = page();
  p.load("google-ima.js");
  const r = await p.run<Record<string, unknown>>(`(function () {
    var ima = google.ima;
    ima.settings.setVpaidMode(ima.ImaSdkSettings.VpaidMode.ENABLED);
    ima.settings.setLocale("de");
    var loader = new ima.AdsLoader(new ima.AdDisplayContainer({}));
    var rendering = new ima.AdsRenderingSettings();
    var manager = new ima.AdsManager();
    manager.init(640, 360, ima.ViewMode.NORMAL);
    manager.setVolume(0);
    return Promise.resolve({
      sameSettings: loader.getSettings() === ima.settings,
      vpaid: ima.settings.getVpaidMode(),
      locale: ima.settings.getLocale(),
      version: typeof ima.VERSION,
      resume: ima.AdEvent.Type.CONTENT_RESUME_REQUESTED,
      done: ima.AdEvent.Type.ALL_ADS_COMPLETED,
      restore: rendering.restoreCustomPlaybackStateOnAdBreakComplete,
      cuePoints: manager.getCuePoints().length,
      volume: manager.getVolume(),
      ui: ima.UiElements.COUNTDOWN
    });
  })()`);
  assert.deepEqual(r, {
    sameSettings: true,
    vpaid: 1,
    locale: "de",
    version: "string",
    resume: "contentResumeRequested",
    done: "allAdsCompleted",
    restore: false,
    cuePoints: 0,
    volume: 0,
    ui: "countdown",
  });
});

test("google-ima.js keeps the rest of window.google, and a loaded SDK", async () => {
  const p = page();
  await p.run("window.google = { maps: { ok: true } }");
  p.load("google-ima.js");
  assert.equal(await p.run("google.maps.ok && typeof google.ima.AdsLoader"), "function");

  const real = page();
  await real.run("window.google = { ima: { AdsLoader: function () {}, real: true } }");
  real.load("google-ima.js");
  assert.equal(await real.run("google.ima.real"), true);
});
