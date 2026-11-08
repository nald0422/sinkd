// Global Privacy Control in the page's main world: navigator
// .globalPrivacyControl is true, as on browsers that support GPC natively.
// The Sec-GPC request header comes from a DNR rule. Registered only where
// the feature is on (the background leaves excepted and paused sites out).
//
// Chrome has no such property, so it is added. Firefox has it, true only
// when the user turned GPC on in its settings (or in private windows), so
// there it is replaced when it says false: the header goes out regardless.
//
// A script, not a module (content scripts can't import), hence the IIFE.

(() => {
  const proto = Navigator.prototype;
  const native = Object.getOwnPropertyDescriptor(proto, "globalPrivacyControl");
  if (native?.get && Reflect.apply(native.get, navigator, []) === true) {
    // The browser sends GPC itself.
    return;
  }
  // A bound native function returning true: native-looking source, no
  // closure of ours a page could step into.
  const getter = Boolean.bind(null, true);
  Object.defineProperty(getter, "name", { value: "get globalPrivacyControl" });
  Object.defineProperty(proto, "globalPrivacyControl", {
    get: getter,
    enumerable: native?.enumerable ?? true,
    configurable: true,
  });
})();
