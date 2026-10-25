// Runs in <head>, before the stylesheet, so the page never flashes the wrong theme.
// Light is the default and is what you get unless you chose otherwise. "auto" follows the system setting; "dark" is dark.
(function () {
  var pref = "light";
  try {
    pref = localStorage.getItem("cve.theme") || "light";
  } catch (e) {}
  if (pref !== "dark" && pref !== "auto") pref = "light";
  var mq = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
  var root = document.documentElement;
  function apply() {
    var dark = pref === "dark" || (pref === "auto" && mq && mq.matches);
    root.setAttribute("data-theme", dark ? "dark" : "light");
    root.setAttribute("data-theme-pref", pref);
  }
  apply();
  if (mq && mq.addEventListener) {
    mq.addEventListener("change", function () {
      if (pref === "auto") {
        apply();
        window.dispatchEvent(new Event("cve:theme"));
      }
    });
  }
  window.cveTheme = {
    get: function () {
      return pref;
    },
    set: function (next) {
      pref = next === "dark" || next === "auto" ? next : "light";
      try {
        localStorage.setItem("cve.theme", pref);
      } catch (e) {}
      apply();
      window.dispatchEvent(new Event("cve:theme"));
    },
  };
})();
