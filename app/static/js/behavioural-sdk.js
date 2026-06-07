(function () {
  "use strict";

  var typingEvents = [];
  var scrollEvents = [];
  var mouseEvents = [];
  var formEvents = [];
  var touchEvents = [];

  var lastKeyDownTime = null;
  var lastKeyDownKey = null;
  var lastClickTime = null;
  var lastScrollTime = Date.now();
  var lastScrollY = window.scrollY || 0;

  var fieldNavigationOrder = [];
  var sdkEnabled = false;

  function pushBounded(arr, item, maxLen) {
    arr.push(item);
    if (arr.length > maxLen) {
      arr.shift();
    }
  }

  function classifyKeyType(key) {
    if (/^[a-zA-Z]$/.test(key)) {
      return "letter";
    }
    if (/^[0-9]$/.test(key)) {
      return "number";
    }
    if (key === "Backspace") {
      return "backspace";
    }
    return "special";
  }

  function mean(values) {
    if (!values.length) {
      return 0;
    }
    var total = values.reduce(function (acc, value) {
      return acc + value;
    }, 0);
    return total / values.length;
  }

  function stdev(values) {
    if (values.length < 2) {
      return 0;
    }
    var avg = mean(values);
    var variance = mean(values.map(function (value) {
      var d = value - avg;
      return d * d;
    }));
    return Math.sqrt(variance);
  }

  function ratio(count, total) {
    if (!total) {
      return 0;
    }
    return count / total;
  }

  function shannonEntropy(sequence) {
    if (!sequence.length) {
      return 0;
    }
    var transitions = {};
    for (var i = 1; i < sequence.length; i += 1) {
      var key = sequence[i - 1] + "->" + sequence[i];
      transitions[key] = (transitions[key] || 0) + 1;
    }
    var counts = Object.values(transitions);
    var total = counts.reduce(function (acc, value) {
      return acc + value;
    }, 0);
    if (!total) {
      return 0;
    }
    return counts.reduce(function (acc, count) {
      var p = count / total;
      return acc - (p * Math.log2(p));
    }, 0);
  }

  function computeFeatureVector() {
    var validTyping = typingEvents.filter(function (event) {
      return Number.isFinite(event.iki_ms) && event.iki_ms >= 0 && Number.isFinite(event.dwell_ms) && event.dwell_ms >= 0;
    });
    var validScroll = scrollEvents.filter(function (event) {
      return Number.isFinite(event.velocity_pxms) && event.velocity_pxms >= 0;
    });
    var validMouse = mouseEvents.filter(function (event) {
      return Number.isFinite(event.click_iat_ms) && event.click_iat_ms >= 0;
    });
    var validTouch = touchEvents.filter(function (event) {
      return Number.isFinite(event.pressure) && event.pressure >= 0;
    });

    var ikis = validTyping.map(function (e) { return e.iki_ms; });
    var dwells = validTyping.map(function (e) { return e.dwell_ms; });
    var scrollVelocities = validScroll.map(function (e) { return e.velocity_pxms; });
    var clickIats = validMouse.map(function (e) { return e.click_iat_ms; });

    var letters = validTyping.filter(function (e) { return e.key_type === "letter"; }).length;
    var numbers = validTyping.filter(function (e) { return e.key_type === "number"; }).length;
    var backspaces = validTyping.filter(function (e) { return e.key_type === "backspace"; }).length;
    var pasteCount = formEvents.filter(function (e) { return e.paste_detected; }).length;

    var featureVector = [
      mean(ikis),
      stdev(ikis),
      mean(dwells),
      stdev(dwells),
      ratio(letters, validTyping.length),
      ratio(numbers, validTyping.length),
      ratio(backspaces, validTyping.length),
      mean(scrollVelocities),
      mean(clickIats),
      shannonEntropy(fieldNavigationOrder)
    ];

    if (validTouch.length) {
      featureVector[9] = (featureVector[9] + mean(validTouch.map(function (t) { return t.pressure; })) + ratio(pasteCount, Math.max(1, formEvents.length))) / 3;
    }

    return featureVector.map(function (value) {
      return Number.isFinite(value) ? Number(value.toFixed(4)) : 0;
    });
  }

  function clearBuffers() {
    typingEvents = [];
    scrollEvents = [];
    mouseEvents = [];
    formEvents = [];
    touchEvents = [];
    fieldNavigationOrder = [];
    lastKeyDownTime = null;
    lastKeyDownKey = null;
    lastClickTime = null;
    lastScrollTime = Date.now();
    lastScrollY = window.scrollY || 0;
  }

  function getCsrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") : "";
  }

  async function sendBehaviouralSample() {
    if (!sdkEnabled || typingEvents.length < 10) {
      return;
    }

    var payload = {
      user_id: document.body.dataset.userId || "",
      event_type: "behaviour_sample",
      feature_vector: computeFeatureVector(),
      typing_events: typingEvents.slice(),
      scroll_events: scrollEvents.slice(),
      mouse_events: mouseEvents.slice(),
      form_events: formEvents.slice(),
      touch_events: touchEvents.slice()
    };

    try {
      var response = await fetch("/api/v1/risk/evaluate", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": getCsrfToken()
        },
        body: JSON.stringify(payload)
      });

      if (response.ok) {
        var result = await response.json();
        if (result && result.recommended_action === "stepup") {
          document.dispatchEvent(new CustomEvent("ts:stepup-required", { detail: result }));
        }
        if (result && result.recommended_action === "block") {
          var loginUrl = document.body.dataset.loginUrl || "/auth/login";
          window.location.assign(loginUrl);
        }
      }
    } catch (_error) {
      return;
    } finally {
      clearBuffers();
    }
  }

  function onKeyDown(event) {
    var now = Date.now();
    var keyType = classifyKeyType(event.key || "");
    var iki = 0;
    if (lastKeyDownTime !== null) {
      iki = now - lastKeyDownTime;
    }
    pushBounded(typingEvents, {
      iki_ms: iki,
      dwell_ms: 0,
      key_type: keyType
    }, 200);
    lastKeyDownTime = now;
    lastKeyDownKey = keyType;
  }

  function onKeyUp() {
    if (lastKeyDownTime === null || !typingEvents.length) {
      return;
    }
    var dwell = Date.now() - lastKeyDownTime;
    typingEvents[typingEvents.length - 1].dwell_ms = Math.max(0, dwell);
    typingEvents[typingEvents.length - 1].key_type = lastKeyDownKey || typingEvents[typingEvents.length - 1].key_type;
  }

  function onScroll() {
    var now = Date.now();
    var deltaY = Math.abs((window.scrollY || 0) - lastScrollY);
    var deltaT = Math.max(1, now - lastScrollTime);
    var velocity = deltaY / deltaT;
    pushBounded(scrollEvents, { velocity_pxms: velocity }, 100);
    lastScrollY = window.scrollY || 0;
    lastScrollTime = now;
  }

  function onClick() {
    var now = Date.now();
    var iat = lastClickTime === null ? 0 : now - lastClickTime;
    pushBounded(mouseEvents, { click_iat_ms: iat }, 100);
    lastClickTime = now;
  }

  function onPaste() {
    var active = document.activeElement;
    pushBounded(formEvents, {
      field_order: active && active.id ? active.id : "unknown",
      paste_detected: true
    }, 50);
  }

  function onFocusIn() {
    var active = document.activeElement;
    var fieldId = active && active.id ? active.id : "unknown";
    pushBounded(formEvents, { field_order: fieldId, paste_detected: false }, 50);
    pushBounded(fieldNavigationOrder, fieldId, 100);
  }

  function onTouchStart(event) {
    var pressure = 0.5;
    if (event.touches && event.touches.length > 0 && typeof event.touches[0].force === "number") {
      pressure = event.touches[0].force;
    }
    pushBounded(touchEvents, { pressure: pressure }, 100);
  }

  function initSDK() {
    sdkEnabled = !!(document.body && document.body.dataset && document.body.dataset.sdk === "active");
    if (!sdkEnabled) {
      return;
    }

    document.addEventListener("keydown", onKeyDown, { passive: true });
    document.addEventListener("keyup", onKeyUp, { passive: true });
    document.addEventListener("scroll", onScroll, { passive: true });
    document.addEventListener("click", onClick, { passive: true });
    document.addEventListener("paste", onPaste, { passive: true });
    document.addEventListener("focusin", onFocusIn, { passive: true });
    document.addEventListener("touchstart", onTouchStart, { passive: true });

    window.setInterval(sendBehaviouralSample, 30000);
  }

  document.addEventListener("DOMContentLoaded", initSDK);

  window.TrustSphereSDK = {
    initSDK: initSDK,
    sendBehaviouralSample: sendBehaviouralSample,
    computeFeatureVector: computeFeatureVector
  };
})();
