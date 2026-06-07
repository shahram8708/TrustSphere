(function () {
  "use strict";

  function bytesToHex(bytes) {
    return Array.from(bytes).map(function (byte) {
      return byte.toString(16).padStart(2, "0");
    }).join("");
  }

  async function hashString(str) {
    var encoder = new TextEncoder();
    var data = encoder.encode(str);
    var hashBuffer = await crypto.subtle.digest("SHA-256", data);
    return bytesToHex(new Uint8Array(hashBuffer));
  }

  async function getCanvasFingerprint() {
    try {
      var canvas = document.createElement("canvas");
      canvas.width = 200;
      canvas.height = 50;
      var ctx = canvas.getContext("2d");
      if (!ctx) {
        return "unavailable";
      }

      ctx.fillStyle = "#0b1f4e";
      ctx.fillRect(0, 0, 200, 50);
      ctx.fillStyle = "#c9a84c";
      ctx.font = "16px Arial";
      ctx.fillText("TrustSphere FP 2026", 8, 22);
      ctx.fillStyle = "#006d77";
      ctx.font = "14px Courier New";
      ctx.fillText("<canvas>", 8, 40);
      ctx.beginPath();
      ctx.arc(170, 25, 12, 0, Math.PI * 2);
      ctx.fillStyle = "rgba(201, 168, 76, 0.65)";
      ctx.fill();

      var pixelData = ctx.getImageData(0, 0, 200, 50).data;
      return await hashString(Array.prototype.join.call(pixelData, ","));
    } catch (_error) {
      return "unavailable";
    }
  }

  function getWebGLRenderer() {
    try {
      var canvas = document.createElement("canvas");
      var gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
      if (!gl) {
        return "unavailable";
      }

      var ext = gl.getExtension("WEBGL_debug_renderer_info");
      if (!ext) {
        return "unavailable";
      }
      return gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || "unavailable";
    } catch (_error) {
      return "unavailable";
    }
  }

  function detectOsFamily(userAgent) {
    if (/iPad|iPhone|iPod/i.test(userAgent)) {
      return "iOS";
    }
    if (/Android/i.test(userAgent)) {
      return "Android";
    }
    if (/Windows/i.test(userAgent)) {
      return "Windows";
    }
    if (/Mac OS X|Macintosh/i.test(userAgent)) {
      return "macOS";
    }
    if (/Linux/i.test(userAgent)) {
      return "Linux";
    }
    return "Unknown";
  }

  function detectBrowserFamily(userAgent) {
    if (/SamsungBrowser/i.test(userAgent)) {
      return "Samsung";
    }
    if (/Edg\//i.test(userAgent)) {
      return "Edge";
    }
    if (/Firefox\//i.test(userAgent)) {
      return "Firefox";
    }
    if (/Chrome\//i.test(userAgent) && !/Edg\//i.test(userAgent)) {
      return "Chrome";
    }
    if (/Safari\//i.test(userAgent) && !/Chrome\//i.test(userAgent)) {
      return "Safari";
    }
    return "Unknown";
  }

  function detectDeviceType(userAgent, width, touchPoints) {
    if (/Mobi|Android/i.test(userAgent)) {
      return "mobile";
    }
    if (width >= 600 && width <= 1024 && touchPoints > 0) {
      return "tablet";
    }
    return "desktop";
  }

  async function collectDeviceAttributes() {
    var userAgent = navigator.userAgent || "";
    var width = window.screen ? window.screen.width : 0;
    var height = window.screen ? window.screen.height : 0;
    var touchPoints = navigator.maxTouchPoints || 0;

    var canvasFingerprint = await getCanvasFingerprint();
    var webglRenderer = getWebGLRenderer();

    return {
      userAgent: userAgent,
      platform: navigator.platform || "",
      hardwareConcurrency: navigator.hardwareConcurrency || 0,
      screenWidth: width,
      screenHeight: height,
      screenColorDepth: window.screen ? window.screen.colorDepth : 0,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "",
      language: navigator.language || "",
      languages: navigator.languages ? navigator.languages.join(",") : "",
      deviceMemory: navigator.deviceMemory || 0,
      touchPoints: touchPoints,
      canvasFingerprint: canvasFingerprint,
      webglRenderer: webglRenderer,
      deviceType: detectDeviceType(userAgent, width, touchPoints),
      osFamily: detectOsFamily(userAgent),
      browserFamily: detectBrowserFamily(userAgent),
      isEmulator: (navigator.hardwareConcurrency || 0) === 0 || /android sdk|emulator/i.test(userAgent),
      isRooted: false
    };
  }

  async function getDeviceFingerprint() {
    var attributes = await collectDeviceAttributes();
    var stable = [
      attributes.hardwareConcurrency,
      attributes.screenWidth,
      attributes.screenHeight,
      attributes.screenColorDepth,
      attributes.canvasFingerprint,
      attributes.webglRenderer,
      attributes.timezone
    ].join("|");
    return hashString(stable);
  }

  function getCsrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") : "";
  }

  async function autoRegisterIfEnabled() {
    var shouldRegister = document.body && document.body.dataset && document.body.dataset.registerDevice === "true";
    if (!shouldRegister) {
      return;
    }

    try {
      var attributes = await collectDeviceAttributes();
      var fingerprint = await getDeviceFingerprint();
      var payload = {
        user_id: document.body.dataset.userId || null,
        device_fingerprint_hash: fingerprint,
        device_type: attributes.deviceType,
        os_family: attributes.osFamily,
        browser_family: attributes.browserFamily,
        user_agent: attributes.userAgent,
        is_rooted: attributes.isRooted,
        is_emulator: attributes.isEmulator,
        screen_resolution: attributes.screenWidth + "x" + attributes.screenHeight,
        hardware_concurrency: attributes.hardwareConcurrency,
        attributes: attributes
      };

      var response = await fetch("/api/v1/device/register", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": getCsrfToken()
        },
        body: JSON.stringify(payload)
      });

      if (response.ok) {
        console.log("[TrustSphere] Device registered/updated");
      } else {
        console.warn("[TrustSphere] Device auto registration failed");
      }
    } catch (_error) {
      console.warn("[TrustSphere] Device auto registration failed");
    }
  }

  window.TrustSphereDevice = {
    getDeviceFingerprint: getDeviceFingerprint,
    collectDeviceAttributes: collectDeviceAttributes
  };

  document.addEventListener("DOMContentLoaded", function () {
    autoRegisterIfEnabled();
  });
})();
