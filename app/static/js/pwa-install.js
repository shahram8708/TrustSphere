(function () {
  "use strict";

  var deferredPrompt = null;
  var isInstalled = false;
  var installBtn = null;

  function ready(callback) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", callback);
    } else {
      callback();
    }
  }

  function getInstallButton() {
    installBtn = installBtn || document.getElementById("ts-install-btn");
    return installBtn;
  }

  function checkIfAlreadyInstalled() {
    var standaloneDisplay = false;
    if (window.matchMedia) {
      standaloneDisplay = window.matchMedia("(display-mode: standalone)").matches;
    }
    var iosStandalone = window.navigator.standalone === true;

    if (standaloneDisplay || iosStandalone) {
      isInstalled = true;
      document.body.setAttribute("data-pwa-installed", "true");
      hideInstallButton();
    }
    return isInstalled;
  }

  function isIOS() {
    return /iPad|iPhone|iPod/i.test(navigator.userAgent) && !window.MSStream;
  }

  function isIOSSafari() {
    return (
      isIOS()
      && /Safari/i.test(navigator.userAgent)
      && !/CriOS|FxiOS|EdgiOS/i.test(navigator.userAgent)
    );
  }

  function isSupportedForInstall() {
    return deferredPrompt !== null || isIOSSafari();
  }

  function showInstallButton() {
    var button = getInstallButton();
    if (!button || isInstalled || !isSupportedForInstall()) {
      return;
    }
    button.classList.remove("d-none");
    button.classList.add("ts-pulse");
    button.setAttribute("aria-hidden", "false");
  }

  function hideInstallButton() {
    var button = getInstallButton();
    if (!button) {
      return;
    }
    button.classList.add("d-none");
    button.classList.remove("ts-pulse");
    button.setAttribute("aria-hidden", "true");
  }

  function updateInstallButtonVisibility() {
    if (checkIfAlreadyInstalled()) {
      return;
    }
    if (isSupportedForInstall()) {
      showInstallButton();
    } else {
      hideInstallButton();
    }
  }

  window.addEventListener("beforeinstallprompt", function (event) {
    event.preventDefault();
    deferredPrompt = event;
    if (!isInstalled) {
      showInstallButton();
    }
    console.log("[TrustSphere PWA] Install prompt available");
  });

  window.addEventListener("appinstalled", function () {
    isInstalled = true;
    deferredPrompt = null;
    hideInstallButton();
    showInstallSuccessToast();
    console.log("[TrustSphere PWA] App installed successfully");
    document.body.setAttribute("data-pwa-installed", "true");
  });

  window.triggerPWAInstall = async function () {
    if (checkIfAlreadyInstalled()) {
      return;
    }

    if (deferredPrompt) {
      try {
        deferredPrompt.prompt();
        var choice = await deferredPrompt.userChoice;
        if (choice && choice.outcome === "accepted") {
          isInstalled = true;
          hideInstallButton();
          showInstallSuccessToast();
          document.body.setAttribute("data-pwa-installed", "true");
          console.log("[TrustSphere PWA] Native install accepted");
        } else {
          console.log("[TrustSphere PWA] Native install dismissed");
          showInstallButton();
        }
      } catch (error) {
        console.warn("[TrustSphere PWA] Native install failed", error);
        showUnsupportedInstallToast();
      } finally {
        deferredPrompt = null;
      }
      return;
    }

    if (isIOSSafari()) {
      showIOSInstallModal();
      return;
    }

    showUnsupportedInstallToast();
  };

  function showIOSInstallModal() {
    var existingModal = document.getElementById("ts-ios-install-modal");
    if (!existingModal) {
      existingModal = createIOSInstallModal();
    }
    if (window.bootstrap && window.bootstrap.Modal) {
      window.bootstrap.Modal.getOrCreateInstance(existingModal).show();
    }
  }

  function createIOSInstallModal() {
    var modal = document.createElement("div");
    modal.className = "modal fade";
    modal.id = "ts-ios-install-modal";
    modal.tabIndex = -1;
    modal.setAttribute("aria-labelledby", "ts-ios-install-title");
    modal.setAttribute("aria-hidden", "true");
    modal.innerHTML =
      '<div class="modal-dialog modal-dialog-centered modal-lg">' +
      '<div class="modal-content">' +
      '<div class="modal-header">' +
      '<div class="d-flex align-items-center gap-2">' +
      '<span class="badge rounded-pill text-bg-warning">TS</span>' +
      '<h2 class="modal-title fs-5 mb-0" id="ts-ios-install-title">Install TrustSphere</h2>' +
      "</div>" +
      '<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>' +
      "</div>" +
      '<div class="modal-body">' +
      '<ol class="list-group list-group-numbered mb-4">' +
      iosStep("bi-box-arrow-up", "Tap the Share button at the bottom of your Safari browser") +
      iosStep("bi-list-ul", "Scroll down and tap Add to Home Screen") +
      iosStep("bi-plus-square", "Tap Add in the top right corner to install") +
      "</ol>" +
      '<div class="ts-ios-phone mx-auto">' +
      '<div class="ts-ios-screen">' +
      '<div class="ts-ios-bar"></div>' +
      '<div class="ts-ios-sheet">' +
      '<div class="ts-ios-handle"></div>' +
      '<div class="ts-ios-option"><i class="bi bi-bookmark-plus"></i><span>Add to Home Screen</span></div>' +
      '<div class="ts-ios-option"><i class="bi bi-shield-check"></i><span>TrustSphere</span></div>' +
      "</div>" +
      "</div>" +
      "</div>" +
      "</div>" +
      '<div class="modal-footer">' +
      '<button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>' +
      (!isIOSSafari()
        ? '<a class="btn btn-primary" href="' + escapeAttribute(window.location.href) + '">Open in Safari</a>'
        : "") +
      "</div>" +
      "</div>" +
      "</div>";

    var style = document.createElement("style");
    style.textContent =
      ".ts-ios-phone{width:min(100%,260px);border:10px solid #1A1A2E;border-radius:28px;background:#1A1A2E;padding:10px}" +
      ".ts-ios-screen{min-height:360px;border-radius:18px;background:#F8F9FA;position:relative;overflow:hidden}" +
      ".ts-ios-bar{height:44px;background:#FFFFFF;border-bottom:1px solid #E0E0E0}" +
      ".ts-ios-sheet{position:absolute;left:12px;right:12px;bottom:12px;padding:12px;background:#FFFFFF;border-radius:18px;box-shadow:0 8px 24px rgba(0,0,0,.18)}" +
      ".ts-ios-handle{width:44px;height:4px;margin:0 auto 12px;border-radius:99px;background:#CED4DA}" +
      ".ts-ios-option{display:flex;align-items:center;gap:10px;margin-top:8px;padding:10px;border:2px solid #C9A84C;border-radius:10px;color:#0B1F4E;font-weight:700}" +
      ".ts-ios-option + .ts-ios-option{border-color:#E0E0E0;font-weight:600}";
    document.head.appendChild(style);
    document.body.appendChild(modal);
    return modal;
  }

  function iosStep(iconClass, text) {
    return (
      '<li class="list-group-item d-flex align-items-start gap-3">' +
      '<i class="bi ' + iconClass + ' text-primary fs-4" aria-hidden="true"></i>' +
      '<span><strong>Step</strong> ' + escapeHtml(text) + "</span>" +
      "</li>"
    );
  }

  function showInstallSuccessToast() {
    showToast("TrustSphere has been installed on this device.", "success");
  }

  function showUnsupportedInstallToast() {
    showToast("Install is available in Chrome, Edge, or Safari on supported devices.", "info");
  }

  function showToast(message, type) {
    if (window.TrustSphere && typeof window.TrustSphere.showToast === "function") {
      window.TrustSphere.showToast(message, type);
      return;
    }

    var container = document.getElementById("ts-toast-container");
    if (!container || !window.bootstrap || !window.bootstrap.Toast) {
      return;
    }
    var toast = document.createElement("div");
    toast.className = "toast align-items-center text-bg-" + (type || "info") + " border-0";
    toast.setAttribute("role", "status");
    toast.setAttribute("aria-live", "polite");
    toast.setAttribute("aria-atomic", "true");

    var wrapper = document.createElement("div");
    wrapper.className = "d-flex";

    var body = document.createElement("div");
    body.className = "toast-body";
    body.textContent = message;

    var button = document.createElement("button");
    button.type = "button";
    button.className = "btn-close btn-close-white me-2 m-auto";
    button.setAttribute("data-bs-dismiss", "toast");
    button.setAttribute("aria-label", "Close");

    wrapper.appendChild(body);
    wrapper.appendChild(button);
    toast.appendChild(wrapper);
    container.appendChild(toast);

    var instance = new window.bootstrap.Toast(toast, { delay: 4500 });
    toast.addEventListener("hidden.bs.toast", function () {
      toast.remove();
    });
    instance.show();
  }

  function escapeHtml(value) {
    var div = document.createElement("div");
    div.textContent = String(value || "");
    return div.innerHTML;
  }

  function escapeAttribute(value) {
    return String(value || "").replace(/"/g, "&quot;");
  }

  ready(function () {
    getInstallButton();
    updateInstallButtonVisibility();
  });
})();
