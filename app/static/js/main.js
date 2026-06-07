(function () {
  "use strict";

  var serviceWorkerRegistrationStarted = false;
  var lastAdminShortcutKey = "";
  var lastAdminShortcutAt = 0;

  window.TrustSphere = window.TrustSphere || {};

  function ready(callback) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", callback);
    } else {
      callback();
    }
  }

  function csrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") : "";
  }

  function sameOrigin(input) {
    try {
      var url = new URL(typeof input === "string" ? input : input.url, window.location.href);
      return url.origin === window.location.origin;
    } catch (error) {
      return true;
    }
  }

  function enhanceFetchWithCsrf() {
    if (!window.fetch || window.fetch.__trustspherePatched) {
      return;
    }

    var originalFetch = window.fetch.bind(window);
    var safeMethods = ["GET", "HEAD", "OPTIONS", "TRACE"];

    window.fetch = function (resource, options) {
      var requestOptions = options ? Object.assign({}, options) : {};
      var method = (
        requestOptions.method
        || (resource && resource.method)
        || "GET"
      ).toUpperCase();

      if (safeMethods.indexOf(method) === -1 && sameOrigin(resource)) {
        var headers = new Headers(requestOptions.headers || (resource && resource.headers) || {});
        if (!headers.has("X-CSRFToken")) {
          headers.set("X-CSRFToken", csrfToken());
        }
        requestOptions.headers = headers;
      }

      return originalFetch(resource, requestOptions);
    };
    window.fetch.__trustspherePatched = true;
  }

  function initializeBootstrap() {
    if (!window.bootstrap) {
      return;
    }

    document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(function (element) {
      window.bootstrap.Tooltip.getOrCreateInstance(element);
    });

    document.querySelectorAll('[data-bs-toggle="popover"]').forEach(function (element) {
      window.bootstrap.Popover.getOrCreateInstance(element);
    });

    document.querySelectorAll(".toast").forEach(function (element) {
      window.bootstrap.Toast.getOrCreateInstance(element);
    });
  }

  function autoDismissFlashMessages() {
    document.querySelectorAll(".ts-flash-message").forEach(function (element) {
      window.setTimeout(function () {
        element.classList.add("fade");
        element.classList.remove("show");
        window.setTimeout(function () {
          if (element.parentNode) {
            element.parentNode.removeChild(element);
          }
        }, 250);
      }, 5000);
    });
  }

  function formatRelativeTime(dateValue) {
    var date = new Date(dateValue);
    if (Number.isNaN(date.getTime())) {
      return "";
    }

    var seconds = Math.round((Date.now() - date.getTime()) / 1000);
    var tense = seconds >= 0 ? "ago" : "from now";
    seconds = Math.abs(seconds);

    if (seconds < 5) {
      return tense === "ago" ? "just now" : "in a moment";
    }
    if (seconds < 60) {
      return seconds + " second" + (seconds === 1 ? "" : "s") + " " + tense;
    }

    var intervals = [
      { label: "year", seconds: 31536000 },
      { label: "month", seconds: 2592000 },
      { label: "week", seconds: 604800 },
      { label: "day", seconds: 86400 },
      { label: "hour", seconds: 3600 },
      { label: "minute", seconds: 60 }
    ];

    for (var index = 0; index < intervals.length; index += 1) {
      var interval = intervals[index];
      var count = Math.floor(seconds / interval.seconds);
      if (count >= 1) {
        if (tense === "ago" && interval.label === "day" && count === 1) {
          return "yesterday";
        }
        if (tense !== "ago" && interval.label === "day" && count === 1) {
          return "tomorrow";
        }
        return (
          (tense === "ago" ? "" : "in ")
          + count
          + " "
          + interval.label
          + (count === 1 ? "" : "s")
          + (tense === "ago" ? " ago" : "")
        );
      }
    }

    return "";
  }

  function refreshRelativeTimes() {
    document.querySelectorAll("[data-timestamp]").forEach(function (element) {
      var formatted = formatRelativeTime(element.getAttribute("data-timestamp"));
      if (formatted) {
        element.textContent = formatted;
      }
    });
  }

  function initializeSidebarToggle() {
    var sidebar = document.getElementById("ts-admin-sidebar");
    var overlay = document.getElementById("ts-sidebar-overlay");
    var toggles = document.querySelectorAll(".ts-sidebar-toggle");
    if (!sidebar || !overlay || toggles.length === 0) {
      return;
    }

    var storageKey = "trustsphere.admin.sidebar.open";

    function persist(open) {
      try {
        window.localStorage.setItem(storageKey, open ? "true" : "false");
      } catch (error) {}
    }

    function setSidebar(open) {
      sidebar.classList.toggle("ts-sidebar-open", open);
      overlay.classList.toggle("d-none", !open);
      overlay.classList.toggle("ts-overlay", open);
      persist(open);
    }

    try {
      if (window.localStorage.getItem(storageKey) === "true" && window.innerWidth < 992) {
        setSidebar(true);
      }
    } catch (error) {}

    toggles.forEach(function (button) {
      button.addEventListener("click", function () {
        setSidebar(!sidebar.classList.contains("ts-sidebar-open"));
      });
    });

    overlay.addEventListener("click", function () {
      setSidebar(false);
    });

    window.addEventListener("resize", function () {
      if (window.innerWidth >= 992) {
        overlay.classList.add("d-none");
        overlay.classList.remove("ts-overlay");
      }
    });
  }

  function showToast(message, type, options) {
    var container = document.getElementById("ts-toast-container");
    if (!container) {
      container = document.createElement("div");
      container.id = "ts-toast-container";
      container.className = "ts-toast-container";
      document.body.appendChild(container);
    }

    var normalizedType = ["success", "danger", "warning", "info"].indexOf(type) !== -1 ? type : "info";
    var toast = document.createElement("div");
    toast.className = "toast align-items-center text-bg-" + normalizedType + " border-0";
    toast.setAttribute("role", normalizedType === "danger" ? "alert" : "status");
    toast.setAttribute("aria-live", normalizedType === "danger" ? "assertive" : "polite");
    toast.setAttribute("aria-atomic", "true");

    var wrapper = document.createElement("div");
    wrapper.className = "d-flex";

    var body = document.createElement("div");
    body.className = "toast-body";
    body.textContent = String(message || "");

    var close = document.createElement("button");
    close.type = "button";
    close.className = "btn-close btn-close-white me-2 m-auto";
    close.setAttribute("data-bs-dismiss", "toast");
    close.setAttribute("aria-label", "Close");

    wrapper.appendChild(body);
    wrapper.appendChild(close);
    toast.appendChild(wrapper);
    container.appendChild(toast);

    if (window.bootstrap && window.bootstrap.Toast) {
      var instance = new window.bootstrap.Toast(toast, Object.assign({ delay: 4500 }, options || {}));
      toast.addEventListener("hidden.bs.toast", function () {
        toast.remove();
      });
      instance.show();
    } else {
      window.setTimeout(function () {
        toast.remove();
      }, (options && options.delay) || 4500);
    }
  }

  function confirmationModal() {
    var modal = document.getElementById("ts-confirm-action-modal");
    if (modal) {
      return modal;
    }

    modal = document.createElement("div");
    modal.className = "modal fade";
    modal.id = "ts-confirm-action-modal";
    modal.tabIndex = -1;
    modal.setAttribute("aria-hidden", "true");
    modal.innerHTML =
      '<div class="modal-dialog modal-dialog-centered">' +
      '<div class="modal-content">' +
      '<div class="modal-header">' +
      '<h2 class="modal-title fs-5">Confirm Action</h2>' +
      '<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>' +
      "</div>" +
      '<div class="modal-body"><p class="mb-0" id="ts-confirm-action-message"></p></div>' +
      '<div class="modal-footer">' +
      '<button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>' +
      '<button type="button" class="btn btn-danger" id="ts-confirm-action-accept">Confirm</button>' +
      "</div>" +
      "</div>" +
      "</div>";
    document.body.appendChild(modal);
    return modal;
  }

  function confirmAction(message) {
    return new Promise(function (resolve) {
      if (!window.bootstrap || !window.bootstrap.Modal) {
        resolve(window.confirm(message));
        return;
      }

      var modal = confirmationModal();
      var messageElement = modal.querySelector("#ts-confirm-action-message");
      var acceptButton = modal.querySelector("#ts-confirm-action-accept");
      var instance = window.bootstrap.Modal.getOrCreateInstance(modal);
      var resolved = false;

      messageElement.textContent = message;

      function cleanup(value) {
        if (resolved) {
          return;
        }
        resolved = true;
        acceptButton.removeEventListener("click", onAccept);
        modal.removeEventListener("hidden.bs.modal", onHidden);
        resolve(value);
      }

      function onAccept() {
        cleanup(true);
        instance.hide();
      }

      function onHidden() {
        cleanup(false);
      }

      acceptButton.addEventListener("click", onAccept);
      modal.addEventListener("hidden.bs.modal", onHidden);
      instance.show();
    });
  }

  function initializeConfirmations() {
    document.addEventListener("click", function (event) {
      var trigger = event.target.closest("[data-confirm]");
      if (!trigger || trigger.dataset.tsConfirmed === "true") {
        return;
      }

      var message = trigger.getAttribute("data-confirm") || "Are you sure?";
      event.preventDefault();
      event.stopPropagation();

      confirmAction(message).then(function (confirmed) {
        if (!confirmed) {
          return;
        }

        trigger.dataset.tsConfirmed = "true";
        if (trigger.tagName === "BUTTON" && trigger.form) {
          if (trigger.form.requestSubmit) {
            trigger.form.requestSubmit(trigger);
          } else {
            trigger.form.submit();
          }
        } else {
          trigger.click();
        }
        window.setTimeout(function () {
          delete trigger.dataset.tsConfirmed;
        }, 0);
      });
    }, true);
  }

  function initializeExpandButtons() {
    document.querySelectorAll(".ts-expand-btn").forEach(function (button) {
      var targetSelector = button.getAttribute("data-bs-target") || button.getAttribute("href");
      if (!targetSelector || targetSelector.charAt(0) !== "#") {
        return;
      }

      var target = document.querySelector(targetSelector);
      var icon = button.querySelector(".bi");
      if (!target || !icon) {
        return;
      }

      target.addEventListener("show.bs.collapse", function () {
        icon.classList.remove("bi-chevron-down");
        icon.classList.add("bi-chevron-up");
        button.setAttribute("aria-expanded", "true");
      });

      target.addEventListener("hide.bs.collapse", function () {
        icon.classList.remove("bi-chevron-up");
        icon.classList.add("bi-chevron-down");
        button.setAttribute("aria-expanded", "false");
      });
    });
  }

  function notifyServiceWorkerUpdate(registration) {
    showToast("A TrustSphere update is ready. Refresh to use the latest version.", "info", { delay: 8000 });
    var waiting = registration && registration.waiting;
    if (waiting) {
      waiting.postMessage({ type: "SKIP_WAITING" });
    }
  }

  function registerServiceWorker() {
    if (serviceWorkerRegistrationStarted || !("serviceWorker" in navigator)) {
      return Promise.resolve(null);
    }
    serviceWorkerRegistrationStarted = true;

    return navigator.serviceWorker.register("/sw.js", { scope: "/" })
      .then(function (registration) {
        console.log("TrustSphere service worker registered", registration.scope);

        if (registration.waiting && navigator.serviceWorker.controller) {
          notifyServiceWorkerUpdate(registration);
        }

        registration.addEventListener("updatefound", function () {
          var worker = registration.installing;
          if (!worker) {
            return;
          }
          worker.addEventListener("statechange", function () {
            if (worker.state === "installed" && navigator.serviceWorker.controller) {
              notifyServiceWorkerUpdate(registration);
            }
          });
        });

        return registration;
      })
      .catch(function (error) {
        console.warn("TrustSphere service worker registration failed", error);
        return null;
      });
  }

  function isEditableTarget(target) {
    if (!target) {
      return false;
    }
    var tag = target.tagName;
    return (
      target.isContentEditable
      || tag === "INPUT"
      || tag === "TEXTAREA"
      || tag === "SELECT"
    );
  }

  function goToAdminPath(path) {
    var link = document.querySelector('a[href="' + path + '"]');
    if (link) {
      window.location.href = link.href;
    }
  }

  function handleAdminSequence(key) {
    var now = Date.now();
    if (lastAdminShortcutKey !== "g" || now - lastAdminShortcutAt > 1200) {
      lastAdminShortcutKey = key;
      lastAdminShortcutAt = now;
      return false;
    }

    lastAdminShortcutKey = "";
    lastAdminShortcutAt = 0;

    var routes = {
      d: "/admin/dashboard",
      a: "/admin/alerts",
      u: "/admin/users",
      s: "/admin/sessions",
      r: "/admin/reports"
    };

    if (routes[key]) {
      goToAdminPath(routes[key]);
      return true;
    }
    return false;
  }

  function initializeKeyboardShortcuts() {
    if (document.body.getAttribute("data-admin-portal") !== "true") {
      return;
    }

    document.addEventListener("keydown", function (event) {
      if (isEditableTarget(event.target)) {
        return;
      }

      var key = event.key.toLowerCase();

      if ((event.ctrlKey || event.metaKey) && key === "k") {
        var filterInput = document.querySelector('input[type="search"], input[name="search"], input[name="user_id"], input[name="action_contains"]');
        if (filterInput) {
          event.preventDefault();
          filterInput.focus();
        }
        return;
      }

      if (key === "g" || ["d", "a", "u", "s", "r"].indexOf(key) !== -1) {
        if (handleAdminSequence(key)) {
          event.preventDefault();
        }
      }
    });
  }

  window.TrustSphere.csrfToken = csrfToken;
  window.TrustSphere.formatRelativeTime = formatRelativeTime;
  window.TrustSphere.refreshRelativeTimes = refreshRelativeTimes;
  window.TrustSphere.showToast = showToast;
  window.TrustSphere.confirmAction = confirmAction;
  window.TrustSphere.registerServiceWorker = registerServiceWorker;

  enhanceFetchWithCsrf();

  ready(function () {
    initializeBootstrap();
    autoDismissFlashMessages();
    initializeSidebarToggle();
    refreshRelativeTimes();
    window.setInterval(refreshRelativeTimes, 60000);
    initializeConfirmations();
    initializeExpandButtons();
    initializeKeyboardShortcuts();
  });
})();
