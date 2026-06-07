(function () {
  "use strict";

  window.TrustSphereAdmin = window.TrustSphereAdmin || {};

  // ─── helpers ───────────────────────────────────────────────────────────────

  var RISK_COLORS = {
    low: "#1A7A4A",
    medium: "#E67E22",
    high: "#C0392B",
    critical: "#922B21"
  };

  var ACTION_COLORS = {
    allow: "#1A7A4A",
    monitor: "#2980B9",
    stepup: "#E67E22",
    block: "#C0392B"
  };

  function riskColorForScore(score) {
    if (score <= 30) return RISK_COLORS.low;
    if (score <= 60) return RISK_COLORS.medium;
    if (score <= 80) return RISK_COLORS.high;
    return RISK_COLORS.critical;
  }

  function thresholdDatasets(length) {
    function constantArr(val) {
      var arr = [];
      for (var i = 0; i < length; i++) arr.push(val);
      return arr;
    }
    return [
      {
        label: "Low (30)",
        data: constantArr(30),
        borderColor: "#1A7A4A",
        borderDash: [5, 5],
        borderWidth: 1,
        pointRadius: 0,
        fill: false,
        tension: 0
      },
      {
        label: "Medium (60)",
        data: constantArr(60),
        borderColor: "#E67E22",
        borderDash: [5, 5],
        borderWidth: 1,
        pointRadius: 0,
        fill: false,
        tension: 0
      },
      {
        label: "High (80)",
        data: constantArr(80),
        borderColor: "#C0392B",
        borderDash: [5, 5],
        borderWidth: 1,
        pointRadius: 0,
        fill: false,
        tension: 0
      }
    ];
  }

  function formatTimestamp(isoString) {
    var d = new Date(isoString);
    if (isNaN(d.getTime())) return isoString;
    var day = String(d.getDate()).padStart(2, "0");
    var month = String(d.getMonth() + 1).padStart(2, "0");
    var hours = String(d.getHours()).padStart(2, "0");
    var minutes = String(d.getMinutes()).padStart(2, "0");
    return day + "/" + month + " " + hours + ":" + minutes;
  }

  // ─── initRiskDistributionChart ─────────────────────────────────────────────

  function initRiskDistributionChart() {
    var canvas = document.getElementById("ts-risk-dist-chart");
    if (!canvas || !window.Chart) return;

    var rawLabels = canvas.getAttribute("data-chart-labels");
    var rawValues = canvas.getAttribute("data-chart-values");

    var labels, values;
    try {
      labels = JSON.parse(rawLabels);
      values = JSON.parse(rawValues);
    } catch (e) {
      return;
    }

    var total = values.reduce(function (a, b) { return a + b; }, 0);

    new window.Chart(canvas, {
      type: "doughnut",
      data: {
        labels: labels,
        datasets: [
          {
            data: values,
            backgroundColor: [
              RISK_COLORS.low,
              RISK_COLORS.medium,
              RISK_COLORS.high,
              RISK_COLORS.critical
            ],
            borderWidth: 2,
            borderColor: "#ffffff"
          }
        ]
      },
      options: {
        cutout: "65%",
        responsive: true,
        plugins: {
          legend: {
            position: "bottom",
            labels: {
              boxWidth: 12,
              padding: 16,
              font: { size: 12 }
            }
          },
          tooltip: {
            callbacks: {
              label: function (context) {
                var count = context.parsed;
                var pct = total > 0 ? Math.round((count / total) * 100) : 0;
                return context.label + ": " + count + " sessions (" + pct + "%)";
              }
            }
          }
        }
      }
    });
  }

  // ─── initRiskHistoryChart ──────────────────────────────────────────────────

  function initRiskHistoryChart() {
    var canvas = document.getElementById("ts-risk-history");
    if (!canvas || !window.Chart) return;

    var raw = canvas.getAttribute("data-risk-history");
    var events;
    try {
      events = JSON.parse(raw);
    } catch (e) {
      return;
    }
    if (!events || events.length === 0) return;

    var ctx = canvas.getContext("2d");
    var gradient = ctx.createLinearGradient(0, 0, 0, canvas.offsetHeight || 220);
    gradient.addColorStop(0, "rgba(192, 57, 43, 0.35)");
    gradient.addColorStop(1, "rgba(26, 122, 74, 0.05)");

    var labels = events.map(function (e) { return formatTimestamp(e.x); });
    var scores = events.map(function (e) { return e.y; });
    var pointColors = events.map(function (e) {
      return ACTION_COLORS[e.cre_response_action] || "#2980B9";
    });

    var thresholds = thresholdDatasets(events.length);

    new window.Chart(canvas, {
      type: "line",
      data: {
        labels: labels,
        datasets: [
          {
            label: "Risk Score",
            data: scores,
            borderColor: "#C0392B",
            backgroundColor: gradient,
            fill: true,
            tension: 0.3,
            pointBackgroundColor: pointColors,
            pointRadius: 5,
            pointHoverRadius: 8,
            borderWidth: 2
          }
        ].concat(thresholds)
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: {
            ticks: { font: { size: 11 }, maxRotation: 45 },
            grid: { color: "rgba(0,0,0,0.04)" }
          },
          y: {
            min: 0,
            max: 100,
            ticks: { stepSize: 20 },
            grid: { color: "rgba(0,0,0,0.06)" }
          }
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              title: function (items) { return "Event: " + items[0].label; },
              label: function (item) {
                if (item.datasetIndex === 0) {
                  var ev = events[item.dataIndex];
                  return [
                    "Risk Score: " + item.parsed.y,
                    "Action: " + (ev.cre_response_action || "n/a")
                  ];
                }
                return item.dataset.label + ": " + item.parsed.y;
              }
            }
          }
        }
      }
    });
  }

  // ─── initUserGauges ────────────────────────────────────────────────────────

  function initUserGauges() {
    document.querySelectorAll("canvas[data-risk-score]").forEach(function (canvas) {
      if (canvas._gaugeInitialized) return;
      var score = parseInt(canvas.getAttribute("data-risk-score"), 10);
      if (isNaN(score)) return;
      if (typeof window.renderRiskGauge === "function") {
        canvas._gaugeInitialized = true;
        window.renderRiskGauge(canvas.id, score);
      }
    });
  }

  // ─── initDashboardPolling ──────────────────────────────────────────────────

  var _pollInterval = null;
  var _reloadInterval = null;

  function initDashboardPolling() {
    var indicator = document.getElementById("ts-refresh-indicator");
    if (!indicator) return;

    var healthUrl = indicator.getAttribute("data-health-url") || "/api/v1/health";

    function pulse() {
      fetch(healthUrl)
        .then(function (r) {
          if (r.ok) {
            indicator.className = "badge bg-success";
            indicator.textContent = "Live";
          } else {
            throw new Error("non-ok");
          }
        })
        .catch(function () {
          showStaleToast();
        });
    }

    function showStaleToast() {
      var container = document.getElementById("ts-toast-container");
      if (!container) return;
      var id = "ts-stale-toast";
      if (document.getElementById(id)) return;
      var div = document.createElement("div");
      div.id = id;
      div.className = "toast align-items-center text-bg-warning border-0";
      div.setAttribute("role", "alert");
      div.setAttribute("aria-live", "assertive");
      div.innerHTML =
        '<div class="d-flex"><div class="toast-body">Connection issues — data may be stale.</div>' +
        '<button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button></div>';
      container.appendChild(div);
      if (window.bootstrap && window.bootstrap.Toast) {
        new window.bootstrap.Toast(div, { delay: 6000 }).show();
      }
    }

    _pollInterval = window.setInterval(pulse, 30000);

    _reloadInterval = window.setInterval(function () {
      var openModal = document.querySelector(".modal.show");
      if (!openModal) {
        window.location.reload();
      }
    }, 60000);
  }

  // ─── initBulkSelection ─────────────────────────────────────────────────────

  function initBulkSelection() {
    var selectAll = document.getElementById("ts-select-all");
    var bulkActions = document.getElementById("ts-bulk-actions");
    var bulkCount = document.getElementById("ts-bulk-count");
    var bulkDismissBtn = document.getElementById("ts-bulk-dismiss-btn");

    if (!selectAll || !bulkActions) return;

    function updateBulkBar() {
      var checked = document.querySelectorAll(".ts-alert-checkbox:checked");
      var count = checked.length;
      if (bulkCount) bulkCount.textContent = count;
      if (count > 0) {
        bulkActions.classList.remove("d-none");
      } else {
        bulkActions.classList.add("d-none");
      }
    }

    selectAll.addEventListener("change", function () {
      document.querySelectorAll(".ts-alert-checkbox").forEach(function (cb) {
        cb.checked = selectAll.checked;
      });
      updateBulkBar();
    });

    document.querySelectorAll(".ts-alert-checkbox").forEach(function (cb) {
      cb.addEventListener("change", function () {
        var allChecked = document.querySelectorAll(".ts-alert-checkbox").length ===
          document.querySelectorAll(".ts-alert-checkbox:checked").length;
        selectAll.checked = allChecked;
        selectAll.indeterminate = !allChecked &&
          document.querySelectorAll(".ts-alert-checkbox:checked").length > 0;
        updateBulkBar();
      });
    });

    var clearBtn = document.getElementById("ts-bulk-clear");
    if (clearBtn) {
      clearBtn.addEventListener("click", function (e) {
        e.preventDefault();
        selectAll.checked = false;
        selectAll.indeterminate = false;
        document.querySelectorAll(".ts-alert-checkbox").forEach(function (cb) {
          cb.checked = false;
        });
        updateBulkBar();
      });
    }

    if (bulkDismissBtn) {
      bulkDismissBtn.addEventListener("click", function (e) {
        e.preventDefault();
        var checked = document.querySelectorAll(".ts-alert-checkbox:checked");
        if (checked.length === 0) return;
        var form = document.getElementById("ts-bulk-action-form");
        if (!form) return;
        var existing = form.querySelectorAll("input[name='alert_ids']");
        existing.forEach(function (el) { el.remove(); });
        checked.forEach(function (cb) {
          var input = document.createElement("input");
          input.type = "hidden";
          input.name = "alert_ids";
          input.value = cb.value;
          form.appendChild(input);
        });
        form.submit();
      });
    }
  }

  // ─── initAlertRowActions ───────────────────────────────────────────────────

  function initAlertRowActions() {
    document.querySelectorAll(".ts-quick-dismiss-form").forEach(function (form) {
      form.addEventListener("submit", function (e) {
        e.preventDefault();
        var confirmed = window.confirm(
          "Are you sure you want to dismiss this alert? This action will be logged."
        );
        if (confirmed) {
          form.submit();
        }
      });
    });
  }

  // ─── initCollapsibleFilters ────────────────────────────────────────────────

  function initCollapsibleFilters() {
    var filterCollapse = document.getElementById("ts-alert-filters") ||
      document.getElementById("ts-session-filters") ||
      document.getElementById("ts-user-filters");
    if (!filterCollapse) return;

    var storageKey = "ts-filter-open-" + (filterCollapse.id || "default");

    if (window.localStorage && window.localStorage.getItem(storageKey) === "true") {
      filterCollapse.classList.add("show");
    }

    filterCollapse.addEventListener("shown.bs.collapse", function () {
      if (window.localStorage) {
        window.localStorage.setItem(storageKey, "true");
      }
    });

    filterCollapse.addEventListener("hidden.bs.collapse", function () {
      if (window.localStorage) {
        window.localStorage.setItem(storageKey, "false");
      }
    });
  }

  // ─── initTimestampFormatting ───────────────────────────────────────────────

  function initTimestampFormatting() {
    // main.js already handles [data-timestamp] elements globally.
    // If it exposes a global refresh function we call it; otherwise this is a no-op.
    if (typeof window.TrustSphereMain === "object" &&
        typeof window.TrustSphereMain.refreshTimestamps === "function") {
      window.TrustSphereMain.refreshTimestamps();
    }
  }

  // ─── initModalActions ──────────────────────────────────────────────────────

  function initModalActions() {
    // Populate hidden action field in each modal when the trigger button is clicked.
    document.querySelectorAll("[data-action][data-bs-target]").forEach(function (btn) {
      var targetId = btn.getAttribute("data-bs-target");
      if (!targetId) return;
      var modal = document.querySelector(targetId);
      if (!modal) return;

      btn.addEventListener("click", function () {
        var actionField = modal.querySelector("input[name='action']");
        if (actionField) {
          actionField.value = btn.getAttribute("data-action");
        }
        // Populate user / alert IDs if present.
        ["user-id", "alert-id", "session-id"].forEach(function (attr) {
          var val = btn.getAttribute("data-" + attr);
          if (!val) return;
          var fieldName = attr.replace("-", "_");
          var field = modal.querySelector("input[name='" + fieldName + "']");
          if (field) field.value = val;
        });
      });
    });

    // Institution filter dropdown: auto-submit on change.
    var instFilter = document.getElementById("ts-institution-filter");
    if (instFilter) {
      instFilter.addEventListener("change", function () {
        var form = document.getElementById("ts-institution-filter-form");
        if (form) form.submit();
      });
    }
  }

  // ─── DOMContentLoaded ─────────────────────────────────────────────────────

  document.addEventListener("DOMContentLoaded", function () {
    initRiskDistributionChart();
    initRiskHistoryChart();
    initUserGauges();
    initDashboardPolling();
    initBulkSelection();
    initAlertRowActions();
    initCollapsibleFilters();
    initTimestampFormatting();
    initModalActions();
  });

  // Expose for external use if needed.
  window.TrustSphereAdmin.initRiskDistributionChart = initRiskDistributionChart;
  window.TrustSphereAdmin.initRiskHistoryChart = initRiskHistoryChart;
  window.TrustSphereAdmin.initUserGauges = initUserGauges;
})();

