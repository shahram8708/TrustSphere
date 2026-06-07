(function () {
  "use strict";

  // ─── helpers ───────────────────────────────────────────────────────────────

  var ACTION_COLORS = {
    allow: "#1A7A4A",
    monitor: "#2980B9",
    stepup: "#E67E22",
    block: "#C0392B"
  };

  var THRESHOLD_DASHED = [5, 5];

  function thresholdDatasets(length) {
    function constantArr(val) {
      var arr = [];
      for (var i = 0; i < length; i++) arr.push(val);
      return arr;
    }
    return [
      {
        label: "Low threshold (30)",
        data: constantArr(30),
        borderColor: "#1A7A4A",
        borderDash: THRESHOLD_DASHED,
        borderWidth: 1,
        pointRadius: 0,
        fill: false,
        tension: 0,
        order: 10
      },
      {
        label: "Medium threshold (60)",
        data: constantArr(60),
        borderColor: "#E67E22",
        borderDash: THRESHOLD_DASHED,
        borderWidth: 1,
        pointRadius: 0,
        fill: false,
        tension: 0,
        order: 10
      },
      {
        label: "High threshold (80)",
        data: constantArr(80),
        borderColor: "#C0392B",
        borderDash: THRESHOLD_DASHED,
        borderWidth: 1,
        pointRadius: 0,
        fill: false,
        tension: 0,
        order: 10
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

  function actionLabel(action) {
    var map = {
      allow: "Allowed",
      monitor: "Monitoring",
      stepup: "Step-Up Triggered",
      block: "Blocked"
    };
    return map[action] || action || "Unknown";
  }

  // ─── vertical stepup plugin ───────────────────────────────────────────────

  var stepUpPlugin = {
    id: "ts-stepup-lines",
    afterDraw: function (chart) {
      var meta = chart.data.datasets[0]._stepupIndexes;
      if (!meta || meta.length === 0) return;
      var ctx = chart.ctx;
      var xAxis = chart.scales.x;
      var yAxis = chart.scales.y;

      ctx.save();
      ctx.strokeStyle = "#E67E22";
      ctx.lineWidth = 1.5;
      ctx.setLineDash([4, 4]);
      ctx.globalAlpha = 0.7;

      meta.forEach(function (idx) {
        var x = xAxis.getPixelForValue(idx);
        ctx.beginPath();
        ctx.moveTo(x, yAxis.top);
        ctx.lineTo(x, yAxis.bottom);
        ctx.stroke();
      });

      ctx.restore();
    }
  };

  if (window.Chart) {
    window.Chart.register(stepUpPlugin);
  }

  // ─── showEmptyState ────────────────────────────────────────────────────────

  function showEmptyState(canvas) {
    canvas.style.display = "none";
    var wrapper = canvas.parentNode;
    var info = document.createElement("div");
    info.className = "alert alert-info mb-0";
    info.setAttribute("role", "alert");
    info.innerHTML =
      '<i class="bi bi-info-circle me-2"></i>' +
      "No session event data available for this alert.";
    wrapper.appendChild(info);
  }

  // ─── initSessionTimeline ──────────────────────────────────────────────────

  function initSessionTimeline() {
    var canvas = document.getElementById("ts-session-timeline");
    if (!canvas || !window.Chart) return;

    var raw = canvas.getAttribute("data-timeline");
    var events;
    try {
      events = JSON.parse(raw);
    } catch (e) {
      showEmptyState(canvas);
      return;
    }

    if (!events || events.length === 0) {
      showEmptyState(canvas);
      return;
    }

    var ctx = canvas.getContext("2d");

    // Build gradient: red at the top (high risk) fading down.
    var gradient = ctx.createLinearGradient(0, 0, 0, canvas.clientHeight || 280);
    gradient.addColorStop(0, "rgba(192, 57, 43, 0.45)");
    gradient.addColorStop(0.6, "rgba(192, 57, 43, 0.12)");
    gradient.addColorStop(1, "rgba(192, 57, 43, 0.01)");

    var xLabels = events.map(function (ev, idx) { return idx; });
    var scores = events.map(function (ev) { return ev.risk; });

    var pointColors = events.map(function (ev) {
      return ACTION_COLORS[ev.action] || "#2980B9";
    });

    var pointRadii = events.map(function (ev) {
      return (ev.action === "block" || ev.action === "stepup") ? 6 : 4;
    });

    var pointHitRadii = events.map(function () { return 15; });

    var stepupIndexes = [];
    events.forEach(function (ev, idx) {
      if (ev.action === "stepup") stepupIndexes.push(idx);
    });

    var mainDataset = {
      label: "Risk Score",
      data: scores,
      borderColor: "#C0392B",
      backgroundColor: gradient,
      fill: true,
      tension: 0.3,
      pointBackgroundColor: pointColors,
      pointBorderColor: pointColors,
      pointRadius: pointRadii,
      pointHoverRadius: pointRadii.map(function (r) { return r + 3; }),
      pointHitRadius: pointHitRadii,
      borderWidth: 2,
      order: 1,
      // Custom property consumed by the stepup plugin.
      _stepupIndexes: stepupIndexes
    };

    var thresholds = thresholdDatasets(events.length);

    new window.Chart(canvas, {
      type: "line",
      data: {
        labels: xLabels,
        datasets: [mainDataset].concat(thresholds)
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: {
          duration: 800,
          easing: "easeInOutQuart"
        },
        scales: {
          x: {
            title: {
              display: true,
              text: "Event Sequence",
              font: { size: 11 }
            },
            ticks: { font: { size: 11 } },
            grid: { color: "rgba(0,0,0,0.04)" }
          },
          y: {
            min: 0,
            max: 100,
            title: {
              display: true,
              text: "Risk Score",
              font: { size: 11 }
            },
            ticks: { stepSize: 20 },
            grid: { color: "rgba(0,0,0,0.06)" }
          }
        },
        plugins: {
          legend: {
            display: true,
            position: "bottom",
            labels: {
              filter: function (item) {
                // Hide threshold legend unless user explicitly wants to see them.
                return item.datasetIndex === 0;
              },
              boxWidth: 12
            }
          },
          tooltip: {
            callbacks: {
              title: function (items) {
                var idx = items[0].dataIndex;
                var ev = events[idx];
                return ev ? (ev.label || "Event " + idx) : "Event " + idx;
              },
              label: function (item) {
                if (item.datasetIndex !== 0) return null;
                var ev = events[item.dataIndex];
                if (!ev) return "Risk: " + item.parsed.y;
                var ts = ev.timestamp
                  ? formatTimestamp(ev.timestamp)
                  : "";
                var lines = [
                  "Risk Score: " + ev.risk,
                  "Action: " + actionLabel(ev.action)
                ];
                if (ts) lines.push("Time: " + ts);
                return lines;
              },
              filter: function (item) {
                return item.datasetIndex === 0;
              }
            },
            displayColors: true,
            backgroundColor: "rgba(30,30,30,0.88)",
            titleColor: "#ffffff",
            bodyColor: "#cccccc",
            padding: 10,
            cornerRadius: 6
          }
        }
      }
    });
  }

  // ─── auto-initialize ──────────────────────────────────────────────────────

  document.addEventListener("DOMContentLoaded", function () {
    initSessionTimeline();
  });

  window.TrustSphereAdmin = window.TrustSphereAdmin || {};
  window.TrustSphereAdmin.initSessionTimeline = initSessionTimeline;
})();
