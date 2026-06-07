(function () {
  "use strict";

  var chartRegistry = {};

  function getRiskCategory(score) {
    if (score <= 30) {
      return "Low";
    }
    if (score <= 60) {
      return "Medium";
    }
    if (score <= 80) {
      return "High";
    }
    return "Critical";
  }

  function getRiskColor(score) {
    if (score <= 30) {
      return "#1A7A4A";
    }
    if (score <= 60) {
      return "#E67E22";
    }
    return "#C0392B";
  }

  function clampScore(score) {
    var parsed = Number(score);
    if (Number.isNaN(parsed)) {
      return 0;
    }
    return Math.max(0, Math.min(100, Math.round(parsed)));
  }

  var centerTextPlugin = {
    id: "tsCenterText",
    afterDraw: function (chart) {
      var meta = chart.options.plugins.tsCenterText || {};
      var score = clampScore(meta.score || 0);
      var category = meta.category || getRiskCategory(score);
      var color = meta.color || getRiskColor(score);
      var ctx = chart.ctx;
      var chartArea = chart.chartArea;
      if (!chartArea) {
        return;
      }

      var centerX = (chartArea.left + chartArea.right) / 2;
      var centerY = chartArea.bottom - ((chartArea.bottom - chartArea.top) * 0.16);

      ctx.save();
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";

      ctx.fillStyle = color;
      ctx.font = "700 2rem Inter, sans-serif";
      ctx.fillText(String(score), centerX, centerY - 10);

      ctx.fillStyle = "#6C757D";
      ctx.font = "500 1rem Inter, sans-serif";
      ctx.fillText(category, centerX, centerY + 20);
      ctx.restore();
    }
  };

  if (window.Chart && !window.Chart.registry.plugins.get("tsCenterText")) {
    window.Chart.register(centerTextPlugin);
  }

  function renderRiskGauge(canvasId, riskScore) {
    if (!window.Chart) {
      return null;
    }
    var canvas = document.getElementById(canvasId);
    if (!canvas) {
      return null;
    }

    var score = clampScore(riskScore);
    var fillColor = getRiskColor(score);
    var category = getRiskCategory(score);

    if (score > 80 && canvas.parentElement) {
      canvas.parentElement.classList.add("ts-risk-pulse");
    } else if (canvas.parentElement) {
      canvas.parentElement.classList.remove("ts-risk-pulse");
    }

    if (chartRegistry[canvasId]) {
      chartRegistry[canvasId].destroy();
      delete chartRegistry[canvasId];
    }

    var chart = new window.Chart(canvas, {
      type: "doughnut",
      data: {
        datasets: [
          {
            data: [score, 100 - score, 100],
            backgroundColor: [fillColor, "rgba(0, 0, 0, 0.06)", "transparent"],
            borderWidth: 0,
            hoverOffset: 0
          },
          {
            data: [100, 100],
            backgroundColor: ["rgba(0, 0, 0, 0.08)", "transparent"],
            borderWidth: 0,
            hoverOffset: 0,
            cutout: "75%"
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        rotation: -90,
        circumference: 180,
        cutout: "75%",
        animation: {
          duration: 1200
        },
        plugins: {
          legend: {
            display: false
          },
          tooltip: {
            enabled: false
          },
          tsCenterText: {
            score: score,
            category: category,
            color: fillColor
          }
        }
      }
    });

    chartRegistry[canvasId] = chart;
    return chart;
  }

  function updateGauge(canvasId, newScore) {
    var chart = chartRegistry[canvasId];
    if (!chart) {
      return renderRiskGauge(canvasId, newScore);
    }

    var score = clampScore(newScore);
    var fillColor = getRiskColor(score);
    var category = getRiskCategory(score);
    chart.data.datasets[0].data = [score, 100 - score, 100];
    chart.data.datasets[0].backgroundColor = [fillColor, "rgba(0, 0, 0, 0.06)", "transparent"];
    chart.options.plugins.tsCenterText = {
      score: score,
      category: category,
      color: fillColor
    };
    chart.update("active");
    return chart;
  }

  document.addEventListener("DOMContentLoaded", function () {
    var canvases = document.querySelectorAll("canvas[data-risk-score]");
    canvases.forEach(function (canvas, index) {
      if (!canvas.id) {
        canvas.id = "ts-risk-gauge-" + index;
      }
      renderRiskGauge(canvas.id, parseInt(canvas.dataset.riskScore || "0", 10));
    });
  });

  window.renderRiskGauge = renderRiskGauge;
  window.updateGauge = updateGauge;
})();
