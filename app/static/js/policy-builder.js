(function () {
  "use strict";

  var alertDistribution = { Low: 0, Medium: 0, High: 0, Critical: 0 };

  function toInt(value, fallback) {
    var num = parseInt(value, 10);
    return Number.isNaN(num) ? fallback : num;
  }

  function toFloat(value, fallback) {
    var num = parseFloat(value);
    return Number.isNaN(num) ? fallback : num;
  }

  function getForm() {
    return document.getElementById("ts-policy-form");
  }

  function getRulesTableBody() {
    var table = document.getElementById("ts-rules-table");
    return table ? table.querySelector("tbody") : null;
  }

  function parseJsonDataset(value, fallback) {
    if (!value) {
      return fallback;
    }
    try {
      var parsed = JSON.parse(value);
      return parsed == null ? fallback : parsed;
    } catch (err) {
      return fallback;
    }
  }

  function normalizeRule(rule) {
    return {
      risk_min: toInt(rule && rule.risk_min, 31),
      risk_max: toInt(rule && rule.risk_max, 60),
      channel: (rule && rule.channel) || "all",
      verification_method: (rule && rule.verification_method) || "otp",
      timeout_seconds: toInt(rule && rule.timeout_seconds, 120)
    };
  }

  function createSelect(options, cssClass, value) {
    var select = document.createElement("select");
    select.className = "form-select form-select-sm " + cssClass;

    options.forEach(function (item) {
      var option = document.createElement("option");
      option.value = item;
      option.textContent = item.replace(/_/g, " ");
      if (item === value) {
        option.selected = true;
      }
      select.appendChild(option);
    });

    return select;
  }

  function createNumberInput(cssClass, min, max, value) {
    var input = document.createElement("input");
    input.type = "number";
    input.className = "form-control form-control-sm " + cssClass;
    input.min = String(min);
    input.max = String(max);
    input.value = String(value);
    return input;
  }

  function createCell(child) {
    var td = document.createElement("td");
    td.appendChild(child);
    return td;
  }

  function createRuleRow(rule) {
    var data = normalizeRule(rule || {});
    var tr = document.createElement("tr");

    tr.appendChild(createCell(createNumberInput("ts-rule-risk-min", 0, 100, data.risk_min)));
    tr.appendChild(createCell(createNumberInput("ts-rule-risk-max", 0, 100, data.risk_max)));

    var channelSelect = createSelect(["all", "mobile_app", "web_browser", "api", "atm"], "ts-rule-channel", data.channel);
    tr.appendChild(createCell(channelSelect));

    var methodSelect = createSelect([
      "push_notification",
      "biometric",
      "otp",
      "video_kyc",
      "agent_call"
    ], "ts-rule-method", data.verification_method);
    tr.appendChild(createCell(methodSelect));

    tr.appendChild(createCell(createNumberInput("ts-rule-timeout", 30, 600, data.timeout_seconds)));

    var removeBtn = document.createElement("button");
    removeBtn.type = "button";
    removeBtn.className = "btn btn-sm btn-outline-danger ts-remove-rule";
    removeBtn.innerHTML = '<i class="bi bi-trash"></i>';
    tr.appendChild(createCell(removeBtn));

    return tr;
  }

  function renderRuleRows(rulesArray) {
    var tbody = getRulesTableBody();
    if (!tbody) {
      return;
    }

    tbody.innerHTML = "";
    (rulesArray || []).forEach(function (rule) {
      tbody.appendChild(createRuleRow(rule));
    });

    serializeRules();
  }

  function serializeRules() {
    var tbody = getRulesTableBody();
    var hidden = document.getElementById("stepup_rules_json");
    if (!tbody || !hidden) {
      return [];
    }

    var rules = [];
    var rows = tbody.querySelectorAll("tr");

    rows.forEach(function (row) {
      var riskMin = toInt(row.querySelector(".ts-rule-risk-min") && row.querySelector(".ts-rule-risk-min").value, 0);
      var riskMax = toInt(row.querySelector(".ts-rule-risk-max") && row.querySelector(".ts-rule-risk-max").value, 100);
      var channel = (row.querySelector(".ts-rule-channel") && row.querySelector(".ts-rule-channel").value) || "all";
      var method = (row.querySelector(".ts-rule-method") && row.querySelector(".ts-rule-method").value) || "otp";
      var timeout = toInt(row.querySelector(".ts-rule-timeout") && row.querySelector(".ts-rule-timeout").value, 120);

      rules.push({
        risk_min: riskMin,
        risk_max: riskMax,
        channel: channel,
        verification_method: method,
        timeout_seconds: timeout
      });
    });

    hidden.value = JSON.stringify(rules);
    return rules;
  }

  function syncThresholdHiddenInputs() {
    var low = document.getElementById("ts-slider-low");
    var medium = document.getElementById("ts-slider-medium");
    var high = document.getElementById("ts-slider-high");

    var lowHidden = document.getElementById("threshold_low");
    var mediumHidden = document.getElementById("threshold_medium");
    var highHidden = document.getElementById("threshold_high");

    if (low && lowHidden) {
      lowHidden.value = low.value;
    }
    if (medium && mediumHidden) {
      mediumHidden.value = medium.value;
    }
    if (high && highHidden) {
      highHidden.value = high.value;
    }

    var lowVal = document.getElementById("ts-val-low");
    var mediumVal = document.getElementById("ts-val-medium");
    var highVal = document.getElementById("ts-val-high");

    if (lowVal && low) {
      lowVal.textContent = low.value;
    }
    if (mediumVal && medium) {
      mediumVal.textContent = medium.value;
    }
    if (highVal && high) {
      highVal.textContent = high.value;
    }
  }

  function clampThresholds(source) {
    var low = document.getElementById("ts-slider-low");
    var medium = document.getElementById("ts-slider-medium");
    var high = document.getElementById("ts-slider-high");

    if (!low || !medium || !high) {
      return;
    }

    var lowVal = toInt(low.value, 30);
    var mediumVal = toInt(medium.value, 60);
    var highVal = toInt(high.value, 80);

    if (source === "low") {
      if (lowVal >= mediumVal) {
        mediumVal = Math.min(95, lowVal + 5);
      }
      if (mediumVal >= highVal) {
        highVal = Math.min(99, mediumVal + 5);
      }
    }

    if (source === "medium") {
      if (mediumVal <= lowVal) {
        lowVal = Math.max(5, mediumVal - 5);
      }
      if (mediumVal >= highVal) {
        highVal = Math.min(99, mediumVal + 5);
      }
    }

    if (source === "high") {
      if (highVal <= mediumVal) {
        mediumVal = Math.max(10, highVal - 5);
      }
      if (mediumVal <= lowVal) {
        lowVal = Math.max(5, mediumVal - 5);
      }
    }

    low.value = String(lowVal);
    medium.value = String(mediumVal);
    high.value = String(highVal);

    syncThresholdHiddenInputs();
    updateThresholdPreview();
  }

  function buildApproxDistribution(low, medium, high) {
    var baseLow = toInt(alertDistribution.Low, 0);
    var baseMedium = toInt(alertDistribution.Medium, 0);
    var baseHigh = toInt(alertDistribution.High, 0);
    var baseCritical = toInt(alertDistribution.Critical, 0);

    var deltaLow = low - 30;
    var deltaMedium = medium - 60;
    var deltaHigh = high - 80;

    var shiftMedToLow = Math.round(baseMedium * (deltaLow / 30));
    var shiftHighToMed = Math.round(baseHigh * (deltaMedium / 40));
    var shiftCriticalToHigh = Math.round(baseCritical * (deltaHigh / 20));

    var newLow = baseLow + shiftMedToLow;
    var newMedium = baseMedium - shiftMedToLow + shiftHighToMed;
    var newHigh = baseHigh - shiftHighToMed + shiftCriticalToHigh;
    var newCritical = baseCritical - shiftCriticalToHigh;

    return {
      low: Math.max(0, newLow),
      medium: Math.max(0, newMedium),
      high: Math.max(0, newHigh),
      critical: Math.max(0, newCritical)
    };
  }

  function setPreviewBar(key, count, total) {
    var bar = document.getElementById("ts-preview-" + key);
    var label = document.getElementById("ts-preview-" + key + "-label");
    if (!bar || !label) {
      return;
    }

    var pct = total > 0 ? (count / total) * 100 : 0;
    bar.style.width = pct.toFixed(1) + "%";
    bar.textContent = pct.toFixed(1) + "%";
    label.textContent = String(count) + " events";
  }

  function updateThresholdPreview() {
    var low = document.getElementById("ts-slider-low");
    var medium = document.getElementById("ts-slider-medium");
    var high = document.getElementById("ts-slider-high");

    if (!low || !medium || !high) {
      return;
    }

    var lowVal = toInt(low.value, 30);
    var medVal = toInt(medium.value, 60);
    var highVal = toInt(high.value, 80);

    var approx = buildApproxDistribution(lowVal, medVal, highVal);
    var total = approx.low + approx.medium + approx.high + approx.critical;

    setPreviewBar("low", approx.low, total);
    setPreviewBar("medium", approx.medium, total);
    setPreviewBar("high", approx.high, total);
    setPreviewBar("critical", approx.critical, total);
  }

  function updateWeightSum() {
    var fields = document.querySelectorAll(".ts-weight-input");
    var sumElement = document.getElementById("ts-weight-sum");
    if (!sumElement || !fields.length) {
      return;
    }

    var sum = 0;
    fields.forEach(function (field) {
      sum += toFloat(field.value, 0);
    });

    sumElement.textContent = sum.toFixed(2);
    sumElement.classList.remove("text-success", "text-danger");
    if (sum >= 0.95 && sum <= 1.05) {
      sumElement.classList.add("text-success");
    } else {
      sumElement.classList.add("text-danger");
    }
  }

  function collectChannelPolicies() {
    var cards = document.querySelectorAll(".ts-channel-card");
    var payload = {};

    cards.forEach(function (card) {
      var channel = card.getAttribute("data-channel");
      if (!channel) {
        return;
      }
      var enabledEl = card.querySelector(".ts-channel-enabled");
      var multiplierEl = card.querySelector(".ts-channel-multiplier");
      var thresholdEl = card.querySelector(".ts-channel-threshold");

      payload[channel] = {
        enabled: !!(enabledEl && enabledEl.checked),
        risk_multiplier: toFloat(multiplierEl && multiplierEl.value, 1),
        stepup_threshold: toInt(thresholdEl && thresholdEl.value, 60)
      };
    });

    var hidden = document.getElementById("channel_policies_json");
    if (hidden) {
      hidden.value = JSON.stringify(payload);
    }
  }

  function getCsrfToken(form) {
    var meta = document.querySelector('meta[name="csrf-token"]');
    if (meta && meta.content) {
      return meta.content;
    }
    var csrfInput = form.querySelector('input[name="csrf_token"]');
    return csrfInput ? csrfInput.value : "";
  }

  function showTestResult(html, type) {
    var container = document.getElementById("ts-test-result");
    if (!container) {
      return;
    }

    container.classList.remove("d-none");
    container.innerHTML = '<div class="alert alert-' + type + ' mb-0 py-2">' + html + "</div>";
  }

  function testFirstRule(form) {
    var testBtn = document.getElementById("ts-test-rule-btn");
    if (!testBtn) {
      return;
    }

    var rules = serializeRules();
    if (!rules.length) {
      showTestResult("Add at least one rule to test.", "warning");
      return;
    }

    var testUrl = testBtn.getAttribute("data-test-url") || form.getAttribute("data-test-rule-url") || "";
    if (!testUrl) {
      showTestResult("Test endpoint is not configured.", "danger");
      return;
    }

    var firstRule = rules[0];
    showTestResult('<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Testing selected rule...', "secondary");

    fetch(testUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": getCsrfToken(form)
      },
      body: JSON.stringify(firstRule)
    })
      .then(function (response) {
        return response.json().then(function (payload) {
          return { ok: response.ok, payload: payload };
        });
      })
      .then(function (result) {
        if (!result.ok || !result.payload || result.payload.status !== "success") {
          var errorMsg = (result.payload && result.payload.message) || "Rule test failed.";
          showTestResult(errorMsg, "danger");
          return;
        }

        var data = result.payload.data || {};
        var count = toInt(data.match_count, 0);
        var pct = toFloat(data.match_percentage, toFloat(data.match_pct, 0));
        var message = "This rule would trigger on <strong>" + count + "</strong> of the last 100 sessions (" + pct.toFixed(1) + "%).";

        var samples = data.sample_matches || [];
        if (samples.length) {
          message += "<ul class=\"mt-2 mb-0 small\">";
          samples.slice(0, 3).forEach(function (sample) {
            var user = sample.masked_user_id || "Protected";
            var score = sample.risk_score_peak != null ? sample.risk_score_peak : sample.risk_score;
            message += "<li>" + user + " | " + (sample.channel || "unknown") + " | risk " + score + "</li>";
          });
          message += "</ul>";
        }

        showTestResult(message, "success");
      })
      .catch(function () {
        showTestResult("Unable to test this rule right now.", "danger");
      });
  }

  function bindRuleTableEvents() {
    var tbody = getRulesTableBody();
    if (!tbody) {
      return;
    }

    tbody.addEventListener("click", function (event) {
      var removeBtn = event.target.closest(".ts-remove-rule");
      if (!removeBtn) {
        return;
      }
      var row = removeBtn.closest("tr");
      if (row) {
        row.remove();
      }
      serializeRules();
    });

    tbody.addEventListener("input", function () {
      serializeRules();
    });

    tbody.addEventListener("change", function () {
      serializeRules();
    });
  }

  function bindThresholdEvents() {
    var low = document.getElementById("ts-slider-low");
    var medium = document.getElementById("ts-slider-medium");
    var high = document.getElementById("ts-slider-high");

    if (low) {
      low.addEventListener("input", function () {
        clampThresholds("low");
      });
    }
    if (medium) {
      medium.addEventListener("input", function () {
        clampThresholds("medium");
      });
    }
    if (high) {
      high.addEventListener("input", function () {
        clampThresholds("high");
      });
    }

    var resetBtn = document.getElementById("ts-reset-thresholds") || document.getElementById("ts-reset-defaults");
    if (resetBtn) {
      resetBtn.addEventListener("click", function () {
        if (low) {
          low.value = "30";
        }
        if (medium) {
          medium.value = "60";
        }
        if (high) {
          high.value = "80";
        }
        syncThresholdHiddenInputs();
        updateThresholdPreview();
      });
    }
  }

  function bindWeightEvents() {
    var fields = document.querySelectorAll(".ts-weight-input");
    fields.forEach(function (field) {
      field.addEventListener("input", updateWeightSum);
    });

    var restoreBtn = document.getElementById("ts-restore-weights");
    if (restoreBtn) {
      restoreBtn.addEventListener("click", function () {
        var defaults = [0.25, 0.20, 0.15, 0.15, 0.15, 0.10];
        fields.forEach(function (field, index) {
          if (defaults[index] != null) {
            field.value = defaults[index].toFixed(2);
          }
        });
        updateWeightSum();
      });
    }

    updateWeightSum();
  }

  function bindChannelPolicyEvents() {
    var cards = document.querySelectorAll(".ts-channel-card");
    cards.forEach(function (card) {
      var toggle = card.querySelector(".ts-channel-enabled");
      var settings = card.querySelector(".ts-channel-settings");
      if (toggle && settings) {
        toggle.addEventListener("change", function () {
          settings.classList.toggle("d-none", !toggle.checked);
          collectChannelPolicies();
        });
      }

      card.querySelectorAll(".ts-channel-multiplier, .ts-channel-threshold").forEach(function (input) {
        input.addEventListener("input", collectChannelPolicies);
        input.addEventListener("change", collectChannelPolicies);
      });
    });

    collectChannelPolicies();
  }

  function initPolicyForm() {
    var form = getForm();
    if (!form) {
      return;
    }

    var initialRules = parseJsonDataset(form.getAttribute("data-stepup-rules"), []);
    renderRuleRows(Array.isArray(initialRules) ? initialRules : []);

    var distribution = parseJsonDataset(form.getAttribute("data-alert-distribution"), {});
    if (distribution && typeof distribution === "object") {
      alertDistribution = {
        Low: toInt(distribution.Low, 0),
        Medium: toInt(distribution.Medium, 0),
        High: toInt(distribution.High, 0),
        Critical: toInt(distribution.Critical, 0)
      };
    }

    syncThresholdHiddenInputs();
    updateThresholdPreview();

    bindRuleTableEvents();
    bindThresholdEvents();
    bindWeightEvents();
    bindChannelPolicyEvents();

    var addRuleBtn = document.getElementById("ts-add-rule-btn") || document.getElementById("ts-add-rule");
    if (addRuleBtn) {
      addRuleBtn.addEventListener("click", function () {
        var tbody = getRulesTableBody();
        if (!tbody) {
          return;
        }
        tbody.appendChild(createRuleRow({
          risk_min: 31,
          risk_max: 60,
          channel: "all",
          verification_method: "otp",
          timeout_seconds: 120
        }));
        serializeRules();
      });
    }

    var testRuleBtn = document.getElementById("ts-test-rule-btn");
    if (testRuleBtn) {
      testRuleBtn.addEventListener("click", function () {
        testFirstRule(form);
      });
    }

    form.addEventListener("submit", function () {
      serializeRules();
      collectChannelPolicies();
    });
  }

  document.addEventListener("DOMContentLoaded", initPolicyForm);
})();
