function toggleAlertRow(row) {
  const detail = document.getElementById(row.getAttribute("data-target"));
  const chevron = row.querySelector(".chevron");
  const expanded = row.getAttribute("aria-expanded") === "true";
  row.setAttribute("aria-expanded", String(!expanded));
  detail.hidden = expanded;
  if (chevron) chevron.innerHTML = expanded ? "&#9656;" : "&#9662;";
}

document.querySelectorAll(".alert-row").forEach((row) => {
  row.addEventListener("click", () => toggleAlertRow(row));
  row.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      toggleAlertRow(row);
    }
  });
});

// Test-alert form: prefill from a named template, randomize, or leave as a blank
// custom alert — all three end up as the same set of editable fields the form submits.
(function () {
  const dataEl = document.getElementById("demo-data");
  if (!dataEl) return;

  const data = JSON.parse(dataEl.textContent);
  const templatesById = {};
  data.templates.forEach((t) => { templatesById[t.id] = t.payload; });

  const FIELD_KEYS = [
    "source", "alert_type", "severity", "asset_id",
    "asset_criticality", "indicator_type", "indicator_value", "message",
  ];

  function fillFields(payload) {
    FIELD_KEYS.forEach((key) => {
      const el = document.getElementById("f-" + key);
      if (el) el.value = payload[key] || "";
    });
  }

  function randomChoice(list) {
    return list[Math.floor(Math.random() * list.length)];
  }

  function randomPayload() {
    const pool = data.random_pool;
    const indicator = randomChoice(pool.indicator);
    return {
      source: randomChoice(pool.source),
      alert_type: randomChoice(pool.alert_type),
      severity: randomChoice(pool.severity),
      asset_id: randomChoice(pool.asset_id),
      asset_criticality: randomChoice(pool.asset_criticality),
      message: randomChoice(pool.message),
      indicator_type: indicator.indicator_type,
      indicator_value: indicator.indicator_value,
    };
  }

  const select = document.getElementById("scenario-select");
  const randomizeBtn = document.getElementById("randomize-btn");

  function applyScenario(value) {
    if (value === "random") {
      fillFields(randomPayload());
    } else if (templatesById[value]) {
      fillFields(templatesById[value]);
    } else {
      fillFields({});
    }
  }

  if (select) {
    select.addEventListener("change", () => applyScenario(select.value));
  }
  if (randomizeBtn) {
    randomizeBtn.addEventListener("click", () => {
      if (select) select.value = "random";
      fillFields(randomPayload());
    });
  }

  // First-load convenience: an untouched, empty form gets seeded with the first
  // template. A form re-rendered after a validation error keeps what was submitted,
  // even if that means showing the empty fields that caused the error.
  const form = document.getElementById("demo-form");
  const sourceField = document.getElementById("f-source");
  const hadError = form && form.dataset.hadError === "true";
  if (!hadError && sourceField && !sourceField.value && data.templates.length) {
    const first = data.templates[0];
    if (select) select.value = first.id;
    fillFields(first.payload);
  }
})();
