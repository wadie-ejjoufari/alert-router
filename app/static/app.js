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
