// Expand / collapse a triage row's evidence. Kept in a file: the CSP allows no inline scripts.
document.addEventListener("click", function (e) {
  var b = e.target.closest("button.toggle");
  if (!b) return;
  var row = document.getElementById(b.dataset.target);
  if (!row) return;
  row.hidden = !row.hidden;
  b.textContent = row.hidden ? "+" : "−";
  b.setAttribute("aria-expanded", String(!row.hidden));
});
