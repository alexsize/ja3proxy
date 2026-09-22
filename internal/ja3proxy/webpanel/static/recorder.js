"use strict";
const byId = id => document.getElementById(id);
let selectedA = "", selectedB = "", nextCursor = "";
async function api(path) {
  const response = await fetch(path, {cache: "no-store"});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}
function fail(error) { byId("status").textContent = error.message; byId("status").className = "error"; }
function button(label, action) { const b = document.createElement("button"); b.type = "button"; b.textContent = label; b.addEventListener("click", action); return b; }
function select(slot, id) {
  if (slot === "A") selectedA = id; else selectedB = id;
  byId("selection").textContent = `A: ${selectedA || "—"}   B: ${selectedB || "—"}`;
  byId("compare").disabled = !(selectedA && selectedB);
}
async function refresh(cursor = "") {
  try {
    const status = await api("/api/v1/status");
    byId("status").className = status.stats.recording_degraded ? "error" : "";
    byId("status").textContent = status.enabled ? `Обработано: ${status.stats.processed}; очередь: ${status.stats.queue_depth}; потеряно: ${status.stats.dropped}; ошибки экспорта: ${status.stats.write_errors}.` : "Recorder выключен. Запустите proxy с --capture-tls.";
    const params = new URLSearchParams({q: byId("query").value, limit: "50"});
    if (cursor) params.set("cursor", cursor);
    const data = await api(`/api/v1/observations?${params}`);
    const body = byId("observations"); body.replaceChildren();
    for (const observation of data.items) {
      const row = document.createElement("tr");
	  const fingerprint = observation.fingerprints?.ja4 || `${observation.completeness}: ${observation.error_code || ""}`;
	  const verified = observation.verification?.status ? `${fingerprint} · ${observation.verification.status}` : fingerprint;
	  for (const value of [new Date(observation.captured_at).toLocaleTimeString(), observation.destination, observation.capture_point, observation.mode, verified]) {
        const cell = document.createElement("td"); cell.textContent = value; row.append(cell);
      }
      const detail = document.createElement("td");
      detail.append(button("JSON", async () => {try {byId("detail").textContent = JSON.stringify(await api(`/api/v1/observations/${encodeURIComponent(observation.id)}`), null, 2);} catch(error) {fail(error);}}), button("В профиль", () => {location.href=`/profiles.html?observation=${encodeURIComponent(observation.id)}`;})); row.append(detail);
      const picks = document.createElement("td"); picks.append(button("A", () => select("A", observation.id)), button("B", () => select("B", observation.id))); row.append(picks); body.append(row);
    }
    if (!data.items.length) {const row=document.createElement("tr"), cell=document.createElement("td");cell.colSpan=7;cell.textContent="Наблюдений нет. Подключите TLS-клиент или измените поиск.";row.append(cell);body.append(row);}
    nextCursor = data.next_cursor || ""; byId("more").hidden = !nextCursor;
  } catch(error) { fail(error); }
}
byId("search").addEventListener("submit", event => {event.preventDefault();refresh();});
byId("refresh").addEventListener("click", () => refresh());
byId("more").addEventListener("click", () => refresh(nextCursor));
byId("compare").addEventListener("click", async () => {try {byId("diff").textContent = JSON.stringify(await api(`/api/v1/fingerprints/diff?${new URLSearchParams({a:selectedA,b:selectedB})}`),null,2);}catch(error){fail(error);}});
refresh();
