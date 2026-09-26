"use strict";
const byId = id => document.getElementById(id);

async function loadFingerprintFamilies() {
  const container = byId("families");
  if (!container) return;
  container.textContent = "Загрузка семейств…";
  try {
    const result = await api("/api/v1/fingerprint-families");
    container.replaceChildren();
    const observationFamilies = result.items || [];
    const profileFamilies = result.profile_families || [];
    if (!observationFamilies.length && !profileFamilies.length) {
      container.textContent = "Пока нет наблюдений с достаточной идентификацией для безопасной группировки.";
      return;
    }
    const scope = document.createElement("p");
    scope.textContent = result.scope === "sqlite_history_plus_recent" ? "Охват: сохранённая SQLite-история и новые наблюдения." : "Охват: недавние наблюдения в памяти (SQLite-хранилище выключено).";
    container.append(scope);
    for (const family of observationFamilies) {
      const section = document.createElement("section");
      const title = document.createElement("h3");
      title.textContent = `${family.application || family.application_id || "Приложение"} · ${family.device_id} · ${family.variants.length} вариантов`;
      const evidence = document.createElement("p");
      evidence.textContent = family.evidence;
      const list = document.createElement("ul");
      for (const variant of family.variants) {
        const item = document.createElement("li");
        const profile = variant.profile_id ? `Профиль ${variant.profile_id}@${variant.profile_version || 1}` : "без профиля";
        const familyLink = variant.profile_family_id ? `семейство профилей ${variant.profile_family_id}` : "";
        const fp = [variant.ja4 || "JA4 неизвестен", variant.tls_state, profile, familyLink, ...(variant.http_fingerprints || [])].filter(Boolean).join(" · ");
        item.textContent = `${fp} — ${variant.observation_ids.length} наблюдений`;
        list.append(item);
      }
      section.append(title, evidence, list);
      container.append(section);
    }
    if (profileFamilies.length) {
      const heading = document.createElement("h3");
      heading.textContent = "Явные семейства TLS-профилей";
      container.append(heading);
      for (const family of profileFamilies) {
        const section = document.createElement("section");
        const title = document.createElement("h4");
        title.textContent = family.family_id;
        const evidence = document.createElement("p");
        evidence.textContent = family.evidence;
        const list = document.createElement("ul");
        for (const profile of family.profiles) {
          const item = document.createElement("li");
          item.textContent = `${profile.name} (${profile.profile_id}) · версия ${profile.version} · ${profile.ja4 || "без ожидаемого JA4"}`;
          list.append(item);
        }
        section.append(title, evidence, list);
        container.append(section);
      }
    }
  } catch (error) {
    container.textContent = `Не удалось загрузить семейства: ${error.message}`;
  }
}

byId("families-refresh")?.addEventListener("click", loadFingerprintFamilies);
loadFingerprintFamilies();
let selectedA = "", selectedB = "", nextCursor = "";
async function api(path) {
  const response = await ja3proxyFetch(path, {cache: "no-store"});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}
function fail(error) { byId("status").textContent = error.message; byId("status").className = "error"; }
function button(label, action) { const b = document.createElement("button"); b.type = "button"; b.textContent = label; b.addEventListener("click", action); return b; }
const fingerprintFamilies = [
  ["fingerprints", "TLS ClientHello", value => [["JA3", value.ja3], ["JA4", value.ja4], ["Нормализация", value.normalization_version]]],
  ["server_fingerprints", "TLS ServerHello", value => [["JA3S", value.ja3s], ["JA4S", value.ja4s], ["Версия JA4S", value.ja4s_version]]],
  ["http1", "HTTP/1", value => [["Направление", value.direction], ["Сообщение", `${value.method || value.status_code || "—"} · HTTP/${value.http_version}`], ["Порядок заголовков", value.header_order], ["Полнота тела", value.completeness], ["Фрейминг", value.body_framing]]],
  ["http2", "HTTP/2", value => [["Направление", value.direction], ["Fingerprint hash", value.hash], ["Порядок SETTINGS", value.settings_order], ["Типы кадров", value.frame_types], ["Полнота", value.completeness]]],
  ["tcp_syn", "TCP SYN / JA4T", value => [["JA4T", value.ja4t], ["Версия", value.ja4t_version], ["IP version", value.ip_version]]],
  ["dns", "DNS exchange", value => [["Транспорт", value.transport], ["Статус", value.status], ["Вопросы", value.questions], ["Адреса", value.addresses], ["CNAME", value.cname_answers]]],
  ["quic", "QUIC Initial", value => [["Версия", `0x${(value.version || 0).toString(16)}`], ["Transport parameters", value.transport_parameters]]],
];
function showObservation(observation) {
  const card = byId("detail-card");
  const match = fingerprintFamilies.find(([key]) => observation[key]);
  card.replaceChildren();
  const title = document.createElement("h3");
  title.textContent = `${match?.[1] || "Наблюдение"} · ${observation.completeness || "статус неизвестен"}`;
  const dl = document.createElement("dl");
  const entries = [["ID", observation.id], ["Время", observation.captured_at], ["Назначение", observation.destination], ["Точка захвата", observation.capture_point]];
  if (match) entries.push(...match[2](observation[match[0]]));
  for (const [label, value] of entries) {
    if (value === undefined || value === null || value === "") continue;
    const term = document.createElement("dt"), detail = document.createElement("dd");
    term.textContent = label;
    detail.textContent = typeof value === "object" ? JSON.stringify(value) : String(value);
    dl.append(term, detail);
  }
  card.append(title, dl);
  byId("detail").textContent = JSON.stringify(observation, null, 2);
}
function select(slot, id) {
  if (slot === "A") selectedA = id; else selectedB = id;
  byId("selection").textContent = `A: ${selectedA || "—"}   B: ${selectedB || "—"}`;
  byId("compare").disabled = !(selectedA && selectedB);
}
async function refresh(cursor = "") {
  try {
    const status = await api("/api/v1/status");
    byId("status").className = status.stats.recording_degraded ? "error" : "";
    byId("status").textContent = status.enabled ? `Обработано: ${status.stats.processed}; очередь: ${status.stats.queue_depth}; потеряно: ${status.stats.dropped}; ошибки записи: ${status.stats.write_errors}; spool: ${status.stats.spool_events || 0}.` : "Recorder выключен. Запустите proxy с --capture-tls.";
    const params = new URLSearchParams({q: byId("query").value, limit: "50", storage: byId("storage").value});
    for (const [field, param] of [["device-id", "device_id"], ["application", "application"], ["application-id", "application_id"], ["application-version", "application_version"], ["analysis-revision", "analysis_revision"]]) {
      const value = byId(field).value.trim();
      if (value) params.set(param, value);
    }
    for (const field of ["from", "to"]) {
      const value = byId(field).value;
      if (value) params.set(field, new Date(value).toISOString());
    }
    if (cursor) params.set("cursor", cursor);
    const data = await api(`/api/v1/observations?${params}`);
    const body = byId("observations"); body.replaceChildren();
    for (const observation of data.items) {
      const row = document.createElement("tr");
	  const fingerprint = observation.fingerprints?.ja4 || observation.server_fingerprints?.ja3s || (observation.http1 ? `HTTP/1 ${observation.http1.method || observation.http1.status_code || "—"} ${observation.http1.request_target || ""}` : observation.http2 ? `H2 ${observation.http2.hash?.slice(0, 12) || "—"}` : observation.negotiated_state ? `TLS ${observation.negotiated_state.negotiated_protocol || "—"} / 0x${(observation.negotiated_state.cipher_suite || 0).toString(16)}` : `${observation.completeness}: ${observation.error_code || ""}`);
	  const status = observation.verification?.status || observation.forwarding?.status || "";
	  const verified = status ? `${fingerprint} · ${status}` : fingerprint;
	  for (const value of [new Date(observation.captured_at).toLocaleTimeString(), observation.destination, observation.capture_point, observation.mode, verified]) {
        const cell = document.createElement("td"); cell.textContent = value; row.append(cell);
      }
      const detail = document.createElement("td");
      detail.append(button("Карточка", async () => {try {showObservation(await api(`/api/v1/observations/${encodeURIComponent(observation.id)}?storage=${byId("storage").value}`));} catch(error) {fail(error);}}), button("В профиль", () => {location.href=`/profiles.html?observation=${encodeURIComponent(observation.id)}`;}));
      if (observation.raw_client_hello_available) detail.append(button("Повторный разбор", async () => {try {const result = await ja3proxyFetch(`/api/v1/observations/${encodeURIComponent(observation.id)}/reparse?storage=${byId("storage").value}`, {method: "POST"}); const data = await result.json(); if (!result.ok) throw new Error(data.error || `HTTP ${result.status}`); showObservation(data); await refresh();} catch(error) {fail(error);}}));
      row.append(detail);
      const picks = document.createElement("td"); picks.append(button("A", () => select("A", observation.id)), button("B", () => select("B", observation.id))); row.append(picks); body.append(row);
    }
    if (!data.items.length) {const row=document.createElement("tr"), cell=document.createElement("td");cell.colSpan=7;cell.textContent="Наблюдений нет. Подключите TLS-клиент или измените поиск.";row.append(cell);body.append(row);}
    nextCursor = data.next_cursor || ""; byId("more").hidden = !nextCursor;
  } catch(error) { fail(error); }
}
byId("search").addEventListener("submit", event => {event.preventDefault();refresh();});
byId("refresh").addEventListener("click", () => refresh());
byId("more").addEventListener("click", () => refresh(nextCursor));
byId("compare").addEventListener("click", async () => {try {const result = await api(`/api/v1/fingerprints/diff?${new URLSearchParams({a:selectedA,b:selectedB,storage:byId("storage").value})}`); const family = result.family || "семейство не определено"; const note = result.reason === "captured_fingerprint_fields_only" ? " Сравнивались только профильные поля, доступные в этих наблюдениях; это не заключение о полном совпадении или различии протокольного обмена." : ""; byId("diff").textContent = `${family}: ${result.status}${result.reason ? ` (${result.reason})` : ""}.${note}\n\n${JSON.stringify(result.changes,null,2)}`;}catch(error){fail(error);}});
refresh();
