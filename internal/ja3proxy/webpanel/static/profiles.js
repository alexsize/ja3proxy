"use strict";
const el = id => document.getElementById(id);
let library = {config_version: 0, active_id: "", templates: []};
let draft = null;
const sourceObservation = new URLSearchParams(location.search).get("observation") || "";

async function api(path, options = {}) {
  const response = await fetch(path, {cache: "no-store", ...options});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}
function request(method, body) { return {method, headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)}; }
function show(message, error = false) { el("status").textContent = message; el("status").className = error ? "error" : ""; }
function pretty(value) { return JSON.stringify(value ?? [], null, 2); }
function parseArray(id, kind) {
  let value;
  try { value = JSON.parse(el(id).value); } catch (error) { throw new Error(`${id}: некорректный JSON: ${error.message}`); }
  if (!Array.isArray(value)) throw new Error(`${id}: требуется JSON-массив`);
  if (kind === "number" && value.some(item => !Number.isInteger(item) || item < 0 || item > 65535)) throw new Error(`${id}: допустимы только uint16`);
  if (kind === "string" && value.some(item => typeof item !== "string")) throw new Error(`${id}: допустимы только строки`);
  return value;
}
function selectedPreset() {
	const [client, version] = el("preset").value.split("|");
  return {client, version};
}
function hosts() { return el("hosts").value.split(/\r?\n|,/).map(value => value.trim()).filter(Boolean); }
function collect() {
  const base = draft || {};
  return {
    ...base,
    name: el("name").value.trim(), enabled: el("enabled").checked, host_patterns: hosts(), base_preset: selectedPreset(),
    fields: {
    cipher_suites: parseArray("ciphers", "number"), extension_order: parseArray("extensions", "number"), alpn: parseArray("alpn", "string"),
      alpn_policy: el("alpn-policy").value, custom_alpn: parseArray("custom-alpn", "string"),
      supported_versions: parseArray("versions", "number"), supported_groups: parseArray("groups", "number"), signature_algorithms: parseArray("signatures", "number")
    },
	policy: {...(base.policy || {}), must_match: parseArray("must-match", "string"), should_match: parseArray("should-match", "string"), constraints: parseArray("constraints")}
  };
}
function fill(template) {
  draft = template;
  el("editor-title").textContent = template.id ? `Профиль: ${template.name}, версия ${template.version}` : "Новый профиль";
  el("name").value = template.name || ""; el("enabled").checked = template.enabled !== false; el("hosts").value = (template.host_patterns || []).join("\n");
	el("preset").value = `${template.base_preset.client}|${template.base_preset.version}`;
  el("ciphers").value = pretty(template.fields.cipher_suites); el("extensions").value = pretty(template.fields.extension_order); el("alpn").value = pretty(template.fields.alpn);
  el("alpn-policy").value = template.fields.alpn_policy || "INTERSECTION"; el("custom-alpn").value = pretty(template.fields.custom_alpn);
  el("versions").value = pretty(template.fields.supported_versions); el("groups").value = pretty(template.fields.supported_groups); el("signatures").value = pretty(template.fields.signature_algorithms);
  el("must-match").value = pretty(template.policy.must_match); el("should-match").value = pretty(template.policy.should_match);
	el("constraints").value = pretty(template.policy.constraints);
  renderPreview(template);
}
function renderPreview(template) {
  const expected = template.expected;
  el("replayability").textContent = `${template.replayability?.status || "—"}${template.replayability?.unsupported?.length ? `: ${template.replayability.unsupported.join("; ")}` : ""}`;
  el("expected-ja4").textContent = expected?.ja4 || "—"; el("expected-ja3").textContent = expected?.ja3 || "—"; el("expected-normalized").textContent = expected?.normalized_sha256 || "—";
  el("preview-json").textContent = JSON.stringify(template, null, 2);
}
function renderLibrary() {
  el("config-version").textContent = library.config_version; const active = library.templates.find(item => item.id === library.active_id); el("active-profile").textContent = active?.name || "не выбран";
  const body = el("profiles"); body.replaceChildren();
  for (const profile of library.templates) {
    const row = document.createElement("tr");
    for (const value of [profile.name, profile.version, `${profile.base_preset.client}@${profile.base_preset.version}`, (profile.host_patterns || []).join(", ") || "все", profile.expected?.ja4 || "—", profile.replayability.status]) { const cell = document.createElement("td"); cell.textContent = value; row.append(cell); }
    if (profile.id === library.active_id) row.className = "active";
    const actions = document.createElement("td");
    const edit = document.createElement("button"); edit.type = "button"; edit.textContent = "Изменить"; edit.onclick = () => fill(profile); actions.append(edit);
	const activate = document.createElement("button"); activate.type = "button"; activate.textContent = "Активировать"; activate.disabled = profile.replayability.status === "UNSUPPORTED" || !profile.enabled; activate.onclick = () => setActive(profile.id); actions.append(activate);
	const history = document.createElement("button"); history.type = "button"; history.textContent = "История / откат"; history.onclick = () => profileHistory(profile).catch(error => show(error.message, true)); actions.append(history);
	const remove = document.createElement("button"); remove.type = "button"; remove.textContent = "Удалить"; remove.disabled = profile.id === library.active_id; remove.onclick = () => deleteProfile(profile); actions.append(remove);
	row.append(actions); body.append(row);
  }
  if (!library.templates.length) { const row=document.createElement("tr"), cell=document.createElement("td"); cell.colSpan=7; cell.textContent="Сохранённых профилей нет."; row.append(cell); body.append(row); }
}
async function loadLibrary() { library = await api("/api/v1/tls/profiles"); renderLibrary(); }
async function loadPresets() {
  const presets = await api("/api/v1/tls/presets");
	el("preset").innerHTML = presets.map(item => `<option value="${item.client}|${item.version}">${item.client}@${item.version}</option>`).join("");
	if (presets.some(item => item.client === "Chrome" && item.version === "120")) el("preset").value = "Chrome|120";
}
async function fromPreset() {
  const template = await api("/api/v1/tls/profiles/from-preset", request("POST", {name: el("name").value.trim() || "Новый профиль", base_preset: selectedPreset(), host_patterns: hosts()})); fill(template); show("Поля заполнены из uTLS-пресета. Проверьте ожидаемый JA4.");
}
async function fromObservation() {
  const template = await api("/api/v1/tls/profiles/from-observation", request("POST", {save:false, expected_version:library.config_version, observation_id:sourceObservation, name:el("name").value.trim() || `Наблюдение ${sourceObservation}`, base_preset:selectedPreset(), host_patterns:hosts()})); fill(template); show("Структура получена из наблюдения. Невоспроизводимые поля показаны в статусе.");
}
async function preview() { const template = await api("/api/v1/tls/profiles/preview", request("POST", collect())); draft = template; renderPreview(template); show("Ожидаемые fingerprints пересчитаны."); }
async function save(event) {
  event.preventDefault(); await preview();
  const path = draft.id ? `/api/v1/tls/profiles/${encodeURIComponent(draft.id)}` : "/api/v1/tls/profiles"; const method = draft.id ? "PUT" : "POST";
  const result = await api(path, request(method, {expected_version:library.config_version, template:draft})); library = result.library; fill(result.template); renderLibrary(); show("Новая версия профиля сохранена.");
}
async function setActive(id) { library = await api("/api/v1/tls/profiles/active", request("PUT", {expected_version:library.config_version, id})); renderLibrary(); show(id ? "Профиль активирован для новых соединений." : "Пользовательский профиль отключён."); }
async function deleteProfile(profile) { if (!confirm(`Удалить профиль «${profile.name}»?`)) return; library = await api(`/api/v1/tls/profiles/${encodeURIComponent(profile.id)}`, request("DELETE", {expected_version:library.config_version})); if (draft?.id === profile.id) reset(); renderLibrary(); show("Профиль удалён из текущей конфигурации; прежние snapshot остаются в журнале версий."); }
async function profileHistory(profile) {
	const versions = await api(`/api/v1/tls/profiles/${encodeURIComponent(profile.id)}/versions`);
	el("preview-json").textContent = JSON.stringify(versions, null, 2);
	const answer = prompt(`Версии профиля: ${versions.map(item => item.version).join(", ")}. Для отката введите номер версии или оставьте поле пустым.`);
	if (answer === null || answer.trim() === "") { show("История версий показана ниже."); return; }
	const target = Number(answer); if (!Number.isSafeInteger(target) || target < 1 || !versions.some(item => item.version === target)) throw new Error("Такой версии профиля нет.");
	const result = await api(`/api/v1/tls/profiles/${encodeURIComponent(profile.id)}/rollback`, request("POST", {expected_version:library.config_version, target_version:target}));
	library = result.library; fill(result.template); renderLibrary(); show(`Откат оформлен как новая версия ${result.template.version}.`);
}
function reset() { draft=null; el("profile-form").reset(); el("editor-title").textContent="Новый профиль"; el("preview-json").textContent="Сначала загрузите пресет или наблюдение."; el("expected-ja4").textContent=el("expected-ja3").textContent=el("expected-normalized").textContent=el("replayability").textContent="—"; }

el("from-preset").onclick = () => fromPreset().catch(error => show(error.message, true)); el("preview").onclick = () => preview().catch(error => show(error.message, true)); el("profile-form").onsubmit = event => save(event).catch(error => show(error.message, true)); el("deactivate").onclick = () => setActive("").catch(error => show(error.message, true)); el("reset").onclick = reset;
if (sourceObservation) { el("from-observation").hidden=false; el("from-observation").onclick=()=>fromObservation().catch(error=>show(error.message,true)); }
Promise.all([loadPresets(), loadLibrary()]).then(()=>{show("Готово."); if(!sourceObservation) fromPreset().catch(error=>show(error.message,true));}).catch(error=>show(error.message,true));
