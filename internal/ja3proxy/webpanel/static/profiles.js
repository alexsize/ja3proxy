"use strict";
const el = id => document.getElementById(id);
let library = {config_version: 0, active_id: "", active_ids: [], templates: []};
let draft = null;
const sourceObservation = new URLSearchParams(location.search).get("observation") || "";

async function api(path, options = {}) {
  const response = await ja3proxyFetch(path, {cache: "no-store", ...options});
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
  if (el("profile-type").value === "RANDOMIZED") return {
    ...base, name: el("name").value.trim(), family_id: el("family-id").value.trim(), enabled: el("enabled").checked, host_patterns: hosts(),
    profile_type: "RANDOMIZED", profile_mode: el("profile-mode").value, randomized_alpn: el("randomized-alpn").value, base_preset: {}, fields: {}, policy: {}
  };
  return {
    ...base,
    name: el("name").value.trim(), family_id: el("family-id").value.trim(), enabled: el("enabled").checked, host_patterns: hosts(), profile_type: el("profile-type").value, profile_mode: el("profile-mode").value, randomized_alpn: "", base_preset: selectedPreset(),
    fields: {
    cipher_suites: parseArray("ciphers", "number"), extension_order: parseArray("extensions", "number"), alpn: parseArray("alpn", "string"),
      alpn_policy: el("alpn-policy").value, custom_alpn: parseArray("custom-alpn", "string"),
      alps: parseArray("alps", "string"), alps_policy: el("alps-policy").value, custom_alps: parseArray("custom-alps", "string"),
      supported_versions: parseArray("versions", "number"), supported_groups: parseArray("groups", "number"), signature_algorithms: parseArray("signatures", "number")
    },
	policy: {...(base.policy || {}), must_match: parseArray("must-match", "string"), should_match: parseArray("should-match", "string"), constraints: parseArray("constraints")}
  };
}
function fill(template) {
  draft = template;
  el("profile-type").value = template.profile_type || "CUSTOM";
  el("profile-mode").value = template.profile_mode || "ADAPTIVE";
  el("randomized-alpn").value = template.randomized_alpn || "AUTO";
  el("editor-title").textContent = template.id ? `Профиль: ${template.name}, версия ${template.version}` : "Новый профиль";
  el("name").value = template.name || ""; el("family-id").value = template.family_id || ""; el("enabled").checked = template.enabled !== false; el("hosts").value = (template.host_patterns || []).join("\n");
	if (template.base_preset?.client) el("preset").value = `${template.base_preset.client}|${template.base_preset.version}`;
  el("ciphers").value = pretty(template.fields.cipher_suites); el("extensions").value = pretty(template.fields.extension_order); el("alpn").value = pretty(template.fields.alpn);
  el("alpn-policy").value = template.fields.alpn_policy || "INTERSECTION"; el("custom-alpn").value = pretty(template.fields.custom_alpn);
  el("alps").value = pretty(template.fields.alps); el("alps-policy").value = template.fields.alps_policy || "INTERSECTION"; el("custom-alps").value = pretty(template.fields.custom_alps);
  el("versions").value = pretty(template.fields.supported_versions); el("groups").value = pretty(template.fields.supported_groups); el("signatures").value = pretty(template.fields.signature_algorithms);
  el("must-match").value = pretty(template.policy.must_match); el("should-match").value = pretty(template.policy.should_match);
	el("constraints").value = pretty(template.policy.constraints);
  updateProfileTypeUI();
  renderPreview(template);
}
function renderPreview(template) {
  const expected = template.expected;
  el("replayability").textContent = `${template.replayability?.status || "—"}${template.replayability?.unsupported?.length ? `: ${template.replayability.unsupported.join("; ")}` : ""}`;
  el("expected-ja4").textContent = expected?.ja4 || "—"; el("expected-ja3").textContent = expected?.ja3 || "—"; el("expected-normalized").textContent = expected?.normalized_sha256 || "—";
  el("preview-json").textContent = JSON.stringify(template, null, 2);
}
function renderLibrary() {
  const activeIDs = new Set(library.active_ids?.length ? library.active_ids : (library.active_id ? [library.active_id] : []));
  el("config-version").textContent = library.config_version; const active = library.templates.filter(item => activeIDs.has(item.id)); el("active-profile").textContent = active.map(item => ["PROFILE_REVALIDATION_REQUIRED", "INCOMPATIBLE"].includes(item.compatibility_status) ? `${item.name} (${item.compatibility_status})` : item.name).join(", ") || "не выбран";
  const body = el("profiles"); body.replaceChildren();
  for (const profile of library.templates) {
    const row = document.createElement("tr");
    for (const value of [profile.name, profile.family_id || "автоматически", profile.version, profile.profile_type === "RANDOMIZED" ? `RANDOMIZED (${profile.randomized_alpn || "AUTO"})` : `${profile.base_preset?.client || "—"}@${profile.base_preset?.version || "—"}`, (profile.host_patterns || []).join(", ") || "все", profile.expected?.ja4 || "—", profile.replayability.status, `создан: ${profile.created_with_utls || "неизвестно"} · runtime: ${profile.current_runtime_utls || "неизвестно"} · проверен: ${profile.last_validated_with_utls || "нет"} · ${profile.compatibility_status || "NOT_VALIDATED"}`]) { const cell = document.createElement("td"); cell.textContent = value; row.append(cell); }
    if (activeIDs.has(profile.id)) row.className = "active";
    const actions = document.createElement("td");
    const edit = document.createElement("button"); edit.type = "button"; edit.textContent = "Изменить"; edit.onclick = () => fill(profile); actions.append(edit);
	const activate = document.createElement("button"); activate.type = "button"; activate.textContent = "Активировать"; activate.disabled = profile.replayability.status === "UNSUPPORTED" || !profile.enabled || (!profile.created_with_utls && !profile.last_validated_with_utls) || ["PROFILE_REVALIDATION_REQUIRED", "INCOMPATIBLE"].includes(profile.compatibility_status); activate.onclick = () => setActive(profile.id); actions.append(activate);
	const replay = document.createElement("a"); replay.href = `/replay-lab.html?profile=${encodeURIComponent(profile.id)}`; replay.textContent = "Проверить"; actions.append(replay);
	const history = document.createElement("button"); history.type = "button"; history.textContent = "История / откат"; history.onclick = () => profileHistory(profile).catch(error => show(error.message, true)); actions.append(history);
	const remove = document.createElement("button"); remove.type = "button"; remove.textContent = "Удалить"; remove.disabled = activeIDs.has(profile.id); remove.onclick = () => deleteProfile(profile); actions.append(remove);
	row.append(actions); body.append(row);
  }
  if (!library.templates.length) { const row=document.createElement("tr"), cell=document.createElement("td"); cell.colSpan=9; cell.textContent="Сохранённых профилей нет."; row.append(cell); body.append(row); }
}
async function loadLibrary() { library = await api("/api/v1/tls/profiles"); renderLibrary(); }
async function loadPresets() {
  const presets = await api("/api/v1/tls/presets");
	const option = item => `<option value="${item.client}|${item.version}">${item.client}@${item.version}${item.handshake_type === "PSK" ? " — PSK / resumption profile" : " — full-handshake profile"}</option>`;
	const full = presets.filter(item => item.handshake_type !== "PSK");
	const psk = presets.filter(item => item.handshake_type === "PSK");
	el("preset").innerHTML = `<optgroup label="Обычный full-handshake">${full.map(option).join("")}</optgroup>${psk.length ? `<optgroup label="PSK / resumption profile">${psk.map(option).join("")}</optgroup>` : ""}`;
	if (presets.some(item => item.client === "Chrome" && item.version === "120")) el("preset").value = "Chrome|120";
}
async function fromPreset() {
  const template = await api("/api/v1/tls/profiles/from-preset", request("POST", {name: el("name").value.trim() || "Новый профиль", family_id: el("family-id").value.trim(), base_preset: selectedPreset(), host_patterns: hosts()})); fill(template); show("Поля заполнены из uTLS-пресета. Проверьте ожидаемый JA4.");
}
async function fromObservation() {
  const template = await api("/api/v1/tls/profiles/from-observation", request("POST", {save:false, expected_version:library.config_version, observation_id:sourceObservation, name:el("name").value.trim() || `Наблюдение ${sourceObservation}`, family_id:el("family-id").value.trim(), base_preset:selectedPreset(), host_patterns:hosts()})); fill(template); show("Структура получена из наблюдения. Невоспроизводимые поля показаны в статусе.");
}
async function preview() { const template = await api("/api/v1/tls/profiles/preview", request("POST", collect())); draft = template; renderPreview(template); show(template.profile_type === "RANDOMIZED" ? "Профиль проверен; фактический JA3/JA4 появится в исходящей записи соединения." : "Ожидаемые fingerprints пересчитаны."); }
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
function updateProfileTypeUI() {
  const randomized = el("profile-type").value === "RANDOMIZED";
  el("profile-mode-field").hidden = randomized;
  el("preset-field").hidden = randomized;
  el("randomized-alpn-field").hidden = !randomized;
  document.querySelectorAll(".deterministic-only").forEach(item => item.hidden = randomized);
  document.querySelectorAll(".fields textarea, .fields select").forEach(item => item.required = !randomized);
  el("preset").required = !randomized;
}
function reset() { draft=null; el("profile-form").reset(); updateProfileTypeUI(); el("editor-title").textContent="Новый профиль"; el("preview-json").textContent="Сначала загрузите пресет или наблюдение."; el("expected-ja4").textContent=el("expected-ja3").textContent=el("expected-normalized").textContent=el("replayability").textContent="—"; }

el("from-preset").onclick = () => fromPreset().catch(error => show(error.message, true)); el("preview").onclick = () => preview().catch(error => show(error.message, true)); el("profile-form").onsubmit = event => save(event).catch(error => show(error.message, true)); el("deactivate").onclick = () => setActive("").catch(error => show(error.message, true)); el("reset").onclick = reset;
el("profile-type").onchange = updateProfileTypeUI;
if (sourceObservation) { el("from-observation").hidden=false; el("from-observation").onclick=()=>fromObservation().catch(error=>show(error.message,true)); }
Promise.all([loadPresets(), loadLibrary()]).then(()=>{show("Готово."); if(!sourceObservation) fromPreset().catch(error=>show(error.message,true));}).catch(error=>show(error.message,true));
