"use strict";
const el = id => document.getElementById(id);
const selectedProfile = new URLSearchParams(location.search).get("profile") || "";

async function api(path, options = {}) {
  const response = await ja3proxyFetch(path, {cache: "no-store", ...options});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}
function request(body) {
  return {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)};
}
function show(message, error = false) {
  el("status").textContent = message;
  el("status").className = error ? "error" : "";
}
function updateSourceFields() {
  const kind = el("profile-kind").value;
  el("saved-profile-field").hidden = kind !== "SAVED";
  el("preset-field").hidden = kind !== "PRESET";
  el("randomized-alpn-field").hidden = kind !== "RANDOMIZED";
}
function fingerprintView(value) {
  if (!value) return "Нет данных.";
  return `JA3: ${value.ja3 || "—"}\nJA3 hash: ${value.ja3_hash || "—"}\nJA4: ${value.ja4 || "—"}\nTLS-NORM SHA-256: ${value.normalized_sha256 || "—"}`;
}
function tlsVersionLabel(version) {
  return ({0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"})[version] || (version ? `0x${version.toString(16)}` : "—");
}
function fillPresets(items) {
  const full = items.filter(item => item.handshake_type !== "PSK");
  const psk = items.filter(item => item.handshake_type === "PSK");
  const option = item => `<option value="${item.client}|${item.version}">${item.client}@${item.version}${item.handshake_type === "PSK" ? " — PSK" : ""}</option>`;
  el("preset").innerHTML = `<optgroup label="Полное TLS-соединение">${full.map(option).join("")}</optgroup>${psk.length ? `<optgroup label="PSK / возобновление сеанса">${psk.map(option).join("")}</optgroup>` : ""}`;
}
function fillProfiles(items) {
  el("profile-id").replaceChildren();
  el("matrix-profiles").replaceChildren();
  for (const profile of items) {
    const option = document.createElement("option");
    option.value = profile.id;
    option.textContent = `${profile.name} · ${profile.profile_type || "CUSTOM"}${profile.replayability?.status === "UNSUPPORTED" ? " · не поддерживается (UNSUPPORTED)" : ""}`;
    el("profile-id").append(option);
    const matrixOption = document.createElement("option");
    matrixOption.value = profile.id;
    matrixOption.textContent = option.textContent;
    el("matrix-profiles").append(matrixOption);
  }
  if (!items.length) {
    const option = document.createElement("option");
    option.value = ""; option.textContent = "Нет сохранённых профилей";
    el("profile-id").append(option);
  }
}
function targetBody() {
  const host = el("target-host").value.trim();
  const port = Number(el("target-port").value);
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Укажите корректные имя или адрес тестового сервера и порт.");
  const timeout = Number(el("timeout").value || 10000);
  if (!Number.isInteger(timeout) || timeout < 100 || timeout > 60000) throw new Error("Таймаут должен быть от 100 до 60000 мс.");
  return {
    target_host: host, target_port: port, server_name: el("server-name").value.trim(),
    timeout_ms: timeout
  };
}
function fillObservations(items) {
  const list = el("observations-list");
  list.replaceChildren();
  for (const observation of items) {
    if (!observation.fingerprints) continue;
    const option = document.createElement("option");
    option.value = observation.id;
    const direction = observation.direction || "";
    option.textContent = `${observation.captured_at || observation.persisted_at || ""} · ${direction} · ${observation.destination || "без хоста"} · ${observation.fingerprints.ja4 || "без JA4"}`;
    list.append(option);
  }
}
function renderResult(result) {
  el("expected").textContent = fingerprintView(result.expected);
  el("compiled").textContent = `${result.compiled?.status || "—"}\n${fingerprintView(result.compiled?.fingerprint)}`;
  el("actual").textContent = fingerprintView(result.actual);
  el("server-response").textContent = JSON.stringify(result.server_response || {}, null, 2);
  el("diff").textContent = JSON.stringify(result.diff || {}, null, 2);
  el("policy-verification").textContent = JSON.stringify(result.policy_verification || {status: "нет данных"}, null, 2);
  el("result-json").textContent = JSON.stringify(result, null, 2);
  show(`${result.status}: ${result.profile} → ${result.target}${result.compatibility_status ? ` · совместимость ${result.compatibility_status}` : ""}${result.error ? ` · ${result.error}` : ""}`, result.status !== "OK");
}
async function run() {
  const body = {...targetBody(), observation_id: el("observation-id").value};
  if (el("profile-kind").value === "SAVED") body.profile_id = el("profile-id").value;
  if (el("profile-kind").value === "PRESET") {
    const [client, version] = el("preset").value.split("|");
    body.profile_type = "PRESET"; body.preset_client = client; body.preset_version = version;
  }
  if (el("profile-kind").value === "RANDOMIZED") {
    body.profile_type = "RANDOMIZED"; body.randomized_alpn = el("randomized-alpn").value;
  }
  el("run").disabled = true;
  show("Устанавливается TLS-соединение с тестовым сервером…");
  try { renderResult(await api("/api/v1/replay-lab/run", request(body))); }
  finally { el("run").disabled = false; }
}
async function runMatrix() {
  const ids = [...el("matrix-profiles").selectedOptions].map(option => option.value);
  if (!ids.length) throw new Error("Выберите хотя бы один сохранённый профиль для матрицы.");
  const target = targetBody();
  const body = el("matrix-results");
  body.replaceChildren();
  const rollerMode = el("roller-mode").checked;
  const rows = ids.map(id => {
    const option = [...el("matrix-profiles").options].find(item => item.value === id);
    const row = document.createElement("tr");
    const cells = Array.from({length: 6}, () => document.createElement("td"));
    cells[0].textContent = option?.textContent || id;
    cells[3].textContent = "Ожидает";
    for (const cell of cells) row.append(cell);
    body.append(row);
    return {id, row, cells};
  });
  el("run-matrix").disabled = true;
  let winner = "";
  let attempted = 0;
  try {
    for (let index = 0; index < rows.length; index++) {
      const {id, row, cells} = rows[index];
      cells[3].textContent = "Выполняется…";
      attempted++;
      show(`${rollerMode ? "Быстрый перебор" : "Матрица совместимости"}: ${attempted}/${ids.length} — ${cells[0].textContent}`);
      try {
        const result = await api("/api/v1/replay-lab/run", request({...target, profile_id: id}));
        cells[1].textContent = tlsVersionLabel(result.server_response?.tls_version);
        cells[2].textContent = result.server_response?.negotiated_alpn || "—";
        cells[3].textContent = result.compatibility_status ? `${result.status} · ${result.compatibility_status}` : result.status;
        cells[4].textContent = result.actual?.ja4 || "—";
        const diffStatuses = Object.values(result.diff || {}).map(item => item.status).join(", ");
        const policy = result.policy_verification;
        const policySummary = policy ? `${policy.status}; MUST: ${(policy.mismatched_must_match || []).join(", ") || "OK"}; SHOULD: ${(policy.mismatched_should_match || []).join(", ") || "OK"}; constraints: ${(policy.violated_constraints || []).join(", ") || "OK"}` : "policy —";
        cells[5].textContent = [diffStatuses, policySummary].filter(Boolean).join(" · ");
        const profileCompatible = ["VALID", "VALID_WITH_DIFFERENCES"].includes(result.compatibility_status);
        row.className = result.status === "OK" && profileCompatible ? "active" : "error";
        if (rollerMode && result.status === "OK" && profileCompatible) {
          winner = cells[0].textContent;
          for (const skipped of rows.slice(index + 1)) {
            skipped.cells[3].textContent = "Пропущен — найден рабочий профиль";
            skipped.row.className = "";
          }
          break;
        }
      } catch (error) {
        cells[3].textContent = `Ошибка: ${error.message}`;
        row.className = "error";
      }
    }
    if (rollerMode) {
      show(winner ? `Перебор остановлен: первый успешный профиль — ${winner}; проверено ${attempted} из ${ids.length}.` : `Перебор завершил все ${attempted} попыток, успешного профиля нет.`, !winner);
    } else {
      show(`Матрица завершена: ${attempted} профилей.`);
    }
  } finally { el("run-matrix").disabled = false; }
}

el("profile-kind").onchange = updateSourceFields;
el("run").onclick = () => run().catch(error => show(error.message, true));
el("run-matrix").onclick = () => runMatrix().catch(error => show(error.message, true));
Promise.all([
  api("/api/v1/tls/profiles"),
  api("/api/v1/tls/presets"),
  api("/api/v1/observations?limit=100").catch(() => ({items: []}))
]).then(([library, presets, observations]) => {
  fillProfiles(library.templates || []);
  if (selectedProfile && [...el("profile-id").options].some(option => option.value === selectedProfile)) {
    el("profile-kind").value = "SAVED";
    el("profile-id").value = selectedProfile;
  }
  fillPresets(presets || []);
  fillObservations(observations.items || []);
  updateSourceFields(); show("Готово к локальной проверке TLS-профиля.");
}).catch(error => show(error.message, true));
