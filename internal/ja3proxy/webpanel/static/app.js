const elements = Object.fromEntries([
  "connection", "route-chain", "upload-rate",
  "download-rate", "active-sessions", "total-sessions", "total-upload",
  "total-download", "uptime", "sessions", "events", "error-toast",
  "config-form", "tls-fingerprint", "proxy-protocol-choice", "traffic-page", "settings-page",
  "upstream-choice", "upstream-field", "upstream-input", "config-note", "proxy-port",
  "proxy-auth-choice", "proxy-username-field", "proxy-username", "proxy-password-field", "proxy-password", "mitm-ca-validity", "panel-cert-validity", "ca-reload-button", "ca-reload-note", "ca-rotate-button", "ca-rotate-note",
  "spool-key-reload-button", "spool-key-reload-note", "mitm-ca-identity",
  "proxy-auth-reload-button", "proxy-auth-reload-note", "upstream-credentials-reload-button", "upstream-credentials-reload-note"
].map(id => [id, document.getElementById(id)]));

let previous = null;
let filter = "all";
let configInitialized = false;
let configuredProxyAuthEnabled = false;
let proxyAuthFilesConfigured = false;
let upstreamCredentialFilesConfigured = false;
let runtimeConfigVersion = 0;
let lastEventsSignature = "";
let lastRouteSignature = "";
let refreshPromise = null;
let refreshTimer = null;

const escapeHTML = value => String(value ?? "")
  .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;").replaceAll("'", "&#039;");

function formatBytes(value, suffix = "") {
  const bytes = Number(value) || 0;
  const units = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
  let amount = bytes;
  let unit = 0;
  while (Math.abs(amount) >= 1000 && unit < units.length - 1) { amount /= 1000; unit += 1; }
  const digits = amount >= 100 || unit === 0 ? 0 : amount >= 10 ? 1 : 2;
  return `${amount.toFixed(digits)} ${units[unit]}${suffix}`;
}

function elapsed(from, to = Date.now()) {
  const seconds = Math.max(0, Math.floor((to - new Date(from).getTime()) / 1000));
  if (seconds < 60) return `${seconds} с`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} мин ${seconds % 60} с`;
  return `${Math.floor(seconds / 3600)} ч ${Math.floor((seconds % 3600) / 60)} мин`;
}

function uptime(from) {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(from).getTime()) / 1000));
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return `${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}`;
}

function createSessionRow(sessionID) {
  const row = document.createElement("tr");
  row.dataset.sessionId = String(sessionID);
  row.innerHTML = `<td data-label="Состояние"><span class="state"></span></td>
    <td data-label="Протокол"></td>
    <td class="target-cell" data-label="Назначение"><strong></strong><small></small></td>
    <td data-label="Клиент"></td>
    <td data-label="Передача"></td>
    <td class="age-cell" data-label="Возраст"></td>`;
  return row;
}

function updateSessionRow(row, session) {
  const state = session.state || "closed";
  const stateClass = ["active", "closed", "failed"].includes(state) ? state : "closed";
  const detail = session.sni && session.sni !== session.target ? session.sni : (session.error || "");
  const cells = row.cells;
  const stateBadge = cells[0].firstElementChild;
  const target = cells[2];

  row.title = session.error || "";
  stateBadge.className = `state state-${stateClass}`;
  stateBadge.textContent = { active: "активно", closed: "закрыто", failed: "ошибка" }[stateClass];
  cells[1].textContent = session.protocol || "—";
  target.firstElementChild.textContent = session.target || "—";
  target.lastElementChild.textContent = detail;
  target.lastElementChild.hidden = !detail;
  cells[3].textContent = session.clientAddr || "—";
  cells[4].textContent = `${formatBytes(session.uploadBytes)} ↑ · ${formatBytes(session.downloadBytes)} ↓`;
  cells[5].dataset.startedAt = session.startedAt;
  cells[5].textContent = elapsed(session.startedAt);
}

function visibleSessions(sessions) {
  const visible = [];
  for (const session of sessions || []) {
    if (filter !== "all" && session.state !== filter) continue;
    visible.push(session);
    if (visible.length === 40) break;
  }
  return visible;
}

function renderSessions(sessions) {
  const visible = visibleSessions(sessions);
  if (!visible.length) {
    const title = filter === "all" ? "Трафика пока нет" : "Подходящих сессий нет";
    const detail = filter === "all" ? "Подключите клиент к JA3Proxy, и здесь появятся сессии." : "Выберите другой фильтр или дождитесь нового трафика.";
    elements.sessions.innerHTML = `<tr><td colspan="6" class="empty"><strong>${title}</strong><span>${detail}</span></td></tr>`;
    return;
  }

  const existingRows = new Map([...elements.sessions.rows]
    .filter(row => row.dataset.sessionId)
    .map(row => [row.dataset.sessionId, row]));
  const fragment = document.createDocumentFragment();
  for (const session of visible) {
    const sessionID = String(session.id);
    const row = existingRows.get(sessionID) || createSessionRow(sessionID);
    updateSessionRow(row, session);
    fragment.append(row);
  }
  elements.sessions.replaceChildren(fragment);
}

function renderEvents(events) {
  const visible = [...(events || [])].reverse().slice(0, 10);
  const signature = JSON.stringify(visible);
  if (signature === lastEventsSignature) return;
  lastEventsSignature = signature;
  if (!visible.length) { elements.events.innerHTML = '<li class="empty"><strong>Событий нет</strong><span>Здесь появятся события работающего прокси.</span></li>'; return; }
  elements.events.innerHTML = visible.map(event => `<li class="${event.level === "warn" ? "warn" : ""}">
    <time>${new Date(event.time).toLocaleTimeString([], { hour12: false })}</time>
    <strong>${escapeHTML(event.message)}</strong>
    <p>${escapeHTML(event.target || event.error || event.protocol || "Событие процесса")}</p>
  </li>`).join("");
}

function renderRoute(runtime) {
  const protocolLabels = { mixed: "HTTP + SOCKS5", http: "HTTP", socks5: "SOCKS5" };
  const fallback = [
    { role: "Клиент", address: "Клиент прокси" },
    { role: "JA3Proxy", address: runtime.proxyListen || "—" },
    { role: "Маршрут", address: runtime.upstream || "Прямое соединение" },
    { role: "Назначение", address: "Запрошенный адрес" }
  ];
  const chain = runtime.chain?.length ? runtime.chain : fallback;
  const signature = JSON.stringify([chain, runtime.proxyProtocol, runtime.tlsClient, runtime.tlsVersion]);
  if (signature === lastRouteSignature) return;
  lastRouteSignature = signature;
  elements["route-chain"].innerHTML = chain.map((hop, index) => {
    const proxy = String(hop.role).toLowerCase() === "ja3proxy";
    const identity = `${runtime.tlsClient || "—"}@${runtime.tlsVersion || "—"}`;
    const protocol = protocolLabels[runtime.proxyProtocol] || "HTTP + SOCKS5";
    return `<li class="${proxy ? "route-proxy" : ""}">
      <span class="route-index">${String(index + 1).padStart(2, "0")}</span>
      <strong>${escapeHTML(hop.role || "Узел")}</strong>
      <small>${escapeHTML(hop.address || "—")}</small>
      ${proxy ? `<em>${escapeHTML(protocol)} · ${escapeHTML(identity)}</em>` : ""}
    </li>`;
  }).join("");
}

function setSelectOptions(select, options, selected) {
  select.innerHTML = options.map(option => {
    const value = typeof option === "string" ? option : option.value;
    const label = typeof option === "string" ? option : option.label;
    return `<option value="${escapeHTML(value)}"${value === selected ? " selected" : ""}>${escapeHTML(label)}</option>`;
  }).join("");
}

function syncConfig(runtime, force = false) {
	runtimeConfigVersion = Number(runtime.configVersion) || 0;
	if (configInitialized && !force) return;

  const currentFingerprint = `${runtime.tlsClient || "Golang"}@${runtime.tlsVersion || "0"}`;
  const fingerprints = [...new Set([currentFingerprint, ...(runtime.tlsFingerprints || [])])];
  setSelectOptions(elements["tls-fingerprint"], fingerprints, currentFingerprint);
  elements["tls-fingerprint"].disabled = runtime.configurationMode === "fingerprint-file";

  elements["proxy-port"].value = runtime.proxyPort || "";
  elements["proxy-protocol-choice"].value = runtime.proxyProtocol || "mixed";
  elements["proxy-auth-choice"].value = runtime.proxyAuthEnabled ? "enabled" : "disabled";
  configuredProxyAuthEnabled = Boolean(runtime.proxyAuthEnabled);
  elements["proxy-username"].value = runtime.proxyUsername || "";
  elements["proxy-password"].value = "";
  syncProxyAuthFields();

  const upstreamOptions = [{ value: "direct", label: "Прямое соединение" }];
  if (runtime.upstreamEnabled) upstreamOptions.push({ value: "current", label: runtime.upstream });
  upstreamOptions.push({ value: "custom", label: "Другой прокси…" });
  setSelectOptions(elements["upstream-choice"], upstreamOptions, runtime.upstreamEnabled ? "current" : "direct");
  elements["upstream-field"].hidden = true;
  elements["upstream-input"].value = "";

  elements["config-note"].textContent = runtime.configurationMode === "fingerprint-file"
    ? "TLS-отпечаток задаётся файлом; следующий прокси можно изменить."
    : "Изменения применяются к новым соединениям без прерывания активных сессий.";
  elements["config-note"].className = "config-note";
  configInitialized = true;
}

function render(data) {
  const traffic = data.traffic;
  const runtime = data.runtime;
  proxyAuthFilesConfigured = Boolean(runtime.proxyAuthFilesConfigured);
  elements["proxy-auth-reload-button"].disabled = !proxyAuthFilesConfigured;
  if (!proxyAuthFilesConfigured && !elements["proxy-auth-reload-note"].textContent) {
    elements["proxy-auth-reload-note"].textContent = "Файлы учётных данных не настроены.";
  }
  upstreamCredentialFilesConfigured = Boolean(runtime.upstreamCredentialFilesConfigured);
  elements["upstream-credentials-reload-button"].disabled = !upstreamCredentialFilesConfigured;
  if (!upstreamCredentialFilesConfigured && !elements["upstream-credentials-reload-note"].textContent) {
    elements["upstream-credentials-reload-note"].textContent = "Файлы учётных данных вышестоящего прокси не настроены.";
  }
  const caStatus = runtime.mitmCaCertificateStatus || "UNAVAILABLE";
  const caStarted = runtime.mitmCaCertificateNotBefore ? new Date(runtime.mitmCaCertificateNotBefore).toLocaleString() : "не определено";
  elements["mitm-ca-identity"].textContent = `Субъект: ${runtime.mitmCaCertificateSubject || "—"} · SHA-256: ${runtime.mitmCaCertificateSHA256 || "—"} · Действует с: ${caStarted}`;
  const caLabels = { VALID: "Действителен", EXPIRING: "Скоро истекает", EXPIRED: "Истёк", NOT_YET_VALID: "Ещё не действует", UNAVAILABLE: "Не загружен" };
  const expiresAt = runtime.mitmCaCertificateNotAfter ? new Date(runtime.mitmCaCertificateNotAfter).toLocaleString() : "срок не определён";
  const remaining = runtime.mitmCaCertificateDaysRemaining;
  elements["mitm-ca-validity"].textContent = `${caLabels[caStatus] || caStatus} · до ${expiresAt}${remaining === undefined ? "" : ` · ${remaining} дн.`}`;
  elements["mitm-ca-validity"].className = ["EXPIRED", "EXPIRING", "NOT_YET_VALID"].includes(caStatus) ? "ca-validity-warning" : "ca-validity";
  const panelStatus = runtime.panelCertificateStatus || "UNAVAILABLE";
  const panelLabels = { VALID: "Действителен", EXPIRING: "Скоро истекает", EXPIRED: "Истёк", NOT_YET_VALID: "Ещё не действует", UNAVAILABLE: "Не настроен или не прочитан" };
  const panelExpiresAt = runtime.panelCertificateNotAfter ? new Date(runtime.panelCertificateNotAfter).toLocaleString() : "срок не определён";
  const panelRemaining = runtime.panelCertificateDaysRemaining;
  elements["panel-cert-validity"].textContent = `${panelLabels[panelStatus] || panelStatus} · до ${panelExpiresAt}${panelRemaining === undefined ? "" : ` · ${panelRemaining} дн.`}`;
  elements["panel-cert-validity"].className = ["EXPIRED", "EXPIRING", "NOT_YET_VALID"].includes(panelStatus) ? "ca-validity-warning" : "ca-validity";
  const now = new Date(traffic.capturedAt);
  let uploadRate = 0;
  let downloadRate = 0;
  if (previous) {
    const interval = Math.max(.1, (now - new Date(previous.capturedAt)) / 1000);
    uploadRate = Math.max(0, (traffic.totalUploadBytes - previous.totalUploadBytes) / interval);
    downloadRate = Math.max(0, (traffic.totalDownloadBytes - previous.totalDownloadBytes) / interval);
  }

  renderRoute(runtime);
  elements["upload-rate"].textContent = formatBytes(uploadRate, "/с");
  elements["download-rate"].textContent = formatBytes(downloadRate, "/с");
  elements["active-sessions"].textContent = traffic.activeSessions.toLocaleString();
  elements["total-sessions"].textContent = traffic.totalSessions.toLocaleString();
  elements["total-upload"].textContent = formatBytes(traffic.totalUploadBytes);
  elements["total-download"].textContent = formatBytes(traffic.totalDownloadBytes);
  elements.uptime.textContent = uptime(traffic.startedAt);
  renderSessions(traffic.sessions);
  renderEvents(traffic.events);
  syncConfig(runtime);
  previous = traffic;
}

async function refreshState() {
  try {
    const response = await ja3proxyFetch("/api/state", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    render(await response.json());
    elements.connection.className = "connection live";
    elements.connection.innerHTML = "<i></i>На связи";
    elements["error-toast"].classList.remove("show");
  } catch (_) {
    elements.connection.className = "connection lost";
    elements.connection.innerHTML = "<i></i>Связь потеряна";
    elements["error-toast"].classList.add("show");
  }
}

function refresh() {
  if (!refreshPromise) {
    refreshPromise = refreshState().finally(() => { refreshPromise = null; });
  }
  return refreshPromise;
}

function scheduleRefresh(delay = document.hidden ? 5000 : 1000) {
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(runRefreshLoop, delay);
}

async function runRefreshLoop() {
  await refresh();
  scheduleRefresh();
}

document.querySelectorAll("[data-filter]").forEach(button => button.addEventListener("click", () => {
  filter = button.dataset.filter;
  document.querySelectorAll("[data-filter]").forEach(item => {
    const selected = item === button;
    item.classList.toggle("active", selected);
    item.setAttribute("aria-pressed", String(selected));
  });
  if (previous) renderSessions(previous.sessions);
}));

function activateTab(name, updateHash = true) {
  document.querySelectorAll("[data-tab]").forEach(tab => {
    const active = tab.dataset.tab === name;
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-selected", String(active));
    tab.tabIndex = active ? 0 : -1;
  });
  elements["traffic-page"].hidden = name !== "traffic";
  elements["settings-page"].hidden = name !== "settings";
  if (updateHash) history.replaceState(null, "", name === "settings" ? "#settings" : location.pathname);
}

document.querySelectorAll("[data-tab]").forEach(tab => {
  tab.addEventListener("click", () => activateTab(tab.dataset.tab));
  tab.addEventListener("keydown", event => {
    let target;
    if (event.key === "Home") target = "traffic";
    else if (event.key === "End") target = "settings";
    else if (event.key === "ArrowLeft" || event.key === "ArrowRight") {
      target = tab.dataset.tab === "traffic" ? "settings" : "traffic";
    } else return;
    event.preventDefault();
    activateTab(target);
    document.querySelector(`[data-tab="${target}"]`).focus();
  });
});

elements["upstream-choice"].addEventListener("change", () => {
  const custom = elements["upstream-choice"].value === "custom";
  elements["upstream-field"].hidden = !custom;
  if (custom) elements["upstream-input"].focus();
});

function syncProxyAuthFields() {
  const enabled = elements["proxy-auth-choice"].value === "enabled";
  elements["proxy-username-field"].hidden = !enabled;
  elements["proxy-password-field"].hidden = !enabled;
}

elements["proxy-auth-choice"].addEventListener("change", () => {
  syncProxyAuthFields();
  if (elements["proxy-auth-choice"].value === "enabled") elements["proxy-username"].focus();
});

elements["ca-reload-button"].addEventListener("click", async () => {
  if (!window.confirm("Применить CA из настроенного файла? Новые TLS-соединения потребуют доверия к новому публичному сертификату.")) return;
  const button = elements["ca-reload-button"];
  const note = elements["ca-reload-note"];
  button.disabled = true;
  note.className = "config-note";
  note.textContent = "Проверка и применение CA…";
  try {
    const response = await ja3proxyFetch("/api/v1/admin/ca/reload", { method: "POST" });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `HTTP ${response.status}`);
    note.textContent = "CA применён к новым соединениям. Проверьте доверие клиентов к публичному сертификату.";
    note.className = "config-note success";
    await refreshState();
  } catch (error) {
    note.textContent = error.message || "Не удалось применить CA; прежний CA остаётся активным.";
    note.className = "config-note error";
  } finally {
    button.disabled = false;
  }
});

elements["ca-rotate-button"].addEventListener("click", async () => {
  if (!window.confirm("Создать новый CA и немедленно активировать его? Все клиенты должны будут установить новый публичный сертификат; старый CA больше не будет подписывать новые TLS-сертификаты.")) return;
  const button = elements["ca-rotate-button"];
  const note = elements["ca-rotate-note"];
  button.disabled = true;
  note.className = "config-note";
  note.textContent = "Создание и активация нового CA…";
  try {
    const response = await ja3proxyFetch("/api/v1/admin/ca/rotate", { method: "POST" });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `HTTP ${response.status}`);
    note.innerHTML = `Новый CA активирован. <a href="/api/v1/ca/certificate" data-auth-download data-filename="ja3proxy-ca.pem">Скачайте новый публичный сертификат</a> и установите его на клиентах.`;
    note.className = "config-note success";
    await refreshState();
  } catch (error) {
    note.textContent = error.message || "Ротация не выполнена; действующий CA не изменён.";
    note.className = "config-note error";
  } finally {
    button.disabled = false;
  }
});

elements["spool-key-reload-button"].addEventListener("click", async () => {
  const button = elements["spool-key-reload-button"];
  const note = elements["spool-key-reload-note"];
  if (button.disabled) return;
  button.disabled = true;
  note.className = "config-note";
  note.textContent = "Применение ключа…";
  try {
    const response = await ja3proxyFetch("/api/v1/admin/spool/reload-key", { method: "POST" });
    if (!response.ok) {
      const result = await response.json();
      throw new Error(result.error || `HTTP ${response.status}`);
    }
    note.textContent = "Ключ применён. Новые записи spool используют новый ключ.";
    note.className = "config-note success";
  } catch (error) {
    note.textContent = error.message || "Не удалось получить результат. Проверьте состояние перед перезапуском.";
    note.className = "config-note error";
  } finally {
    button.disabled = false;
  }
});

elements["proxy-auth-reload-button"].addEventListener("click", async () => {
  const button = elements["proxy-auth-reload-button"];
  const note = elements["proxy-auth-reload-note"];
  if (button.disabled) return;
  button.disabled = true;
  note.className = "config-note";
  note.textContent = "Чтение и проверка файлов учётных данных…";
  try {
    const response = await ja3proxyFetch("/api/v1/admin/proxy-auth/reload", { method: "POST" });
    if (!response.ok) {
      const result = await response.json();
      throw new Error(result.error || `HTTP ${response.status}`);
    }
    note.textContent = "Новые учётные данные применены для новых подключений.";
    note.className = "config-note success";
    await refreshState();
  } catch (error) {
    note.textContent = error.message || "Не удалось применить файлы учётных данных; прежняя пара сохранена.";
    note.className = "config-note error";
  } finally {
    button.disabled = !proxyAuthFilesConfigured;
  }
});

elements["upstream-credentials-reload-button"].addEventListener("click", async () => {
  const button = elements["upstream-credentials-reload-button"];
  const note = elements["upstream-credentials-reload-note"];
  if (button.disabled) return;
  button.disabled = true;
  note.className = "config-note";
  note.textContent = "Чтение файлов учётных данных вышестоящего прокси…";
  try {
    const response = await ja3proxyFetch("/api/v1/admin/upstream-credentials/reload", { method: "POST" });
    if (!response.ok) {
      const result = await response.json();
      throw new Error(result.error || `HTTP ${response.status}`);
    }
    note.textContent = "Новые учётные данные вышестоящего прокси применены для новых подключений.";
    note.className = "config-note success";
    await refreshState();
  } catch (error) {
    note.textContent = error.message || "Не удалось применить файлы; текущие подключения сохранены.";
    note.className = "config-note error";
  } finally {
    button.disabled = !upstreamCredentialFilesConfigured;
  }
});

elements["config-form"].addEventListener("submit", async event => {
  event.preventDefault();
  const submit = event.submitter;
  const payload = {};
  payload.expected_version = runtimeConfigVersion;
  const proxyPort = Number(elements["proxy-port"].value);
  if (!Number.isInteger(proxyPort) || proxyPort < 1 || proxyPort > 65535) {
    elements["config-note"].textContent = "Введите порт прокси от 1 до 65535.";
    elements["config-note"].className = "config-note error";
    elements["proxy-port"].focus();
    return;
  }
  payload.proxyPort = proxyPort;
  payload.proxyProtocol = elements["proxy-protocol-choice"].value;

  const proxyAuthEnabled = elements["proxy-auth-choice"].value === "enabled";
  payload.proxyAuthEnabled = proxyAuthEnabled;
  if (proxyAuthEnabled) {
    const username = elements["proxy-username"].value.trim();
    if (!username) {
      elements["config-note"].textContent = "Введите имя пользователя клиента.";
      elements["config-note"].className = "config-note error";
      elements["proxy-username"].focus();
      return;
    }
    payload.proxyUsername = username;
    const password = elements["proxy-password"].value;
    if (!configuredProxyAuthEnabled && !password) {
      elements["config-note"].textContent = "Введите пароль клиента.";
      elements["config-note"].className = "config-note error";
      elements["proxy-password"].focus();
      return;
    }
    if (password) payload.proxyPassword = password;
  }
  if (!elements["tls-fingerprint"].disabled) payload.tlsFingerprint = elements["tls-fingerprint"].value;

  const upstreamChoice = elements["upstream-choice"].value;
  if (upstreamChoice === "direct") payload.upstream = "";
  if (upstreamChoice === "custom") {
    const upstream = elements["upstream-input"].value.trim();
    if (!upstream) {
      elements["config-note"].textContent = "Введите URL прокси SOCKS5 или HTTP.";
      elements["config-note"].className = "config-note error";
      elements["upstream-input"].focus();
      return;
    }
    payload.upstream = upstream;
  }

  if (!Object.keys(payload).length) {
    elements["config-note"].textContent = "Изменения конфигурации не выбраны.";
    elements["config-note"].className = "config-note";
    return;
  }

  submit.disabled = true;
  elements["config-note"].className = "config-note";
  elements["config-note"].textContent = "Применение…";
  try {
    const response = await ja3proxyFetch("/api/config", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `HTTP ${response.status}`);
    configInitialized = false;
    syncConfig(result.runtime, true);
    elements["config-note"].textContent = "Применено к новым соединениям.";
    elements["config-note"].className = "config-note success";
    await refresh();
  } catch (error) {
    elements["config-note"].textContent = error.message || "Не удалось обновить конфигурацию.";
    elements["config-note"].className = "config-note error";
  } finally {
    submit.disabled = false;
  }
});

activateTab(location.hash === "#settings" ? "settings" : "traffic", false);
document.addEventListener("visibilitychange", () => scheduleRefresh(document.hidden ? 5000 : 0));
runRefreshLoop();
