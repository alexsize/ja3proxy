"use strict";

const tokenStatus = document.getElementById("token-status");
const tokenTable = document.getElementById("tokens");
const issuedPanel = document.getElementById("issued-panel");
const issuedSecret = document.getElementById("issued-secret");

function tokenDate(value) {
  if (!value) return "Без срока";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString();
}

async function tokenAPI(path, options = {}) {
  const response = await window.ja3proxyFetch(path, options);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
  return body;
}

async function refreshTokens() {
  tokenStatus.textContent = "Загружаю реестр…";
  try {
    const result = await tokenAPI("/api/v1/admin/tokens");
    tokenTable.replaceChildren();
    for (const item of result.tokens || []) {
      const row = document.createElement("tr");
      const idCell = document.createElement("td"); idCell.textContent = item.id; row.append(idCell);
      const roleCell = document.createElement("td");
      const role = document.createElement("select");
      for (const [value, label] of [["viewer", "Наблюдатель"], ["operator", "Оператор"], ["investigator", "Исследователь"], ["admin", "Администратор"]]) {
        const option = document.createElement("option"); option.value = value; option.textContent = label; option.selected = item.role === value; role.append(option);
      }
      role.disabled = item.revoked;
      roleCell.append(role); row.append(roleCell);
      for (const value of [(item.scopes || []).join(", "), tokenDate(item.expires_at), item.revoked ? "Отозван" : "Активен"]) {
        const cell = document.createElement("td"); cell.textContent = value; row.append(cell);
      }
      const actions = document.createElement("td");
      if (!item.revoked) {
        const saveRole = document.createElement("button"); saveRole.type = "button"; saveRole.textContent = "Изменить роль";
        saveRole.addEventListener("click", () => runTokenAction(async () => {
          await tokenAPI(`/api/v1/admin/tokens/${encodeURIComponent(item.id)}`, {method: "PUT", headers: {"Content-Type": "application/json"}, body: JSON.stringify({role: role.value, expires_at: item.expires_at || ""})});
          await refreshTokens();
        }));
        const rotate = document.createElement("button"); rotate.type = "button"; rotate.textContent = "Заменить токен";
        rotate.addEventListener("click", () => runTokenAction(async () => showIssued(await tokenAPI(`/api/v1/admin/tokens/${encodeURIComponent(item.id)}/rotate`, {method: "POST"}), true)));
        const revoke = document.createElement("button"); revoke.type = "button"; revoke.textContent = "Отозвать";
        revoke.addEventListener("click", () => runTokenAction(async () => { await tokenAPI(`/api/v1/admin/tokens/${encodeURIComponent(item.id)}`, {method: "DELETE"}); await refreshTokens(); }));
        actions.append(saveRole, rotate, revoke);
      }
      row.append(actions); tokenTable.append(row);
    }
    tokenStatus.textContent = `Токенов: ${(result.tokens || []).length}`;
  } catch (error) { tokenStatus.textContent = `Ошибка: ${error.message}`; }
}

function showIssued(result, replaceSessionToken = false) {
  issuedSecret.textContent = result.token;
  issuedPanel.hidden = false;
  if (replaceSessionToken) window.ja3proxySetToken(result.token);
  refreshTokens();
}

async function runTokenAction(action) {
  try { await action(); }
  catch (error) { tokenStatus.textContent = `Ошибка: ${error.message}`; }
}

document.getElementById("issue-token").addEventListener("submit", event => {
  event.preventDefault();
  runTokenAction(async () => {
    const expiryValue = document.getElementById("token-expiry").value;
    const payload = {
      id: document.getElementById("token-id").value.trim(),
      role: document.getElementById("token-role").value,
      expires_at: expiryValue ? new Date(expiryValue).toISOString() : ""
    };
    showIssued(await tokenAPI("/api/v1/admin/tokens", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload)}));
    event.target.reset();
  });
});

document.getElementById("refresh-tokens").addEventListener("click", refreshTokens);
document.getElementById("copy-secret").addEventListener("click", async () => {
  try { await navigator.clipboard.writeText(issuedSecret.textContent); tokenStatus.textContent = "Секрет скопирован."; }
  catch (_) { tokenStatus.textContent = "Не удалось скопировать автоматически; скопируйте значение вручную."; }
});

refreshTokens();
