"use strict";

const panelTokenKey = "ja3proxy.panelToken";

function panelHeaders(options, token) {
  const headers = new Headers(options.headers || {});
  if (token) headers.set("Authorization", `Bearer ${token}`);
  return headers;
}

async function panelFetch(path, options = {}, allowPrompt = true) {
  let token = sessionStorage.getItem(panelTokenKey) || "";
  let response = await fetch(path, {...options, headers: panelHeaders(options, token)});
  if (response.status !== 401 || !allowPrompt) return response;

  sessionStorage.removeItem(panelTokenKey);
  token = window.prompt("Введите bearer-токен веб-панели");
  if (!token) return response;
  token = token.trim();
  if (!token) return response;
  sessionStorage.setItem(panelTokenKey, token);
  response = await panelFetch(path, options, false);
  if (response.status === 401) sessionStorage.removeItem(panelTokenKey);
  return response;
}

async function downloadWithPanelAuth(link) {
  const response = await panelFetch(link.href);
  if (!response.ok) {
    let message = `HTTP ${response.status}`;
    try { message = (await response.json()).error || message; } catch (_) { /* non-JSON response */ }
    throw new Error(message);
  }
  const blobURL = URL.createObjectURL(await response.blob());
  const anchor = document.createElement("a");
  anchor.href = blobURL;
  anchor.download = link.dataset.filename || "ja3proxy-export.jsonl";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(blobURL);
}

window.ja3proxyFetch = panelFetch;
window.ja3proxySetToken = token => sessionStorage.setItem(panelTokenKey, token);

document.addEventListener("click", event => {
  const link = event.target.closest("a[data-auth-download]");
  if (!link) return;
  event.preventDefault();
  downloadWithPanelAuth(link).catch(error => window.alert(error.message));
});
