"use strict";
const $ = id => document.getElementById(id);
let state = {sites: [], principal: "", console_host: ""}, selected = "", selectionVersion = 0;
let busy = false;

async function api(path, data) {
  const response = await fetch(path, {credentials: "same-origin", redirect: "error",
    ...(data ? {method: "POST", headers: {"Content-Type": "application/json", "X-Requested-With": "authn-permissions"}, body: JSON.stringify(data)} : {})});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "Request failed. Refresh your session and try again.");
  return result;
}

function message(text, error = false) {
  $("message").textContent = text;
  $("message").className = error ? "error" : "";
}

function renderSites() {
  const query = $("search").value.toLowerCase();
  $("sites").replaceChildren();
  for (const site of state.sites.filter(s => ((s.title || s.name) + " " + s.host).toLowerCase().includes(query))) {
    const button = document.createElement("button");
    button.type = "button"; button.className = "site";
    button.setAttribute("aria-current", String(site.host === selected));
    const name = document.createElement("strong"), host = document.createElement("span");
    name.textContent = site.title || site.name; host.textContent = site.host;
    button.append(name, host); button.addEventListener("click", () => { if (!busy) select(site.host); });
    $("sites").append(button);
  }
}

async function select(host) {
  selected = host; const version = ++selectionVersion;
  const site = state.sites.find(s => s.host === host);
  if (!site) { $("details").hidden = true; return; }
  renderSites(); $("details").hidden = false;
  $("title").textContent = site.title || site.name;
  $("host").textContent = host; $("host").href = "https://" + host + "/";
  $("source").textContent = site.source === "built-in" ? "BUILT-IN SITE" : "ADDON · " + site.source;
  $("admin-note").hidden = host !== state.console_host;
  $("identity-link").href = "https://" + host + "/authn/identity";
  $("grants").textContent = "Loading permissions…"; $("grant-count").textContent = "…";
  try {
    const {principals} = await api("/api/grants?host=" + encodeURIComponent(host));
    if (version !== selectionVersion) return;
    $("grants").replaceChildren();
    $("grant-count").textContent = principals.length + " granted";
    if (!principals.length) {
      const empty = document.createElement("p"); empty.className = "empty";
      empty.textContent = "No access granted. Add a person or agent below."; $("grants").append(empty);
    }
    for (const principal of principals) {
      const row = document.createElement("div"), code = document.createElement("code"), button = document.createElement("button");
      row.className = "grant"; code.textContent = principal;
      button.type = "button"; button.className = "remove"; button.textContent = "Revoke";
      button.setAttribute("aria-label", "Revoke " + principal);
      button.addEventListener("click", () => change("revoke", principal, host));
      row.append(code, button); $("grants").append(row);
    }
  } catch (error) { if (version === selectionVersion) { $("grants").textContent = "Could not load permissions."; message(error.message, true); } }
}

async function refresh() {
  if (busy) return;
  try {
    state = await api("/api/catalog");
    state.sites.sort((a, b) => a.host.localeCompare(b.host));
    $("actor").textContent = state.principal; $("count").textContent = state.sites.length;
    $("rejected").replaceChildren();
    for (const [route, reason] of Object.entries(state.rejected)) {
      const item = document.createElement("li"); item.textContent = route + ": " + reason; $("rejected").append(item);
    }
    $("rejected-section").hidden = !Object.keys(state.rejected).length;
    const next = state.sites.some(s => s.host === selected) ? selected : state.sites[0]?.host;
    renderSites(); if (next) await select(next); else $("details").hidden = true;
    message("Sites loaded. Select a site to view its grants.");
  } catch (error) { message(error.message, true); }
}

async function change(action, principal, host) {
  if (busy) return;
  if (action === "revoke" && !window.confirm("Revoke " + principal + " from " + host + "?" + (host === state.console_host && principal === state.principal ? " You will lose access to this console. Recovery requires the CLI." : ""))) return;
  busy = true; $("grant-button").disabled = true;
  try {
    await api("/api/membership", {action, principal, host});
    message((action === "grant" ? "Granted" : "Revoked") + " access for " + principal + ".");
    $("principal").value = "";
    await select(host);
  } catch (error) { message(error.message, true); }
  finally { busy = false; $("grant-button").disabled = false; }
}

$("search").addEventListener("input", renderSites);
$("refresh").addEventListener("click", refresh);
$("grant-form").addEventListener("submit", event => {
  event.preventDefault(); change("grant", $("principal").value.trim(), selected);
});
refresh();
