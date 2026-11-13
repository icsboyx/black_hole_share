// Helpers shared by the admin pages (admin.html, files.html). Loaded as a classic script
// before each page's own script, so these are plain globals.

const MIB = 1024 * 1024;
const GIB = 1024 * MIB;

function setMessage(id, text, kind = "error") {
  const element = document.getElementById(id);
  element.textContent = text;
  element.className = `message ${kind}`;
}

// Builds DOM nodes; strings become text nodes, so server data is never parsed as HTML.
function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  Object.assign(node, props);
  for (const child of children) {
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

// Calls the admin API; `data` is the parsed JSON body, or null for any other response.
async function api(path, options = {}) {
  const init = { method: options.method || "GET", headers: {} };
  if (options.body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(options.body);
  }
  const response = await fetch(`/api/admin${path}`, init);
  let data = null;
  const type = response.headers.get("content-type") || "";
  if (type.includes("application/json")) {
    data = await response.json();
  }
  return { response, data };
}

function errorText(result, fallback) {
  return (result.data && result.data.error) || `${fallback} (HTTP ${result.response.status})`;
}

function formatBytes(bytes) {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(sizes.length - 1, Math.floor(Math.log(bytes) / Math.log(k)));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

function formatDuration(ms) {
  const total = Math.max(0, Math.floor(ms / 1000));
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m ${String(total % 60).padStart(2, "0")}s`;
}

function formatTime(millis) {
  return new Date(millis).toLocaleString("en-GB", { hour12: false });
}

function formatRemaining(expiresAt) {
  const seconds = Math.max(0, Math.round((expiresAt - Date.now()) / 1000));
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${String(seconds % 60).padStart(2, "0")}s`;
}

function table(headers, rows) {
  if (rows.length === 0) {
    return el("p", { className: "empty" }, "Nothing here.");
  }
  return el(
    "table",
    {},
    el("thead", {}, el("tr", {}, ...headers.map((h) => el("th", {}, h)))),
    el("tbody", {}, ...rows)
  );
}
