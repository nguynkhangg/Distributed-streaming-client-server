"use strict";
/*
 * app.js — LOGIC GIAO DIỆN: vẽ màn hình và xử lý thao tác của người dùng. Không chứa logic mạng.
 *
 * Luồng hoạt động:
 *   - Thao tác của người dùng (đăng nhập, gửi tin, gửi/nhận file) -> gọi hàm trong `Api` (api.js).
 *   - Mọi dữ liệu hiển thị (tin nhắn, danh sách online, tiến độ file, trạng thái mạng) đến từ các
 *     SỰ KIỆN do agent gửi qua Api.startEvents -> handleEvent() cập nhật biến trạng thái `S`
 *     rồi vẽ lại phần giao diện tương ứng (renderSidebar / renderMessages / renderTransfers ...).
 *   - Nội dung do người dùng gõ luôn được đưa vào DOM bằng textContent (hàm h()), không dùng
 *     innerHTML, để tránh chèn mã độc (XSS).
 *
 * Đang chạy dữ liệu giả (mock)? Xem hướng dẫn TẮT MOCK ở đầu file api.js
 * (đổi USE_MOCK = false, hoặc thêm ?mock=0 vào URL). Dòng "?as=<tên>" ở cuối file chỉ có tác dụng
 * khi mock đang bật, dùng để tự đăng nhập khi thử giao diện.
 */

const ERROR_TEXT = {
  INVALID_PACKET: "Malformed packet",
  UNSUPPORTED_VERSION: "Unsupported protocol version",
  UNKNOWN_MESSAGE_TYPE: "Unknown message type",
  INVALID_PAYLOAD: "Invalid request data",
  AUTH_FAILED: "Wrong username or password",
  ALREADY_LOGGED_IN: "This account is already logged in elsewhere",
  ALREADY_AUTHENTICATED: "You are already logged in",
  NOT_AUTHENTICATED: "Please log in first",
  USER_NOT_FOUND: "User not found",
  USER_OFFLINE: "User is offline",
  FILE_REJECTED: "The recipient rejected the file",
  TRANSFER_NOT_FOUND: "Transfer not found",
  TRANSFER_FAILED: "File transfer failed",
  INTERNAL_ERROR: "Internal server error",
};
const CONN_TEXT = {
  disconnected: "Disconnected", connecting: "Connecting…", established: "Handshake done",
  authenticated: "Connected", closing: "Closing…",
};
const FILE_TEXT = {
  incoming: "Waiting for you", offered: "Waiting for recipient", ready: "Ready",
  transferring: "Transferring", verifying: "Verifying", completed: "Completed ✓",
  rejected: "Rejected", failed: "Failed", cancelled: "Cancelled",
};
const FILE_DONE = new Set(["completed", "rejected", "failed", "cancelled"]);
const AUTH_TIMEOUT_MS = 10000; // server closes unauthenticated connections after 10 s (spec 7)

const S = {
  me: null,
  conn: "disconnected",
  link: true,
  users: new Map(),     // online usernames -> {ip, port}
  convs: new Map(),     // "*" or username -> [{sender, text, ts}]
  transfers: new Map(), // key -> transfer
  net: {},
  active: "*",
  authTimer: null,
};

const $ = (id) => document.getElementById(id);

/** Build a DOM node. Text is always set via textContent/append, never innerHTML (XSS-safe). */
function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (v === true) el.setAttribute(k, "");
    else if (v !== false && v != null) el.setAttribute(k, v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid);
  return el;
}

const initials = (name) => (name || "?").slice(0, 2).toUpperCase();
const fmtTime = (ts) => new Date(ts * 1000).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
function fmtBytes(n) {
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  if (n < 1073741824) return (n / 1048576).toFixed(1) + " MB";
  return (n / 1073741824).toFixed(2) + " GB";
}
const errText = (code, fallback) => ERROR_TEXT[code] || fallback || code || "Unknown error";

/* ------------------------------------------------------------------ */
/* Toasts, banner, views                                              */
/* ------------------------------------------------------------------ */
function toast(text, info) {
  const el = h("div", { class: "toast" + (info ? " info" : ""), role: "alert" }, text);
  $("toasts").append(el);
  setTimeout(() => el.remove(), 5000);
}

function showView(app) {
  $("login-view").hidden = app;
  $("app-view").hidden = !app;
}

function renderBanner() {
  const b = $("banner");
  b.replaceChildren();
  if (!S.link) {
    b.className = "banner bad";
    b.append("Cannot reach the local agent (127.0.0.1) — retrying…");
    b.hidden = false;
  } else if (S.me && S.conn === "disconnected") {
    b.className = "banner";
    b.append("Lost connection to the server.", h("button", { class: "btn ghost sm", type: "button", onclick: backToLogin }, "Back to login"));
    b.hidden = false;
  } else {
    b.hidden = true;
  }
}

function backToLogin() {
  S.me = null;
  S.users.clear();
  S.convs.clear();
  S.transfers.clear();
  S.net = {};
  S.active = "*";
  setLoginBusy(false);
  showView(false);
  renderBanner();
}

/* ------------------------------------------------------------------ */
/* Login                                                              */
/* ------------------------------------------------------------------ */
function setLoginBusy(busy) {
  $("login-btn").disabled = busy;
  $("login-btn").textContent = busy ? "Logging in…" : "Log in";
  clearTimeout(S.authTimer);
  if (busy) {
    S.authTimer = setTimeout(() => {
      setLoginBusy(false);
      showLoginError("Timed out waiting for the server");
    }, AUTH_TIMEOUT_MS);
  }
}

function showLoginError(text) {
  $("login-error").textContent = text;
  $("login-error").hidden = !text;
}

async function submitLogin(user, pass) {
  showLoginError("");
  setLoginBusy(true);
  try {
    const res = await Api.login(user, pass);
    if (!res.ok) {
      setLoginBusy(false);
      showLoginError(errText(res.code, res.message));
    }
  } catch (err) {
    setLoginBusy(false);
    showLoginError("Cannot reach the local agent");
  }
}

$("login-form").addEventListener("submit", (e) => {
  e.preventDefault();
  submitLogin($("login-user").value.trim(), $("login-pass").value);
});

$("logout-btn").addEventListener("click", async () => {
  try { await Api.logout(); } catch (err) { /* agent already gone: just leave */ }
  backToLogin();
});

/* ------------------------------------------------------------------ */
/* Conversations: "*" is the global chat, a username is a private chat */
/* ------------------------------------------------------------------ */
function convItems(key) {
  if (!S.convs.has(key)) S.convs.set(key, []);
  return S.convs.get(key);
}

function selectConv(key) {
  S.active = key;
  renderSidebar();
  renderHeader();
  renderMessages();
  $("text-input").focus();
}

function convButton(key, avatar, label) {
  return h("li", {}, h("button", {
    type: "button", class: key === S.active ? "act" : "", onclick: () => selectConv(key),
    "aria-current": key === S.active ? "true" : false,
  }, h("span", { class: "av" }, avatar), h("span", { class: "name" }, label),
  key !== "*" ? h("span", { class: "dot", title: "online" }) : null));
}

function renderSidebar() {
  $("channel-list").replaceChildren(convButton("*", "#", "Global chat"));
  const names = [...S.users.keys()].filter((n) => n !== S.me).sort((a, b) => a.localeCompare(b));
  $("user-list").replaceChildren(...names.map((n) => convButton(n, initials(n), n)));
  $("self-avatar").textContent = initials(S.me);
  $("self-name").textContent = S.me || "";
}

function renderHeader() {
  const priv = S.active !== "*";
  $("conv-title").textContent = priv ? "@ " + S.active : "# Global chat";
  const connected = S.conn === "authenticated" && S.link;
  $("pill-conn").textContent = (connected ? "● " : "○ ") + (CONN_TEXT[S.conn] || S.conn);
  $("pill-conn").className = "pill " + (connected ? "ok" : "bad");
  $("text-input").disabled = !connected;
  $("send-btn").disabled = !connected;
  $("attach-btn").disabled = !connected || !priv;
  $("attach-btn").title = priv ? "Send a file to " + S.active : "Select a user to send a file";
}

function renderMessages() {
  const box = $("messages");
  const items = convItems(S.active);
  const stick = box.scrollHeight - box.scrollTop - box.clientHeight < 60 || !box.children.length;
  if (!items.length) {
    box.replaceChildren(h("div", { class: "empty" }, "No messages yet."));
    return;
  }
  box.replaceChildren(...items.map((it) => {
    const mine = it.sender === S.me;
    return h("div", { class: "m" + (mine ? " mine" : "") }, h("div", { class: "av" }, initials(it.sender)),
      h("div", {}, h("div", { class: "meta" }, it.sender + " · " + fmtTime(it.ts)), h("div", { class: "bubble" }, it.text)));
  }));
  if (stick) box.scrollTop = box.scrollHeight;
}

function addMessage(key, msg) {
  convItems(key).push(msg);
  if (key === S.active) renderMessages();
}

/* ------------------------------------------------------------------ */
/* Sending messages and files                                         */
/* ------------------------------------------------------------------ */
$("composer").addEventListener("submit", async (e) => {
  e.preventDefault();
  const input = $("text-input");
  const text = input.value.trim();
  if (!text) return;
  input.value = "";
  const target = S.active;
  try {
    const res = await Api.send(target, text);
    if (!res.ok) return toast(errText(res.code, res.message));
    addMessage(target, { sender: S.me, text, ts: Date.now() / 1000 }); // server does not echo our own messages
  } catch (err) {
    toast("Could not send: cannot reach the local agent");
  }
});

$("attach-btn").addEventListener("click", () => $("file-input").click());
$("file-input").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  e.target.value = "";
  if (!file) return;
  const target = S.active;
  try {
    const res = await Api.offerFile(target, file);
    if (!res.ok) return toast(errText(res.code, res.message));
    if (!findTransfer({ ref: res.ref })) { // the agent's first "file" event may already have created it
      upsertTransfer({ key: res.ref, ref: res.ref, direction: "send", peer: target, filename: file.name, size_bytes: file.size, state: "offered" });
      renderTransfers();
    }
  } catch (err) {
    toast("Could not send the file: cannot reach the local agent");
  }
});

/* ------------------------------------------------------------------ */
/* File transfers (progress bars in the right panel)                  */
/* ------------------------------------------------------------------ */
function findTransfer(ev) {
  for (const t of S.transfers.values()) {
    if ((ev.file_id && t.file_id === ev.file_id) || (ev.ref && t.ref === ev.ref)) return t;
  }
  return null;
}

function upsertTransfer(data) {
  let t = findTransfer(data);
  if (!t) {
    t = { key: data.key || data.file_id || data.ref, transferred_bytes: 0, size_bytes: 0 };
    S.transfers.set(t.key, t);
  }
  Object.assign(t, Object.fromEntries(Object.entries(data).filter(([, v]) => v != null)));
  return t;
}

function fileCard(t) {
  const done = FILE_DONE.has(t.state);
  const pct = t.size_bytes ? Math.min(100, Math.floor((t.transferred_bytes / t.size_bytes) * 100)) : 0;
  const bad = t.state === "failed" || t.state === "rejected" || t.state === "cancelled";
  const barCls = t.state === "completed" ? "done" : bad ? "fail" : "";
  const stCls = t.state === "completed" ? "st-ok" : bad ? "st-bad" : "st-wait";
  const arrow = (t.direction === "send" ? "↑ " : "↓ ") + t.peer;
  return h("div", { class: "card", "data-file": t.key },
    h("div", { class: "fname" }, t.filename),
    h("div", { class: "frow" }, h("span", {}, fmtBytes(t.size_bytes) + " · " + arrow), h("span", {}, t.state === "transferring" ? pct + "%" : "")),
    h("div", { class: "bar " + barCls, role: "progressbar", "aria-valuenow": pct, "aria-valuemin": 0, "aria-valuemax": 100 },
      h("i", { style: "width:" + (t.state === "completed" ? 100 : pct) + "%" })),
    h("div", { class: "frow" }, h("span", { class: stCls }, FILE_TEXT[t.state] || t.state)),
    t.state === "incoming" ? h("div", { class: "fact" },
      h("button", { class: "btn sm", type: "button", onclick: () => respond(t, true) }, "Accept"),
      h("button", { class: "btn ghost sm", type: "button", onclick: () => respond(t, false) }, "Reject")) : null);
}

function patchTransfer(t) {
  const el = document.querySelector('[data-file="' + CSS.escape(t.key) + '"]');
  if (el) el.replaceWith(fileCard(t));
  else renderTransfers();
}

function renderTransfers() {
  const list = [...S.transfers.values()].reverse();
  $("transfer-list").replaceChildren(...(list.length ? list.map(fileCard) : [h("div", { class: "small" }, "No files yet.")]));
}

async function respond(t, accepted) {
  try {
    const res = await Api.respondFile(t.file_id, accepted);
    if (!res.ok) return toast(errText(res.code, res.message));
    t.state = accepted ? "ready" : "rejected";
    patchTransfer(t);
  } catch (err) {
    toast("Cannot reach the local agent");
  }
}

/* ------------------------------------------------------------------ */
/* Network status card                                                */
/* ------------------------------------------------------------------ */
function renderNet() {
  const n = S.net;
  const row = (k, v) => h("div", { class: "row" }, h("span", {}, k), h("span", {}, v));
  $("net-card").replaceChildren(
    row("State", CONN_TEXT[S.conn] || S.conn),
    row("RTT", n.rtt_ms != null ? Math.round(n.rtt_ms) + " ms" : "—"),
    row("Packet loss", n.loss != null ? (n.loss * 100).toFixed(1) + "%" : "—"),
  );
}

/* ------------------------------------------------------------------ */
/* Events from the agent                                              */
/* ------------------------------------------------------------------ */
function handleEvent(ev) {
  switch (ev.type) {
    case "conn":
      S.conn = ev.state;
      if (ev.state === "disconnected" && !S.me) setLoginBusy(false);
      break;
    case "net":
      Object.assign(S.net, ev);
      break;
    case "auth_ack":
      setLoginBusy(false);
      if (ev.success) {
        S.me = ev.username;
        showView(true);
        selectConv("*");
      } else {
        showLoginError(errText(ev.error));
      }
      break;
    case "user_list":
      S.users.clear();
      ev.users.forEach((u) => { if (u.status === "online") S.users.set(u.username, { ip: u.ip, port: u.port }); });
      break;
    case "presence":
      if (ev.status === "online") S.users.set(ev.username, {});
      else S.users.delete(ev.username);
      break;
    case "msg":
      addMessage(ev.target === "*" ? "*" : ev.sender === S.me ? ev.target : ev.sender, { sender: ev.sender, text: ev.text, ts: ev.timestamp });
      break;
    case "file_incoming":
      upsertTransfer({ key: ev.file_id, file_id: ev.file_id, direction: "recv", peer: ev.sender, filename: ev.filename, size_bytes: ev.size_bytes, state: "incoming" });
      renderTransfers();
      toast(ev.sender + " wants to send " + ev.filename, true);
      break;
    case "file": {
      const isNew = !findTransfer(ev);
      const t = upsertTransfer({ key: ev.ref || ev.file_id, file_id: ev.file_id, ref: ev.ref, direction: ev.direction, peer: ev.peer, filename: ev.filename, size_bytes: ev.size_bytes, state: ev.state, transferred_bytes: ev.transferred_bytes });
      if (isNew) renderTransfers();
      else patchTransfer(t);
      break;
    }
    case "error":
      toast(errText(ev.code, ev.message));
      break;
  }
}

function handleEvents(events) {
  events.forEach(handleEvent);
  renderBanner();
  if (S.me) {
    renderSidebar();
    renderHeader();
    renderNet();
  }
}

/* ------------------------------------------------------------------ */
/* Start                                                              */
/* ------------------------------------------------------------------ */
if (MOCK) $("login-hint").textContent = "Mock mode — not connected to a real agent.";
renderNet();
renderTransfers();
Api.startEvents(handleEvents, (up) => {
  if (S.link === up) return;
  S.link = up;
  renderBanner();
  if (S.me) renderHeader();
});

const autoUser = new URLSearchParams(location.search).get("as");
if (MOCK && autoUser) submitLogin(autoUser, "demo");
