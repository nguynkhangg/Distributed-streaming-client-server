"use strict";
/*
 * api.js — LỚP GIAO TIẾP giữa trang web và "agent" (chương trình Python chạy trên máy của mỗi
 * người dùng, xem protocol-spec.md mục 13). File này là nơi DUY NHẤT trong giao diện gọi ra mạng.
 * Giao diện (app.js) chỉ gọi các hàm của đối tượng `Api` bên dưới, không tự gọi fetch.
 *
 * ================= CÁCH TẮT MOCK (QUAN TRỌNG) =================
 * MOCK = dữ liệu giả chạy ngay trong trình duyệt, để làm giao diện khi agent chưa có.
 * Khi agent thật đã chạy và phục vụ các endpoint /api/*, hãy chuyển sang dùng agent thật:
 *   Cách 1 (tắt vĩnh viễn): đổi `const USE_MOCK = true;` thành `const USE_MOCK = false;` bên dưới.
 *   Cách 2 (thử nhanh, không sửa code): thêm ?mock=0 vào URL, ví dụ http://127.0.0.1:8080/?mock=0
 *            (ngược lại ?mock=1 ép bật mock dù USE_MOCK = false).
 * Trước khi nộp bài nhớ đặt USE_MOCK = false. Có thể xóa luôn hàm createMockApi() ở cuối file.
 *
 * Khi đang bật mock:
 *   - Thêm ?as=alice vào URL để tự đăng nhập (bỏ qua màn hình login).
 *   - Password "wrong" -> lỗi AUTH_FAILED; username bob/carol/dave -> lỗi ALREADY_LOGGED_IN.
 *   - Gửi tin cho dave (sẽ offline sau 20 giây) -> lỗi USER_OFFLINE.
 *   - Tên file chứa "reject" -> bị từ chối; chứa "fail" -> truyền đến ~60% rồi lỗi.
 *   - Số liệu RTT / mất gói trong "Network status" là SỐ GIẢ ngẫu nhiên, không đo mạng thật.
 *
 * ================= HỢP ĐỒNG VỚI AGENT (đề xuất, chưa được nhóm duyệt) =================
 * Trang web chỉ nói chuyện HTTP với agent (cùng origin, 127.0.0.1):
 *   POST /api/login          {username, password}      -> {ok}; kết quả đến sau qua sự kiện "auth_ack"
 *   POST /api/send           {target, text}            -> {ok}   (target "*" = gửi cho tất cả)
 *   POST /api/file/offer?target=<user>&filename=<tên>   body = byte thô của file -> {ok, ref}
 *   POST /api/file/respond   {file_id, accepted}       -> {ok}   (nhận / từ chối file đến)
 *   POST /api/logout         {}                        -> {ok}
 *   GET  /api/events?since=<n>   long-polling          -> {events: [...], next: <n>}
 * Khi lỗi, agent trả {ok:false, code, message} với code lấy từ bảng mã lỗi (spec mục 14).
 *
 * Các SỰ KIỆN agent gửi qua /api/events (mỗi sự kiện là một object có trường "type").
 * Định dạng này do UI đề xuất, spec chưa định nghĩa, cần thống nhất với Khang:
 *   conn          {state: disconnected|connecting|established|authenticated|closing}
 *   net           {rtt_ms, loss}                          (tùy chọn; thiếu thì UI hiện "—")
 *   auth_ack      {success, username, error}
 *   user_list     {users: [{username, ip, port, status}]}
 *   presence      {username, status: online|offline}
 *   msg           {sender, target, text, timestamp}       (timestamp: giây kiểu Unix)
 *   file_incoming {file_id, sender, filename, size_bytes}
 *   file          {file_id, ref?, direction: send|recv, peer, filename, size_bytes,
 *                  state: offered|ready|transferring|verifying|completed|rejected|failed|cancelled,
 *                  transferred_bytes}
 *   error         {code, message, related_type}
 */

// >>> CÔNG TẮC MOCK: true = dùng dữ liệu giả, false = nối agent thật <<<
const USE_MOCK = true;

// URL có ?mock=0 hoặc ?mock=1 sẽ ghi đè công tắc ở trên.
const mockParam = new URLSearchParams(location.search).get("mock");
const MOCK = mockParam === "1" ? true : mockParam === "0" ? false : USE_MOCK;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const Api = (() => {
  if (MOCK) return createMockApi();

  async function post(path, body) {
    const res = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    return res.json();
  }

  return {
    login: (username, password) => post("/api/login", { username, password }),
    send: (target, text) => post("/api/send", { target, text }),
    respondFile: (file_id, accepted) => post("/api/file/respond", { file_id, accepted }),
    logout: () => post("/api/logout", {}),
    async offerFile(target, file) {
      const q = new URLSearchParams({ target, filename: file.name });
      const res = await fetch("/api/file/offer?" + q, {
        method: "POST",
        headers: { "Content-Type": "application/octet-stream" },
        body: file,
      });
      return res.json();
    },
    /** Long-poll loop. onEvents(list) per batch; onLink(true|false) when the agent is (un)reachable. */
    startEvents(onEvents, onLink) {
      let since = 0;
      (async function loop() {
        let delay = 500;
        for (;;) {
          try {
            const res = await fetch("/api/events?since=" + since);
            const data = await res.json();
            since = data.next;
            onLink(true);
            delay = 500;
            if (data.events.length) onEvents(data.events);
          } catch (err) {
            onLink(false);
            await sleep(delay);
            delay = Math.min(delay * 2, 5000);
          }
        }
      })();
    },
  };
})();

/* ------------------------------------------------------------------ */
/* MOCK AGENT: giả lập agent bằng dữ liệu giả (chỉ dùng khi USE_MOCK = true). */
/* Khi nộp bài có thể xóa toàn bộ hàm createMockApi() này.                   */
/* ------------------------------------------------------------------ */
function createMockApi() {
  let handler = () => {};
  let timers = [];
  let seq = 0;
  let me = null;
  const online = new Set();
  const transfers = new Map();
  const emit = (...events) => handler(events);
  const later = (ms, fn) => timers.push(setTimeout(fn, ms));
  const ip = { bob: "192.168.1.22", carol: "192.168.1.23", dave: "192.168.1.24", eve: "192.168.1.25" };

  function userList() {
    return [...online].map((u) => ({ username: u, ip: ip[u] || "192.168.1.50", port: 50000 + u.length, status: "online" }));
  }

  function runTransfer(t) {
    t.state = "ready";
    emit(fileEvent(t));
    later(500, () => {
      if (t.state !== "ready") return;
      t.state = "transferring";
      const tick = setInterval(() => {
        if (t.state !== "transferring") return clearInterval(tick);
        t.transferred = Math.min(t.size, t.transferred + t.size / 40);
        if (t.name.includes("fail") && t.transferred >= t.size * 0.6) { // ">=" so an empty "fail" file also fails
          clearInterval(tick);
          t.state = "failed";
        } else if (t.transferred >= t.size) {
          clearInterval(tick);
          t.state = "verifying";
          emit(fileEvent(t));
          later(600, () => { t.state = "completed"; emit(fileEvent(t)); });
          return;
        }
        emit(fileEvent(t));
      }, 250);
      t.tick = tick;
    });
  }

  function fileEvent(t) {
    return {
      type: "file", file_id: t.id, ref: t.ref, direction: t.direction, peer: t.peer,
      filename: t.name, size_bytes: t.size, state: t.state, transferred_bytes: Math.round(t.transferred),
    };
  }

  function startSession() {
    emit({ type: "conn", state: "authenticated" });
    emit({ type: "user_list", users: userList() });
    emit({ type: "net", rtt_ms: 12, loss: 0.004 });
    later(1500, () => emit({ type: "msg", sender: "bob", target: "*", text: "Hi everyone, does anyone have the chapter 3 slides?", timestamp: Date.now() / 1000 }));
    later(4000, () => emit({ type: "msg", sender: "carol", target: me, text: "Group meeting tonight at 8, okay?", timestamp: Date.now() / 1000 }));
    later(6000, () => { online.add("eve"); emit({ type: "presence", username: "eve", status: "online" }); });
    later(9000, () => {
      const id = "f-in-" + ++seq;
      transfers.set(id, { id, direction: "recv", peer: "carol", name: "demo_slides.pdf", size: 3200000, transferred: 0, state: "offered" });
      emit({ type: "file_incoming", file_id: id, sender: "carol", filename: "demo_slides.pdf", size_bytes: 3200000 });
    });
    later(20000, () => { online.delete("dave"); emit({ type: "presence", username: "dave", status: "offline" }); });
    const netTimer = setInterval(() => emit({
      type: "net", rtt_ms: 8 + Math.round(Math.random() * 14), loss: Math.random() * 0.02,
    }), 2000);
    timers.push(netTimer);
  }

  const api = {
    async login(username, password) {
      await sleep(300);
      if (!username || !password) return { ok: false, code: "INVALID_PAYLOAD", message: "Username and password are required" };
      later(400, () => {
        if (password === "wrong") return emit({ type: "auth_ack", success: false, username: null, error: "AUTH_FAILED" });
        if (["bob", "carol", "dave"].includes(username)) return emit({ type: "auth_ack", success: false, username: null, error: "ALREADY_LOGGED_IN" });
        me = username;
        ["bob", "carol", "dave"].forEach((u) => online.add(u));
        emit({ type: "auth_ack", success: true, username: me, error: null });
        startSession();
      });
      emit({ type: "conn", state: "established" });
      return { ok: true };
    },
    async send(target, text) {
      await sleep(80);
      if (target !== "*" && !online.has(target)) {
        later(100, () => emit({ type: "error", code: "USER_OFFLINE", message: "", related_type: "MSG" }));
        return { ok: true };
      }
      if (target === "bob") later(1000, () => emit({ type: "msg", sender: "bob", target: me, text: "(mock) bob got: " + text, timestamp: Date.now() / 1000 }));
      return { ok: true };
    },
    async offerFile(target, file) {
      await sleep(150);
      if (!online.has(target)) return { ok: false, code: "USER_OFFLINE", message: "" };
      const ref = "r" + ++seq;
      const t = { id: "f-out-" + seq, ref, direction: "send", peer: target, name: file.name, size: file.size, transferred: 0, state: "offered" };
      transfers.set(t.id, t);
      later(0, () => emit(fileEvent(t)));
      later(1200, () => {
        if (t.state !== "offered") return;
        if (file.name.includes("reject")) { t.state = "rejected"; emit(fileEvent(t)); }
        else runTransfer(t);
      });
      return { ok: true, ref };
    },
    async respondFile(file_id, accepted) {
      const t = transfers.get(file_id);
      if (!t) return { ok: false, code: "TRANSFER_NOT_FOUND", message: "" };
      if (accepted) runTransfer(t);
      else { t.state = "rejected"; later(0, () => emit(fileEvent(t))); }
      return { ok: true };
    },
    async logout() {
      timers.forEach((x) => { clearTimeout(x); clearInterval(x); });
      timers = [];
      transfers.forEach((t) => clearInterval(t.tick));
      online.clear();
      me = null;
      setTimeout(() => emit({ type: "conn", state: "disconnected" }), 100);
      return { ok: true };
    },
    startEvents(onEvents, onLink) {
      handler = onEvents;
      onLink(true);
    },
  };
  return api;
}
