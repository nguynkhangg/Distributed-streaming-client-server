"use strict";
/*
 * api.js — LỚP GIAO TIẾP giữa trang web và "agent" (chương trình Python chạy trên máy của mỗi
 * người dùng, xem protocol-spec.md mục 13). File này là nơi DUY NHẤT trong giao diện gọi ra mạng.
 * Giao diện (app.js) chỉ gọi các hàm của đối tượng `Api` bên dưới, không tự gọi fetch.
 *
 * Trang phải được agent phục vụ (cùng origin, 127.0.0.1) để các lời gọi /api/... tới được agent.
 *
 * ================= HỢP ĐỒNG VỚI AGENT (xem protocol-spec.md mục 13) =================
 * Agent chạy trên StreapRous của thầy (không được sửa): route khớp đúng đường dẫn nên KHÔNG có
 * ?query, MỌI lệnh là POST với body JSON, body phải nhỏ (< 350 byte), mã HTTP luôn là 200.
 *   POST /api/login          {username, password}      -> {ok}; kết quả đến sau qua sự kiện "auth_ack"
 *   POST /api/send           {target, text}            -> {ok}   (target "*" = gửi cho tất cả; text <= 250 byte UTF-8)
 *   POST /api/file/offer     {target}                  -> {ok, ref, filename, size_bytes}
 *                            (agent tự mở hộp thoại chọn file của hệ điều hành; ref = null nếu đóng hộp thoại)
 *   POST /api/file/respond   {file_id, accepted}       -> {ok}   (nhận / từ chối file đến)
 *   POST /api/logout         {}                        -> {ok}
 *   POST /api/events         {since}  long-polling     -> {events: [...], next: <n>}
 * Khi lỗi, agent trả {ok:false, code, message} (vẫn HTTP 200) với code lấy từ bảng mã lỗi (spec mục 14).
 *
 * Các SỰ KIỆN agent gửi qua /api/events (mỗi sự kiện là một object có trường "type"):
 *   conn          {state: disconnected|connecting|established|authenticated|closing}
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

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function post(path, body) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  return res.json();
}

const Api = {
  login: (username, password) => post("/api/login", { username, password }),
  send: (target, text) => post("/api/send", { target, text }),
  respondFile: (file_id, accepted) => post("/api/file/respond", { file_id, accepted }),
  logout: () => post("/api/logout", {}),
  offerFile: (target) => post("/api/file/offer", { target }),

  /** Long-poll loop. onEvents(list) per batch; onLink(true|false) when the agent is (un)reachable. */
  startEvents(onEvents, onLink) {
    let since = 0;
    (async function loop() {
      let delay = 500;
      for (;;) {
        try {
          const data = await post("/api/events", { since });
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
