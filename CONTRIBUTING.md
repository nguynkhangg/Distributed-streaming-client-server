# Contributing and Git Workflow Rules
Trước khi mn làm việc thì tui có một số lưu ý, mn nhớ đọc trước khi làm nha:


## 1. Phân công thành viên
| Thành viên | Vai trò | Công việc chính |
|---|---|---|
| Nguyên Khang | Team Lead, Protocol & Integration | Thiết kế protocol, thống nhất interface giữa các module, tích hợp code, review PR và theo dõi tiến độ. |
| Minh Quốc | Server & Authentication | Xây dựng server, xử lý đăng nhập, xác thực và quản lý trạng thái người dùng. |
| Minh Nhật | Client Networking & Messaging | Xây dựng networking phía client, gửi và nhận tin nhắn broadcast và private message. |
| Thành An | Reliable File Transfer | Truyền file tin cậy, chia và ghép chunk, ACK, timeout, truyền lại dữ liệu và kiểm tra tính toàn vẹn. |
| Nhật | Concurrency, Security & Resilience | Xử lý đồng thời, mã hóa dữ liệu, xử lý lỗi mạng, client mất kết nối và graceful shutdown. |
| Minh Trí | Web UI & Integration Testing | Xây dựng giao diện, hiển thị người dùng, tin nhắn, tiến trình truyền file và kiểm thử tích hợp. |

Mỗi thành viên chịu trách nhiệm chính cho module được phân công và cần phối hợp với các thành viên khác khi có phụ thuộc giữa các module.


## 2. Quy tắc chung

1. Ngôn ngữ lập trình chính của dự án là Python.
2. Thống nhất protocol và interface trước khi tự thiết kế packet format hoặc API riêng.
3. Không tự ý thay đổi packet format, tên message type, hàm public hoặc định dạng dữ liệu dùng chung mà chưa trao đổi với nhóm.
4. Không commit mật khẩu, token, khóa bí mật hoặc thông tin nhạy cảm lên GitHub.
5. Không commit file tạm, cache, môi trường ảo hoặc file sinh ra khi chạy chương trình.

## 3. Quy tắc commit

Commit message nên ngắn gọn, mô tả đúng thay đổi và ưu tiên viết bằng tiếng Anh.

Công thức:

`<type>: <mô tả ngắn>`

Ví dụ:

- `feat: implement user authentication`
- `feat: add private messaging`
- `fix: handle disconnected clients`
- `test: add file transfer tests`
- `docs: update protocol specification`
- `refactor: separate client networking logic`
- `chore: add Python dependencies`

Lưu ý:

- Mỗi commit nên tập trung vào một thay đổi có ý nghĩa.
- Không dùng message chung chung như `update`, `fix`, `final` hoặc `test1`.
- Không gom toàn bộ công việc nhiều ngày vào một commit duy nhất.
- Không commit file `.env`, mật khẩu, token hoặc private key.
## 4. Về Branch của mỗi người
Thì tui có tạo sẵn vài branch cho mn làm việc á
Cái tiền tố của mỗi branch là 
| `feat/` | Thêm tính năng mới |
| `fix/` | Sửa lỗi |
| `test/` | Thêm hoặc sửa kiểm thử |
nên là hiện tại mn sẽ làm branch mang tên feature mà mình phụ trách nha 
mn làm trên branch của bản thân mình, nếu cần thêm tạo thêm branch để test hay lưu nhiều bản nháp thì mn tạo thêm branch con thì branch của bản thân, k tạo từ main hay branch của người khác nha
## 5. Quy trình làm việc trên GitHub

### Bước 1: Cập nhật main

Trước khi bắt đầu công việc mới, chạy:

```bash
git switch main
git pull origin main
```

### Bước 2: Tạo branch mới

Ví dụ:

```bash
git switch -c feat/client-messaging
```

Thay tên branch bằng công việc thực tế của mình.

### Bước 3: Code và kiểm tra thay đổi

```bash
git status
git diff
```

Sau khi kiểm tra, thêm và commit các file cần thiết:

```bash
git add <ten-file-hoac-thu-muc>
git commit -m "feat: add private messaging"
```

### Bước 4: Đẩy branch lên GitHub

```bash
git push -u origin feat/client-messaging
```

### Bước 5: Tạo Pull Request (PR)

- Tạo PR từ branch của mình vào `main`.
- Mô tả rõ những gì đã làm và cách kiểm thử.
- Thông báo cho các thành viên liên quan nếu thay đổi protocol hoặc interface.
- Chờ review và xử lý góp ý trước khi merge.

Không push trực tiếp lên `main`. Không tự merge PR của mình nếu nhóm yêu cầu người khác review.

## 6. Đồng bộ code sau khi thành viên khác merge

Khi Team Lead thông báo có thay đổi mới được merge vào `main`, các thành viên cần đồng bộ code trước khi tiếp tục làm việc.

Nếu không có thay đổi dang dở:

```bash
git switch main
git pull origin main
git switch <branch-cua-minh>
git merge main
```

Ví dụ:

```bash
git switch main
git pull origin main
git switch feat/client-messaging
git merge main
```

Nếu đang có thay đổi chưa commit, hãy lưu công việc trước.

**Cách 1: Commit công việc đang làm**

```bash
git add <file-can-luu>
git commit -m "wip: save current work"
```

**Cách 2: Tạm cất thay đổi bằng stash**

```bash
git stash push -m "work in progress"
git switch main
git pull origin main
git switch <branch-cua-minh>
git merge main
git stash pop
```

Sau khi đồng bộ, chạy lại chương trình hoặc các test liên quan. Nếu xảy ra conflict, giải quyết phần thuộc module mình và trao đổi với người liên quan nếu conflict ảnh hưởng đến protocol hoặc interface chung.

Sau khi hoàn tất, thông báo trong nhóm: **"Đã sync main"**.

## 7. Quy tắc viết code

- Đặt tên biến và hàm bằng `snake_case`.
- Đặt tên class bằng `PascalCase`.
- Tách code thành các module theo chức năng, tránh viết toàn bộ chương trình trong một file.
- Xử lý lỗi rõ ràng, không bắt exception rồi bỏ qua mà không có lý do.
- Không ghi mật khẩu hoặc khóa bí mật trực tiếp trong source code.
- Viết comment hoặc docstring khi logic cần được giải thích thêm.
- Không tự ý thêm thư viện mới mà chưa thông báo nhóm.
- Khi thêm dependency, cập nhật file quản lý thư viện chung, ví dụ `requirements.txt`.
- Tuân theo cấu trúc thư mục và interface đã được nhóm thống nhất.

## 8. Checklist trước khi tạo Pull Request

- [ ] Code thuộc đúng module hoặc công việc được giao.
- [ ] Tên branch và commit message rõ ràng.
- [ ] Đã kiểm tra `git diff`, không thêm file không liên quan.
- [ ] Đã chạy chương trình hoặc test phù hợp.
- [ ] Không commit mật khẩu, token, khóa bí mật, file `.env` hoặc môi trường ảo.
- [ ] Đã cập nhật tài liệu hoặc dependency nếu cần.
- [ ] PR mô tả rõ nội dung thay đổi và kết quả kiểm thử.
- [ ] Đã thông báo cho các thành viên liên quan nếu thay đổi protocol hoặc interface.

## 9. Quy tắc phối hợp

- Nếu đang chờ protocol, interface hoặc module khác, hãy báo sớm trong nhóm.
- Không tự đoán packet format hoặc API khi chưa thống nhất.
- Khi muốn thay đổi cấu trúc chung, trao đổi với Team Lead và các thành viên bị ảnh hưởng trước.
- Khi hoàn thành một phần việc, cập nhật tiến độ để cả nhóm nắm được.
- Nếu phát hiện lỗi ở module khác, cung cấp cách tái hiện và thông báo người phụ trách.
- Các thành viên cần hỗ trợ debug và tích hợp khi cần thiết, không chỉ hoàn thành phần việc riêng rồi bỏ qua việc tích hợp toàn hệ thống.

## 10. Lưu ý về kiến trúc

Đề bài đề cập đến TCP, UDP và HTTP-based UI. Nhóm cần xác nhận với giảng viên và thống nhất cách kết hợp các thành phần này trong tài liệu kiến trúc trước khi triển khai sâu.

Không tự ý chọn một kiến trúc khác với yêu cầu đã thống nhất của nhóm.

---

**Nguyên tắc chung:** Thống nhất trước khi code, làm việc trên branch riêng, commit rõ ràng, tạo PR để review, đồng bộ `main` thường xuyên và kiểm thử trước khi merge.