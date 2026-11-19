# Distributed and Streaming-Based Client-Server Collaboration Application

Course project for **Network Application Development**.

> **Project status:** In development. Chat (login, presence, broadcast and private messages) and file transfer work end to end, also with 5% and 10% datagram loss (see `tests/test_reliability.py`).

## 1. Project Overview

This project aims to build a lightweight client-server collaboration application for users communicating over a local network or VPN. The application is intended to support real-time messaging, active-user discovery, reliable file transfer, connection resilience, and basic payload encryption.

The implementation must demonstrate core network-programming concepts using raw sockets rather than high-level networking frameworks.

## 2. Required Features

- **Authentication and user discovery:** Users can log in, announce their presence, and view active peers.
- **Messaging:** Support global/broadcast messages and private/unicast messages.
- **Reliable file transfer:** Send and receive files of different formats and sizes without corruption.
- **Connection resilience:** Handle client disconnections, timeouts, and network interruptions gracefully.
- **Secure transmission:** Encrypt payloads before sending and decrypt them when received.
- **Concurrency:** Handle multiple clients concurrently using multithreading or asynchronous I/O.
- **Custom application protocol:** Define packet/message types, headers, payloads, and message boundaries.
- **Sequencing and reliability:** The assignment mentions sequence numbers, sliding windows, acknowledgements, and retransmission of missing segments.
- **User interface:** Display messages, active users, and network status. The grading rubric specifically mentions an HTTP-based UI using client-side JavaScript, so the team must confirm the intended UI/networking integration with the instructor.

## 3. Technology Stack

- **Programming language:** Python
- **Networking:** Raw `socket` programming. Client ↔ server: UDP with the custom CCP protocol (sequence numbers, ACK, retransmission). Browser ↔ local agent: HTTP over the StreapRous raw-socket TCP on the machine's own address, not `127.0.0.1` (see `protocol-spec.md` §2 and §13)
- **Concurrency:** Threading — shared `submit_datagram` pool; one lock per session so a client's packets are handled in order; locked session table; background sweeper for heartbeat, timeouts and resending
- **Serialization:** 16-byte binary packet header; control messages are JSON with a 4-byte length prefix
- **Cryptography:** X25519 key exchange + HKDF + AES-256-GCM (`src/security`); hop-by-hop ENC after HELLO, required by the server (see protocol-spec §12)
- **UI:** Plain HTML + client-side JavaScript (`CO3094_streaprous/www/chat.html`, `static/api.js`, `static/app.js`), served by the local agent (`src/client/agent.py`) on the course's StreapRous framework
- **Supported operating systems:** Windows, macOS, and Linux are listed in the assignment requirements

### Design decisions

- **Transport:** everything between client and server runs over UDP (CCP), including messages, heartbeat and file data (`protocol-spec.md` §2). HTTP is used only between the browser and the agent on the same machine.
- **UI:** a browser cannot send UDP and WebSockets are prohibited, so each user runs an agent (`src/client/agent.py`). The page only renders state and forwards user actions; all protocol logic stays in the agent (`protocol-spec.md` §13).
- **Open questions** are listed in `protocol-spec.md` §13.5.

## 4. Architecture

```text
Browser (HTML + JS) --HTTP over raw-socket TCP, <agent IP>:8080--> Agent (src/client/agent.py) --UDP / CCP, encrypted--> Server (src/server/)
```

Logical separation:

1. **User interface** — login, active-user list, messaging, file-transfer progress, and network status.
2. **Client networking layer** — connection handling, protocol encoding/decoding, message/file transfer, and payload encryption.
3. **Server/tracker** — client sessions, active-user state, message routing, and file-transfer coordination as defined by the final protocol.
4. **Shared protocol module** — packet definitions, serialization, validation, and error codes.

The assignment expects the server/tracker to handle approximately 10–20 concurrent clients.

## 5. Repository Structure

```text
.
├── README.md
├── CONTRIBUTING.md
├── protocol-spec.md        # protocol and local HTTP API
├── requirements.txt
├── src/
│   ├── client/             # CCP client (client.py), network/transport, CLI, local agent (agent.py)
│   ├── server/             # UDP server, authentication, sessions, file relay
│   ├── file_transfer/      # chunking, ACK/retransmission, congestion control
│   ├── security/           # X25519 + AES-256-GCM, worker pool
│   └── common/             # constants, exceptions
├── CO3094_streaprous/      # course HTTP framework + the web UI files
│   ├── www/chat.html
│   └── static/api.js, app.js
└── tests/                  # unit tests; manual_server_handshake.py is a manual script
```

## 6. Setup and Run

The assignment requires HTTP over raw sockets (no OS TCP), so the agent runs on **Linux with root**. On Windows use WSL2 (`wsl -d Ubuntu -u root`). Commands below were tested in WSL2 Ubuntu 24.04 (Python 3.12) with the browser on Windows. Run them from the repository root (in WSL: `cd "/mnt/d/<path to the repo>"`).

### Prerequisites

- Git
- Linux (or WSL2) and root privileges
- Python 3.11 or newer
- The `cryptography` package (see `requirements.txt`; on Ubuntu also `apt install python3-cryptography`)

### Clone the repository

```bash
git clone <REPOSITORY_URL>
cd <REPOSITORY_DIRECTORY>
```

### Install dependencies

```bash
python3 -c "import cryptography" 2>/dev/null || apt install -y python3-cryptography
```

On Ubuntu 24.04 `python3 -m pip install -r requirements.txt` stops with `externally-managed-environment`; use `apt` as above (or a virtual environment).

### Start the server

```bash
python3 -m src.server.server --host 127.0.0.1 --port 9000 --users-file data/users.json --demo-password 123456
```

`--demo-password` creates the accounts `alice, bob, carol, dave, quoc, khang, nhat, tri, an` with that password when `data/users.json` does not exist yet. Use `--host 0.0.0.0` to accept clients from other machines on the LAN.

### Start a client

**Web UI (agent, raw-socket HTTP).** The agent builds its own TCP on raw sockets, so the kernel must not interfere. Run once per boot as root (in WSL the first line is needed because its default MTU of 1280 is smaller than the framework's 1460-byte segments):

```bash
ip link set dev eth0 mtu 1500
iptables -A OUTPUT -p tcp --sport 8080 --tcp-flags RST RST -j DROP   # once per agent HTTP port
```

Then open one terminal per user and start an agent with its own HTTP port:

```bash
python3 -m src.client.agent --server-host 127.0.0.1 --server-port 9000 --http-port 8080
```

The page is `http://<IP of the Linux machine>:8080/chat.html` (get the IP with `hostname -I`; it must not be `127.0.0.1`). Log in (for example `alice` / `123456`). For a second user add the iptables rule for `8081`, start another agent with `--http-port 8081`, open `http://<IP>:8081/chat.html` in a private window and log in as `bob`. `--server-host` / `--server-port` point the agent at the server.

**Command-line client.** The messaging CLI can be used without a browser:

```bash
python3 -m src.client.run_client_cli --host 127.0.0.1 --port 9000
```

| Option | Default | Meaning |
|---|---|---|
| `--host` | `127.0.0.1` | Server address |
| `--port` | `9000` | Server UDP port |
| `--username` | prompt | Username; asked interactively if omitted |
| `--hello-attempts` | `3` | `HELLO` attempts before giving up |

The password is always prompted (hidden). The username must already exist in the
server's user store. After a successful login the CLI shows the command list below.

| Command | Description |
|---|---|
| `/broadcast <message>` | Send a message to all other logged-in users |
| `/private <user[,user...]> <message>` | Send a private message to one or more users (one `MSG` per recipient) |
| `/users` | Refresh and print the online-user list |
| `/file <user> <path>` | Offer a file to one user; it is sent in the background once the receiver accepts |
| `/accept <number>` | Accept a file offered to you (number from `/transfers`); it is saved in `downloads/` |
| `/reject <number>` | Reject a file offered to you |
| `/transfers` | List file transfers, sent and received, with state and progress (numbered from 1) |
| `/cancel <number>` | Cancel a file transfer you sent, or one you accepted, that has not finished |
| `/help` | Show the command list |
| `/quit` | Log out and exit (`Ctrl+C` also works) |

File transfer notes:

- A file is sent to one user at a time (no broadcast). The path may be quoted; the
  file size and SHA-256 are computed before the offer is sent.
- When someone offers you a file the CLI prints the sender, name and size. Nothing is
  written until you `/accept`. Received files are saved in `downloads/` (partial
  data stays in `downloads/.partial/` until the file is verified). An existing file
  with the same name is overwritten after verification.
- Transfer states are `offered`, `rejected`, `ready`, `transferring`, `verifying`,
  `completed`, `failed` and `cancelled`. A sent file is `completed` only after the
  receiver reports a matching size and SHA-256; a received file only after its size
  and SHA-256 match the offer, otherwise it is deleted and reported as `failed`.
- `/cancel` works after the transfer has been accepted (state `ready` or later; for a
  received file, after `/accept`). A transfer also ends as `failed` if the connection
  is lost, the sent file changes or becomes unreadable, a received segment is
  invalid, or the server sends an invalid `FILE_READY`.
- The server implements the file messages of section 11 of
  [`protocol-spec.md`](protocol-spec.md) (`FILE_OFFER`, `FILE_INCOMING`,
  `FILE_RESPONSE`, `FILE_ACCEPT`, `FILE_READY`, `FILE_COMPLETE`, `FILE_CANCEL`) in `src/server/file_relay.py`.
- The server requires encryption: packets after `HELLO` that are not AES-GCM encrypted are dropped. `--allow-plaintext` turns this off for development only.

### Step-by-step guide: web UI with two users (Windows + WSL)

The assignment requires HTTP over raw sockets, so the agent only runs on **Linux with root**. On Windows use WSL: the server and the agents run **inside WSL**, the browser runs **on Windows**.

You need **3 windows**: window 1 (server) and window 2 (agent) are root shells of WSL, window 3 is the browser.

The `cryptography` package is required. Check it with `python3 -c "import cryptography; print(cryptography.__version__)"`. If Python reports `No module named 'cryptography'`, install it with `apt install -y python3-cryptography`. Do not use `pip install` on Ubuntu 24.04: it fails with `externally-managed-environment` (it can only be forced with `--break-system-packages`, which is not recommended).

#### Quick start (one block of commands, two users)

In a root shell of WSL (`wsl -d Ubuntu -u root`):

```bash
cd "/mnt/d/<path to the repo>"
python3 -c "import cryptography" 2>/dev/null || apt install -y python3-cryptography
ip link set dev eth0 mtu 1500
for p in 8080 8081; do iptables -C OUTPUT -p tcp --sport $p --tcp-flags RST RST -j DROP 2>/dev/null || iptables -A OUTPUT -p tcp --sport $p --tcp-flags RST RST -j DROP; done
mkdir -p share share_bob
nohup python3 -m src.server.server --host 127.0.0.1 --port 9000 --users-file data/users.json --demo-password 123456 > /tmp/server.log 2>&1 &
sleep 2
nohup python3 -m src.client.agent --server-port 9000 --http-port 8080 > /tmp/agent_alice.log 2>&1 &
nohup python3 -m src.client.agent --server-port 9000 --http-port 8081 --share-dir share_bob --download-dir downloads_bob > /tmp/agent_bob.log 2>&1 &
sleep 3
IP=$(hostname -I | awk '{print $1}')
echo "alice (normal window):    http://$IP:8080/chat.html"
echo "bob   (private window):   http://$IP:8081/chat.html"
```

Log in as `alice` / `123456` and `bob` / `123456`. To send a file, put it in `share/` (alice sends) or `share_bob/` (bob sends), then type the **file name** after pressing *Attach file*. A received file is saved in `downloads/` (alice) or `downloads_bob/` (bob). To stop (after pressing Log out in the browser): `pkill -f src.client.agent; pkill -f src.server.server`. To look at errors: `tail -20 /tmp/server.log /tmp/agent_alice.log /tmp/agent_bob.log`.

The steps below explain each command.

#### Step 1. Open a root shell of WSL (window 1)

In PowerShell or Windows Terminal:

```powershell
wsl -d Ubuntu -u root
```

When the prompt changes to `root@...:~#` you are in.

#### Step 2. Go to the project folder

```bash
cd "/mnt/d/<path to the repo>"
```

(Drive `D:` of Windows is `/mnt/d/` inside WSL.)

#### Step 3. Prepare the network (repeat after every restart of WSL)

```bash
ip link set dev eth0 mtu 1500
iptables -C OUTPUT -p tcp --sport 8080 --tcp-flags RST RST -j DROP 2>/dev/null || iptables -A OUTPUT -p tcp --sport 8080 --tcp-flags RST RST -j DROP
hostname -I
```

- Line 1 raises the MTU from 1280 to 1500. Without it a file larger than a few hundred bytes fails with `Message too long`.
- Line 2 drops the RST packets of the Linux kernel for port 8080 (the kernel does not know the agent's self-built TCP connection and would reset it). If you also run an agent on port 8081 in step 7, add the same rule for that port. The command checks first, so running it again does not add a duplicate.
- Line 3 prints the **IP of WSL**, for example `172.31.219.246`. **Write it down**: it is used in step 6.

#### Step 4. Start the server (still in window 1)

```bash
python3 -m src.server.server --host 127.0.0.1 --port 9000 --users-file data/users.json --demo-password 123456
```

You must see the line `listening on udp://127.0.0.1:9000`. **Keep this window open.**

Available accounts: `alice, bob, carol, dave, quoc, khang, nhat, tri, an`, password `123456`.

#### Step 5. Open a second root shell and start the agent (window 2)

Open a new PowerShell window:

```powershell
wsl -d Ubuntu -u root
```

Then:

```bash
cd "/mnt/d/<path to the repo>"
python3 -m src.client.agent --server-port 9000 --http-port 8080
```

You must see the line `[Backend] Listening on port 8080`. **Keep this window open.** The agent creates the folders `share/` (files to send) and `downloads/` (received files) where it runs; change them with `--share-dir` and `--download-dir`.

#### Step 6. Open the browser on Windows (window 3)

```
http://<IP from step 3>:8080/chat.html
```

For example `http://172.31.219.246:8080/chat.html`. **Do not use `127.0.0.1`**: the raw-socket mode refuses that address. Log in as `alice` / `123456`.

#### Step 7. Try a second user (optional)

In window 1 or in a new root shell, add the rule for port 8081:

```bash
iptables -C OUTPUT -p tcp --sport 8081 --tcp-flags RST RST -j DROP 2>/dev/null || iptables -A OUTPUT -p tcp --sport 8081 --tcp-flags RST RST -j DROP
```

Open a third root shell, `cd` to the project folder as in step 2 and start the second agent. **Give it its own folders**, otherwise both agents use the same `share/` and `downloads/` and the files of the two users get mixed:

```bash
python3 -m src.client.agent --server-port 9000 --http-port 8081 --share-dir share_bob --download-dir downloads_bob
```

In the browser (preferably a private window) open `http://<IP>:8081/chat.html` and log in as `bob` / `123456`. The two users can now send private messages and broadcasts to each other. For a third user repeat this step with the next port, for example `8082`, its own rule, `--share-dir share_carol --download-dir downloads_carol` and the account `carol`: every user needs their own agent.

#### Step 8. Send a file (optional)

The **sender** puts the file in the `share` folder of their own agent: alice (port 8080) uses `share/`, bob (port 8081, started as in step 7) uses `share_bob/`. In the UI select the receiver, press *Attach file* and type the **file name** (not a path). The **receiver** does not need to put any file anywhere: they see the offer, press accept, and the file is saved in the download folder of their agent (`downloads/` for alice, `downloads_bob/` for bob). A name containing `../` or an absolute path is refused.

#### Step 9. Stop

Press **Ctrl+C** in the agent window and then in the server window. If you are in the browser, press **Log out** first so that the other user sees you go offline (closing the tab does not log out: the agent stays logged in).

#### Troubleshooting

| Symptom | Cause and fix |
|---|---|
| The agent reports `raw sockets need Linux and root` | It runs on Windows or not as root. Run it again inside `wsl -d Ubuntu -u root` |
| The browser cannot open the page, or the page is cut off | The `iptables` rule of step 3 is missing (or you forgot port 8081 for the second agent) |
| The page opens but a large JS/HTML file does not load | The MTU is not 1500 (step 3). The agent log contains `Message too long` |
| `http://IP:8080` cannot be reached | The IP changed after WSL restarted: run `hostname -I` for the new one |
| "Wrong username or password" | The server has no accounts: start it with `--demo-password 123456` |
| `SERVER_UNREACHABLE` when logging in | The server (step 4) is not running, or the agent points to the wrong `--server-port` |
| `ALREADY_AUTHENTICATED` when logging in again | The agent is still logged in from before (the tab was closed without Log out). Stop the agent (Ctrl+C) and start it again |
| `Address already in use` when starting the agent or the server | An old window is still running. Press Ctrl+C there, or run `pkill -f src.client.agent` / `pkill -f src.server.server` |
| Sending a file reports `the file must be inside the share folder` or `no such file in the share folder` | Type only the name of a file that already is in `share/`, not a path |
| `No module named 'cryptography'` | `apt install -y python3-cryptography` |
| `pip install` reports `externally-managed-environment` | Ubuntu does not let pip install into the system: use `apt install -y python3-cryptography` instead of pip |

Quick check of the WSL state:

```bash
cat /sys/class/net/eth0/mtu          # must be 1500
iptables -S OUTPUT | grep 8080       # must show one DROP line
hostname -I                          # IP of WSL
pgrep -fa "src.server|src.client"    # is the server/agent running
```

#### Command line instead of the browser

See **Command-line client** above (`python3 -m src.client.run_client_cli --host 127.0.0.1 --port 9000`). The tests run with `python3 -m unittest discover -s tests -p "test_*.py"` (69 tests, about one minute because of the packet-loss and disconnection tests).

#### Editing the UI

The UI files are in the course framework folder: `CO3094_streaprous/www/chat.html`, `static/api.js` and `static/app.js`. Edit them in place and reload the page (Ctrl+F5); the agent does not need a restart.

### Run tests

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

**Sending a file from the web UI:** put the file in the `share/` folder next to where the agent runs, select a user, press *Attach file* and type the file name. Received files are saved in `downloads/` (`--share-dir` / `--download-dir` change the folders). The agent uses the client library (`src/client/client.py`) directly.

The server relays the file between the two users (`src/server/file_relay.py`); the receiver must accept the offer first. Packets relayed to the receiver are sent again when the receiver does not acknowledge them in time.

## 7. Protocol Documentation

Before implementation is considered complete, document:

- Packet/message types (for example, `AUTH`, `MSG`, and `FILE`)
- Header and payload fields
- Serialization format and message boundaries
- Client/server state transitions
- Sequence-number and acknowledgement behavior
- Timeout and retransmission rules, where applicable
- Error responses and disconnect behavior
- Encryption/decryption flow

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for development workflow rules.

## 8. Testing Plan

At minimum, test:

- Successful and unsuccessful login
- Client connection and graceful disconnection
- Active-user list updates
- Broadcast and private messaging
- Multiple clients connecting and sending messages concurrently
- File transfer with small and large files
- File integrity after transfer
- Packet loss, duplicate/out-of-order chunks, and retransmission if UDP reliability is implemented
- Socket timeout and unexpected client exit
- Encryption/decryption round trip
- UI status and file-transfer progress
- Local-network simulation using multiple client instances

Automated tests (`python3 -m unittest discover -s tests -p "test_*.py"`) include a network that drops 0%, 5% and 10% of the datagrams (`tests/test_reliability.py`): login, ordered messages and a file with matching SHA-256. `tests/test_resilience.py` covers 20 clients at once, chat that keeps flowing during a file transfer on a lossy network, and a sender or receiver that vanishes in the middle of a transfer.

Record known limitations and unresolved issues in the technical report.

## 9. Team Workflow

- Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before making changes.
- Do not work directly on `main`.
- Use a task-specific branch and open a Pull Request (PR) into `main`.
- Keep commits small and use descriptive commit messages.
- Update your local `main` after a merge announcement, then merge the updated `main` into your feature branch before continuing.
- Do not commit credentials, private keys, generated files, or unrelated local configuration.

## 10. Submission Checklist

The assignment asks for a ZIP file or private GitHub repository containing the source code and a README with step-by-step installation/run instructions. It also requires a technical explanation report in PDF that includes:

- [ ] System architecture diagram
- [ ] Protocol specification
- [ ] Sequence diagram for message lifecycle and file transfer
- [ ] One-page reflection on challenges and solutions
- [ ] Tested installation and run instructions
- [ ] Cleanly formatted and commented code
- [ ] Local-network simulation with multiple clients

## 11. Project Information

- **Course:** Network Application Development
- **Project:** Distributed and Streaming-Based Client-Server Collaboration Application
- **Team members:** Nguyên Khang (team lead, protocol, integration), Minh Quốc (server, authentication), Minh Nhật (client networking, messaging), Thành An (reliable file transfer), Nhật (concurrency, security, resilience), Minh Trí (web UI, integration testing)
- **Architecture:** the HTTP layer uses the StreapRous framework (`CO3094_streaprous/`); open points are listed in `protocol-spec.md` §13.5
- **Submission deadline:** The assignment states “Sunday, November 17, 2026, at 11:59 PM.” The weekday and date do not appear to match; confirm the actual deadline with the instructor.
