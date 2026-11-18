# Distributed and Streaming-Based Client-Server Collaboration Application

Course project for **Network Application Development**.

> **Project status:** In development. Chat (login, presence, broadcast and private messages) works end to end; file transfer is not wired in yet.

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

Fill this section in after the team confirms the implementation choices.

- **Programming language:** Python
- **Networking:** Raw `socket` programming. Client ↔ server: UDP with the custom CCP protocol (sequence numbers, ACK, retransmission). Browser ↔ local agent: HTTP on `127.0.0.1` (see `protocol-spec.md` §2 and §13)
- **Concurrency:** Threading — shared `submit_datagram` pool + locked session table / heartbeat sweeper
- **Serialization:** 16-byte binary packet header; control messages are JSON with a 4-byte length prefix
- **Cryptography:** AES-256-GCM + HKDF (`src/security`); hop-by-hop ENC after HELLO (see protocol-spec §12)
- **UI:** Plain HTML + client-side JavaScript (`CO3094_streaprous/www/chat.html`, `static/api.js`, `static/app.js`), served by the local agent (`src/client/agent.py`) on the instructor's StreapRous framework
- **Supported operating systems:** Windows, macOS, and Linux are listed in the assignment requirements

### Design decisions

- **Transport:** everything between client and server runs over UDP (CCP), including messages, heartbeat and file data (`protocol-spec.md` §2). HTTP is used only between the browser and the agent on the same machine.
- **UI:** a browser cannot send UDP and WebSockets are prohibited, so each user runs an agent (`src/client/agent.py`). The page only renders state and forwards user actions; all protocol logic stays in the agent (`protocol-spec.md` §13).
- **Open questions for the instructor** are listed in `protocol-spec.md` §13.5.

## 4. Architecture

```text
Browser (HTML + JS) --HTTP, 127.0.0.1:8080--> Agent (src/client/agent.py) --UDP / CCP--> Server (src/server/)
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
│   ├── client/             # CCP client, messaging, local agent (agent.py)
│   ├── server/             # UDP server, authentication, sessions
│   ├── file_transfer/      # chunking, ACK/retransmission, congestion control
│   ├── security/           # X25519 + AES-256-GCM, worker pool
│   └── common/             # constants, packet encoding, exceptions
├── CO3094_streaprous/      # instructor's HTTP framework + the web UI files
│   ├── www/chat.html
│   └── static/api.js, app.js
└── tests/
```

## 6. Setup and Run

The instructor requires HTTP over raw sockets (no OS TCP), so the agent runs on **Linux with root**. On Windows use WSL2 (`wsl -d Ubuntu -u root`). Commands below were tested in WSL2 Ubuntu 24.04 (Python 3.12) with the browser on Windows. Run them from the repository root (in WSL: `cd "/mnt/d/<path to the repo>"`).

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
python3 -m pip install -r requirements.txt   # or: apt install python3-cryptography
```

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
python -m src.client.client --host 127.0.0.1 --port 9000
```

It prompts for a username and password. Use `/broadcast <message>` to message all
other logged-in users, `/private <user[,user...]> <message>` to message one or
more named users, `/users` to refresh the online list, and `/quit` to log out.
Each private recipient is sent as an individual `MSG` addressed to that username.
The username must already exist in the server's configured user store.

### Run tests

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

Known limitations at the time of writing: file transfer is not wired into the server and client yet (the page reports that it is not implemented), and the client does not enable payload encryption yet.

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
- **Instructor-approved architecture:** the instructor asked the team to use the StreapRous framework (`CO3094_streaprous/`); open points are listed in `protocol-spec.md` §13.5
- **Submission deadline:** The assignment states “Sunday, November 17, 2026, at 11:59 PM.” The weekday and date do not appear to match; confirm the actual deadline with the instructor.
