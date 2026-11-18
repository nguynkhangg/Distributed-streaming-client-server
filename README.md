# Distributed and Streaming-Based Client-Server Collaboration Application

Course project for **Network Application Development**.

> **Project status:** In development. Replace the `TODO` items below when the team finalizes the implementation and runtime instructions.

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
- **Networking:** Raw sockets; final TCP/UDP responsibilities to be confirmed
- **Concurrency:** Threading — shared `submit_datagram` pool + locked session table / heartbeat sweeper
- **Serialization:** TODO — JSON, XML, or custom binary format
- **Cryptography:** AES-256-GCM + HKDF (`src/security`); hop-by-hop ENC after HELLO (see protocol-spec §12)
- **UI:** TODO — implementation approach to be confirmed with the instructor
- **Supported operating systems:** Windows, macOS, and Linux are listed in the assignment requirements

### Important design questions to resolve

The assignment describes UDP streaming and requires reliable file transfer over UDP in one milestone, but its technology section also mentions TCP for reliable file/message transfer and UDP for heartbeat/discovery. The team should confirm the intended transport split with the instructor and document the final decision here.

The design requirements allow a CLI or GUI, while milestone 9 asks for an HTTP-based UI with client-side JavaScript only. The assignment also prohibits Flask/Django and WebSockets and requires raw sockets. Confirm how the UI is expected to communicate with the networking implementation before committing to an architecture.

## 4. Architecture

Add the finalized architecture diagram here.

Suggested logical separation:

1. **User interface** — login, active-user list, messaging, file-transfer progress, and network status.
2. **Client networking layer** — connection handling, protocol encoding/decoding, message/file transfer, and payload encryption.
3. **Server/tracker** — client sessions, active-user state, message routing, and file-transfer coordination as defined by the final protocol.
4. **Shared protocol module** — packet definitions, serialization, validation, and error codes.

The assignment expects the server/tracker to handle approximately 10–20 concurrent clients.

## 5. Repository Structure

Update this example to match the actual codebase.

```text
.
├── README.md
├── CONTRIBUTING.md
├── docs/
│   ├── architecture.md
│   ├── protocol-spec.md
│   └── diagrams/
├── src/
│   ├── client/
│   ├── server/
│   └── shared/
└── tests/
```

## 6. Setup and Run

> **TODO:** These commands are placeholders until the team selects a language, dependency list, entry-point filenames, and UI/networking architecture. Update this section with tested commands before submission.

### Prerequisites

- Git
- The selected language runtime/compiler and version: TODO
- Dependencies: TODO
- Local network access or localhost for testing

### Clone the repository

```bash
git clone <REPOSITORY_URL>
cd <REPOSITORY_DIRECTORY>
```

### Install dependencies

TODO — add the exact dependency-installation commands for the selected language.

### Start the server

TODO — add the exact command and required arguments.

### Start a client

Open another terminal for each client and run:

TODO — add the exact client command and explain how to configure the server address/port.

The current messaging CLI is available with:

```bash
python -m src.client.client --host 127.0.0.1 --port 9000
```

It prompts for a username and password. Use `/broadcast <message>` to message all
other logged-in users, `/private <user[,user...]> <message>` to message one or
more named users, `/users` to refresh the online list, and `/quit` to log out.
Each private recipient is sent as an individual `MSG` addressed to that username.
The username must already exist in the server's configured user store.

### Run tests

TODO — add the unit-test and integration-test commands. Include a test with multiple client instances and file-transfer integrity verification.

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
- **Team members:** TODO — add names and responsibilities
- **Instructor-approved architecture:** TODO
- **Submission deadline:** The assignment states “Sunday, November 17, 2026, at 11:59 PM.” The weekday and date do not appear to match; confirm the actual deadline with the instructor.
