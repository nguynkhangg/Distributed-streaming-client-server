"""Local agent: HTTP API for the web UI on top of the CCP messaging client.

The browser only speaks HTTP, so each user runs this agent on their own machine
(protocol-spec.md section 13). It owns one MessagingClient (UDP/CCP to the server)
and one HTTP server built on the instructor's StreapRous framework.

The instructor requires HTTP over the framework's own raw-socket TCP (no OS TCP), so
the agent needs Linux and root (on Windows use WSL) and an address that is not
127.0.0.1. Run from the repository root:
    python3 -m src.client.agent --server-port 9000 --http-port 8080
and open http://<IP of this machine>:8080/chat.html in the browser.

The framework folder (CO3094_streaprous/) is imported as-is; create_backend() is its
stock entry point for raw sockets.

Commands are POST requests with a small JSON body; results come back as events
through the long-polling endpoint /api/events (see protocol-spec.md 13.3 and 13.4).
File transfer is not available yet: the client and server have no FILE_* support.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import threading
from datetime import datetime
from pathlib import Path

try:
    from ..common.exceptions import AuthenticationError
except ImportError:  # run as a script from src/client
    from common.exceptions import AuthenticationError
from .messaging import MessagingClient
from .network import CcpClient

log = logging.getLogger("ccp.agent")

DEFAULT_FRAMEWORK_DIR = Path(__file__).resolve().parents[2] / "CO3094_streaprous"
LONG_POLL_SECONDS = 25.0
MAX_TEXT_BYTES = 250          # protocol-spec 13.1: the HTTP request must stay under ~350 bytes
BROADCAST = "*"


class Agent:
    """State shared by the HTTP routes and the receive thread."""

    def __init__(self, server_host: str, server_port: int) -> None:
        self.server_host = server_host
        self.server_port = server_port
        self.client: MessagingClient | None = None
        self.events: list[dict] = []
        self.cond = threading.Condition()
        self._login_running = False

    # ---- event queue -------------------------------------------------
    def emit(self, **event) -> None:
        with self.cond:
            self.events.append(event)
            self.cond.notify_all()

    def events_since(self, since: int, timeout: float = LONG_POLL_SECONDS) -> dict:
        """Return events after index `since`, waiting up to `timeout` s if there are none."""
        with self.cond:
            self.cond.wait_for(lambda: len(self.events) > since, timeout=timeout)
            return {"events": self.events[since:], "next": len(self.events)}

    # ---- login -------------------------------------------------------
    def start_login(self, username: str, password: str) -> dict:
        with self.cond:
            if self.client is not None:
                return fail("ALREADY_AUTHENTICATED", "already logged in")
            if self._login_running:
                return fail("ALREADY_AUTHENTICATED", "a login is already in progress")
            self._login_running = True
        threading.Thread(
            target=self._login, args=(username, password), name="agent-login", daemon=True
        ).start()
        return {"ok": True}          # the result arrives as an auth_ack event

    def _login(self, username: str, password: str) -> None:
        connection = None
        try:
            self.emit(type="conn", state="connecting")
            connection = CcpClient(self.server_host, self.server_port)
            client = MessagingClient(connection)
            result = client.login(username, password)
            users = client.request_users()
        except AuthenticationError as exc:
            self._login_failed(connection, str(exc) or "AUTH_FAILED")
            return
        except (TimeoutError, ConnectionError, OSError, ValueError, RuntimeError) as exc:
            log.warning("login failed: %s", exc)
            self._login_failed(connection, "SERVER_UNREACHABLE")
            return
        with self.cond:
            self.client = client
            self._login_running = False
        self.emit(type="auth_ack", success=True, username=result.get("username", username), error=None)
        self.emit(type="conn", state="authenticated")
        self.emit(type="user_list", users=users)
        threading.Thread(
            target=self._receive_loop, args=(client,), name="agent-receive", daemon=True
        ).start()

    def _login_failed(self, connection: CcpClient | None, error: str) -> None:
        if connection is not None:
            connection.shutdown()
        with self.cond:
            self._login_running = False
        self.emit(type="auth_ack", success=False, username=None, error=error)
        self.emit(type="conn", state="disconnected")

    # ---- messages from the server -----------------------------------
    def _receive_loop(self, client: MessagingClient) -> None:
        while self.client is client:
            try:
                message = client.receive(timeout=1.0)
            except TimeoutError:
                continue
            except Exception as exc:     # connection lost, or logout closed the client
                if self.client is client:
                    log.info("receive loop ended: %s", exc)
                    self._drop(client)
                return
            event = to_event(message)
            if event is not None:
                self.emit(**event)

    def _drop(self, client: MessagingClient) -> None:
        with self.cond:
            if self.client is not client:
                return
            self.client = None
        try:
            client.connection.shutdown()
        except Exception:
            pass
        self.emit(type="conn", state="disconnected")

    # ---- commands ----------------------------------------------------
    def send(self, target: str, text: str) -> dict:
        client = self.client
        if client is None:
            return fail("NOT_AUTHENTICATED", "log in first")
        if len(text.encode("utf-8")) > MAX_TEXT_BYTES:
            return fail("INVALID_PAYLOAD", "text is longer than %d bytes" % MAX_TEXT_BYTES)
        try:
            if target == BROADCAST:
                client.send_broadcast(text)
            else:
                client.send_private([target], text)
        except ValueError as exc:
            return fail("INVALID_PAYLOAD", str(exc))
        except (ConnectionError, TimeoutError, OSError) as exc:
            return fail("INTERNAL_ERROR", str(exc))
        return {"ok": True}

    def logout(self) -> dict:
        with self.cond:
            client, self.client = self.client, None
        if client is not None:
            try:
                client.logout()
            except Exception as exc:     # the server may already be gone; leave anyway
                log.info("logout: %s", exc)
            self.emit(type="conn", state="disconnected")
        return {"ok": True}


def fail(code: str, message: str = "") -> dict:
    return {"ok": False, "code": code, "message": message}


def unix_seconds(value) -> float:
    """The server sends ISO text such as 2026-11-17T15:50:55Z; the UI wants Unix seconds."""
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return datetime.now().timestamp()


def to_event(message: dict) -> dict | None:
    """Translate a CCP message from the server into a UI event (protocol-spec 13.4)."""
    kind, payload = message.get("type"), message.get("payload", {})
    if kind == "MSG_DELIVER":
        return {
            "type": "msg",
            "sender": payload.get("sender"),
            "target": payload.get("target"),
            "text": payload.get("text"),
            "timestamp": unix_seconds(payload.get("timestamp")),
        }
    if kind == "PRESENCE":
        return {"type": "presence", "username": payload.get("username"), "status": payload.get("status")}
    if kind == "USER_LIST":
        return {"type": "user_list", "users": payload.get("users", [])}
    if kind == "ERROR":
        return {
            "type": "error",
            "code": payload.get("code"),
            "message": payload.get("message"),
            "related_type": payload.get("related_type"),
        }
    return None


def build_app(agent: Agent):
    """Register the HTTP routes on a StreapRous app (import happens here, after sys.path is set)."""
    from daemon import StreapRous

    app = StreapRous()

    def reply(obj: dict) -> bytes:
        return json.dumps(obj, ensure_ascii=False).encode("utf-8")

    def parse(body) -> dict | None:
        try:
            data = json.loads(body) if body else {}
        except ValueError:
            return None
        return data if isinstance(data, dict) else None

    def route(path: str, handler):
        """Wrap a handler(data) -> dict so every route parses JSON and never raises."""
        @app.route(path, methods=["POST"])
        def view(headers, body):
            data = parse(body)
            if data is None:
                return reply(fail("INVALID_PAYLOAD", "body must be a JSON object"))
            try:
                return reply(handler(data))
            except Exception:
                log.exception("%s failed", path)
                return reply(fail("INTERNAL_ERROR", "unexpected agent error"))
        return view

    def login(data):
        user, password = data.get("username"), data.get("password")
        if not isinstance(user, str) or not isinstance(password, str) or not user or not password:
            return fail("INVALID_PAYLOAD", "username and password are required")
        return agent.start_login(user, password)

    def send(data):
        target, text = data.get("target"), data.get("text")
        if not isinstance(target, str) or not isinstance(text, str) or not target or not text.strip():
            return fail("INVALID_PAYLOAD", "target and text are required")
        return agent.send(target, text)

    def events(data):
        since = data.get("since", 0)
        if not isinstance(since, int) or since < 0:
            return fail("INVALID_PAYLOAD", "since must be a non-negative integer")
        return agent.events_since(since)

    def file_not_ready(data):
        return fail("INTERNAL_ERROR", "file transfer is not implemented yet")

    route("/api/login", login)
    route("/api/send", send)
    route("/api/events", events)
    route("/api/logout", lambda data: agent.logout())
    route("/api/file/offer", file_not_ready)
    route("/api/file/respond", file_not_ready)
    return app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local HTTP agent for the CollabNet web UI")
    parser.add_argument("--server-host", default="127.0.0.1", help="CCP server address")
    parser.add_argument("--server-port", type=int, default=9000, help="CCP server UDP port")
    parser.add_argument("--http-ip", default="0.0.0.0",
                        help="address the browser connects to (raw sockets: never 127.0.0.1)")
    parser.add_argument("--http-port", type=int, default=8080)
    parser.add_argument("--framework-dir", default=str(DEFAULT_FRAMEWORK_DIR),
                        help="folder that contains the StreapRous framework (default: CO3094_streaprous)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args(argv)
    logging.basicConfig(level=args.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    if not (hasattr(os, "geteuid") and os.geteuid() == 0):
        log.error("raw sockets need Linux and root (on Windows: wsl -d Ubuntu -u root)")
        return 1

    sys.dont_write_bytecode = True       # keep __pycache__ out of the instructor's folder
    sys.path.insert(0, args.framework_dir)
    from daemon.backend import create_backend

    agent = Agent(args.server_host, args.server_port)
    app = build_app(agent)
    log.info("agent for CCP server %s:%d, browser at http://<this machine>:%d/chat.html",
             args.server_host, args.server_port, args.http_port)
    try:
        create_backend(args.http_ip, args.http_port, app.routes)   # raw sockets, own TCP (needs root)
    except KeyboardInterrupt:
        log.info("shutting down")
    finally:
        agent.logout()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
