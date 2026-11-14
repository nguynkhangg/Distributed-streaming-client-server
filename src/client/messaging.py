"""Authentication and broadcast/private messaging over CCP streams."""

from __future__ import annotations

from enum import Enum
from typing import Iterable

try:
    from ..common.exceptions import AuthenticationError
except ImportError:
    from common.exceptions import AuthenticationError

from .network import CcpClient, ConnectionState

AUTH_TIMEOUT = 5.0
CONTROL_STREAM = 0
CHAT_STREAM = 1
BROADCAST_TARGET = "*"


class MessageMode(Enum):
    BROADCAST = "broadcast"
    PRIVATE = "private"


class MessagingClient:
    """Provide login and chat operations on top of a CCP network client."""

    def __init__(self, connection: CcpClient) -> None:
        self.connection = connection
        self.username: str | None = None

    @property
    def authenticated(self) -> bool:
        return self.username is not None

    def login(self, username: str, password: str, timeout: float = AUTH_TIMEOUT) -> dict:
        if self.authenticated:
            raise RuntimeError("client is already authenticated")
        if self.connection.state is ConnectionState.DISCONNECTED:
            self.connection.connect()

        request_id = self.connection.send_message(
            CONTROL_STREAM,
            "AUTH",
            {"username": username, "password": password},
        )
        response = self.connection.wait_for_message(
            "AUTH_ACK", request_id=request_id, timeout=timeout
        )
        if response["type"] == "ERROR":
            raise AuthenticationError(
                str(response["payload"].get("message") or "authentication failed")
            )
        result = response["payload"]
        if result.get("success") is not True:
            raise AuthenticationError(
                str(result.get("error") or "authentication failed")
            )
        self.username = result["username"]
        return result

    def send(
        self,
        mode: MessageMode,
        text: str,
        recipients: Iterable[str] = (),
    ) -> list[str]:
        self._require_authentication()
        if not isinstance(text, str) or not text.strip():
            raise ValueError("message text must not be empty")

        if mode is MessageMode.BROADCAST:
            return [
                self.connection.send_message(
                    CHAT_STREAM,
                    "MSG",
                    {"target": BROADCAST_TARGET, "text": text},
                )
            ]
        if mode is not MessageMode.PRIVATE:
            raise ValueError(f"unsupported message mode: {mode!r}")

        recipient_list = list(recipients)
        if any(not isinstance(target, str) for target in recipient_list):
            raise ValueError("private message recipients must be usernames")
        targets = list(dict.fromkeys(recipient_list))
        if not targets or any(not target.strip() for target in targets):
            raise ValueError("private messages require one or more usernames")
        if BROADCAST_TARGET in targets:
            raise ValueError("'*' is reserved for broadcast messages")

        return [
            self.connection.send_message(
                CHAT_STREAM,
                "MSG",
                {"target": target, "text": text},
            )
            for target in targets
        ]

    def send_broadcast(self, text: str) -> str:
        return self.send(MessageMode.BROADCAST, text)[0]

    def send_private(self, recipients: Iterable[str], text: str) -> list[str]:
        return self.send(MessageMode.PRIVATE, text, recipients)

    def request_users(self, timeout: float = 5.0) -> list[dict]:
        self._require_authentication()
        request_id = self.connection.send_message(
            CONTROL_STREAM, "USER_LIST_REQ", {}
        )
        response = self.connection.wait_for_message(
            "USER_LIST", request_id=request_id, timeout=timeout
        )
        if response["type"] == "ERROR":
            raise RuntimeError(
                str(response["payload"].get("message") or "user-list request failed")
            )
        users = response["payload"].get("users")
        if not isinstance(users, list):
            raise ValueError("server returned an invalid user list")
        return users

    def receive(self, timeout: float | None = None) -> dict:
        self._require_authentication()
        return self.connection.receive_message(timeout)

    def logout(self, timeout: float = 2.0) -> None:
        if not self.authenticated:
            self.connection.shutdown()
            return
        try:
            request_id = self.connection.send_message(
                CONTROL_STREAM, "LOGOUT", {}
            )
            response = self.connection.wait_for_message(
                "LOGOUT_ACK", request_id=request_id, timeout=timeout
            )
            if response["type"] == "ERROR":
                raise RuntimeError(
                    str(response["payload"].get("message") or "logout failed")
                )
        finally:
            self.username = None
            self.connection.shutdown()

    def _require_authentication(self) -> None:
        if not self.authenticated:
            raise AuthenticationError("log in before using messaging")