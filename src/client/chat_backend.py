"""The only place where the agent touches the CCP client library.

The agent (agent.py) calls ChatBackend and nothing else from the client package, so a
reorganisation of the client only needs a change here. Two client layouts are supported:

  * merged client: src/client/client.py -> class Client (chat and file transfer)
  * earlier client: src/client/messaging.py -> class MessagingClient (chat only)

Which one is used is decided at run time, so the agent works before and after the merge.
"""
from __future__ import annotations

from pathlib import Path

from .network import CcpClient


def _load_client():
    """Return (client class, incoming-transfer class or None, supports files)."""
    try:
        from .client import Client, IncomingTransfer      # merged client
        return Client, IncomingTransfer, True
    except ImportError:
        from .messaging import MessagingClient            # earlier, chat-only client
        return MessagingClient, None, False


class ChatBackend:
    """Login, chat and file transfer for one user, whatever client library sits below."""

    def __init__(self, connection: CcpClient, download_dir: str | Path = "downloads") -> None:
        client_class, self._incoming_class, self.supports_files = _load_client()
        self.connection = connection
        self._impl = (client_class(connection, download_dir=download_dir)
                      if self.supports_files else client_class(connection))

    # ---- chat ---------------------------------------------------------
    def login(self, username: str, password: str) -> dict:
        return self._impl.login(username, password)

    def request_users(self) -> list[dict]:
        return self._impl.request_users()

    def receive(self, timeout: float | None = None) -> dict:
        return self._impl.receive(timeout=timeout)

    def send_broadcast(self, text: str):
        return self._impl.send_broadcast(text)

    def send_private(self, recipients, text: str):
        return self._impl.send_private(recipients, text)

    def logout(self) -> None:
        self._impl.logout()

    def close(self) -> None:
        self.connection.shutdown()

    # ---- file transfer (only with the merged client) -------------------
    def send_file(self, path: str | Path, target: str):
        return self._impl.send_file(path, target)

    def respond_file(self, file_id: str, accepted: bool) -> bool:
        """Accept or reject an incoming file; False when no incoming transfer has this id."""
        for transfer in self.transfers():
            if self.describe(transfer)["file_id"] == file_id and self._is_incoming(transfer):
                self._impl.respond_file(transfer, accepted)
                return True
        return False

    def transfers(self) -> list:
        return self._impl.transfers() if self.supports_files else []

    def describe(self, transfer) -> dict:
        """One transfer as the fields the UI event needs (protocol-spec 13.4, `file`)."""
        meta = transfer.record.metadata
        incoming = self._is_incoming(transfer)
        return {
            "file_id": meta.file_id,
            "direction": "recv" if incoming else "send",
            "peer": meta.sender if incoming else meta.target,
            "filename": meta.filename,
            "size_bytes": meta.size_bytes,
            "state": getattr(transfer.record.state, "value", str(transfer.record.state)),
            "transferred_bytes": self._impl.transfer_progress(transfer),
        }

    def _is_incoming(self, transfer) -> bool:
        return self._incoming_class is not None and isinstance(transfer, self._incoming_class)
