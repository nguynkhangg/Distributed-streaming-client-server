from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from time import time
from typing import Optional


class TransferState(str, Enum):
    OFFERED = "offered"
    REJECTED = "rejected"
    READY = "ready"
    TRANSFERRING = "transferring"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

@dataclass(frozen=True)
class TransferMetadata:
    file_id: str
    sender: str
    target: str
    filename: str
    size_bytes: int
    sha256: str

    def __post_init__(self):
        if not self.file_id:
            raise ValueError("file_id must not be empty")

        if self.size_bytes < 0:
            raise ValueError("size_bytes must be >= 0")

        if len(self.sha256) != 64:
            raise ValueError("sha256 must be 64 characters")

        try:
            int(self.sha256, 16)
        except ValueError:
            raise ValueError("Invalid SHA-256")

        if Path(self.filename).name != self.filename:
            raise ValueError("filename must be a basename")

@dataclass
class TransferRecord:
    metadata: TransferMetadata

    state: TransferState = TransferState.OFFERED

    sender_stream_id: Optional[int] = None
    receiver_stream_id: Optional[int] = None

    chunk_size: int = 1000

    temp_path: Optional[Path] = None

    bytes_contiguous: int = 0

    error: Optional[str] = None

    created_at: float = field(default_factory=time)
    updated_at: float = field(default_factory=time)

    def transition(self, new_state, error=None):

        allowed = {
            TransferState.OFFERED: {
                TransferState.REJECTED,
                TransferState.READY,
                TransferState.CANCELLED,
                TransferState.FAILED
            },

            TransferState.READY: {
                TransferState.TRANSFERRING,
                TransferState.CANCELLED,
                TransferState.FAILED
            },

            TransferState.TRANSFERRING: {
                TransferState.VERIFYING,
                TransferState.CANCELLED,
                TransferState.FAILED
            },

            TransferState.VERIFYING: {
                TransferState.COMPLETED,
                TransferState.FAILED
            }
        }

        if new_state == self.state:
            return

        if new_state not in allowed.get(self.state, set()):
            raise ValueError(
                f"Invalid transition: {self.state} -> {new_state}"
            )

        self.state = new_state
        self.error = error
        self.updated_at = time()