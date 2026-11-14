import hashlib
import os
from pathlib import Path

from file_transfer.models import TransferMetadata


class FileReceiver:
    def __init__(self, metadata: TransferMetadata, temp_dir: Path, chunk_size: int = 1000):
        self.metadata = metadata
        self.chunk_size = chunk_size
        self.temp_path = Path(temp_dir) / f"{metadata.file_id}.part"
        self.temp_path.parent.mkdir(parents=True, exist_ok=True)

        self._file = open(self.temp_path, "w+b")
        self._received_offsets = set()
        self.bytes_received = 0
        self.fin_received = False

    @property
    def is_complete(self) -> bool:
        """Check FIN + No gap"""
        return self.fin_received and self.bytes_received == self.metadata.size_bytes

    def on_data(self, offset: int, data: bytes, fin: bool) -> None:
        """
        receive a chunk
        """
        size = self.metadata.size_bytes
        expected_length = min(self.chunk_size, size - offset)

        if offset % self.chunk_size != 0 or len(data) != expected_length:
            raise ValueError("Invalid segment")

        if fin and offset + len(data) != size:
            raise ValueError("FIN is not on the last segment")

        if fin:
            self.fin_received = True

        if offset in self._received_offsets:
            return

        self._file.seek(offset)
        self._file.write(data)
        self._received_offsets.add(offset)
        self.bytes_received += len(data)

    def finish(self, dest_dir: Path) -> Path:
        """
        Check SHA-256 and move file to dest_dir

        If mismatch => delete the temp file 
        """
        if not self.is_complete:
            raise ValueError("File is not complete yet")

        self._file.seek(0)
        digest = hashlib.sha256()
        while True:                               
            chunk = self._file.read(64 * 1024)    
            if not chunk:                         
                break                            
            digest.update(chunk)
        self._file.close()

        if digest.hexdigest() != self.metadata.sha256.lower():
            os.remove(self.temp_path)
            raise ValueError("SHA-256 mismatch")

        final_path = Path(dest_dir) / self.metadata.filename
        final_path.parent.mkdir(parents=True, exist_ok=True)
        os.replace(self.temp_path, final_path)
        return final_path

    def abort(self) -> None:
        """Cancel the transfer """
        self._file.close()
        if self.temp_path.exists():
            os.remove(self.temp_path)