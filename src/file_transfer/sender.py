import hashlib
from pathlib import Path


def compute_file_info(path: Path) -> tuple[int, str]:
    """Return (size_bytes, sha256 hex) of a file, reading it in 64 KB blocks"""
    size = 0
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        while block := file.read(64 * 1024):
            size += len(block)
            digest.update(block)
    return size, digest.hexdigest()


def build_file_offer(path: Path, target: str) -> dict:
    """Build the FILE_OFFER payload"""
    size, sha256 = compute_file_info(path)
    return {
        "target": target,
        "filename": Path(path).name,
        "size_bytes": size,
        "sha256": sha256,
    }


def iter_segments(path: Path, size_bytes: int, chunk_size: int = 1000):
    """
    Yield (offset, data, fin) for every chunk of the file.

    Offsets are multiples of chunk_size and FIN is set on the last chunk,
    as FileReceiver expects. An empty file yields one empty FIN segment.
    Raises ValueError if the file no longer matches size_bytes.
    """
    if size_bytes == 0:
        yield 0, b"", True
        return

    with open(path, "rb") as file:
        for offset in range(0, size_bytes, chunk_size):
            data = file.read(chunk_size)
            if len(data) != min(chunk_size, size_bytes - offset):
                raise ValueError("File changed after FILE_OFFER")
            yield offset, data, offset + len(data) == size_bytes