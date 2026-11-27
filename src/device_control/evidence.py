"""Evidence object storage port and a local filesystem implementation.

Binary evidence never goes into SQLite. The control plane owns metadata,
hashes, retention and authorization; bytes live in an object store. The local
implementation is for single-host/dev deployments; a production adapter can
implement the same three methods against the platform object store.
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Any, Protocol

from device_control import config

KEY_RE = re.compile(r"^[a-f0-9]{2}/[A-Za-z0-9._-]{1,200}/[A-Za-z0-9._-]{1,260}$")


class EvidenceStoreError(RuntimeError):
    pass


class ObjectStore(Protocol):
    def put(self, key: str, data: bytes) -> None:
        ...

    def get(self, key: str) -> bytes:
        ...

    def head(self, key: str) -> dict[str, Any]:
        ...

    def list(self, prefix: str = "") -> list[str]:
        ...

    def health(self) -> dict[str, Any]:
        ...

    def delete(self, key: str) -> None:
        ...


def get_object_store() -> ObjectStore:
    backend = (os.environ.get("DEVICE_CONTROL_EVIDENCE_BACKEND") or "local").strip().lower()
    if backend in {"foundation", "ai-platform", "s3", "cos"}:
        try:
            from ai_platform_foundation_storage import storage_from_env
        except ImportError as exc:
            raise EvidenceStoreError(
                "DEVICE_CONTROL_EVIDENCE_BACKEND=foundation but ai-platform-foundation-storage is not installed"
            ) from exc
        return FoundationObjectStore(storage_from_env())
    return LocalObjectStore()


class LocalObjectStore:
    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root or config.evidence_dir()).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        if not KEY_RE.fullmatch(key):
            raise EvidenceStoreError("invalid evidence storage key")
        target = (self.root / key).resolve()
        if self.root not in target.parents:
            raise EvidenceStoreError("evidence key escaped storage root")
        return target

    def put(self, key: str, data: bytes) -> None:
        target = self._path(key)
        target.parent.mkdir(parents=True, exist_ok=True)
        handle, temporary = tempfile.mkstemp(prefix=".incoming-", dir=target.parent)
        try:
            with os.fdopen(handle, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
            os.chmod(target, 0o600)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def get(self, key: str) -> bytes:
        target = self._path(key)
        try:
            return target.read_bytes()
        except OSError as exc:
            raise EvidenceStoreError("evidence object is unavailable") from exc

    def head(self, key: str) -> dict[str, Any]:
        target = self._path(key)
        if not target.is_file():
            raise EvidenceStoreError("evidence object is unavailable")
        return {"key": key, "size": target.stat().st_size}

    def list(self, prefix: str = "") -> list[str]:
        base = self.root if not prefix else self._path(prefix.rstrip("/") + "/x").parent
        return [
            str(path.relative_to(self.root)).replace(os.sep, "/")
            for path in base.rglob("*") if path.is_file()
        ]

    def health(self) -> dict[str, Any]:
        return {"backend": "local", "root_writable": os.access(self.root, os.W_OK)}

    def delete(self, key: str) -> None:
        target = self._path(key)
        try:
            target.unlink(missing_ok=True)
        except OSError:
            return


class FoundationObjectStore:
    """Adapter over ai-platform-foundation-storage (local/S3/COS)."""

    def __init__(self, store: Any) -> None:
        self.store = store

    def put(self, key: str, data: bytes) -> None:
        self.store.write(key, data)

    def get(self, key: str) -> bytes:
        return self.store.read(key)

    def head(self, key: str) -> dict[str, Any]:
        info = self.store.head(key)
        return {"key": key, "size": getattr(info, "size", None)}

    def list(self, prefix: str = "") -> list[str]:
        if hasattr(self.store, "list"):
            return list(self.store.list(prefix))
        return []

    def health(self) -> dict[str, Any]:
        return {"backend": "foundation"}

    def delete(self, key: str) -> None:
        self.store.delete(key)
