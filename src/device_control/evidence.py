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
from typing import Protocol

from device_control import config

KEY_RE = re.compile(r"^[a-f0-9]{2}/[A-Za-z0-9._-]{1,200}/[A-Za-z0-9._-]{1,260}$")


class EvidenceStoreError(RuntimeError):
    pass


class ObjectStore(Protocol):
    def put(self, key: str, data: bytes) -> None:
        ...

    def get(self, key: str) -> bytes:
        ...

    def delete(self, key: str) -> None:
        ...


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

    def delete(self, key: str) -> None:
        target = self._path(key)
        try:
            target.unlink(missing_ok=True)
        except OSError:
            return
