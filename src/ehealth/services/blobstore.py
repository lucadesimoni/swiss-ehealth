# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Where document contents live, and why the store is not trusted.

A dossier document is two things: metadata in the database (title, class,
confidentiality, author, SHA-256 of the content) and the content itself,
which is too large for a row and belongs in object storage.

The store is treated as **untrusted**, in both directions:

* **Confidentiality.** Content is encrypted with AES-256-GCM under a key
  derived for this purpose alone (``KeyPurpose.DOCUMENT_ENCRYPTION``), before
  it leaves the application. Whoever operates the bucket — or restores a
  backup of it somewhere else — holds ciphertext.
* **Integrity.** The ciphertext is bound (as AEAD associated data) to the
  document's uid, so a blob copied onto another document's key fails to
  decrypt. And the plaintext is checked against the SHA-256 recorded in the
  database on every read, so a store that serves the wrong bytes is caught
  rather than believed.

Two backends: :class:`FileSystemBlobStore` for a single server or a mounted
volume, and :class:`MemoryBlobStore` for tests. An S3-compatible backend on a
Swiss provider implements the same three methods.
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Protocol

from ehealth.security.crypto import CryptoError, KeyPurpose, KeyRing

_UID = re.compile(r"^[a-z]{3}_[0-9A-Za-z]{10,40}$")


class BlobError(Exception):
    """Content could not be stored, found, or verified."""


class BlobBackend(Protocol):
    """Raw bytes by key. Knows nothing about encryption or documents."""

    def put(self, key: str, data: bytes) -> None: ...

    def get(self, key: str) -> bytes: ...

    def exists(self, key: str) -> bool: ...

    def delete(self, key: str) -> None:
        """Remove a blob. Only the retention job calls this: content is
        otherwise immutable, and a correction is a superseding document."""
        ...


class MemoryBlobStore:
    def __init__(self) -> None:
        self.blobs: dict[str, bytes] = {}

    def put(self, key: str, data: bytes) -> None:
        self.blobs[key] = data

    def get(self, key: str) -> bytes:
        try:
            return self.blobs[key]
        except KeyError:
            raise BlobError("content not found") from None

    def exists(self, key: str) -> bool:
        return key in self.blobs

    def delete(self, key: str) -> None:
        self.blobs.pop(key, None)


class FileSystemBlobStore:
    """One file per document under a root directory.

    Writes go to a temporary file and are renamed into place, so a crash
    mid-write leaves either the old state or the new one, never half a blob.
    Existing blobs are never overwritten: document content is immutable, and a
    correction is a new document that supersedes the old.
    """

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        if not _UID.match(key):
            # Keys become file names; anything that is not a plain uid could
            # walk out of the root directory.
            raise BlobError("invalid content key")
        return self._root / key[4:6] / key

    def put(self, key: str, data: bytes) -> None:
        path = self._path(key)
        if path.exists():
            raise BlobError("content already stored for this key; blobs are immutable")
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".partial")
        with open(temporary, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)

    def get(self, key: str) -> bytes:
        path = self._path(key)
        try:
            return path.read_bytes()
        except FileNotFoundError:
            raise BlobError("content not found") from None

    def exists(self, key: str) -> bool:
        return self._path(key).exists()

    def delete(self, key: str) -> None:
        self._path(key).unlink(missing_ok=True)


class DocumentContentStore:
    """Encrypts on the way in, decrypts and verifies on the way out."""

    def __init__(self, backend: BlobBackend, keyring: KeyRing) -> None:
        self._backend = backend
        self._keyring = keyring

    @staticmethod
    def _aad(document_uid: str) -> bytes:
        return f"document-content|{document_uid}".encode()

    def store(self, document_uid: str, content: bytes) -> str:
        """Encrypt and store; returns the storage reference for the row."""
        envelope = self._keyring.encrypt(
            KeyPurpose.DOCUMENT_ENCRYPTION, content, aad=self._aad(document_uid)
        )
        self._backend.put(document_uid, envelope.encode("ascii"))
        return f"blob:{document_uid}"

    def destroy(self, document_uid: str) -> None:
        self._backend.delete(document_uid)

    def load(self, document_uid: str, *, expected_sha256: str) -> bytes:
        """Fetch, decrypt and check against the hash in the database."""
        envelope = self._backend.get(document_uid).decode("ascii")
        try:
            content = self._keyring.decrypt(envelope, aad=self._aad(document_uid))
        except CryptoError as exc:
            raise BlobError(
                "stored content does not decrypt for this document"
            ) from exc
        if hashlib.sha256(content).hexdigest() != expected_sha256:
            raise BlobError("stored content does not match the recorded hash")
        return content
