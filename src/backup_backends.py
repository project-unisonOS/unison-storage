"""Provider-neutral blob backends for provider-blind backup."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any, Protocol

from unison_common.backup import BackendCapabilities


class ObjectNotFoundError(FileNotFoundError):
    pass


class ConditionalWriteError(RuntimeError):
    pass


class BackupBackend(Protocol):
    @property
    def capabilities(self) -> BackendCapabilities: ...

    def put(self, key: str, data: bytes, *, if_absent: bool = False) -> None: ...

    def get(self, key: str) -> bytes: ...

    def exists(self, key: str) -> bool: ...

    def list(self, prefix: str) -> list[str]: ...

    def delete(self, key: str) -> bool: ...


def _validate_key(key: str) -> str:
    normalized = key.replace("\\", "/").strip("/")
    if not normalized or ".." in normalized.split("/"):
        raise ValueError("backend object key is invalid")
    return normalized


class FileSystemBackend:
    """Atomic reference backend; the filesystem sees ciphertext only."""

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    @property
    def capabilities(self) -> BackendCapabilities:
        return BackendCapabilities(
            backend_type="filesystem",
            conditional_write=True,
            range_read=True,
            resumable_transfer=True,
            delete=True,
            list_prefix=True,
        )

    def _path(self, key: str) -> Path:
        target = (self.root / _validate_key(key)).resolve()
        if self.root not in target.parents:
            raise ValueError("backend object key escapes root")
        return target

    def put(self, key: str, data: bytes, *, if_absent: bool = False) -> None:
        target = self._path(key)
        target.parent.mkdir(parents=True, exist_ok=True)
        if if_absent and target.exists():
            raise ConditionalWriteError(f"object already exists: {key}")
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{target.name}.",
            dir=target.parent,
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def get(self, key: str) -> bytes:
        target = self._path(key)
        try:
            return target.read_bytes()
        except FileNotFoundError as exc:
            raise ObjectNotFoundError(key) from exc

    def exists(self, key: str) -> bool:
        return self._path(key).is_file()

    def list(self, prefix: str) -> list[str]:
        normalized = _validate_key(prefix)
        target = self._path(normalized)
        if target.is_file():
            return [normalized]
        if not target.exists():
            return []
        return sorted(
            str(item.relative_to(self.root)).replace("\\", "/")
            for item in target.rglob("*")
            if item.is_file() and not item.name.startswith(".")
        )

    def delete(self, key: str) -> bool:
        target = self._path(key)
        try:
            target.unlink()
        except FileNotFoundError:
            return False
        return True


class HostileMemoryBackend:
    """Deterministic fake provider with tamper/truncate/reorder controls."""

    def __init__(self):
        self.objects: dict[str, bytes] = {}
        self.read_log: list[str] = []
        self.write_log: list[str] = []

    @property
    def capabilities(self) -> BackendCapabilities:
        return BackendCapabilities(
            backend_type="hostile-memory",
            conditional_write=True,
            range_read=False,
            resumable_transfer=True,
            delete=True,
            list_prefix=True,
        )

    def put(self, key: str, data: bytes, *, if_absent: bool = False) -> None:
        key = _validate_key(key)
        if if_absent and key in self.objects:
            raise ConditionalWriteError(f"object already exists: {key}")
        self.objects[key] = bytes(data)
        self.write_log.append(key)

    def get(self, key: str) -> bytes:
        key = _validate_key(key)
        self.read_log.append(key)
        try:
            return self.objects[key]
        except KeyError as exc:
            raise ObjectNotFoundError(key) from exc

    def exists(self, key: str) -> bool:
        return _validate_key(key) in self.objects

    def list(self, prefix: str) -> list[str]:
        prefix = _validate_key(prefix)
        return sorted(key for key in self.objects if key.startswith(prefix))

    def delete(self, key: str) -> bool:
        return self.objects.pop(_validate_key(key), None) is not None

    def corrupt(self, key: str, *, offset: int = 0) -> None:
        value = bytearray(self.get(key))
        if not value:
            raise ValueError("cannot corrupt an empty object")
        position = min(max(offset, 0), len(value) - 1)
        value[position] ^= 1
        self.objects[_validate_key(key)] = bytes(value)

    def truncate(self, key: str, *, length: int) -> None:
        self.objects[_validate_key(key)] = self.get(key)[:length]

    def replay(self, source_key: str, target_key: str) -> None:
        self.objects[_validate_key(target_key)] = self.get(source_key)


class S3Backend:
    """S3-compatible backend; validated with MinIO in the Phase 6 harness."""

    def __init__(
        self,
        *,
        bucket: str,
        prefix: str = "unison-backup-v1",
        client: Any | None = None,
        endpoint_url: str | None = None,
        region_name: str | None = None,
    ):
        if client is None:
            try:
                import boto3
            except ImportError as exc:  # pragma: no cover - deployment guard
                raise RuntimeError("boto3 is required for the S3 backend") from exc
            client = boto3.client(
                "s3",
                endpoint_url=endpoint_url,
                region_name=region_name,
            )
        self.client = client
        self.bucket = bucket
        self.prefix = prefix.strip("/")

    @property
    def capabilities(self) -> BackendCapabilities:
        return BackendCapabilities(
            backend_type="s3-compatible",
            conditional_write=True,
            range_read=True,
            resumable_transfer=True,
            delete=True,
            list_prefix=True,
            server_side_encryption_required=False,
        )

    def _key(self, key: str) -> str:
        return f"{self.prefix}/{_validate_key(key)}"

    def put(self, key: str, data: bytes, *, if_absent: bool = False) -> None:
        arguments: dict[str, Any] = {
            "Bucket": self.bucket,
            "Key": self._key(key),
            "Body": data,
            "ContentType": "application/octet-stream",
        }
        if if_absent:
            arguments["IfNoneMatch"] = "*"
        try:
            self.client.put_object(**arguments)
        except Exception as exc:
            response = getattr(exc, "response", {})
            status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if if_absent and status in {409, 412}:
                raise ConditionalWriteError(f"object already exists: {key}") from exc
            raise

    def get(self, key: str) -> bytes:
        try:
            response = self.client.get_object(Bucket=self.bucket, Key=self._key(key))
        except Exception as exc:
            response = getattr(exc, "response", {})
            status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if status == 404:
                raise ObjectNotFoundError(key) from exc
            raise
        return response["Body"].read()

    def exists(self, key: str) -> bool:
        try:
            self.client.head_object(Bucket=self.bucket, Key=self._key(key))
            return True
        except Exception as exc:
            response = getattr(exc, "response", {})
            status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if status == 404:
                return False
            raise

    def list(self, prefix: str) -> list[str]:
        remote_prefix = self._key(prefix)
        continuation: str | None = None
        results: list[str] = []
        while True:
            arguments: dict[str, Any] = {
                "Bucket": self.bucket,
                "Prefix": remote_prefix,
            }
            if continuation:
                arguments["ContinuationToken"] = continuation
            response = self.client.list_objects_v2(**arguments)
            for item in response.get("Contents", []):
                key = item["Key"]
                results.append(key[len(self.prefix) + 1 :])
            if not response.get("IsTruncated"):
                break
            continuation = response["NextContinuationToken"]
        return sorted(results)

    def delete(self, key: str) -> bool:
        existed = self.exists(key)
        self.client.delete_object(Bucket=self.bucket, Key=self._key(key))
        return existed


__all__ = [
    "BackupBackend",
    "ConditionalWriteError",
    "FileSystemBackend",
    "HostileMemoryBackend",
    "ObjectNotFoundError",
    "S3Backend",
]
