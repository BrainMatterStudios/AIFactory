"""Object storage for the archive: Cloudflare R2, or a local directory.

Keys carry a content digest, so a re-upload of identical content is the same
object, and a session that grew since its last upload gets a new object rather
than overwriting the old one. That keeps the archive append-only, which is what
an R2 bucket lock on `raw/` expects.
"""
from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Protocol


class Store(Protocol):
    def put(self, key: str, data: bytes, *, content_type: str) -> None: ...

    def describe(self) -> str: ...


class ReadableStore(Store, Protocol):
    def list(self, prefix: str) -> Iterator[tuple[str, int]]:
        """(key, size in bytes) of every object under `prefix`."""
        ...

    def get(self, key: str) -> bytes: ...


class LocalStore:
    """A directory laid out like the bucket. For dry runs, tests and backups."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).expanduser()

    def put(self, key: str, data: bytes, *, content_type: str) -> None:
        path = self.root / key
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_bytes(data)
        tmp.replace(path)

    def list(self, prefix: str) -> Iterator[tuple[str, int]]:
        base = self.root / prefix
        if not base.is_dir():
            return
        for path in sorted(base.rglob("*")):
            if path.is_file() and not path.name.endswith(".tmp"):
                yield path.relative_to(self.root).as_posix(), path.stat().st_size

    def get(self, key: str) -> bytes:
        return (self.root / key).read_bytes()

    def describe(self) -> str:
        return f"local:{self.root}"


class R2Store:
    """Cloudflare R2 through its S3-compatible API.

    Credentials never come from the config file: see `aif_insights.keychain`
    (environment first, then the macOS Keychain).
    """

    def __init__(self, *, account_id: str, bucket: str, endpoint: str | None = None) -> None:
        try:
            import boto3  # type: ignore
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise RuntimeError("the R2 store needs boto3: pip install 'aif-insights[r2]'") from exc
        from aif_insights.keychain import credentials

        key_id, secret = credentials()
        if not key_id or not secret:
            raise RuntimeError(
                "R2 credentials missing: run `aif-insights setup`, or set "
                "AIF_R2_ACCESS_KEY_ID and AIF_R2_SECRET_ACCESS_KEY"
            )
        self.bucket = bucket
        self.endpoint = endpoint or f"https://{account_id}.r2.cloudflarestorage.com"
        self._client = boto3.client(
            "s3",
            endpoint_url=self.endpoint,
            aws_access_key_id=key_id,
            aws_secret_access_key=secret,
            region_name="auto",
        )

    def put(self, key: str, data: bytes, *, content_type: str) -> None:
        self._client.put_object(Bucket=self.bucket, Key=key, Body=data, ContentType=content_type)

    def list(self, prefix: str) -> Iterator[tuple[str, int]]:
        pages = self._client.get_paginator("list_objects_v2").paginate(
            Bucket=self.bucket, Prefix=prefix)
        for page in pages:
            for obj in page.get("Contents", []):
                yield obj["Key"], int(obj["Size"])

    def get(self, key: str) -> bytes:
        return self._client.get_object(Bucket=self.bucket, Key=key)["Body"].read()

    def describe(self) -> str:
        return f"r2:{self.bucket}"
