"""Object storage for the archive: Cloudflare R2, or a local directory.

Keys carry a content digest, so a re-upload of identical content is the same
object, and a session that grew since its last upload gets a new object rather
than overwriting the old one. That keeps the archive append-only, which is what
an R2 bucket lock on `raw/` expects.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Protocol


class Store(Protocol):
    def put(self, key: str, data: bytes, *, content_type: str) -> None: ...

    def describe(self) -> str: ...


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

    def describe(self) -> str:
        return f"local:{self.root}"


class R2Store:
    """Cloudflare R2 through its S3-compatible API.

    Credentials come from the environment, never from the config file:
    `AIF_R2_ACCESS_KEY_ID` and `AIF_R2_SECRET_ACCESS_KEY` (falling back to the
    standard `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`).
    """

    def __init__(self, *, account_id: str, bucket: str, endpoint: str | None = None) -> None:
        try:
            import boto3  # type: ignore
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise RuntimeError("the R2 store needs boto3: pip install 'aif-insights[r2]'") from exc
        key_id = os.environ.get("AIF_R2_ACCESS_KEY_ID") or os.environ.get("AWS_ACCESS_KEY_ID")
        secret = os.environ.get("AIF_R2_SECRET_ACCESS_KEY") or os.environ.get("AWS_SECRET_ACCESS_KEY")
        if not key_id or not secret:
            raise RuntimeError(
                "R2 credentials missing: set AIF_R2_ACCESS_KEY_ID and AIF_R2_SECRET_ACCESS_KEY"
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

    def describe(self) -> str:
        return f"r2:{self.bucket}"
