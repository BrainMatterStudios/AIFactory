"""R2 credentials from the environment or, on macOS, the login Keychain.

The environment wins (`AIF_R2_ACCESS_KEY_ID`, `AIF_R2_SECRET_ACCESS_KEY`, or the
standard `AWS_*` names), which is what a VPS or CI uses. On a Mac, `aif-insights
setup` stores the keys as generic passwords under the service
`aif-insights-r2`, and the collector reads them from there, so neither the
config file nor the launchd job ever holds a secret.
"""
from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable

SERVICE = "aif-insights-r2"
ITEM_KEY_ID = "access-key-id"
ITEM_PRIVATE = "secret-access-key"

Runner = Callable[..., subprocess.CompletedProcess]


def read(account: str, *, run: Runner = subprocess.run, platform: str = sys.platform) -> str | None:
    if platform != "darwin":
        return None
    try:
        proc = run(
            ["security", "find-generic-password", "-s", SERVICE, "-a", account, "-w"],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = (proc.stdout or "").strip()
    return value if proc.returncode == 0 and value else None


def write(account: str, value: str, *, run: Runner = subprocess.run) -> None:
    """Create or update one Keychain item.

    `security` takes the password as an argument, so it is briefly visible in
    the local process list while the command runs. That is the documented way to
    script it; on a single-user Mac the exposure is to your own processes only.
    """
    proc = run(
        ["security", "add-generic-password", "-U", "-s", SERVICE, "-a", account,
         "-l", f"aif-insights R2 {account}", "-w", value],
        capture_output=True, text=True, timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"could not store {account} in the Keychain (security exited {proc.returncode})")


def credentials(*, run: Runner = subprocess.run,
                platform: str = sys.platform) -> tuple[str | None, str | None]:
    key_id = os.environ.get("AIF_R2_ACCESS_KEY_ID") or os.environ.get("AWS_ACCESS_KEY_ID")
    secret = os.environ.get("AIF_R2_SECRET_ACCESS_KEY") or os.environ.get("AWS_SECRET_ACCESS_KEY")
    if key_id and secret:
        return key_id, secret
    return (key_id or read(ITEM_KEY_ID, run=run, platform=platform),
            secret or read(ITEM_PRIVATE, run=run, platform=platform))
