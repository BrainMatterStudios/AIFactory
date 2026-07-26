"""Alert adapters (reference) — Slack and Telegram via webhook/bot, using only
the stdlib (urllib), so the core stays dependency-free. The webhook/token is
read from an env var named in the manifest; it is never written to disk."""
from __future__ import annotations

import json
import os
import urllib.request
from collections.abc import Mapping
from typing import Any

from software_factory.adapters.base import Severity
from software_factory.adapters.registry import register

_PREFIX = {Severity.INFO: "", Severity.WARN: "⚠️ ", Severity.CRITICAL: "🚨 "}


def _post_json(url: str, payload: dict) -> None:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        resp.read()


class SlackAlert:
    def __init__(self, *, webhook_env: str) -> None:
        self.webhook_env = webhook_env

    def send(self, text: str, *, severity: Severity = Severity.INFO) -> None:
        url = os.environ.get(self.webhook_env)
        if not url:
            raise KeyError(f"Slack webhook env {self.webhook_env!r} is unset")
        _post_json(url, {"text": _PREFIX[severity] + text})


class TelegramAlert:
    def __init__(self, *, token_env: str, chat_id_env: str) -> None:
        self.token_env = token_env
        self.chat_id_env = chat_id_env

    def send(self, text: str, *, severity: Severity = Severity.INFO) -> None:
        token = os.environ.get(self.token_env)
        chat_id = os.environ.get(self.chat_id_env)
        if not token or not chat_id:
            raise KeyError("Telegram token/chat-id env is unset")
        _post_json(
            f"https://api.telegram.org/bot{token}/sendMessage",
            {"chat_id": chat_id, "text": _PREFIX[severity] + text},
        )


@register("alert", "slack")
def _build_slack(config: Mapping[str, Any]) -> SlackAlert:
    return SlackAlert(webhook_env=config.get("webhook_env", "SLACK_WEBHOOK_URL"))


@register("alert", "telegram")
def _build_telegram(config: Mapping[str, Any]) -> TelegramAlert:
    return TelegramAlert(
        token_env=config.get("token_env", "TELEGRAM_BOT_TOKEN"),
        chat_id_env=config.get("chat_id_env", "TELEGRAM_CHAT_ID"),
    )
