"""Process environments that do not inherit ambient Git authority."""

from __future__ import annotations

import os


def sanitized_git_environment() -> dict[str, str]:
    """Return ambient non-Git state plus fail-closed Git configuration."""
    environment = {
        name: value for name, value in os.environ.items() if not name.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "/usr/bin/false",
            "GIT_EDITOR": "/usr/bin/false",
            "GIT_SEQUENCE_EDITOR": "/usr/bin/false",
            "GIT_PAGER": "cat",
            "GIT_MERGE_AUTOEDIT": "no",
            "SSH_ASKPASS_REQUIRE": "never",
        }
    )
    return environment


__all__ = ["sanitized_git_environment"]
