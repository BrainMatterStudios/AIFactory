#!/usr/bin/env python3
"""Check tracked public-repository content against the versioned policy."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from software_factory.core.publication import scan_public_tree  # noqa: E402


def _one_line(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)[1:-1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=ROOT)
    parser.add_argument("--policy", type=Path, default=ROOT / "public-content-policy.json")
    parser.add_argument(
        "--base-ref",
        help="also inspect every commit after this ancestor through HEAD",
    )
    arguments = parser.parse_args(argv)

    findings = scan_public_tree(
        arguments.repo,
        arguments.policy,
        base_ref=arguments.base_ref,
    )
    for finding in findings:
        print(
            "\t".join(
                (_one_line(finding.path), _one_line(finding.rule), _one_line(finding.detail))
            )
        )
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
