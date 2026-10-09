"""Fail-closed, guest-resident companion to the Lima execution transport.

The bridge deliberately accepts canonical envelopes only.  Every operation is
bounded, uses argument vectors (never a shell), and returns normalized facts
rather than subprocess output.
"""

from __future__ import annotations

import base64
import datetime
import fcntl
import hashlib
import ipaddress
import json
import math
import os
import platform
import re
import secrets
import selectors
import shlex
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from software_factory.build.workspace import (
    _local_scan_evidence,
    _read_regular_at_root,
    _remove_at_root,
    _write_regular_at_root,
    fingerprint_repository_surface,
)
from software_factory.core.contracts.git_check import (
    commits_from_log,
    contract_precedes_implementation,
)
from software_factory.core.git_environment import sanitized_git_environment
from software_factory.execution.context import workspace_context_sha256
from software_factory.execution.leash_artifact import (
    LEASH_HARDENED_BASE_REVISION,
    LEASH_HARDENED_VERSION,
)
from software_factory.execution.leash_installation import (
    LEASH_ENTRY_TARGET,
    LEASH_IDENTITY_FIELDS,
    measure_leash_installation,
)
from software_factory.execution.pnpm_toolchain import (
    PNPM_ARCHIVE_SHA256,
    PNPM_DESTINATION,
    PNPM_ENTRYPOINT,
    PNPM_ENTRYPOINT_SHA256,
    PNPM_TREE_SHA256,
    PNPM_VERSION,
    measure_pnpm_toolchain,
)
from software_factory.execution.protocol import (
    CONTAINMENT_FAILURE_REASONS,
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    SCHEMA_VERSION,
    BridgeProtocolError,
    BridgeRequest,
    BridgeResponse,
    JsonValue,
    contains_control_characters,
    decode_request,
    encode_response,
)

_DIGEST_LENGTH = 64
_SAFE_TURN_KINDS = frozenset({"contract-author", "design-author", "reviewer", "implementation"})
_SAFE_NETWORK_PROFILES = frozenset({"model-only-v1"})
_SAFE_DENIAL_ACTIONS = frozenset({"file.read", "file.write", "network.connect", "process.exec"})
_ENVIRONMENT_ALLOWLIST = ("HOME", "LANG", "LC_ALL", "TZ")
_SAFE_PATH = "/usr/bin:/bin"
_VERIFIER_PREFIX = ("sudo", "-n", "-u", "aifactory-verifier", "--")
_VERIFIER_LAUNCHER = Path("/usr/local/bin/aifactory-execution-bridge")
_VERIFIER_LAUNCH_PROTOCOL = "aifactory-verifier-launch-v1"
_PROC_MOUNTINFO = Path("/proc/self/mountinfo")
_LEASH_ENTRY = Path("/usr/local/bin/leash")
_LEASH_PACKAGE_ROOT = Path("/usr/local/lib/node_modules/@strongdm/leash")
_LEASH_ENV = Path("/usr/bin/env")
_LEASH_NODE = Path("/usr/bin/node")
_NFT_PATH = Path("/usr/sbin/nft")
_MODEL_AUTH_DIR = Path("/var/lib/aifactory/model-auth/.claude")
_MODEL_AUTH_TARGET = "/root/.claude"
_MODEL_AUTH_FILE = Path("/var/lib/aifactory/model-auth/.claude.json")
_MODEL_AUTH_FILE_TARGET = "/root/.claude.json"
_LEASH_HOME = Path("/var/lib/aifactory/automated-leash-home")
_PNPM_IDENTITY_FIELDS = (
    "pnpm_version",
    "pnpm_archive_digest",
    "pnpm_tree_digest",
    "pnpm_entrypoint_digest",
    "pnpm_entrypoint_path",
)
_HARDENED_LEASH_FIELDS = frozenset(
    {
        "leash_artifact_mode",
        "leash_base_revision",
        "leash_bpf_open_object_digest",
        "leash_build_record_digest",
        "leash_source_revision",
        "leash_test_record_digest",
    }
)
_REGISTRY_LEASH_FIELDS = frozenset({"leash_artifact_mode"})


def _leash_authority_fields(authority: Mapping[str, Any]) -> frozenset[str]:
    mode = authority.get("leash_artifact_mode")
    if mode == "local-hardened-v1":
        return _HARDENED_LEASH_FIELDS
    if mode == "upstream-registry-v1":
        return _REGISTRY_LEASH_FIELDS
    return frozenset()


def _valid_leash_reference(authority: Mapping[str, Any]) -> bool:
    reference = authority.get("leash_image_reference")
    digest = authority.get("leash_image_digest")
    if not _is_digest(digest) or type(reference) is not str:
        return False
    mode = authority.get("leash_artifact_mode", "upstream-registry-v1")
    if mode == "upstream-registry-v1":
        return reference == f"public.ecr.aws/s5i7k8t3/strongdm/leash@sha256:{digest}"
    return bool(
        mode == "local-hardened-v1"
        and reference == f"sha256:{digest}"
        and authority.get("leash_base_revision") == LEASH_HARDENED_BASE_REVISION
        and _is_digest(authority.get("leash_bpf_open_object_digest"))
        and _is_digest(authority.get("leash_build_record_digest"))
        and type(authority.get("leash_source_revision")) is str
        and re.fullmatch(r"[0-9a-f]{40}", authority["leash_source_revision"])
        is not None
        and authority["leash_source_revision"] != authority["leash_base_revision"]
        and _is_digest(authority.get("leash_test_record_digest"))
    )


def _image_runtime_failure_reason(
    reference: str, authority: Mapping[str, Any]
) -> str:
    if (
        authority.get("leash_artifact_mode") == "local-hardened-v1"
        and reference == authority.get("leash_image_reference")
    ):
        return "leash-image-identity-drift"
    return "image-runtime-mismatch"


def _fixed_pnpm_identity() -> dict[str, str]:
    return {
        "pnpm_version": PNPM_VERSION,
        "pnpm_archive_digest": PNPM_ARCHIVE_SHA256,
        "pnpm_tree_digest": PNPM_TREE_SHA256,
        "pnpm_entrypoint_digest": PNPM_ENTRYPOINT_SHA256,
        "pnpm_entrypoint_path": str(
            PNPM_DESTINATION / PNPM_ENTRYPOINT.removeprefix("package/")
        ),
    }


_EMPTY_READ_RESPONSE_BYTES = len(
    json.dumps(
        {
            "evidence": (),
            "request_id": "",
            "result": {"content_base64": ""},
            "schema_version": SCHEMA_VERSION,
            "status": "ok",
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
)
_READ_RESPONSE_BASE64_BUDGET = MAX_RESPONSE_BYTES - MAX_REQUEST_BYTES - _EMPTY_READ_RESPONSE_BYTES
_MAX_RAW_READ_BYTES = 3 * (_READ_RESPONSE_BASE64_BUDGET // 4)
while 4 * ((_MAX_RAW_READ_BYTES + 2) // 3) > _READ_RESPONSE_BASE64_BUDGET:
    _MAX_RAW_READ_BYTES -= 1
_DIRECT_INTERPRETER = re.compile(
    r"(?:"
    r"(?:python|pypy)(?:[-.]?\d+(?:\.\d+)*)?"
    r"|(?:node|nodejs|deno|bun|ruby|perl|php|lua|luajit)(?:[-.]?\d+(?:\.\d+)*)?"
    r"|(?:pwsh|powershell)(?:[-.]?\d+(?:\.\d+)*)?"
    r")(?:\.exe)?\Z"
)
_FIXED_GIT_CONFIG = (
    ("core.hooksPath", os.devnull),
    ("core.fsmonitor", "false"),
    ("core.untrackedCache", "false"),
    ("core.attributesFile", "/dev/null"),
    ("commit.gpgSign", "false"),
    ("tag.gpgSign", "false"),
    ("core.editor", "/usr/bin/false"),
    ("sequence.editor", "/usr/bin/false"),
    ("core.pager", "cat"),
    ("credential.helper", ""),
    ("user.name", "AIFactory Guest Bridge"),
    ("user.email", "bridge@aifactory.invalid"),
)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_OPEN_SUPPORTS_DIR_FD = os.open in os.supports_dir_fd
_STAT_SUPPORTS_DIR_FD = os.stat in os.supports_dir_fd
_STAT_SUPPORTS_NOFOLLOW = os.stat in os.supports_follow_symlinks
_RENAME_SUPPORTS_DIR_FD = os.rename in os.supports_dir_fd
_LINK_SUPPORTS_DIR_FD = os.link in os.supports_dir_fd
_PROBE_TABLE = re.compile(r"aifp_[0-9a-f]{16}\Z")
_NETWORK_INTERFACE = re.compile(r"[A-Za-z0-9_.-]{1,15}\Z")
_MAC_ADDRESS = re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}\Z")
_MAX_PROBE_LOG_BYTES = 256 * 1024
_PROBE_LOG_MODE = 0o644
_MAX_NORMALIZED_PROBE_BYTES = 64 * 1024
# The active phase always yields to a fixed cleanup reserve before the controller's
# separate 600 second containment-only transport ceiling.
_PROBE_ACTIVE_BUDGET_SECONDS = 480
_PROBE_CLEANUP_RESERVE_SECONDS = 90
_PROBE_CLEANUP_COMMAND_SECONDS = 8
_PROBE_OPERATION_WORST_CASE_SECONDS = (
    _PROBE_ACTIVE_BUDGET_SECONDS + _PROBE_CLEANUP_RESERVE_SECONDS
)
_PROBE_TRANSPORT_OVERHEAD_SECONDS = 30
_RUN_AGENT_CLEANUP_BUDGET_SECONDS = 15
_RUN_AGENT_CLEANUP_COMMAND_SECONDS = 5
# Leash v1.1.7 source commit 5bf1c644... Dockerfile.coder pins NODE_MAJOR=22,
# installs the NodeSource Debian `nodejs` package, and makes `node --version` the
# image CMD. That package installs the runtime at this Debian path; the live
# process is still authenticated independently through /proc before release.
_PROBE_NODE = "/usr/bin/node"
_NETWORK_PROBE_TARGETS = {
    "network-api-anthropic": ("hostname", "api.anthropic.com", 443, "allowed"),
    "network-claude": ("hostname", "claude.ai", 443, "allowed"),
    "network-mcp-proxy": ("hostname", "mcp-proxy.anthropic.com", 443, "allowed"),
    "network-platform": ("hostname", "platform.claude.com", 443, "allowed"),
    "network-firewall-control": ("address", "192.0.2.1", 443, "allowed"),
    "network-github": ("hostname", "github.com", 443, "denied"),
    "network-metadata": ("address", "169.254.169.254", 80, "denied"),
    "network-rfc1918-10": ("address", "10.255.255.1", 443, "denied"),
    "network-rfc1918-172": ("address", "172.31.255.1", 443, "denied"),
    "network-rfc1918-192": ("address", "192.168.255.1", 443, "denied"),
    "network-sqlserver": ("address", "10.255.255.1", 1433, "denied"),
    "network-postgres": ("address", "172.31.255.1", 5432, "denied"),
    "network-ssh": ("address", "192.168.255.1", 22, "denied"),
}
_MODEL_ENDPOINTS = (
    "api.anthropic.com",
    "claude.ai",
    "mcp-proxy.anthropic.com",
    "platform.claude.com",
)
_PROBE_PHASE1_NETWORK_IDS = (
    "network-api-anthropic",
    "network-claude",
    "network-mcp-proxy",
    "network-platform",
    "network-firewall-control",
)


def _require_bpf_lsm(config: BridgeConfig) -> None:
    try:
        raw = _read_dynamic_regular_path(config.lsm_path, max_bytes=4096)
        value = raw.decode("ascii").strip()
    except (OSError, UnicodeError, BridgeFailure):
        raise BridgeFailure("kernel-invalid") from None
    tokens = value.split(",")
    if (
        not tokens
        or any(re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", token) is None for token in tokens)
        or len(tokens) != len(set(tokens))
        or "bpf" not in tokens
    ):
        raise BridgeFailure("kernel-invalid")


_RESOLVER_PROGRAM = r'''import json
import socket

result = {}
for endpoint in (
    "api.anthropic.com", "claude.ai", "mcp-proxy.anthropic.com",
    "platform.claude.com", "github.com"
):
    result[endpoint] = sorted({
        answer[4][0]
        for answer in socket.getaddrinfo(
            endpoint, 443, family=socket.AF_INET,
            type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
        )
    })
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
'''
_FINGERPRINT_PROGRAM = r'''import sys
from software_factory.build.workspace import fingerprint_repository_surface

if len(sys.argv) != 2:
    raise SystemExit(97)
print(fingerprint_repository_surface(sys.argv[1]))
'''
_PROBE_PROCESS_PATHS = {
    "process-git-push": "/usr/bin/git",
    "process-gh": "/usr/bin/gh",
    "process-kubectl": "/usr/bin/kubectl",
    "process-terraform": "/usr/bin/terraform",
    "process-vercel": "/usr/local/bin/vercel",
    "process-flyctl": "/usr/local/bin/flyctl",
    "process-docker": "/usr/bin/docker",
    "process-sudo": "/usr/bin/sudo",
    "process-su": "/usr/bin/su",
    "process-ssh": "/usr/bin/ssh",
}
_PROBE_FIXED_FILE_PATHS = {
    "filesystem-operator": "/Users/operator/.ssh/config",
    "filesystem-docker-socket": "/var/run/docker.sock",
    "filesystem-cedar": "/etc/aifactory/leash.cedar",
    "filesystem-bridge": "/usr/local/bin/aifactory-execution-bridge",
    "filesystem-guest-authority": "/etc/aifactory/instance-id",
    "filesystem-controller-evidence": "/var/lib/aifactory/sealed",
    "tamper-cedar": "/etc/aifactory/leash.cedar",
    "tamper-bridge": "/usr/local/bin/aifactory-execution-bridge",
    "tamper-guest-authority": "/etc/aifactory/instance-id",
}
_PROBE_BOUNDARY_IDS = (
    "filesystem-marker-read",
    "filesystem-write-control",
    "filesystem-traversal",
    "filesystem-other-workspace",
    "filesystem-operator",
    "filesystem-docker-socket",
    "filesystem-cedar",
    "filesystem-bridge",
    "filesystem-guest-authority",
    "filesystem-controller-evidence",
    *_PROBE_PROCESS_PATHS,
    "tamper-cedar",
    "tamper-bridge",
    "tamper-guest-authority",
    "tamper-controller-evidence",
)
_PROBE_ALL_IDS = (*_PROBE_BOUNDARY_IDS, *_NETWORK_PROBE_TARGETS)
_PROBE_PROGRAM = r'''const fs = require('fs');
const net = require('net');
const path = require('path');
const tls = require('tls');
const {spawn} = require('child_process');

if (process.argv.length !== 3) process.exit(97);
const control = process.argv[1];
const workspace = process.argv[2];
const items = [];

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === 'object') {
    const result = {};
    for (const key of Object.keys(value).sort()) result[key] = canonical(value[key]);
    return result;
  }
  return value;
}
function record(id, category, expectation, observed, reason) {
  items.push({id, category, expectation, observed, reason});
}
function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
async function waitFor(name) {
  const deadline = Date.now() + 60000;
  const candidate = path.join(control, name);
  while (Date.now() < deadline) {
    try {
      if (fs.statSync(candidate).isFile()) return;
    } catch (_) {}
    await delay(50);
  }
  process.exit(96);
}
function publish(name, phase) {
  const payload = Buffer.from(JSON.stringify(canonical({
    schema_version: 'containment-probe-child-v1', phase, probes: items
  })));
  const descriptor = fs.openSync(path.join(control, name), 'wx', 0o600);
  try {
    let offset = 0;
    while (offset < payload.length) offset += fs.writeSync(descriptor, payload, offset);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}
function readProbe(id, candidate) {
  try {
    const descriptor = fs.openSync(candidate, 'r');
    try { fs.readSync(descriptor, Buffer.alloc(1), 0, 1, null); }
    finally { fs.closeSync(descriptor); }
    record(id, 'filesystem', 'denied-or-absent', 'succeeded', 'none');
  } catch (error) {
    const code = error && error.code;
    record(id, 'filesystem', 'denied-or-absent',
      code === 'ENOENT' ? 'absent' : 'failed',
      code === 'ENOENT' ? 'not-found' : (code === 'EACCES' || code === 'EPERM') ?
        'permission-error' : 'os-error');
  }
}
function writeProbe(id, candidate) {
  try {
    fs.writeFileSync(candidate, Buffer.from('tamper'), {flag: 'w'});
    record(id, 'tamper', 'denied-or-absent', 'succeeded', 'none');
  } catch (error) {
    const code = error && error.code;
    record(id, 'tamper', 'denied-or-absent',
      code === 'ENOENT' ? 'absent' : 'failed',
      code === 'ENOENT' ? 'not-found' : (code === 'EACCES' || code === 'EPERM') ?
        'permission-error' : 'os-error');
  }
}
async function processProbe(id, argv) {
  let child;
  try {
    child = spawn(argv[0], argv.slice(1), {
      detached: true, stdio: 'ignore', shell: false
    });
  } catch (_) {
    record(id, 'process', 'denied-or-absent', 'failed', 'os-error');
    return;
  }
  let settled = false;
  const completion = new Promise((resolve) => {
    child.once('error', (error) => {
      settled = true;
      resolve({kind: error && error.code === 'ENOENT' ? 'absent' : 'error'});
    });
    child.once('exit', (code, signal) => {
      settled = true;
      resolve({kind: 'exit', code, signal});
    });
  });
  const outcome = await Promise.race([
    completion,
    delay(4000).then(() => ({kind: 'timeout'}))
  ]);
  if (outcome.kind === 'timeout' && !settled) {
    try { process.kill(-child.pid, 'SIGKILL'); } catch (_) {}
    await Promise.race([completion, delay(2000)]);
    record(id, 'process', 'denied-or-absent', 'failed', 'timeout');
  } else if (outcome.kind === 'absent') {
    record(id, 'process', 'denied-or-absent', 'absent', 'not-found');
  } else if (outcome.kind === 'error') {
    record(id, 'process', 'denied-or-absent', 'failed', 'os-error');
  } else {
    record(id, 'process', 'denied-or-absent',
      outcome.code === 0 ? 'succeeded' : 'failed',
      outcome.code === 0 ? 'none' : 'nonzero-exit');
  }
}
async function networkProbe(id, host, port, expectation, verify, endpoints) {
  const address = net.isIPv4(host) ? host : endpoints[host][0];
  const outcome = await new Promise((resolve) => {
    const options = {
      host: address, port, rejectUnauthorized: verify,
      ALPNProtocols: ['http/1.1']
    };
    if (verify) options.servername = host;
    const socket = tls.connect(options);
    let done = false;
    let response = Buffer.alloc(0);
    const finish = (value) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(value);
    };
    socket.setTimeout(4000, () => finish(false));
    socket.once('error', () => finish(false));
    socket.once('end', () => finish(false));
    socket.once('close', () => finish(false));
    socket.on('data', (chunk) => {
      if (!Buffer.isBuffer(chunk) || response.length + chunk.length > 4096) {
        finish(false);
        return;
      }
      response = Buffer.concat([response, chunk]);
      const lineEnd = response.indexOf('\r\n');
      if (lineEnd === -1) return;
      const match = /^HTTP\/1\.[01] ([1-5][0-9]{2})(?: [\x20-\x7e]*)?$/.exec(
        response.subarray(0, lineEnd).toString('ascii'));
      finish(match !== null && Number(match[1]) >= 200 && Number(match[1]) < 500);
    });
    socket.once('secureConnect', () => {
      socket.write(
        `HEAD / HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`);
    });
  });
  record(id, 'network', expectation, outcome ? 'succeeded' : 'failed',
    outcome ? 'none' : 'network-error');
}

async function main() {
  let endpoints;
  try {
    endpoints = JSON.parse(fs.readFileSync(path.join(control, 'endpoints.json'), 'ascii'));
    const expected = [
      'api.anthropic.com', 'claude.ai', 'github.com',
      'mcp-proxy.anthropic.com', 'platform.claude.com'];
    if (JSON.stringify(Object.keys(endpoints).sort()) !== JSON.stringify(expected)) throw Error();
    for (const values of Object.values(endpoints)) {
      if (!Array.isArray(values) || values.length === 0 ||
          values.some((value) => net.isIPv4(value) === 0)) throw Error();
    }
  } catch (_) {
    process.exit(95);
  }

  await waitFor('start');
  try {
    const marker = fs.readFileSync(path.join(control, 'marker'), 'ascii');
    record('filesystem-marker-read', 'filesystem', 'allowed',
      marker === 'aifactory-containment-control-v1\n' ? 'succeeded' : 'failed',
      marker === 'aifactory-containment-control-v1\n' ? 'none' : 'content-mismatch');
  } catch (_) {
    record('filesystem-marker-read', 'filesystem', 'allowed', 'failed', 'os-error');
  }
  try {
    const candidate = path.join(control, 'write-control');
    fs.writeFileSync(candidate, Buffer.from('probe'));
    const matched = fs.readFileSync(candidate).equals(Buffer.from('probe'));
    fs.unlinkSync(candidate);
    record('filesystem-write-control', 'filesystem', 'allowed',
      matched ? 'succeeded' : 'failed', matched ? 'none' : 'content-mismatch');
  } catch (_) {
    record('filesystem-write-control', 'filesystem', 'allowed', 'failed', 'os-error');
  }

  const other = path.join(path.dirname(workspace),
    path.basename(workspace) === 'f'.repeat(64) ? 'e'.repeat(64) : 'f'.repeat(64));
  for (const [id, candidate] of [
    ['filesystem-traversal', path.join(workspace, '..', path.basename(other), 'marker')],
    ['filesystem-other-workspace', path.join(other, 'marker')],
    ['filesystem-operator', '/Users/operator/.ssh/config'],
    ['filesystem-docker-socket', '/var/run/docker.sock'],
    ['filesystem-cedar', '/etc/aifactory/leash.cedar'],
    ['filesystem-bridge', '/usr/local/bin/aifactory-execution-bridge'],
    ['filesystem-guest-authority', '/etc/aifactory/instance-id'],
    ['filesystem-controller-evidence', '/var/lib/aifactory/sealed']
  ]) readProbe(id, candidate);

  const inert = path.join(control, 'inert.git');
  for (const [id, argv] of [
    ['process-git-push', ['/usr/bin/git', '-c', 'protocol.file.allow=always', 'push', inert,
      'HEAD:refs/heads/probe']],
    ['process-gh', ['/usr/bin/gh', '--version']],
    ['process-kubectl', ['/usr/bin/kubectl', 'version', '--client']],
    ['process-terraform', ['/usr/bin/terraform', 'version']],
    ['process-vercel', ['/usr/local/bin/vercel', '--version']],
    ['process-flyctl', ['/usr/local/bin/flyctl', 'version']],
    ['process-docker', ['/usr/bin/docker', 'version']],
    ['process-sudo', ['/usr/bin/sudo', '-n', '/usr/bin/true']],
    ['process-su', ['/usr/bin/su', '-c', '/usr/bin/true']],
    ['process-ssh', ['/usr/bin/ssh', '-G', 'example.invalid']]
  ]) await processProbe(id, argv);

  for (const [id, candidate] of [
    ['tamper-cedar', '/etc/aifactory/leash.cedar'],
    ['tamper-bridge', '/usr/local/bin/aifactory-execution-bridge'],
    ['tamper-guest-authority', '/etc/aifactory/instance-id'],
    ['tamper-controller-evidence',
      path.join('/var/lib/aifactory/execution-state', path.basename(workspace), 'authority.json')]
  ]) writeProbe(id, candidate);

  await networkProbe('network-api-anthropic', 'api.anthropic.com', 443, 'allowed', true, endpoints);
  await networkProbe('network-claude', 'claude.ai', 443, 'allowed', true, endpoints);
  await networkProbe(
    'network-mcp-proxy', 'mcp-proxy.anthropic.com', 443, 'allowed', true, endpoints);
  await networkProbe('network-platform', 'platform.claude.com', 443, 'allowed', true, endpoints);
  await networkProbe('network-firewall-control', '192.0.2.1', 443, 'outer-denied', false, endpoints);
  publish('phase1.json', 'safety-control');
  await waitFor('forbidden');
  for (const [id, host, port] of [
    ['network-github', 'github.com', 443],
    ['network-metadata', '169.254.169.254', 80],
    ['network-rfc1918-10', '10.255.255.1', 443],
    ['network-rfc1918-172', '172.31.255.1', 443],
    ['network-rfc1918-192', '192.168.255.1', 443],
    ['network-sqlserver', '10.255.255.1', 1433],
    ['network-postgres', '172.31.255.1', 5432],
    ['network-ssh', '192.168.255.1', 22]
  ]) await networkProbe(id, host, port, 'denied', port === 443 && !net.isIPv4(host), endpoints);
  publish('final.json', 'complete');
}
main().catch(() => process.exit(94));
'''


class BridgeFailure(RuntimeError):
    """An expected bridge failure whose reason is safe to return to the controller."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@contextmanager
def _docker_mutation_lock(config: BridgeConfig, *, deadline: float) -> Iterator[None]:
    """Serialize factory-owned Docker mutations inside one controller-owned cell.

    The controller lifecycle keeps the validation cell disposable and free of
    unmediated workloads. This lock coordinates bridge operations only; it does
    not claim to constrain an arbitrary root process outside that threat model.
    """
    _secure_descriptor_primitives()
    parent: int | None = None
    descriptor: int | None = None
    try:
        state_root = _safe_root(config.state_root, create=False)
        parent = os.open(os.fspath(state_root), os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
        descriptor = os.open(
            ".docker-mutation.lock",
            os.O_RDWR | os.O_CREAT | _NOFOLLOW,
            0o600,
            dir_fd=parent,
        )
        opened = os.fstat(descriptor)
        named = os.stat(
            ".docker-mutation.lock", dir_fd=parent, follow_symlinks=False
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != config.root_uid
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
            or not _same_inode(opened, named)
        ):
            raise BridgeFailure("probe-state-unsafe")
        while True:
            _require_probe_deadline(deadline)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                time.sleep(min(0.01, _probe_timeout(deadline, 0.01)))
        locked = os.fstat(descriptor)
        named = os.stat(
            ".docker-mutation.lock", dir_fd=parent, follow_symlinks=False
        )
        if (
            not stat.S_ISREG(locked.st_mode)
            or locked.st_uid != config.root_uid
            or locked.st_nlink != 1
            or stat.S_IMODE(locked.st_mode) != 0o600
            or not _same_inode(locked, named)
        ):
            raise BridgeFailure("probe-state-unsafe")
        yield
    except BridgeFailure:
        raise
    except OSError as error:
        raise BridgeFailure("probe-state-unsafe") from error
    finally:
        if descriptor is not None:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(descriptor)
        if parent is not None:
            os.close(parent)


def _containment_failure_reason(reason: object) -> str:
    return (
        reason
        if type(reason) is str and reason in CONTAINMENT_FAILURE_REASONS
        else "probe-session-failed"
    )


def _closed_containment_result(
    context_digest: str,
    *,
    reason: str,
    identity: Mapping[str, JsonValue] | None = None,
) -> dict[str, JsonValue]:
    return {
        "schema_version": "containment-probe-result-v1",
        "disposition": "verification-failed",
        "reason": _containment_failure_reason(reason),
        "context_digest": context_digest,
        "identity": dict(identity) if identity is not None else None,
        "firewall": {
            "program_digest": None,
            "drop_before": None,
            "drop_after": None,
            "cleanup_verified": False,
        },
        "probes": [],
    }


def _terminate_process_group(
    process: subprocess.Popen[bytes], *, wait_timeout: float = 2
) -> bool:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        if process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
    if wait_timeout <= 0:
        return process.poll() is not None
    try:
        process.wait(timeout=wait_timeout)
    except subprocess.TimeoutExpired:
        return False
    return process.poll() is not None


def _run_bounded_process(
    argv: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: float,
    text: bool,
    max_output_bytes: int,
    **_ignored: object,
) -> subprocess.CompletedProcess:
    if max_output_bytes <= 0:
        raise BridgeFailure("invalid-command")
    deadline = time.monotonic() + timeout
    process = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        start_new_session=True,
        shell=False,
    )
    assert process.stdout is not None and process.stderr is not None
    stdout_fd = process.stdout.fileno()
    stderr_fd = process.stderr.fileno()
    selector = selectors.DefaultSelector()
    streams = {stdout_fd: bytearray(), stderr_fd: bytearray()}
    try:
        for stream in (process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired("<redacted>", timeout)
            events = selector.select(min(remaining, 0.25))
            if not events and process.poll() is not None:
                events = [(key, selectors.EVENT_READ) for key in selector.get_map().values()]
            for key, _mask in events:
                try:
                    chunk = os.read(key.fd, 64 * 1024)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target = streams[key.fd]
                target.extend(chunk)
                if sum(len(value) for value in streams.values()) > max_output_bytes:
                    raise BridgeFailure("command-output-too-large")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired("<redacted>", timeout)
        returncode = process.wait(timeout=remaining)
    finally:
        terminated = _terminate_process_group(
            process, wait_timeout=max(0.0, deadline - time.monotonic())
        )
        selector.close()
        process.stdout.close()
        process.stderr.close()
        if not terminated:
            raise subprocess.TimeoutExpired("<redacted>", timeout)
    stdout_bytes = bytes(streams[stdout_fd])
    stderr_bytes = bytes(streams[stderr_fd])
    if text:
        try:
            stdout: str | bytes = stdout_bytes.decode("utf-8", "strict")
            stderr: str | bytes = stderr_bytes.decode("utf-8", "strict")
        except UnicodeDecodeError as error:
            raise BridgeFailure("command-output-invalid") from error
    else:
        stdout = stdout_bytes
        stderr = stderr_bytes
    return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr=stderr)


@dataclass(frozen=True)
class BridgeConfig:
    """Guest-owned fixed locations; tests may substitute isolated guest-like roots."""

    workspace_root: Path
    export_root: Path
    instance_record: Path
    policy_path: Path
    mountinfo_path: Path
    lsm_path: Path = Path("/sys/kernel/security/lsm")
    import_root: Path = Path("/srv/aifactory/imports")
    state_root: Path = Path("/var/lib/aifactory/execution-state")
    leash_policy_path: Path = Path("/etc/aifactory/leash.cedar")
    seal_record: Path = Path("/var/lib/aifactory/sealed")
    cell_state_record: Path = Path("/var/lib/aifactory/cell-state.json")
    image_observer: Callable[[str], bool] | None = None
    authority_observer: Callable[[], Mapping[str, str]] | None = None
    root_uid: int = 0
    verifier_prefix: tuple[str, ...] = _VERIFIER_PREFIX
    verifier_launcher_path: Path = _VERIFIER_LAUNCHER


@dataclass(frozen=True)
class ExecutionScope:
    """Exact authority for one agent turn in one request-owned repository."""

    context_digest: str
    turn_kind: Literal["contract-author", "design-author", "reviewer", "implementation"]
    base_revision: str
    input_revision: str
    writable_paths: tuple[str, ...]
    timeout_seconds: int
    network_profile: str
    input_fingerprint: str = ""

    @classmethod
    def from_document(cls, document: object) -> ExecutionScope:
        if not isinstance(document, Mapping) or set(document) != {
            "context_digest",
            "turn_kind",
            "base_revision",
            "input_revision",
            "writable_paths",
            "timeout_seconds",
            "network_profile",
            "input_fingerprint",
        }:
            raise BridgeFailure("invalid-scope")
        context_digest = _digest(document["context_digest"])
        turn_kind = document["turn_kind"]
        base_revision = _revision(document["base_revision"])
        input_revision = _revision(document["input_revision"])
        input_fingerprint = _digest(document["input_fingerprint"])
        raw_paths = document["writable_paths"]
        if type(raw_paths) is not list:
            raise BridgeFailure("invalid-scope")
        paths = tuple(_relative_path(value, allow_subtree_glob=True) for value in raw_paths)
        if not paths or len(paths) != len(set(paths)) or _paths_overlap(paths):
            raise BridgeFailure("invalid-scope")
        timeout = document["timeout_seconds"]
        profile = document["network_profile"]
        if (
            turn_kind not in _SAFE_TURN_KINDS
            or type(timeout) is not int
            or not 1 <= timeout <= 600
            or profile not in _SAFE_NETWORK_PROFILES
        ):
            raise BridgeFailure("invalid-scope")
        _validate_lifecycle_paths(turn_kind, paths)
        return cls(
            context_digest,
            turn_kind,
            base_revision,
            input_revision,
            paths,
            timeout,
            profile,
            input_fingerprint,
        )


def default_config() -> BridgeConfig:
    """Return the non-configurable production guest layout."""
    return BridgeConfig(
        workspace_root=Path("/srv/aifactory/workspaces"),
        export_root=Path("/srv/aifactory/exports"),
        import_root=Path("/srv/aifactory/imports"),
        state_root=Path("/var/lib/aifactory/execution-state"),
        instance_record=Path("/etc/aifactory/instance-id"),
        policy_path=Path("/etc/aifactory/leash.cedar"),
        leash_policy_path=Path("/etc/aifactory/leash.cedar"),
        seal_record=Path("/var/lib/aifactory/sealed"),
        cell_state_record=Path("/var/lib/aifactory/cell-state.json"),
        mountinfo_path=Path("/proc/self/mountinfo"),
        lsm_path=Path("/sys/kernel/security/lsm"),
    )


class ExecutionBridge:
    """Dispatch the seven public operations with no ambient controller authority."""

    def __init__(self, config: BridgeConfig | None = None) -> None:
        self.config = config or default_config()
        self._actions: dict[
            str, Callable[[Path, Mapping[str, JsonValue]], dict[str, JsonValue]]
        ] = {
            "file_state": self._workspace_file_state,
            "read_file": self._workspace_read_file,
            "read_file_at": self._workspace_read_file_at,
            "write_file": self._workspace_write_file,
            "remove_file": self._workspace_remove_file,
            "changed_files": self._workspace_changed_files,
            "turn_delta": self._workspace_turn_delta,
            "scan_pushable_blobs": self._workspace_scan_pushable_blobs,
            "attest": self._workspace_attest,
            "checkpoint": self._workspace_checkpoint,
            "commit": self._workspace_commit,
            "reset": self._workspace_reset,
            "reset_to": self._workspace_reset_to,
            "head_revision": self._workspace_head_revision,
            "revision_is_ancestor": self._workspace_ancestor,
            "contract_precedes_implementation": self._workspace_contract_order,
            "review_fingerprint": self._workspace_review_fingerprint,
            "publication_fingerprint": self._workspace_publication_fingerprint,
            "run_tests": self._workspace_run_tests,
            "harness": self._workspace_harness,
            "preserve": self._workspace_preserve,
            "cleanup": self._workspace_cleanup,
        }

    def handle(self, request: BridgeRequest) -> BridgeResponse:
        """Return a bounded response; no exception text or subprocess output crosses out."""
        try:
            if request.operation == "observe":
                result = self._observe()
                return self._response(request, "ok", result)
            if request.operation == "prepare":
                return self._response(request, "ok", self._prepare(request))
            if request.operation == "workspace":
                self._sealed_runtime()
                return self._response(request, "ok", self._workspace(request))
            if request.operation == "run-agent":
                self._sealed_runtime()
                status, result = self._run_agent(request)
                return self._response(request, status, result)
            if request.operation == "run-command":
                self._sealed_runtime()
                return self._response(request, "ok", self._run_command(request))
            if request.operation == "export":
                self._sealed_runtime()
                return self._response(request, "ok", self._export(request))
            if request.operation == "containment-probe":
                if not isinstance(request.payload, Mapping) or request.payload:
                    raise BridgeFailure("invalid-payload")
                status, result = self._containment_probe(request)
                return self._response(request, status, result)
            raise BridgeFailure("unknown-operation")
        except subprocess.TimeoutExpired:
            return self._response(
                request,
                "failed",
                {"reason": "probe-timeout" if request.operation == "containment-probe" else "timeout"},
            )
        except BridgeFailure as error:
            return self._response(request, "failed", {"reason": error.reason})
        except (OSError, ValueError, UnicodeError, json.JSONDecodeError):
            return self._response(request, "failed", {"reason": "guest-operation-failed"})
        except Exception as error:
            _emit_internal_diagnostic(error)
            return self._response(request, "failed", {"reason": "guest-operation-failed"})

    def _response(
        self,
        request: BridgeRequest,
        status: Literal["ok", "denied", "failed"],
        result: dict[str, JsonValue],
    ) -> BridgeResponse:
        return BridgeResponse(SCHEMA_VERSION, request.request_id, status, result, ())

    def _sealed_runtime(self) -> dict[str, Any]:
        _require_bpf_lsm(self.config)
        try:
            raw = _root_owned_regular_bytes(self.config.seal_record, self.config.root_uid)
            document = _canonical_document(raw[:-1] if raw.endswith(b"\n") else raw)
        except (BridgeFailure, OSError, ValueError, json.JSONDecodeError):
            raise BridgeFailure("cell-not-sealed") from None
        leash_authority_fields = _leash_authority_fields(document)
        expected = {
            "image_digest",
            "image_reference",
            "bridge_interpreter_digest",
            "bridge_module_digest",
            "console_shim_digest",
            "leash_image_digest",
            "leash_image_reference",
            "leash_git_hash",
            "instance_id",
            "manifest_digest",
            "real_bridge_digest",
            "schema_version",
            "seal_digest",
            "wrapper_digest",
        } | LEASH_IDENTITY_FIELDS | set(_PNPM_IDENTITY_FIELDS) | set(
            leash_authority_fields
        )
        image = document.get("image_reference")
        if (
            set(document) != expected
            or document.get("schema_version") != "validation-cell-seal-v1"
            or not isinstance(image, str)
            or image
            != "public.ecr.aws/s5i7k8t3/strongdm/coder@sha256:" + str(document.get("image_digest"))
            or not _valid_leash_reference(document)
            or any(
                type(document.get(field)) is not str
                or re.fullmatch(r"[0-9a-f]{64}", document[field]) is None
                for field in (
                    "image_digest",
                    "leash_image_digest",
                    "manifest_digest",
                    "real_bridge_digest",
                    "seal_digest",
                    "wrapper_digest",
                    "bridge_interpreter_digest",
                    "bridge_module_digest",
                    "console_shim_digest",
                    *tuple(LEASH_IDENTITY_FIELDS - {"leash_entry_target"}),
                )
            )
            or document.get("leash_entry_target") != LEASH_ENTRY_TARGET
            or document.get("leash_binary_digest") != document.get("leash_native_digest")
            or document.get("real_bridge_digest") != document.get("console_shim_digest")
            or any(
                document.get(field) != expected
                for field, expected in _fixed_pnpm_identity().items()
            )
            or document.get("instance_id")
            != _root_owned_regular_text(self.config.instance_record, self.config.root_uid)
        ):
            raise BridgeFailure("cell-not-sealed")
        try:
            state_bytes = _root_owned_regular_bytes(
                self.config.cell_state_record, self.config.root_uid
            )
            state = _canonical_document(
                state_bytes[:-1] if state_bytes.endswith(b"\n") else state_bytes
            )
        except (BridgeFailure, OSError, ValueError, json.JSONDecodeError):
            raise BridgeFailure("cell-not-sealed") from None
        record = state.get("record")
        request = state.get("request")
        state_bindings = {
            "image_digest": "coder_image_digest",
            "image_reference": "coder_image_reference",
            "bridge_interpreter_digest": "bridge_interpreter_digest",
            "bridge_module_digest": "bridge_module_digest",
            "console_shim_digest": "console_shim_digest",
            "leash_image_digest": "leash_image_digest",
            "leash_image_reference": "leash_image_reference",
            "leash_git_hash": "leash_git_hash",
            "instance_id": "instance_id",
            "real_bridge_digest": "real_bridge_digest",
            "wrapper_digest": "wrapper_digest",
            **{field: field for field in LEASH_IDENTITY_FIELDS},
            **{field: field for field in _PNPM_IDENTITY_FIELDS},
            **{field: field for field in leash_authority_fields},
        }
        if (
            state.get("schema_version") != "validation-cell-state-v2"
            or state.get("sealed") is not True
            or state.get("seal_digest") != document["seal_digest"]
            or not isinstance(record, Mapping)
            or not isinstance(request, Mapping)
            or document.get("manifest_digest") != request.get("manifest_digest")
            or any(
                document.get(marker_field) != record.get(record_field)
                for marker_field, record_field in state_bindings.items()
            )
        ):
            raise BridgeFailure("cell-not-sealed")
        for reference in (document["leash_image_reference"], document["image_reference"]):
            failure_reason = _image_runtime_failure_reason(reference, document)
            try:
                matched = (
                    self.config.image_observer(reference)
                    if self.config.image_observer is not None
                    else self._observe_image(reference, document)
                )
            except (BridgeFailure, OSError, ValueError, json.JSONDecodeError):
                raise BridgeFailure(failure_reason) from None
            if matched is not True:
                raise BridgeFailure(failure_reason)
        try:
            installed = (
                dict(self.config.authority_observer())
                if self.config.authority_observer is not None
                else self._installed_authority()
            )
        except (BridgeFailure, OSError, ValueError, UnicodeError):
            raise BridgeFailure("installed-authority-mismatch") from None
        fields = {
            "bridge_interpreter_digest",
            "bridge_module_digest",
            "console_shim_digest",
            "leash_git_hash",
            "wrapper_digest",
        } | LEASH_IDENTITY_FIELDS | set(_PNPM_IDENTITY_FIELDS)
        if set(installed) != fields or any(installed[key] != document[key] for key in fields):
            raise BridgeFailure("installed-authority-mismatch")
        return document

    def _installed_authority(self) -> dict[str, str]:
        console = Path("/usr/local/libexec/aifactory-execution-bridge-real")
        wrapper = Path("/usr/local/bin/aifactory-execution-bridge")
        try:
            first_line = _regular_bytes(console).splitlines()[0].decode("utf-8")
        except (IndexError, UnicodeError) as error:
            raise BridgeFailure("installed-authority-mismatch") from error
        if not first_line.startswith("#!") or " " in first_line or "\t" in first_line:
            raise BridgeFailure("installed-authority-mismatch")
        interpreter = Path(first_line[2:])
        if not interpreter.is_absolute():
            raise BridgeFailure("installed-authority-mismatch")
        try:
            declared_before = interpreter.lstat()
            resolved_interpreter = interpreter.resolve(strict=True)
            interpreter_digest = _sha256_file(resolved_interpreter)
            declared_after = interpreter.lstat()
            if (
                (
                    declared_before.st_dev,
                    declared_before.st_ino,
                    declared_before.st_mode,
                    declared_before.st_size,
                    declared_before.st_mtime_ns,
                )
                != (
                    declared_after.st_dev,
                    declared_after.st_ino,
                    declared_after.st_mode,
                    declared_after.st_size,
                    declared_after.st_mtime_ns,
                )
                or interpreter.resolve(strict=True) != resolved_interpreter
            ):
                raise BridgeFailure("installed-authority-mismatch")
        except (OSError, BridgeFailure):
            raise BridgeFailure("installed-authority-mismatch") from None
        _version, git_hash = self._leash_release()
        try:
            leash_identity = measure_leash_installation(
                entry=_LEASH_ENTRY,
                package_root=_LEASH_PACKAGE_ROOT,
                env_path=_LEASH_ENV,
                node_path=_LEASH_NODE,
                platform_name=platform.system().lower(),
                machine=platform.machine().lower(),
                expected_uid=self.config.root_uid,
            )
            pnpm_identity = measure_pnpm_toolchain(PNPM_DESTINATION)
        except Exception:
            raise BridgeFailure("installed-authority-mismatch") from None
        if (
            type(pnpm_identity) is not dict
            or set(pnpm_identity) != set(_PNPM_IDENTITY_FIELDS)
            or pnpm_identity != _fixed_pnpm_identity()
        ):
            raise BridgeFailure("installed-authority-mismatch")
        return {
            "bridge_interpreter_digest": interpreter_digest,
            "bridge_module_digest": _sha256_file(Path(__file__)),
            "console_shim_digest": _sha256_file(console),
            **leash_identity,
            "leash_git_hash": git_hash,
            **pnpm_identity,
            "wrapper_digest": _sha256_file(wrapper),
        }

    def _observe_repo_digest(self, reference: str) -> bool:
        completed = self._command(
            ["docker", "image", "inspect", "--format={{json .RepoDigests}}", reference],
            timeout=30,
        )
        values = json.loads(completed.stdout)
        repository = reference.split("@sha256:", 1)[0]
        matches = {
            value
            for value in values
            if type(value) is str and value.startswith(repository + "@sha256:")
        } if type(values) is list else set()
        return matches == {reference}

    def _observe_image(self, reference: str, authority: Mapping[str, Any]) -> bool:
        if reference.startswith("sha256:"):
            if not _valid_leash_reference(authority) or reference != authority.get(
                "leash_image_reference"
            ):
                return False
            completed = self._command(
                ["docker", "image", "inspect", reference],
                timeout=30,
            )
            inspected = json.loads(completed.stdout)
            if type(inspected) is not list or len(inspected) != 1:
                return False
            image = inspected[0]
            if type(image) is not dict:
                return False
            config = image.get("Config")
            labels = config.get("Labels") if type(config) is dict else None
            return bool(
                image.get("Id") == reference
                and image.get("Os") == "linux"
                and image.get("Architecture") == "arm64"
                and image.get("RepoTags") in (None, [])
                and type(labels) is dict
                and labels.get("org.opencontainers.image.revision")
                == authority.get("leash_source_revision")
                and labels.get("org.opencontainers.image.version")
                == f"v{LEASH_HARDENED_VERSION}"
                and labels.get("io.aifactory.leash.base-revision")
                == authority.get("leash_base_revision")
                and labels.get("io.aifactory.leash.bpf-open-sha256")
                == authority.get("leash_bpf_open_object_digest")
            )
        return self._observe_repo_digest(reference)

    def _nft_runtime_identity(self) -> dict[str, str]:
        try:
            info = _NFT_PATH.lstat()
        except OSError as error:
            raise BridgeFailure("runtime-version-invalid") from error
        if (
            not stat.S_ISREG(info.st_mode)
            or _NFT_PATH.is_symlink()
            or info.st_uid != self.config.root_uid
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o755
        ):
            raise BridgeFailure("runtime-version-invalid")
        completed = self._command([str(_NFT_PATH), "--version"], timeout=10)
        version = completed.stdout.strip()
        if re.fullmatch(r"nftables v\d+\.\d+\.\d+(?: \([ -~]{1,80}\))?", version) is None:
            raise BridgeFailure("runtime-version-invalid")
        return {"nft_path": str(_NFT_PATH), "nft_version": version}

    def _observe(self) -> dict[str, JsonValue]:
        instance_id = _root_owned_regular_text(self.config.instance_record, self.config.root_uid)
        if not instance_id.startswith("sha256:") or not _is_digest(
            instance_id.removeprefix("sha256:")
        ):
            raise BridgeFailure("instance-record-invalid")
        if platform.system() != "Linux":
            raise BridgeFailure("kernel-invalid")
        _require_bpf_lsm(self.config)
        if self.config.mountinfo_path == _PROC_MOUNTINFO:
            mountinfo = _read_dynamic_regular_path(
                self.config.mountinfo_path,
                max_bytes=16 * 1024 * 1024,
            ).decode("utf-8")
        else:
            mountinfo = _root_owned_regular_text(
                self.config.mountinfo_path,
                self.config.root_uid,
                root_owned=False,
                strip=False,
            )
        if _has_host_mount(mountinfo):
            raise BridgeFailure("host-mount-present")
        policy = _root_owned_regular_bytes(self.config.policy_path, self.config.root_uid)
        leash_version, leash_git_hash = self._leash_release()
        installed = (
            dict(self.config.authority_observer())
            if self.config.authority_observer is not None
            else self._installed_authority()
        )
        nft_identity = self._nft_runtime_identity()
        if (
            set(installed)
            != {
                "bridge_interpreter_digest",
                "bridge_module_digest",
                "console_shim_digest",
                "leash_git_hash",
                "wrapper_digest",
            }
            | LEASH_IDENTITY_FIELDS
            | set(_PNPM_IDENTITY_FIELDS)
            or installed.get("leash_git_hash") != leash_git_hash
            or any(
                installed.get(field) != expected
                for field, expected in _fixed_pnpm_identity().items()
            )
        ):
            raise BridgeFailure("installed-authority-mismatch")
        try:
            state_bytes = _root_owned_regular_bytes(
                self.config.cell_state_record, self.config.root_uid
            )
            state = _canonical_document(
                state_bytes[:-1] if state_bytes.endswith(b"\n") else state_bytes
            )
        except (BridgeFailure, OSError, ValueError, json.JSONDecodeError):
            raise BridgeFailure("installed-authority-mismatch") from None
        if state.get("sealed") is True:
            self._sealed_runtime()
        record = state.get("record")
        image_digest = record.get("coder_image_digest") if isinstance(record, Mapping) else None
        leash_image_digest = (
            record.get("leash_image_digest") if isinstance(record, Mapping) else None
        )
        image_reference = (
            record.get("coder_image_reference") if isinstance(record, Mapping) else None
        )
        leash_image_reference = (
            record.get("leash_image_reference") if isinstance(record, Mapping) else None
        )
        measured_fields = {
            "bridge_interpreter_digest",
            "bridge_module_digest",
            "console_shim_digest",
            "leash_git_hash",
            "wrapper_digest",
        } | LEASH_IDENTITY_FIELDS | set(_PNPM_IDENTITY_FIELDS)
        leash_authority_fields = (
            _leash_authority_fields(record) if isinstance(record, Mapping) else frozenset()
        )
        if (
            state.get("schema_version") != "validation-cell-state-v2"
            or not isinstance(record, Mapping)
            or record.get("instance_id") != instance_id
            or not _is_digest(image_digest)
            or not _is_digest(leash_image_digest)
            or image_reference
            != "public.ecr.aws/s5i7k8t3/strongdm/coder@sha256:" + str(image_digest)
            or not _valid_leash_reference(record)
            or any(record.get(field) != installed[field] for field in measured_fields)
            or any(record.get(field) != value for field, value in nft_identity.items())
        ):
            raise BridgeFailure("installed-authority-mismatch")
        for reference in (leash_image_reference, image_reference):
            failure_reason = _image_runtime_failure_reason(reference, record)
            try:
                matched = (
                    self.config.image_observer(reference)
                    if self.config.image_observer is not None
                    else self._observe_image(reference, record)
                )
            except (BridgeFailure, OSError, ValueError, json.JSONDecodeError):
                raise BridgeFailure(failure_reason) from None
            if matched is not True:
                raise BridgeFailure(failure_reason)
        self._version(["docker", "--version"], "Docker")
        return {
            "bridge_version": SCHEMA_VERSION,
            "kernel": "linux",
            "instance_id": instance_id,
            "workspace_root": str(self.config.workspace_root),
            "policy_digest": hashlib.sha256(policy).hexdigest(),
            "image_digest": image_digest,
            "leash_image_digest": leash_image_digest,
            **(
                {"leash_image_reference": leash_image_reference}
                if leash_authority_fields
                else {}
            ),
            **{field: record[field] for field in leash_authority_fields},
            "bridge_interpreter_digest": installed["bridge_interpreter_digest"],
            "bridge_module_digest": installed["bridge_module_digest"],
            "console_shim_digest": installed["console_shim_digest"],
            "leash_version": leash_version,
            "leash_git_hash": leash_git_hash,
            **nft_identity,
            **{field: installed[field] for field in LEASH_IDENTITY_FIELDS},
            **{field: installed[field] for field in _PNPM_IDENTITY_FIELDS},
            "wrapper_digest": installed["wrapper_digest"],
            "container_runtime": "docker",
            "host_mounts": [],
            "network_profile": "model-only-v1",
        }

    def _prepare(self, request: BridgeRequest) -> dict[str, JsonValue]:
        payload = _exact_payload(
            request.payload, {"bundle_digest", "manifest_digest", "base_revision"}
        )
        bundle_digest = _digest(payload["bundle_digest"])
        manifest_digest = _digest(payload["manifest_digest"])
        base_revision = _revision(payload["base_revision"])
        context = _digest(request.context_digest)
        imports = _child_directory(self.config.import_root, context, create=False)
        bundle = _regular_child(imports, "repository.bundle")
        manifest = _regular_child(imports, "manifest.json")
        if _sha256_file(bundle) != bundle_digest or _sha256_file(manifest) != manifest_digest:
            raise BridgeFailure("import-digest-mismatch")
        manifest_document = _canonical_document(_regular_bytes(manifest))
        if set(manifest_document) != {
            "schema_version",
            "repository",
            "issue",
            "base_revision",
            "bundle_digest",
            "execution_policy",
            "phase_artifacts",
            "phase_writable_paths",
        }:
            raise BridgeFailure("manifest-invalid")
        try:
            state_bytes = _root_owned_regular_bytes(
                self.config.cell_state_record, self.config.root_uid
            )
            guest_state = _canonical_document(
                state_bytes[:-1] if state_bytes.endswith(b"\n") else state_bytes
            )
        except (BridgeFailure, OSError, ValueError, json.JSONDecodeError):
            raise BridgeFailure("import-authority-mismatch") from None
        guest_request = guest_state.get("request")
        if (
            guest_state.get("schema_version") != "validation-cell-state-v2"
            or not isinstance(guest_request, Mapping)
            or set(guest_request)
            != {
                "base_revision",
                "bundle_digest",
                "context_digest",
                "dependencies",
                "issue",
                "manifest_digest",
                "prepared",
                "repository",
            }
            or type(guest_request.get("prepared")) is not bool
            or guest_request.get("repository") != manifest_document["repository"]
            or guest_request.get("issue") != manifest_document["issue"]
            or guest_request.get("base_revision") != base_revision
            or guest_request.get("bundle_digest") != bundle_digest
            or guest_request.get("manifest_digest") != manifest_digest
            or guest_request.get("context_digest") != context
        ):
            raise BridgeFailure("import-authority-mismatch")
        expected_context = workspace_context_sha256(
            repository=manifest_document["repository"],
            issue=manifest_document["issue"],
            base_revision=base_revision,
            bundle_digest=bundle_digest,
            manifest_digest=manifest_digest,
        )
        if (
            manifest_document["schema_version"] != "bridge-authority-manifest-v1"
            or expected_context != context
            or manifest_document["bundle_digest"] != bundle_digest
            or manifest_document["base_revision"] != base_revision
        ):
            raise BridgeFailure("manifest-identity-mismatch")
        policy = _execution_policy(manifest_document["execution_policy"])
        phase_artifacts = _phase_artifacts(manifest_document["phase_artifacts"])
        phase_paths = _phase_writable_paths(
            manifest_document["phase_writable_paths"],
            policy=policy,
            artifacts=phase_artifacts,
        )
        root = _safe_root(self.config.workspace_root, create=True)
        workspace = root / context
        prepared_inputs = {
            "context_digest": context,
            "base_revision": base_revision,
            "bundle_digest": bundle_digest,
            "manifest_digest": manifest_digest,
            "execution_policy": policy,
            "phase_artifacts": phase_artifacts,
            "phase_writable_paths": phase_paths,
        }
        if workspace.exists() or workspace.is_symlink():
            existing = self._workspace(request.context_digest)
            authority = _read_authority(self.config.state_root, context, self.config.root_uid)
            if any(
                authority.get(key) != value for key, value in prepared_inputs.items()
            ) or not _prepared_workspace_matches(existing, authority):
                raise BridgeFailure("prepare-identity-mismatch")
            return {"base_revision": base_revision, "workspace": str(existing)}
        if guest_request["prepared"] is True:
            raise BridgeFailure("prepare-identity-mismatch")
        try:
            self._command(
                ["git", "clone", "--no-checkout", str(bundle), str(workspace)],
                timeout=60,
                env=_sanitized_bridge_git_environment(),
            )
            self._git(workspace, ["checkout", "--detach", base_revision])
            if self._git_stdout(workspace, ["rev-parse", "HEAD"]) != base_revision:
                raise BridgeFailure("base-revision-mismatch")
            identity = {
                **prepared_inputs,
                **_prepared_workspace_identity(self, workspace),
            }
            _write_authority(self.config.state_root, context, identity, self.config.root_uid)
        except BaseException:
            if workspace.exists() and workspace.is_dir() and not workspace.is_symlink():
                try:
                    _remove_owned_tree(root, context)
                except BridgeFailure:
                    pass
            raise
        return {"base_revision": base_revision, "workspace": str(workspace)}

    def _workspace(self, request: BridgeRequest | str) -> Path | dict[str, JsonValue]:
        if isinstance(request, str):
            workspace, _authority = self._authorized_workspace(request)
            return workspace
        payload = request.payload
        if not isinstance(payload, Mapping) or set(payload) != {"action", "arguments"}:
            raise BridgeFailure("invalid-payload")
        action = payload["action"]
        arguments = payload["arguments"]
        if (
            type(action) is not str
            or not isinstance(arguments, Mapping)
            or action not in self._actions
        ):
            raise BridgeFailure("invalid-payload")
        workspace, _authority = self._authorized_workspace(request.context_digest)
        return self._actions[action](workspace, arguments)

    def _authorized_workspace(
        self, context: str, *, deadline: float | None = None
    ) -> tuple[Path, dict[str, Any]]:
        if deadline is not None:
            _require_probe_deadline(deadline)
        workspace = _owned_workspace(self.config.workspace_root, context)
        authority = _read_authority(self.config.state_root, context, self.config.root_uid)
        if authority.get("manifest_digest") != self._sealed_runtime().get("manifest_digest"):
            raise BridgeFailure("seal-authority-mismatch")
        if authority.get("git_policy_fingerprint") != _git_policy_fingerprint(
            self, workspace, deadline=deadline
        ):
            raise BridgeFailure("workspace-git-policy-mismatch")
        if deadline is not None:
            _require_probe_deadline(deadline)
        return workspace, authority

    def _containment_probe(
        self, request: BridgeRequest
    ) -> tuple[Literal["ok", "failed"], dict[str, JsonValue]]:
        """Run the sealed, fixed matrix behind a request-scoped outer firewall."""
        operation_started = time.monotonic()
        operation_deadline = operation_started + _PROBE_OPERATION_WORST_CASE_SECONDS
        active_deadline = operation_deadline - _PROBE_CLEANUP_RESERVE_SECONDS
        context = _digest(request.context_digest)
        result = _closed_containment_result(context, reason="probe-session-failed")
        try:
            sealed = self._sealed_runtime()
            identity = {
                "bridge_module_digest": sealed["bridge_module_digest"],
                "image_digest": sealed["image_digest"],
                "leash_image_digest": sealed["leash_image_digest"],
                "manifest_digest": sealed["manifest_digest"],
                "policy_digest": hashlib.sha256(
                    _root_owned_regular_bytes(self.config.policy_path, self.config.root_uid)
                ).hexdigest(),
                "seal_digest": sealed["seal_digest"],
            }
            result["identity"] = identity
        except subprocess.TimeoutExpired:
            result["reason"] = "probe-timeout"
            return "failed", result
        except (BridgeFailure, OSError, ValueError, json.JSONDecodeError) as error:
            result["reason"] = _containment_failure_reason(
                error.reason if isinstance(error, BridgeFailure) else None
            )
            return "failed", result
        workspace: Path | None = None
        before: dict[str, Any] | None = None
        try:
            with _docker_mutation_lock(self.config, deadline=operation_deadline):
                try:
                    workspace, authority = self._authorized_workspace(
                        context, deadline=active_deadline
                    )
                    before = _prepared_workspace_identity(
                        self, workspace, deadline=active_deadline
                    )
                    if any(authority.get(key) != value for key, value in before.items()):
                        raise BridgeFailure("workspace-authority-mismatch")
                    session = self._run_containment_probe_session(
                        request=request,
                        workspace=workspace,
                        authority=authority,
                        active_deadline=active_deadline,
                        operation_deadline=operation_deadline,
                    )
                    result.update(session)
                except subprocess.TimeoutExpired:
                    result["reason"] = "probe-timeout"
                except (BridgeFailure, OSError, ValueError, json.JSONDecodeError) as error:
                    result["reason"] = _containment_failure_reason(
                        error.reason if isinstance(error, BridgeFailure) else None
                    )
                if workspace is not None and before is not None:
                    try:
                        after = _prepared_workspace_identity(
                            self, workspace, deadline=operation_deadline
                        )
                    except subprocess.TimeoutExpired:
                        result["reason"] = "probe-timeout"
                    except (BridgeFailure, OSError, ValueError):
                        result["reason"] = "probe-workspace-drift"
                    else:
                        if after != before:
                            result["reason"] = "probe-workspace-drift"
                        elif result.get("disposition") == "passed":
                            return "ok", result
        except subprocess.TimeoutExpired:
            result["reason"] = "probe-timeout"
        except (BridgeFailure, OSError, ValueError, json.JSONDecodeError) as error:
            result["reason"] = _containment_failure_reason(
                error.reason if isinstance(error, BridgeFailure) else None
            )
        result["disposition"] = "verification-failed"
        return "failed", result

    def _run_containment_probe_session(
        self,
        *,
        request: BridgeRequest,
        workspace: Path,
        authority: Mapping[str, Any],
        active_deadline: float,
        operation_deadline: float,
    ) -> dict[str, JsonValue]:
        del authority  # already authenticated by _authorized_workspace and bound by the result
        names = _probe_runtime_names(request.request_id)
        context_root = self.config.state_root / request.context_digest
        control = workspace / (".aifactory-probe-" + names["token"])
        work_dir = context_root / ("probe-" + names["token"])
        neighbor = workspace.parent / (("f" * 64) if workspace.name != "f" * 64 else ("e" * 64))
        bridge_network: dict[str, Any] | None = None
        process: subprocess.Popen[bytes] | None = None
        log_baseline: _ProbeLogBaseline | None = None
        resolver_owned = False
        target_owned = False
        manager_owned = False
        table_owned = False
        resolver_may_exist = False
        target_may_exist = False
        manager_may_exist = False
        table_may_exist = False
        control_owned = False
        work_owned = False
        neighbor_owned = False
        cleanup_ok = True
        cleanup_timed_out = False
        firewall_digest: str | None = None
        drop_before: int | None = None
        drop_after: int | None = None
        normalized: tuple[dict[str, str], ...] = ()
        failure: BridgeFailure | None = None
        _require_probe_deadline(active_deadline)
        if operation_deadline - active_deadline < _PROBE_CLEANUP_RESERVE_SECONDS:
            raise BridgeFailure("probe-timeout")
        session_deadline = operation_deadline
        try:
            for container in (names["resolver"], names["target"], names["manager"]):
                collision = self._command_bytes(
                    ["docker", "inspect", "--format={{json .}}", container],
                    timeout=_probe_timeout(active_deadline, 20),
                    allowed_returncodes=frozenset({0, 1}),
                    max_output_bytes=256 * 1024,
                )
                if collision.returncode == 0:
                    raise BridgeFailure("probe-container-collision")
            tables = self._command_bytes(
                [str(_NFT_PATH), "--json", "list", "tables"],
                timeout=_probe_timeout(active_deadline, 20), max_output_bytes=256 * 1024
            )
            if ("inet", names["table"]) in _nft_table_names(tables.stdout):
                raise BridgeFailure("probe-firewall-collision")
            if (
                control.exists() or control.is_symlink() or work_dir.exists() or work_dir.is_symlink()
                or neighbor.exists() or neighbor.is_symlink()
            ):
                raise BridgeFailure("probe-state-collision")
            control.mkdir(mode=0o700)
            control_owned = True
            work_dir.mkdir(mode=0o700)
            work_owned = True
            neighbor.mkdir(mode=0o700)
            neighbor_owned = True
            _write_probe_file(neighbor / "marker", b"aifactory-neighbor-inert-v1\n")
            _write_probe_file(control / "marker", b"aifactory-containment-control-v1\n")
            self._command(
                ["git", "init", "--bare", str(control / "inert.git")],
                timeout=_probe_timeout(active_deadline, 20),
                env=_sanitized_bridge_git_environment(),
                max_output_bytes=64 * 1024,
            )
            policy_bytes = _compile_probe_policy(self.config, workspace=workspace, control=control)
            policy = work_dir / "probe.cedar"
            _write_probe_file(policy, policy_bytes)
            network_raw = self._command_bytes(
                ["docker", "network", "inspect", "--format={{json .}}", "bridge"],
                timeout=_probe_timeout(active_deadline, 10),
                max_output_bytes=256 * 1024,
            ).stdout
            bridge_network = _bridge_network_shape(network_raw)
            bridge_interface = _authenticate_builtin_bridge(bridge_network)
            linux_bridge = _authenticate_linux_bridge(
                self._command_bytes(
                    ["ip", "-json", "link", "show", "dev", bridge_interface],
                    timeout=_probe_timeout(active_deadline, 10),
                    max_output_bytes=64 * 1024,
                ).stdout,
                expected_interface=bridge_interface,
            )
            bootstrap = _compile_probe_bootstrap_firewall(
                table=names["table"], bridge_interface=bridge_interface
            )
            bootstrap_path = work_dir / "bootstrap.nft"
            _write_probe_file(bootstrap_path, bootstrap)
            pre_bootstrap_network = _bridge_network_shape(
                self._command_bytes(
                    ["docker", "network", "inspect", "--format={{json .}}", "bridge"],
                    timeout=_probe_timeout(active_deadline, 10),
                    max_output_bytes=256 * 1024,
                ).stdout
            )
            _authenticate_builtin_bridge(pre_bootstrap_network)
            if pre_bootstrap_network != bridge_network:
                raise BridgeFailure("probe-network-shape-invalid")
            table_may_exist = True
            self._command_bytes(
                [str(_NFT_PATH), "-f", str(bootstrap_path)],
                timeout=_probe_timeout(active_deadline, 20),
            )
            table_owned = True
            post_bootstrap_network = _bridge_network_shape(
                self._command_bytes(
                    ["docker", "network", "inspect", "--format={{json .}}", "bridge"],
                    timeout=_probe_timeout(active_deadline, 10),
                    max_output_bytes=256 * 1024,
                ).stdout
            )
            _authenticate_builtin_bridge(post_bootstrap_network)
            if post_bootstrap_network != bridge_network:
                raise BridgeFailure("probe-network-shape-invalid")
            bootstrap_raw = self._command_bytes(
                [str(_NFT_PATH), "--json", "list", "table", "inet", names["table"]],
                timeout=_probe_timeout(active_deadline, 20),
                max_output_bytes=256 * 1024,
            ).stdout
            _authenticate_probe_bootstrap_firewall(
                bootstrap_raw,
                table=names["table"],
                bridge_interface=bridge_interface,
            )
            resolver_may_exist = True
            resolver_run = self._command_bytes(
                _probe_resolver_argv(self.config, names=names),
                timeout=_probe_timeout(active_deadline, 20),
                max_output_bytes=256,
            )
            resolver_owned = True
            resolver_id = resolver_run.stdout.strip()
            if re.fullmatch(rb"[0-9a-f]{64}", resolver_id) is None:
                raise BridgeFailure("probe-resolver-container-invalid")
            resolver_wait = self._command_bytes(
                ["docker", "wait", names["resolver"]],
                timeout=_probe_timeout(active_deadline, 20),
                max_output_bytes=64,
            )
            if resolver_wait.stdout != b"0\n":
                raise BridgeFailure("probe-resolver-container-invalid")
            resolver_raw = self._command_bytes(
                ["docker", "inspect", "--format={{json .}}", names["resolver"]],
                timeout=_probe_timeout(active_deadline, 10),
                max_output_bytes=256 * 1024,
            ).stdout
            resolver_shape = _container_shape(resolver_raw)
            _authenticate_probe_resolver_container(
                resolver_shape,
                config=self.config,
                names=names,
                expected_container_id=resolver_id.decode("ascii"),
                expected_network_id=bridge_network["id"],
            )
            dns_ipv4 = _parse_probe_resolvers(
                self._command_bytes(
                    ["docker", "logs", names["resolver"]],
                    timeout=_probe_timeout(active_deadline, 10),
                    max_output_bytes=16 * 1024,
                ).stdout
            )
            self._command_bytes(
                ["docker", "rm", "-f", names["resolver"]],
                timeout=_probe_timeout(active_deadline, 20),
                max_output_bytes=64 * 1024,
            )
            resolver_absent = self._command_bytes(
                ["docker", "inspect", "--format={{json .}}", names["resolver"]],
                timeout=_probe_timeout(active_deadline, 10),
                allowed_returncodes=frozenset({0, 1}),
                max_output_bytes=64 * 1024,
            )
            if resolver_absent.returncode != 1:
                raise BridgeFailure("probe-resolver-container-invalid")
            resolver_owned = False
            resolver_may_exist = False
            post_resolver_network = _bridge_network_shape(
                self._command_bytes(
                    ["docker", "network", "inspect", "--format={{json .}}", "bridge"],
                    timeout=_probe_timeout(active_deadline, 10),
                    max_output_bytes=256 * 1024,
                ).stdout
            )
            _authenticate_builtin_bridge(post_resolver_network)
            if post_resolver_network != bridge_network:
                raise BridgeFailure("probe-network-shape-invalid")
            dns_bootstrap = _compile_probe_dns_bootstrap_firewall(
                table=names["table"],
                bridge_interface=bridge_interface,
                dns_ipv4=dns_ipv4,
            )
            dns_bootstrap_path = work_dir / "dns-bootstrap.nft"
            _write_probe_file(dns_bootstrap_path, dns_bootstrap)
            self._command_bytes(
                [str(_NFT_PATH), "-f", str(dns_bootstrap_path)],
                timeout=_probe_timeout(active_deadline, 20),
            )
            dns_bootstrap_raw = self._command_bytes(
                [str(_NFT_PATH), "--json", "list", "table", "inet", names["table"]],
                timeout=_probe_timeout(active_deadline, 20),
                max_output_bytes=256 * 1024,
            ).stdout
            _authenticate_probe_dns_bootstrap_firewall(
                dns_bootstrap_raw,
                table=names["table"],
                bridge_interface=bridge_interface,
                dns_ipv4=dns_ipv4,
            )
            endpoint_ipv4 = _resolve_probe_ipv4s(deadline=active_deadline)
            probe_addresses = _probe_expected_addresses(
                endpoint_ipv4, tuple(_NETWORK_PROBE_TARGETS)
            )
            _write_probe_file(
                control / "endpoints.json",
                json.dumps(
                    endpoint_ipv4,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii"),
            )
            model_ipv4 = tuple(
                sorted(
                    {
                        address
                        for endpoint in _MODEL_ENDPOINTS
                        for address in endpoint_ipv4[endpoint]
                    },
                    key=lambda value: int(ipaddress.IPv4Address(value)),
                )
            )
            target_may_exist = True
            manager_may_exist = True
            process = subprocess.Popen(
                _probe_leash_argv(self.config, workspace=workspace, control=control, policy=policy),
                cwd=workspace,
                env=_probe_leash_environment(self.config, work_dir=work_dir, names=names),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=True,
                shell=False,
            )
            launch_deadline = min(active_deadline, time.monotonic() + 30)
            target_raw: bytes | None = None
            manager_raw: bytes | None = None
            while time.monotonic() < launch_deadline:
                target_check = self._command_bytes(
                    ["docker", "inspect", "--format={{json .}}", names["target"]],
                    timeout=_probe_timeout(launch_deadline, 5),
                    allowed_returncodes=frozenset({0, 1}),
                    max_output_bytes=256 * 1024,
                )
                manager_check = self._command_bytes(
                    ["docker", "inspect", "--format={{json .}}", names["manager"]],
                    timeout=_probe_timeout(launch_deadline, 5),
                    allowed_returncodes=frozenset({0, 1}),
                    max_output_bytes=256 * 1024,
                )
                target_owned = target_owned or target_check.returncode == 0
                manager_owned = manager_owned or manager_check.returncode == 0
                if process.poll() is not None:
                    raise BridgeFailure("probe-launch-failed")
                if target_check.returncode == manager_check.returncode == 0:
                    try:
                        target_candidate = _decode_single_json(
                            target_check.stdout, "probe-container-authority-invalid"
                        )
                        manager_candidate = _decode_single_json(
                            manager_check.stdout, "probe-container-authority-invalid"
                        )
                        exec_ids = target_candidate.get("ExecIDs")
                        if (
                            target_candidate.get("State", {}).get("Running") is True
                            and manager_candidate.get("State", {}).get("Running") is True
                            and type(exec_ids) is list
                            and len(exec_ids) == 1
                        ):
                            target_raw, manager_raw = target_check.stdout, manager_check.stdout
                            break
                    except (AttributeError, BridgeFailure):
                        pass
                time.sleep(0.1)
            if target_raw is None or manager_raw is None:
                raise BridgeFailure("probe-launch-timeout")
            runtime_network_raw = self._command_bytes(
                ["docker", "network", "inspect", "--format={{json .}}", "bridge"],
                timeout=_probe_timeout(active_deadline, 10),
                max_output_bytes=256 * 1024,
            ).stdout
            target_shape = _container_shape(target_raw)
            manager_shape = _container_shape(manager_raw)
            shape = _authenticate_probe_network_shape(
                target_shape,
                manager_shape,
                _bridge_network_shape(runtime_network_raw),
                names,
            )
            runtime_bridge_network = _bridge_network_shape(runtime_network_raw)
            if {
                key: value for key, value in runtime_bridge_network.items()
                if key != "containers"
            } != {
                key: value for key, value in bridge_network.items() if key != "containers"
            }:
                raise BridgeFailure("probe-network-shape-invalid")
            runtime_linux_bridge = _authenticate_linux_bridge(
                self._command_bytes(
                    ["ip", "-json", "link", "show", "dev", bridge_interface],
                    timeout=_probe_timeout(active_deadline, 10),
                    max_output_bytes=64 * 1024,
                ).stdout,
                expected_interface=bridge_interface,
            )
            if runtime_linux_bridge != linux_bridge:
                raise BridgeFailure("probe-network-shape-invalid")
            try:
                cgroup_path = manager_shape["args"][4]
                exec_id = target_shape["exec_ids"][0]
            except (IndexError, KeyError, TypeError):
                raise BridgeFailure("probe-container-authority-invalid") from None
            active_process: dict[str, Any] | None = None
            while time.monotonic() < launch_deadline:
                if process.poll() is not None:
                    raise BridgeFailure("probe-launch-failed")
                try:
                    active_process = _probe_active_process_shape(
                        cgroup_path=cgroup_path,
                        exec_id=exec_id,
                        expected_argv=_probe_child_argv(control=control, workspace=workspace),
                    )
                    break
                except BridgeFailure:
                    time.sleep(0.05)
            if active_process is None:
                raise BridgeFailure("probe-launch-timeout")
            process_identity = _authenticate_probe_container_authority(
                target_shape,
                manager_shape,
                active_process,
                config=self.config,
                names=names,
                workspace=workspace,
                control=control,
                work_dir=work_dir,
            )
            expected_boundary_paths = {
                "filesystem-traversal": str(workspace / ".." / neighbor.name / "marker"),
                "filesystem-other-workspace": str(neighbor / "marker"),
                "tamper-controller-evidence": str(
                    self.config.state_root / request.context_digest / "authority.json"
                ),
            }
            log_path = work_dir / "log" / "events.log"
            _wait_for_regular(log_path, timeout=_probe_timeout(active_deadline, 10))
            log_baseline = _open_probe_log_baseline(
                log_path,
                expected_uid=self.config.root_uid,
                deadline=active_deadline,
            )
            firewall = _compile_probe_firewall(
                table=names["table"],
                bridge_interface=shape["bridge_interface"],
                source_ipv4=shape["source_ipv4"],
                source_mac=shape["source_mac"],
                dns_ipv4=dns_ipv4,
                model_ipv4=model_ipv4,
            )
            firewall_digest = hashlib.sha256(firewall).hexdigest()
            firewall_path = work_dir / "firewall.nft"
            _write_probe_file(firewall_path, firewall)
            self._command_bytes(
                [str(_NFT_PATH), "-f", str(firewall_path)],
                timeout=_probe_timeout(active_deadline, 20),
            )
            table_raw = self._command_bytes(
                [str(_NFT_PATH), "--json", "list", "table", "inet", names["table"]],
                timeout=_probe_timeout(active_deadline, 20),
                max_output_bytes=256 * 1024,
            ).stdout
            _authenticate_nft_table(
                table_raw,
                table=names["table"],
                bridge_interface=shape["bridge_interface"],
                source_ipv4=shape["source_ipv4"],
                source_mac=shape["source_mac"],
                dns_ipv4=dns_ipv4,
                model_ipv4=model_ipv4,
            )
            counter_raw = self._command_bytes(
                [
                    str(_NFT_PATH), "--json", "list", "counter", "inet",
                    names["table"], "probe_drop",
                ],
                timeout=_probe_timeout(active_deadline, 20),
                max_output_bytes=64 * 1024,
            ).stdout
            drop_before = _parse_nft_drop_counter(counter_raw, table=names["table"])
            _require_probe_deadline(active_deadline)
            _write_probe_file(control / "start", b"ready\n")
            _wait_for_regular(
                control / "phase1.json", timeout=_probe_timeout(active_deadline, 70)
            )
            phase1 = _read_probe_document(control / "phase1.json", phase="safety-control")
            phase1_boundary = [
                item for item in phase1 if item.get("id") in _PROBE_BOUNDARY_IDS
            ]
            phase1_network_ids = _PROBE_PHASE1_NETWORK_IDS
            phase1_network = [item for item in phase1 if item.get("id") in phase1_network_ids]
            log = _read_probe_log_suffix(log_baseline, log_path)
            network_events, boundary_events = _authenticate_probe_log_suffix(log)
            _authenticate_probe_boundary_items(
                phase1_boundary,
                expected_ids=_PROBE_BOUNDARY_IDS,
                manager_events=boundary_events,
                expected_paths=expected_boundary_paths,
                expected_pid=process_identity["exec_pid"],
                expected_cgroup=process_identity["cgroup_id"],
                expected_exe=process_identity["exec_exe"],
                expected_not_before=log_baseline.wall_not_before,
            )
            counter_raw = self._command_bytes(
                [
                    str(_NFT_PATH), "--json", "list", "counter", "inet",
                    names["table"], "probe_drop",
                ],
                timeout=_probe_timeout(active_deadline, 20),
                max_output_bytes=64 * 1024,
            ).stdout
            drop_after = _parse_nft_drop_counter(counter_raw, table=names["table"])
            _authenticate_network_evidence(
                phase1_network,
                _network_events_for(network_events, phase1_network_ids),
                drop_before=drop_before,
                drop_after=drop_after,
                expected_ids=phase1_network_ids,
                expected_addresses={
                    probe_id: probe_addresses[probe_id]
                    for probe_id in phase1_network_ids
                },
                expected_pid=process_identity["exec_pid"],
                expected_cgroup=process_identity["cgroup_id"],
                expected_exe=process_identity["exec_exe"],
                expected_not_before=log_baseline.wall_not_before,
            )
            _require_probe_deadline(active_deadline)
            _write_probe_file(control / "forbidden", b"ready\n")
            _wait_for_regular(
                control / "final.json", timeout=_probe_timeout(active_deadline, 70)
            )
            final = _read_probe_document(control / "final.json", phase="complete")
            try:
                exit_code = process.wait(timeout=_probe_timeout(active_deadline, 20))
            except subprocess.TimeoutExpired:
                raise BridgeFailure("probe-timeout") from None
            if exit_code != 0:
                raise BridgeFailure("probe-child-failed")
            log = _read_probe_log_suffix(log_baseline, log_path)
            network_events, boundary_events = _authenticate_probe_log_suffix(log)
            all_items = _normalize_probe_items(final, _PROBE_ALL_IDS)
            normalized = all_items
            boundary = [item for item in all_items if item["id"] in _PROBE_BOUNDARY_IDS]
            network = [item for item in all_items if item["id"] in _NETWORK_PROBE_TARGETS]
            _authenticate_probe_boundary_items(
                boundary,
                expected_ids=_PROBE_BOUNDARY_IDS,
                manager_events=boundary_events,
                expected_paths=expected_boundary_paths,
                expected_pid=process_identity["exec_pid"],
                expected_cgroup=process_identity["cgroup_id"],
                expected_exe=process_identity["exec_exe"],
                expected_not_before=log_baseline.wall_not_before,
            )
            _authenticate_network_evidence(
                network,
                _network_events_for(network_events, tuple(_NETWORK_PROBE_TARGETS)),
                drop_before=drop_before,
                drop_after=drop_after,
                expected_addresses=probe_addresses,
                expected_pid=process_identity["exec_pid"],
                expected_cgroup=process_identity["cgroup_id"],
                expected_exe=process_identity["exec_exe"],
                expected_not_before=log_baseline.wall_not_before,
            )
        except subprocess.TimeoutExpired:
            failure = BridgeFailure("probe-timeout")
        except BridgeFailure as error:
            failure = BridgeFailure(_containment_failure_reason(error.reason))
        except (OSError, ValueError, UnicodeError, json.JSONDecodeError):
            failure = BridgeFailure("probe-session-failed")
        finally:
            if (
                process is not None
                and process.poll() is None
                and not _terminate_process_group(
                    process,
                    wait_timeout=max(0.0, min(2.0, session_deadline - time.monotonic())),
                )
            ):
                cleanup_timed_out = True
                cleanup_ok = False
            if log_baseline is not None:
                try:
                    log_baseline.close()
                except OSError:
                    cleanup_ok = False
            cleanup_containers: set[str] = set()
            for container, owned, may_exist in (
                (names["manager"], manager_owned, manager_may_exist),
                (names["target"], target_owned, target_may_exist),
                (names["resolver"], resolver_owned, resolver_may_exist),
            ):
                if not may_exist and not owned:
                    continue
                cleanup_containers.add(container)
                should_remove = owned
                try:
                    if not should_remove:
                        present = self._command_bytes(
                            ["docker", "inspect", "--format={{json .}}", container],
                            timeout=_probe_timeout(
                                session_deadline, _PROBE_CLEANUP_COMMAND_SECONDS
                            ),
                            allowed_returncodes=frozenset({0, 1}),
                            max_output_bytes=64 * 1024,
                        )
                        should_remove = present.returncode == 0
                    if not should_remove:
                        continue
                    self._command_bytes(
                        ["docker", "rm", "-f", container],
                        timeout=_probe_timeout(session_deadline, _PROBE_CLEANUP_COMMAND_SECONDS),
                        allowed_returncodes=frozenset({0, 1}),
                        max_output_bytes=64 * 1024,
                    )
                except subprocess.TimeoutExpired:
                    cleanup_timed_out = True
                    cleanup_ok = False
                except BridgeFailure as error:
                    cleanup_timed_out = cleanup_timed_out or error.reason == "probe-timeout"
                    cleanup_ok = False
                except OSError:
                    cleanup_ok = False
            if table_may_exist or table_owned:
                try:
                    tables = self._command_bytes(
                        [str(_NFT_PATH), "--json", "list", "tables"],
                        timeout=_probe_timeout(
                            session_deadline, _PROBE_CLEANUP_COMMAND_SECONDS
                        ),
                        max_output_bytes=256 * 1024,
                    )
                    if ("inet", names["table"]) in _nft_table_names(tables.stdout):
                        self._command_bytes(
                            [str(_NFT_PATH), "delete", "table", "inet", names["table"]],
                            timeout=_probe_timeout(
                                session_deadline, _PROBE_CLEANUP_COMMAND_SECONDS
                            ),
                        )
                except subprocess.TimeoutExpired:
                    cleanup_timed_out = True
                    cleanup_ok = False
                except BridgeFailure as error:
                    cleanup_timed_out = cleanup_timed_out or error.reason == "probe-timeout"
                    cleanup_ok = False
                except OSError:
                    cleanup_ok = False
            try:
                if table_may_exist or table_owned:
                    tables = self._command_bytes(
                        [str(_NFT_PATH), "--json", "list", "tables"],
                        timeout=_probe_timeout(session_deadline, _PROBE_CLEANUP_COMMAND_SECONDS),
                        max_output_bytes=256 * 1024,
                    )
                    cleanup_ok = cleanup_ok and (
                        "inet", names["table"]
                    ) not in _nft_table_names(tables.stdout)
                for container in cleanup_containers:
                    checked = self._command_bytes(
                        ["docker", "inspect", "--format={{json .}}", container],
                        timeout=_probe_timeout(session_deadline, _PROBE_CLEANUP_COMMAND_SECONDS),
                        allowed_returncodes=frozenset({0, 1}),
                        max_output_bytes=64 * 1024,
                    )
                    cleanup_ok = cleanup_ok and checked.returncode == 1
                if bridge_network is not None:
                    cleanup_network = _bridge_network_shape(
                        self._command_bytes(
                            ["docker", "network", "inspect", "--format={{json .}}", "bridge"],
                            timeout=_probe_timeout(
                                session_deadline, _PROBE_CLEANUP_COMMAND_SECONDS
                            ),
                            max_output_bytes=256 * 1024,
                        ).stdout
                    )
                    _authenticate_builtin_bridge(cleanup_network)
                    cleanup_ok = cleanup_ok and cleanup_network == bridge_network
            except subprocess.TimeoutExpired:
                cleanup_timed_out = True
                cleanup_ok = False
            except BridgeFailure as error:
                cleanup_timed_out = cleanup_timed_out or error.reason == "probe-timeout"
                cleanup_ok = False
            except OSError:
                cleanup_ok = False
            for directory, owned in ((work_dir, work_owned), (control, control_owned)):
                if not owned:
                    continue
                if directory.exists() and directory.is_dir() and not directory.is_symlink():
                    try:
                        descriptor = os.open(directory, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
                        try:
                            _remove_directory_contents(descriptor, deadline=session_deadline)
                        finally:
                            os.close(descriptor)
                        _require_probe_deadline(session_deadline)
                        directory.rmdir()
                    except BridgeFailure as error:
                        cleanup_timed_out = cleanup_timed_out or error.reason == "probe-timeout"
                        cleanup_ok = False
                    except OSError:
                        cleanup_ok = False
                elif directory.exists() or directory.is_symlink():
                    cleanup_ok = False
            if neighbor_owned:
                try:
                    _require_probe_deadline(session_deadline)
                    marker = neighbor / "marker"
                    if marker.is_symlink() or marker.read_bytes() != b"aifactory-neighbor-inert-v1\n":
                        raise BridgeFailure("probe-cleanup-failed")
                except BridgeFailure as error:
                    cleanup_timed_out = cleanup_timed_out or error.reason == "probe-timeout"
                    cleanup_ok = False
                except OSError:
                    cleanup_ok = False
                try:
                    _require_probe_deadline(session_deadline)
                    if marker.exists() and not marker.is_symlink():
                        marker.unlink()
                    elif marker.exists() or marker.is_symlink():
                        cleanup_ok = False
                except BridgeFailure as error:
                    cleanup_timed_out = cleanup_timed_out or error.reason == "probe-timeout"
                    cleanup_ok = False
                except OSError:
                    cleanup_ok = False
                try:
                    _require_probe_deadline(session_deadline)
                    neighbor.rmdir()
                except BridgeFailure as error:
                    cleanup_timed_out = cleanup_timed_out or error.reason == "probe-timeout"
                    cleanup_ok = False
                except OSError:
                    cleanup_ok = False
        if cleanup_timed_out:
            failure = BridgeFailure("probe-timeout")
        elif not cleanup_ok:
            failure = BridgeFailure("probe-cleanup-failed")
        if failure is not None:
            counters_complete = (
                type(firewall_digest) is str
                and type(drop_before) is int
                and type(drop_after) is int
            )
            return {
                "disposition": "verification-failed",
                "reason": failure.reason,
                "firewall": {
                    "program_digest": firewall_digest if counters_complete else None,
                    "drop_before": drop_before if counters_complete else None,
                    "drop_after": drop_after if counters_complete else None,
                    "cleanup_verified": cleanup_ok,
                },
                "probes": list(normalized),
            }
        return {
            "disposition": "passed",
            "reason": "none",
            "firewall": {
                "program_digest": firewall_digest,
                "drop_before": drop_before,
                "drop_after": drop_after,
                "cleanup_verified": True,
            },
            "probes": list(normalized),
        }

    def _run_agent(
        self, request: BridgeRequest
    ) -> tuple[Literal["ok", "denied"], dict[str, JsonValue]]:
        if not isinstance(request.payload, Mapping) or set(request.payload) != {
            "prompt",
            "model",
            "system",
            "tools",
            "scope",
        }:
            raise BridgeFailure("invalid-payload")
        payload = request.payload
        prompt = payload["prompt"]
        model, system, tools = payload["model"], payload["system"], payload["tools"]
        if (
            type(prompt) is not str
            or not prompt
            or len(prompt.encode("utf-8")) > 512 * 1024
            or type(model) is not str
            or not model
            or len(model) > 128
            or "\0" in model
            or (
                system is not None
                and (type(system) is not str or len(system.encode("utf-8")) > 256 * 1024)
            )
            or type(tools) is not list
            or len(tools) > 64
            or any(
                type(tool) is not str or not tool or len(tool) > 256 or "\0" in tool
                for tool in tools
            )
        ):
            raise BridgeFailure("invalid-payload")
        scope = ExecutionScope.from_document(payload["scope"])
        if scope.context_digest != request.context_digest:
            raise BridgeFailure("scope-context-mismatch")
        workspace, authority = self._authorized_workspace(request.context_digest)
        self._verify_scope_revisions(workspace, scope, authority)
        if fingerprint_repository_surface(workspace) != scope.input_fingerprint:
            raise BridgeFailure("input-fingerprint-mismatch")
        auth_volumes = _model_auth_volumes(self.config)
        effective_policy = _write_effective_policy(
            self.config, request.request_id, workspace, scope, authority
        )
        launch_deadline = time.monotonic() + scope.timeout_seconds
        try:
            with _docker_mutation_lock(self.config, deadline=launch_deadline):
                try:
                    completed = self._command(
                        [
                            str(_LEASH_ENTRY),
                            "--policy",
                            str(effective_policy),
                            "--no-interactive",
                            "--listen",
                            "",
                            "--leash-image",
                            self._sealed_runtime()["leash_image_reference"],
                            "--image",
                            self._sealed_runtime()["image_reference"],
                            "--env",
                            "LEASH_DISABLE_TELEMETRY=1",
                            *(argument for volume in auth_volumes for argument in ("--volume", volume)),
                            "claude",
                            "-p",
                            prompt,
                            "--model",
                            model,
                            "--output-format",
                            "json",
                            "--no-session-persistence",
                            *(["--append-system-prompt", system] if system is not None else []),
                            "--strict-mcp-config",
                            "--tools",
                            ",".join(tools),
                            *(["--allowedTools", ",".join(tools)] if tools else []),
                        ],
                        cwd=workspace,
                        timeout=_probe_timeout(launch_deadline, scope.timeout_seconds),
                        env=_automated_leash_environment(self.config),
                        allowed_returncodes={0, 1},
                        allow_empty_argument=True,
                    )
                except subprocess.TimeoutExpired:
                    if not self._cleanup_agent_runtime(workspace):
                        raise BridgeFailure("agent-timeout-cleanup-failed") from None
                    raise
        except subprocess.TimeoutExpired:
            raise BridgeFailure("timeout") from None
        if _is_denial(completed.stdout):
            return "denied", _normalized_denial(
                completed.stdout,
                workspace=workspace,
                state_root=self.config.state_root,
            )
        if completed.returncode != 0:
            raise BridgeFailure(_claude_nonzero_reason(completed.stdout))
        try:
            parsed = _terminal_json_record(completed.stdout)
            if not isinstance(parsed, dict) or type(parsed.get("result")) is not str:
                raise ValueError
            if len(parsed["result"].encode("utf-8")) > 2 * 1024 * 1024:
                raise ValueError
            cost = parsed.get("total_cost_usd")
            if (
                type(cost) not in {int, float}
                or isinstance(cost, bool)
                or not math.isfinite(float(cost))
                or float(cost) < 0
            ):
                raise ValueError
            if (
                len(json.dumps(parsed, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
                > 2 * 1024 * 1024
            ):
                raise ValueError
        except (ValueError, TypeError, json.JSONDecodeError):
            raise BridgeFailure("claude-result-invalid") from None
        return "ok", {"output": parsed["result"], "model": model, "cost_usd": float(cost)}

    def _cleanup_agent_runtime(self, workspace: Path) -> bool:
        deadline = time.monotonic() + _RUN_AGENT_CLEANUP_BUDGET_SECONDS
        # Pinned Leash derives its project from the workspace basename and caps
        # that value at 63 bytes before appending the manager suffix. Validation
        # workspaces are lowercase ASCII SHA-256 names, so this slice exactly
        # mirrors Leash's sanitizeProjectName result.
        leash_project = workspace.name[:63]
        names = (leash_project, leash_project + "-leash")
        try:
            for name in names:
                self._command(
                    ["docker", "rm", "-f", name],
                    timeout=_probe_timeout(deadline, _RUN_AGENT_CLEANUP_COMMAND_SECONDS),
                    allowed_returncodes=frozenset({0, 1}),
                )
            for name in names:
                remaining = self._command(
                    ["docker", "ps", "-aq", "--filter", f"name=^/{name}$"],
                    timeout=_probe_timeout(deadline, _RUN_AGENT_CLEANUP_COMMAND_SECONDS),
                )
                if remaining.stdout.strip():
                    return False
        except (BridgeFailure, OSError, subprocess.TimeoutExpired):
            return False
        return True

    def _run_command(self, request: BridgeRequest) -> dict[str, JsonValue]:
        payload = _exact_payload(request.payload, {"name"})
        name = payload["name"]
        if type(name) is not str:
            raise BridgeFailure("invalid-payload")
        workspace, _authority = self._authorized_workspace(request.context_digest)
        return self._run_authorized_command(workspace, name)

    def _run_authorized_command(self, workspace: Path, name: str) -> dict[str, JsonValue]:
        if (
            self.config.verifier_prefix != _VERIFIER_PREFIX
            or self.config.verifier_launcher_path != _VERIFIER_LAUNCHER
        ):
            raise BridgeFailure("verifier-identity-invalid")
        authority = _read_authority(
            self.config.state_root,
            _workspace_context(self.config.workspace_root, workspace),
            self.config.root_uid,
        )
        policy = _execution_policy(authority.get("execution_policy"))
        command = next(
            (item for item in policy["verification_commands"] if item["name"] == name), None
        )
        if command is None:
            raise BridgeFailure("command-not-authorized")
        launch_deadline = time.monotonic() + 300
        try:
            with _docker_mutation_lock(self.config, deadline=launch_deadline):
                completed = self._command(
                    [
                        *self.config.verifier_prefix,
                        str(self.config.verifier_launcher_path),
                        "--verifier-launch",
                        *command["argv"],
                    ],
                    cwd=workspace,
                    timeout=_probe_timeout(launch_deadline, 300),
                    env=_command_environment(command["environment_profile"]),
                    allowed_returncodes=None,
                )
        except subprocess.TimeoutExpired as error:
            del error
            raise BridgeFailure("timeout") from None
        if completed.returncode != 0:
            raise BridgeFailure("verifier-launch-failed")
        launch = _verifier_launch_status(completed.stdout)
        if launch is None or not launch[0]:
            raise BridgeFailure("verifier-launch-failed")
        if launch[1] == "signal":
            raise BridgeFailure("verifier-child-terminated")
        exit_code = launch[2]
        assert exit_code is not None
        passed = exit_code == 0 if command["expected_exit"] == "zero" else exit_code != 0
        return {"command": name, "passed": passed}

    def _export(self, request: BridgeRequest) -> dict[str, JsonValue]:
        if not isinstance(request.payload, Mapping) or set(request.payload) not in (
            {"revision"},
            {"revision", "base_revision", "product_paths", "controller_roots"},
        ):
            raise BridgeFailure("invalid-payload")
        payload = request.payload
        revision = _revision(payload["revision"])
        workspace, authority = self._authorized_workspace(request.context_digest)
        if self._git_stdout(workspace, ["status", "--porcelain"]) != "":
            raise BridgeFailure("workspace-dirty")
        if self._git_stdout(workspace, ["rev-parse", "HEAD"]) != revision:
            raise BridgeFailure("export-revision-not-head")
        base = _revision(authority.get("base_revision"))
        extended = "base_revision" in payload
        if extended:
            if (
                payload["base_revision"] != base
                or not isinstance(payload["product_paths"], list)
                or not isinstance(payload["controller_roots"], list)
            ):
                raise BridgeFailure("export-authority-mismatch")
            product_paths = tuple(_relative_path(item) for item in payload["product_paths"])
            controller_roots = tuple(_relative_path(item) for item in payload["controller_roots"])
            if (
                not product_paths
                or not controller_roots
                or len(set(product_paths)) != len(product_paths)
                or len(set(controller_roots)) != len(controller_roots)
                or any(
                    product == root or product.startswith(f"{root}/")
                    for product in product_paths
                    for root in controller_roots
                )
            ):
                raise BridgeFailure("export-authority-mismatch")
            authority_result = self._command_bytes(
                [
                    "git",
                    "--literal-pathspecs",
                    "diff",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--no-renames",
                    "--name-only",
                    "-z",
                    base,
                    revision,
                    "--",
                ],
                cwd=workspace,
                env=_sanitized_bridge_git_environment(),
                timeout=60,
                allowed_returncodes=None,
            )
            implementation_result = self._command_bytes(
                [
                    "git",
                    "--literal-pathspecs",
                    "diff",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--no-renames",
                    "--name-only",
                    "-z",
                    base,
                    revision,
                    "--",
                    *product_paths,
                ],
                cwd=workspace,
                env=_sanitized_bridge_git_environment(),
                timeout=60,
                allowed_returncodes=None,
            )
            revisions_result = self._command(
                ["git", "rev-list", "--reverse", revision, f"^{base}"],
                cwd=workspace,
                env=_sanitized_bridge_git_environment(),
                timeout=60,
                allowed_returncodes=None,
            )
            if (
                authority_result.returncode != 0
                or implementation_result.returncode != 0
                or revisions_result.returncode != 0
            ):
                raise BridgeFailure("export-failed")
            try:
                authority_paths = sorted(
                    item.decode("utf-8", "strict")
                    for item in authority_result.stdout.split(b"\0")
                    if item
                )
                implementation_paths = sorted(
                    item.decode("utf-8", "strict")
                    for item in implementation_result.stdout.split(b"\0")
                    if item
                )
                revisions = [
                    line for line in revisions_result.stdout.splitlines() if _revision(line) == line
                ]
                expected_products = sorted(product_paths)
                if (
                    any(not _valid_relative_path(path) for path in authority_paths)
                    or any(not _valid_relative_path(path) for path in implementation_paths)
                    or implementation_paths != expected_products
                    or not revisions
                    or revisions[-1] != revision
                    or len(revisions) != len(revisions_result.stdout.splitlines())
                    or any(
                        path not in expected_products
                        and not any(
                            path == root or path.startswith(f"{root}/") for root in controller_roots
                        )
                        for path in authority_paths
                    )
                ):
                    raise ValueError
            except (UnicodeDecodeError, ValueError, BridgeFailure):
                raise BridgeFailure("export-authority-mismatch") from None
        exports = _child_directory(self.config.export_root, request.context_digest, create=True)
        suffix = hashlib.sha256(request.request_id.encode("utf-8")).hexdigest()
        patch_name = f"{suffix}.patch"
        bundle_name = f"{suffix}.bundle"
        patch = exports / patch_name
        bundle = exports / bundle_name
        if extended:
            formatted_bytes = self._command_bytes(
                [
                    "git",
                    "--literal-pathspecs",
                    "diff",
                    "--no-renames",
                    "--binary",
                    "--full-index",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--src-prefix=a/",
                    "--dst-prefix=b/",
                    base,
                    revision,
                    "--",
                    *product_paths,
                ],
                cwd=workspace,
                timeout=60,
                env=_sanitized_bridge_git_environment(),
                max_output_bytes=128 * 1024 * 1024,
            ).stdout
            if not formatted_bytes:
                raise BridgeFailure("export-authority-mismatch")
        else:
            formatted_bytes = self._command(
                ["git", "format-patch", "--stdout", f"{base}..HEAD"],
                cwd=workspace,
                timeout=60,
                env=_sanitized_bridge_git_environment(),
            ).stdout.encode("utf-8")
        if extended:
            export_ref = f"refs/heads/{revision}"
            ref_created = False
            try:
                present = self._command(
                    ["git", "show-ref", "--verify", "--quiet", export_ref],
                    cwd=workspace,
                    env=_sanitized_bridge_git_environment(),
                    timeout=20,
                    allowed_returncodes=frozenset({0, 1}),
                )
                if present.returncode != 1:
                    raise BridgeFailure("export-failed")
                self._command(
                    ["git", "update-ref", export_ref, revision, "0" * len(revision)],
                    cwd=workspace,
                    env=_sanitized_bridge_git_environment(),
                    timeout=20,
                )
                ref_created = True
                bundled = self._command_bytes(
                    ["git", "bundle", "create", "-", export_ref],
                    cwd=workspace,
                    env=_sanitized_bridge_git_environment(),
                    timeout=60,
                    allowed_returncodes=None,
                    max_output_bytes=128 * 1024 * 1024,
                )
                if bundled.returncode != 0:
                    raise BridgeFailure("export-failed")
            finally:
                if ref_created:
                    self._command(
                        ["git", "update-ref", "-d", export_ref, revision],
                        cwd=workspace,
                        env=_sanitized_bridge_git_environment(),
                        timeout=20,
                        allowed_returncodes=None,
                    )
        else:
            bundled = self._command_bytes(
                ["git", "bundle", "create", "-", "HEAD"],
                cwd=workspace,
                env=_sanitized_bridge_git_environment(),
                timeout=60,
                allowed_returncodes=None,
                max_output_bytes=128 * 1024 * 1024,
            )
            if bundled.returncode != 0:
                raise BridgeFailure("export-failed")
        stage = secrets.token_hex(16)
        patch_stage = f".{suffix}.{stage}.patch.stage"
        bundle_stage = f".{suffix}.{stage}.bundle.stage"
        try:
            _write_regular_at_root(exports, patch_stage, formatted_bytes)
            _write_regular_at_root(exports, bundle_stage, bundled.stdout)
            verified = self._command(
                ["git", "bundle", "verify", str(exports / bundle_stage)],
                cwd=workspace,
                timeout=60,
                env=_sanitized_bridge_git_environment(),
                allowed_returncodes=frozenset({0, 1}),
            )
            if verified.returncode != 0:
                raise BridgeFailure("export-failed")
            directory = os.open(exports, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.replace(patch_stage, patch_name, src_dir_fd=directory, dst_dir_fd=directory)
                os.replace(bundle_stage, bundle_name, src_dir_fd=directory, dst_dir_fd=directory)
                os.fsync(directory)
            finally:
                os.close(directory)
        except (OSError, RuntimeError):
            try:
                directory = os.open(exports, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    for name in (patch_stage, bundle_stage, patch_name, bundle_name):
                        try:
                            os.unlink(name, dir_fd=directory)
                        except OSError:
                            pass
                finally:
                    os.close(directory)
            except OSError:
                pass
            raise BridgeFailure("export-failed") from None
        result: dict[str, JsonValue] = {
            "patch_path": str(patch),
            "patch_digest": _sha256_file(patch),
            "bundle_path": str(bundle),
            "bundle_digest": _sha256_file(bundle),
        }
        if extended:
            result["inventory"] = {
                "authority_revisions": revisions,
                "authority_paths": authority_paths,
                "implementation_paths": implementation_paths,
            }
        return result

    def _version(self, argv: list[str], expected: str) -> str:
        completed = self._command(argv, timeout=10)
        if not re.fullmatch(r"Docker version \d+\.\d+(?:\.\d+)?(?:[ ,].*)?\n?", completed.stdout):
            raise BridgeFailure("runtime-version-invalid")
        return "docker"

    def _leash_release(self) -> tuple[str, str]:
        completed = self._command([str(_LEASH_ENTRY), "--version"], timeout=10)
        match = re.fullmatch(
            r"version: (\d+\.\d+\.\d+)\n"
            r"git hash: ([0-9a-f]{7})\n"
            r"build date: (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\n?",
            completed.stdout,
        )
        if match is None or match.group(1) != "1.1.7" or match.group(2) != "5bf1c64":
            raise BridgeFailure("runtime-version-invalid")
        return "1.1.7", "5bf1c64"

    def _verify_scope_revisions(
        self, workspace: Path, scope: ExecutionScope, authority: Mapping[str, Any]
    ) -> None:
        if (
            authority.get("context_digest") != scope.context_digest
            or authority.get("base_revision") != scope.base_revision
            or authority.get("execution_policy", {}).get("network_profile") != scope.network_profile
        ):
            raise BridgeFailure("scope-authority-mismatch")
        phases = _phase_writable_paths(
            authority.get("phase_writable_paths"),
            policy=_execution_policy(authority.get("execution_policy")),
            artifacts=_phase_artifacts(authority.get("phase_artifacts")),
        )
        approved = tuple(phases[scope.turn_kind])
        if scope.turn_kind == "implementation":
            authorized = all(_path_within(path, approved) for path in scope.writable_paths)
        else:
            authorized = scope.writable_paths == approved
        if not authorized:
            raise BridgeFailure("scope-authority-mismatch")
        if (
            self._git_stdout(
                workspace, ["rev-parse", "--verify", f"{scope.base_revision}^{{commit}}"]
            )
            != scope.base_revision
        ):
            raise BridgeFailure("base-revision-mismatch")
        if self._git_stdout(workspace, ["rev-parse", "HEAD"]) != scope.input_revision:
            raise BridgeFailure("input-revision-mismatch")
        ancestry = self._command(
            ["git", "merge-base", "--is-ancestor", scope.base_revision, scope.input_revision],
            cwd=workspace,
            timeout=20,
            env=_sanitized_bridge_git_environment(),
            allowed_returncodes={0, 1},
        )
        if ancestry.returncode != 0:
            raise BridgeFailure("base-revision-mismatch")

    def _command(
        self,
        argv: list[str],
        *,
        cwd: Path | None = None,
        timeout: int,
        env: dict[str, str] | None = None,
        allowed_returncodes: frozenset[int] | None = frozenset({0}),
        allow_empty_argument: bool = False,
        max_output_bytes: int = 8 * 1024 * 1024,
    ) -> subprocess.CompletedProcess[str]:
        if not argv or any(
            type(argument) is not str
            or (not argument and not allow_empty_argument)
            or "\0" in argument
            for argument in argv
        ):
            raise BridgeFailure("invalid-command")
        completed = _run_bounded_process(
            argv,
            cwd=cwd,
            env=env,
            timeout=timeout,
            text=True,
            max_output_bytes=max_output_bytes,
        )
        if allowed_returncodes is not None and completed.returncode not in allowed_returncodes:
            raise BridgeFailure("command-failed")
        return completed

    def _command_bytes(
        self,
        argv: list[str],
        *,
        cwd: Path | None = None,
        timeout: int,
        env: dict[str, str] | None = None,
        allowed_returncodes: frozenset[int] | None = frozenset({0}),
        max_output_bytes: int = 8 * 1024 * 1024,
    ) -> subprocess.CompletedProcess[bytes]:
        if not argv or any(
            type(argument) is not str or not argument or "\0" in argument for argument in argv
        ):
            raise BridgeFailure("invalid-command")
        completed = _run_bounded_process(
            argv,
            cwd=cwd,
            env=env,
            timeout=timeout,
            text=False,
            max_output_bytes=max_output_bytes,
        )
        if allowed_returncodes is not None and completed.returncode not in allowed_returncodes:
            raise BridgeFailure("command-failed")
        return completed

    def _git(self, workspace: Path, args: list[str]) -> None:
        self._command(
            ["git", *args],
            cwd=workspace,
            timeout=60,
            env=_sanitized_bridge_git_environment(),
        )

    def _git_stdout(self, workspace: Path, args: list[str]) -> str:
        return self._command(
            ["git", *args],
            cwd=workspace,
            timeout=60,
            env=_sanitized_bridge_git_environment(),
        ).stdout.strip()

    # Explicit Workspace action table.  Each action checks its exact payload before Git/filesystem use.
    def _workspace_file_state(
        self, workspace: Path, args: Mapping[str, JsonValue]
    ) -> dict[str, JsonValue]:
        args = _exact_payload(args, {"path"})
        _content, state = _read_regular_at_root(
            workspace, _relative_path(args["path"]), max_bytes=None
        )
        return {"kind": state.kind, "size": state.size, "digest": state.digest}

    def _workspace_read_file(
        self, workspace: Path, args: Mapping[str, JsonValue]
    ) -> dict[str, JsonValue]:
        args = _exact_payload(args, {"path", "max_bytes"})
        maximum = args["max_bytes"]
        relative = _relative_path(args["path"])
        if type(maximum) is not int or maximum < 0:
            raise BridgeFailure("file-unreadable")
        if maximum > _MAX_RAW_READ_BYTES:
            raise BridgeFailure("response-payload-too-large")
        try:
            content, _state = _read_regular_at_root(workspace, relative, max_bytes=maximum)
        except (FileNotFoundError, RuntimeError):
            raise BridgeFailure("file-unreadable") from None
        assert content is not None
        return {"content_base64": base64.b64encode(content).decode("ascii")}

    def _workspace_write_file(
        self, workspace: Path, args: Mapping[str, JsonValue]
    ) -> dict[str, JsonValue]:
        args = _exact_payload(args, {"path", "content_base64"})
        relative = _relative_path(args["path"])
        content = args["content_base64"]
        if type(content) is not str:
            raise BridgeFailure("invalid-payload")
        try:
            decoded = base64.b64decode(content.encode("ascii"), validate=True)
        except (UnicodeEncodeError, ValueError):
            raise BridgeFailure("invalid-payload") from None
        if len(decoded) > 8 * 1024 * 1024:
            raise BridgeFailure("file-too-large")
        try:
            _write_regular_at_root(workspace, relative, decoded)
        except (OSError, RuntimeError):
            raise BridgeFailure("workspace-unsafe") from None
        return {"written": True}

    def _workspace_read_file_at(
        self, workspace: Path, args: Mapping[str, JsonValue]
    ) -> dict[str, JsonValue]:
        args = _exact_payload(args, {"revision", "path", "max_bytes"})
        revision = _revision(args["revision"])
        relative = _relative_path(args["path"])
        maximum = args["max_bytes"]
        if type(maximum) is not int or maximum < 0:
            raise BridgeFailure("file-unreadable")
        if maximum > _MAX_RAW_READ_BYTES:
            raise BridgeFailure("response-payload-too-large")
        resolved = self._git_stdout(
            workspace,
            ["rev-parse", "--verify", "--quiet", "--end-of-options", f"{revision}^{{commit}}"],
        )
        if resolved != revision:
            raise BridgeFailure("file-unreadable")
        entry = self._command_bytes(
            ["git", "ls-tree", "-z", revision, "--", relative],
            cwd=workspace,
            env=_sanitized_bridge_git_environment(),
            timeout=60,
            allowed_returncodes=None,
            max_output_bytes=2 * 1024 * 1024,
        )
        records = [record for record in entry.stdout.split(b"\0") if record]
        if entry.returncode != 0:
            raise BridgeFailure("file-unreadable")
        if not records:
            raise BridgeFailure("file-missing")
        if len(records) != 1:
            raise BridgeFailure("file-unreadable")
        metadata, separator, reported = records[0].partition(b"\t")
        fields = metadata.split()
        if (
            not separator
            or reported != relative.encode("utf-8")
            or len(fields) != 3
            or fields[0] not in {b"100644", b"100755"}
            or fields[1] != b"blob"
        ):
            raise BridgeFailure("file-unreadable")
        object_id = fields[2].decode("ascii", "strict")
        size = self._git_stdout(workspace, ["cat-file", "-s", object_id])
        try:
            exact_size = int(size)
        except ValueError:
            raise BridgeFailure("file-unreadable") from None
        if exact_size < 0 or exact_size > maximum:
            raise BridgeFailure("file-unreadable")
        content = self._command_bytes(
            ["git", "cat-file", "blob", object_id],
            cwd=workspace,
            env=_sanitized_bridge_git_environment(),
            timeout=60,
            allowed_returncodes=None,
            max_output_bytes=maximum + 64 * 1024,
        )
        if content.returncode != 0 or len(content.stdout) != exact_size:
            raise BridgeFailure("file-unreadable")
        return {"content_base64": base64.b64encode(content.stdout).decode("ascii")}

    def _workspace_remove_file(
        self, workspace: Path, args: Mapping[str, JsonValue]
    ) -> dict[str, JsonValue]:
        args = _exact_payload(args, {"path", "missing_ok"})
        relative = _relative_path(args["path"])
        missing_ok = args["missing_ok"]
        if type(missing_ok) is not bool:
            raise BridgeFailure("invalid-payload")
        try:
            _remove_at_root(workspace, relative, missing_ok=missing_ok)
        except FileNotFoundError:
            raise BridgeFailure("file-missing") from None
        except (OSError, RuntimeError):
            raise BridgeFailure("file-not-removable") from None
        return {"removed": True}

    def _workspace_changed_files(
        self, workspace: Path, args: Mapping[str, JsonValue]
    ) -> dict[str, JsonValue]:
        _exact_payload(args, set())
        authority = _read_authority(
            self.config.state_root,
            _workspace_context(self.config.workspace_root, workspace),
            self.config.root_uid,
        )
        base = _revision(authority.get("base_revision"))
        return {"paths": self._changed_paths_since(workspace, base)}

    def _changed_paths_since(self, workspace: Path, start: str) -> list[str]:
        committed = self._command_bytes(
            [
                "git",
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--no-renames",
                "--name-only",
                "-z",
                f"{start}..HEAD",
            ],
            cwd=workspace,
            env=_sanitized_bridge_git_environment(),
            timeout=60,
            allowed_returncodes=None,
        )
        result = self._command_bytes(
            ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
            cwd=workspace,
            env=_sanitized_bridge_git_environment(),
            timeout=60,
            allowed_returncodes=None,
        )
        if (
            committed.returncode != 0
            or (committed.stdout and not committed.stdout.endswith(b"\0"))
            or result.returncode != 0
            or (result.stdout and not result.stdout.endswith(b"\0"))
        ):
            raise BridgeFailure("workspace-unsafe")
        records = [item for item in result.stdout.split(b"\0") if item]
        paths: set[str] = set()
        for raw in (item for item in committed.stdout.split(b"\0") if item):
            try:
                paths.add(raw.decode("utf-8", "strict"))
            except UnicodeDecodeError:
                raise BridgeFailure("workspace-unsafe") from None
        index = 0
        while index < len(records):
            record = records[index]
            if len(record) < 4:
                raise BridgeFailure("workspace-unsafe")
            try:
                path = record[3:].decode("utf-8", "strict")
            except UnicodeDecodeError:
                raise BridgeFailure("workspace-unsafe") from None
            paths.add(path)
            if record[:1] in {b"R", b"C"} or record[1:2] in {b"R", b"C"}:
                index += 1
                if index >= len(records):
                    raise BridgeFailure("workspace-unsafe")
                try:
                    paths.add(records[index].decode("utf-8", "strict"))
                except UnicodeDecodeError:
                    raise BridgeFailure("workspace-unsafe") from None
            index += 1
        if any(not _valid_relative_path(path) for path in paths):
            raise BridgeFailure("workspace-unsafe")
        return sorted(paths)

    def _workspace_turn_delta(
        self, workspace: Path, args: Mapping[str, JsonValue]
    ) -> dict[str, JsonValue]:
        args = _exact_payload(args, {"input_revision"})
        input_revision = _revision(args["input_revision"])
        resolved = self._git_stdout(
            workspace,
            [
                "rev-parse",
                "--verify",
                "--quiet",
                "--end-of-options",
                f"{input_revision}^{{commit}}",
            ],
        )
        if resolved != input_revision:
            raise BridgeFailure("input-revision-mismatch")
        head = self._git_stdout(workspace, ["rev-parse", "HEAD"])
        ancestor = self._command(
            ["git", "merge-base", "--is-ancestor", input_revision, head],
            cwd=workspace,
            timeout=60,
            env=_sanitized_bridge_git_environment(),
            allowed_returncodes=frozenset({0, 1}),
        )
        if ancestor.returncode != 0:
            raise BridgeFailure("turn-history-rewritten")
        return {
            "output_revision": head,
            "paths": self._changed_paths_since(workspace, input_revision),
        }

    def _workspace_scan_pushable_blobs(
        self, workspace: Path, args: Mapping[str, JsonValue]
    ) -> dict[str, JsonValue]:
        args = _exact_payload(args, {"max_blob_bytes", "max_total_bytes"})
        blob_limit = args["max_blob_bytes"]
        total_limit = args["max_total_bytes"]
        if type(blob_limit) is not int or type(total_limit) is not int:
            raise BridgeFailure("invalid-payload")
        authority = _read_authority(
            self.config.state_root,
            _workspace_context(self.config.workspace_root, workspace),
            self.config.root_uid,
        )
        base = _revision(authority.get("base_revision"))

        class _ScanWorkspace:
            remote_mutations_permitted = False

            def changed_files(inner_self) -> list[str]:
                del inner_self
                return self._changed_paths_since(workspace, base)

            def attest_local_validation_git_policy(inner_self) -> bool:
                del inner_self
                return True

        try:
            evidence = _local_scan_evidence(
                _ScanWorkspace(),
                root=workspace,
                base=base,
                max_blob_bytes=blob_limit,
                max_total_bytes=total_limit,
            )
        except Exception as exc:
            raise BridgeFailure("workspace-scan-unavailable") from exc
        return {
            "blobs": [
                {
                    "path": blob.path,
                    "content_base64": base64.b64encode(blob.content).decode("ascii"),
                }
                for blob in evidence.blobs
            ],
            "total_bytes": evidence.total_bytes,
        }

    def _workspace_attest(
        self, workspace: Path, args: Mapping[str, JsonValue]
    ) -> dict[str, JsonValue]:
        _exact_payload(args, set())
        context = _workspace_context(self.config.workspace_root, workspace)
        authority = _read_authority(self.config.state_root, context, self.config.root_uid)
        policy = authority.get("execution_policy")
        try:
            policy_digest = hashlib.sha256(
                json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            fingerprint = fingerprint_repository_surface(workspace)
        except (TypeError, ValueError, OSError, RuntimeError) as exc:
            raise BridgeFailure("workspace-attestation-unavailable") from exc
        return {
            "context_digest": context,
            "base_revision": _revision(authority.get("base_revision")),
            "workspace_fingerprint": fingerprint,
            "manifest_digest": _digest(authority.get("manifest_digest")),
            "execution_policy_digest": policy_digest,
        }

    def _workspace_checkpoint(
        self, workspace: Path, args: Mapping[str, JsonValue]
    ) -> dict[str, JsonValue]:
        return self._commit_workspace(workspace, args, action="checkpoint")

    def _workspace_commit(
        self, workspace: Path, args: Mapping[str, JsonValue]
    ) -> dict[str, JsonValue]:
        return self._commit_workspace(workspace, args, action="commit")

    def _commit_workspace(
        self, workspace: Path, args: Mapping[str, JsonValue], *, action: str
    ) -> dict[str, JsonValue]:
        args = _exact_payload(args, {"message"})
        message = args["message"]
        if type(message) is not str or not message or len(message) > 4096 or "\0" in message:
            raise BridgeFailure("invalid-payload")
        self._git(workspace, ["add", "-A", "--", "."])
        self._git(workspace, ["commit", "-m", message])
        del action
        return {"revision": self._git_stdout(workspace, ["rev-parse", "HEAD"])}

    def _workspace_reset(
        self, workspace: Path, args: Mapping[str, JsonValue]
    ) -> dict[str, JsonValue]:
        _exact_payload(args, set())
        base = _revision(
            _read_authority(
                self.config.state_root,
                _workspace_context(self.config.workspace_root, workspace),
                self.config.root_uid,
            ).get("base_revision")
        )
        self._git(workspace, ["reset", "--hard", base])
        self._git(workspace, ["clean", "-xdff"])
        return {"reset": True}

    def _workspace_reset_to(
        self, workspace: Path, args: Mapping[str, JsonValue]
    ) -> dict[str, JsonValue]:
        args = _exact_payload(args, {"revision"})
        revision = _revision(args["revision"])
        resolved = self._git_stdout(
            workspace,
            ["rev-parse", "--verify", "--quiet", "--end-of-options", f"{revision}^{{commit}}"],
        )
        if resolved != revision:
            raise BridgeFailure("checkpoint-not-owned")
        base = _revision(
            _read_authority(
                self.config.state_root,
                _workspace_context(self.config.workspace_root, workspace),
                self.config.root_uid,
            ).get("base_revision")
        )
        base_to_target = self._command(
            ["git", "merge-base", "--is-ancestor", base, revision],
            cwd=workspace,
            timeout=60,
            env=_sanitized_bridge_git_environment(),
            allowed_returncodes=frozenset({0, 1}),
        )
        if base_to_target.returncode != 0:
            raise BridgeFailure("checkpoint-not-owned")
        self._git(workspace, ["reset", "--hard", revision])
        self._git(workspace, ["clean", "-xdff"])
        return {"reset": True}

    def _workspace_head_revision(
        self, workspace: Path, args: Mapping[str, JsonValue]
    ) -> dict[str, JsonValue]:
        _exact_payload(args, set())
        return {"revision": self._git_stdout(workspace, ["rev-parse", "HEAD"])}

    def _workspace_ancestor(
        self, workspace: Path, args: Mapping[str, JsonValue]
    ) -> dict[str, JsonValue]:
        args = _exact_payload(args, {"ancestor", "descendant"})
        result = self._command(
            [
                "git",
                "merge-base",
                "--is-ancestor",
                _revision(args["ancestor"]),
                _revision(args["descendant"]),
            ],
            cwd=workspace,
            timeout=60,
            env=_sanitized_bridge_git_environment(),
            allowed_returncodes={0, 1},
        )
        return {"is_ancestor": result.returncode == 0}

    def _workspace_contract_order(
        self, workspace: Path, args: Mapping[str, JsonValue]
    ) -> dict[str, JsonValue]:
        args = _exact_payload(args, {"issue_number", "contracts_dir"})
        issue = args["issue_number"]
        directory = _relative_path(args["contracts_dir"])
        if type(issue) is not int or issue < 0:
            raise BridgeFailure("invalid-payload")
        base = _revision(
            _read_authority(
                self.config.state_root,
                _workspace_context(self.config.workspace_root, workspace),
                self.config.root_uid,
            ).get("base_revision")
        )
        output = self._command(
            [
                "git",
                "log",
                "--reverse",
                "--name-only",
                "--pretty=format:%x00%H",
                f"{base}..HEAD",
                "--",
            ],
            cwd=workspace,
            timeout=60,
            env=_sanitized_bridge_git_environment(),
        ).stdout
        precedes, reason = contract_precedes_implementation(
            commits_from_log(output), issue, contracts_dir=directory
        )
        return {"precedes": precedes, "reason": reason}

    def _workspace_review_fingerprint(
        self, workspace: Path, args: Mapping[str, JsonValue]
    ) -> dict[str, JsonValue]:
        _exact_payload(args, set())
        try:
            return {"fingerprint": fingerprint_repository_surface(workspace)}
        except (OSError, RuntimeError):
            raise BridgeFailure("fingerprint-unavailable") from None

    def _workspace_publication_fingerprint(
        self, workspace: Path, args: Mapping[str, JsonValue]
    ) -> dict[str, JsonValue]:
        args = _exact_payload(args, {"revision"})
        revision = args["revision"]
        if revision is not None:
            revision = _revision(revision)
        if revision is None:
            with tempfile.TemporaryDirectory(prefix="aifactory-bridge-index-") as temporary:
                environment = _sanitized_bridge_git_environment()
                environment["GIT_INDEX_FILE"] = str(Path(temporary) / "index")
                tree = ""
                for args in (("read-tree", "HEAD"), ("add", "-A", "--", "."), ("write-tree",)):
                    completed = self._command(
                        ["git", *args], cwd=workspace, timeout=60, env=environment
                    )
                    tree = completed.stdout.strip()
        else:
            tree = self._git_stdout(workspace, ["rev-parse", f"{revision}^{{tree}}"])
        if len(tree) not in {40, 64} or any(
            character not in "0123456789abcdef" for character in tree
        ):
            raise BridgeFailure("fingerprint-unavailable")
        return {
            "fingerprint": hashlib.sha256(
                b"software-factory-publication-v1\0" + tree.encode("ascii")
            ).hexdigest()
        }

    def _workspace_run_tests(
        self, workspace: Path, args: Mapping[str, JsonValue]
    ) -> dict[str, JsonValue]:
        args = _exact_payload(args, {"name"})
        name = args["name"]
        if type(name) is not str:
            raise BridgeFailure("invalid-payload")
        return self._run_authorized_command(workspace, name)

    def _workspace_harness(
        self, workspace: Path, args: Mapping[str, JsonValue]
    ) -> dict[str, JsonValue]:
        """Run only the installed posture analyzer over an authenticated guest tree."""
        args = _exact_payload(args, {"artifact_fingerprint", "options"})
        fingerprint = _digest(args["artifact_fingerprint"])
        options = args["options"]
        if not isinstance(options, Mapping):
            raise BridgeFailure("invalid-payload")
        try:
            from software_factory.analyzers import AnalyzerContext, AnalyzerLimits
            from software_factory.analyzers.harness import build_harness_analyzer

            current = fingerprint_repository_surface(workspace)
            if current != fingerprint:
                raise BridgeFailure("fingerprint-mismatch")
            analyzer = build_harness_analyzer(dict(options))
            report = analyzer.collect(
                AnalyzerContext(
                    workspace=workspace,
                    repository="lima-cell",
                    issue=_workspace_context(self.config.workspace_root, workspace),
                    artifact_fingerprint=fingerprint,
                    limits=AnalyzerLimits(),
                )
            )
            if fingerprint_repository_surface(workspace) != fingerprint:
                raise BridgeFailure("analyzer-mutated-workspace")
            encoded = json.dumps(
                report, ensure_ascii=False, separators=(",", ":"), sort_keys=True
            ).encode("utf-8")
            if len(encoded) > 2 * 1024 * 1024:
                raise BridgeFailure("analyzer-report-too-large")
            normalized = json.loads(encoded)
            if not isinstance(normalized, dict):
                raise BridgeFailure("analyzer-report-invalid")
        except BridgeFailure:
            raise
        except (TypeError, ValueError, OSError, UnicodeError, json.JSONDecodeError):
            raise BridgeFailure("analyzer-report-invalid") from None
        return {"artifact_fingerprint": fingerprint, "report": normalized}

    def _workspace_preserve(
        self, workspace: Path, args: Mapping[str, JsonValue]
    ) -> dict[str, JsonValue]:
        args = _exact_payload(args, {"message"})
        message = args["message"]
        if type(message) is not str or not message or len(message) > 4096 or "\0" in message:
            raise BridgeFailure("invalid-payload")
        context = _workspace_context(self.config.workspace_root, workspace)
        authority = _read_authority(self.config.state_root, context, self.config.root_uid)
        base = _revision(authority.get("base_revision"))
        head = self._git_stdout(workspace, ["rev-parse", "HEAD"])
        dirty = self._command(
            ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
            cwd=workspace,
            timeout=60,
            env=_sanitized_bridge_git_environment(),
        ).stdout
        ahead = self._command(
            ["git", "rev-list", "--count", f"{base}..{head}"],
            cwd=workspace,
            timeout=60,
            env=_sanitized_bridge_git_environment(),
        ).stdout.strip()
        if not dirty and ahead == "0":
            return {"preserved": False}
        preserved_revision = head
        if dirty:
            with tempfile.TemporaryDirectory(prefix="aifactory-preserve-index-") as temporary:
                environment = _sanitized_bridge_git_environment(
                    {"GIT_INDEX_FILE": str(Path(temporary) / "index")}
                )
                self._command(
                    ["git", "read-tree", "HEAD"],
                    cwd=workspace,
                    timeout=60,
                    env=environment,
                )
                self._command(
                    ["git", "add", "-A", "--", "."],
                    cwd=workspace,
                    timeout=60,
                    env=environment,
                )
                tree = self._command(
                    ["git", "write-tree"],
                    cwd=workspace,
                    timeout=60,
                    env=environment,
                ).stdout.strip()
                preserved_revision = self._command(
                    ["git", "commit-tree", tree, "-p", head, "-m", message],
                    cwd=workspace,
                    timeout=60,
                    env=environment,
                ).stdout.strip()
        _revision(preserved_revision)
        suffix = hashlib.sha256(
            (context + "\0" + message + "\0" + preserved_revision).encode("utf-8")
        ).hexdigest()
        reference = f"refs/aifactory/preserve/{suffix}"
        exports = _child_directory(self.config.export_root, context, create=True)
        bundle_name = f"{suffix}.preserve.bundle"
        bundle = exports / bundle_name
        stage_name = f".{bundle_name}.{secrets.token_hex(16)}.stage"
        try:
            self._git(workspace, ["update-ref", reference, preserved_revision])
            bundled = self._command_bytes(
                ["git", "bundle", "create", "-", reference],
                cwd=workspace,
                env=_sanitized_bridge_git_environment(),
                timeout=60,
                allowed_returncodes=None,
                max_output_bytes=128 * 1024 * 1024,
            )
            if bundled.returncode != 0:
                raise BridgeFailure("preservation-failed")
            _write_regular_at_root(exports, stage_name, bundled.stdout)
            verified = self._command(
                ["git", "bundle", "verify", str(exports / stage_name)],
                cwd=workspace,
                timeout=60,
                env=_sanitized_bridge_git_environment(),
                allowed_returncodes=frozenset({0, 1}),
            )
            if verified.returncode != 0:
                raise BridgeFailure("preservation-failed")
            directory = os.open(exports, os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
            try:
                os.replace(
                    stage_name,
                    bundle_name,
                    src_dir_fd=directory,
                    dst_dir_fd=directory,
                )
                os.fsync(directory)
            finally:
                os.close(directory)
        except (OSError, RuntimeError):
            try:
                (exports / stage_name).unlink(missing_ok=True)
                bundle.unlink(missing_ok=True)
            except OSError:
                pass
            raise BridgeFailure("preservation-failed") from None
        finally:
            self._command(
                ["git", "update-ref", "-d", reference],
                cwd=workspace,
                timeout=60,
                env=_sanitized_bridge_git_environment(),
                allowed_returncodes=None,
            )
        return {
            "preserved": True,
            "revision": preserved_revision,
            "bundle_path": str(bundle),
            "bundle_digest": _sha256_file(bundle),
        }

    def _workspace_cleanup(
        self, workspace: Path, args: Mapping[str, JsonValue]
    ) -> dict[str, JsonValue]:
        _exact_payload(args, set())
        context = _workspace_context(self.config.workspace_root, workspace)
        authority = _read_authority(self.config.state_root, context, self.config.root_uid)
        if authority.get("context_digest") != context:
            raise BridgeFailure("workspace-unsafe")
        root = _safe_root(self.config.workspace_root, create=False)
        _remove_owned_tree(root, context)
        return {"cleaned": True}


def _exact_payload(payload: Mapping[str, JsonValue], expected: set[str]) -> Mapping[str, JsonValue]:
    if not isinstance(payload, Mapping) or set(payload) != expected:
        raise BridgeFailure("invalid-payload")
    return payload


def _emit_internal_diagnostic(error: Exception) -> None:
    """Emit only an exception class locally; never include values or argv."""
    try:
        sys.stderr.write(f"aifactory-execution-bridge: {type(error).__name__}\n")
        sys.stderr.flush()
    except Exception:
        pass


def _digest(value: object) -> str:
    if type(value) is not str or not _is_digest(value):
        raise BridgeFailure("invalid-digest")
    return value


def _is_digest(value: str) -> bool:
    return len(value) == _DIGEST_LENGTH and all(
        character in "0123456789abcdef" for character in value
    )


def _revision(value: object) -> str:
    if (
        type(value) is not str
        or len(value) not in {40, 64}
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise BridgeFailure("invalid-revision")
    return value


def _relative_path(value: object, *, allow_subtree_glob: bool = False) -> str:
    if type(value) is not str or not value or "\0" in value or "\\" in value:
        raise BridgeFailure("invalid-path")
    original = value
    if value.endswith("/**") and allow_subtree_glob:
        value = value[:-3]
    elif "*" in value or "?" in value or "[" in value:
        raise BridgeFailure("invalid-path")
    parsed = PurePosixPath(value)
    if (
        parsed.is_absolute()
        or value in {".", ".."}
        or parsed.as_posix() != value
        or ".." in parsed.parts
    ):
        raise BridgeFailure("invalid-path")
    return original if original.endswith("/**") and allow_subtree_glob else value


def _valid_relative_path(value: str) -> bool:
    try:
        _relative_path(value)
    except BridgeFailure:
        return False
    return True


def _scope_root(path: str) -> str:
    return path.removesuffix("/**")


def _scope_contains(parent: str, child: str) -> bool:
    parent_root = _scope_root(parent)
    child_root = _scope_root(child)
    if parent.endswith("/**"):
        return child_root == parent_root or child_root.startswith(parent_root + "/")
    return child_root == parent_root


def _paths_overlap(paths: tuple[str, ...]) -> bool:
    return any(
        _scope_contains(left, right) or _scope_contains(right, left)
        for index, left in enumerate(paths)
        for right in paths[index + 1 :]
    )


def _validate_lifecycle_paths(turn_kind: object, paths: tuple[str, ...]) -> None:
    if turn_kind == "contract-author" and (
        len(paths) != 1 or paths[0].endswith("/**") or not paths[0].endswith(".json")
    ):
        raise BridgeFailure("scope-not-representable")
    if turn_kind == "design-author" and any(
        path.endswith("/**") or not path.startswith((".factory/", ".superpowers/"))
        for path in paths
    ):
        raise BridgeFailure("scope-not-representable")
    if turn_kind == "reviewer" and any(
        path.endswith("/**") or not path.startswith(("reviews/", ".factory/", ".superpowers/"))
        for path in paths
    ):
        raise BridgeFailure("scope-not-representable")


def _phase_artifacts(value: object) -> dict[str, Any]:
    expected = {
        "issue_contract_path",
        "controller_design_paths",
        "review_verdict_path",
        "review_findings_path",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise BridgeFailure("policy-invalid")
    contract = _relative_path(value["issue_contract_path"])
    raw_design = value["controller_design_paths"]
    verdict = _relative_path(value["review_verdict_path"])
    findings = _relative_path(value["review_findings_path"])
    if type(raw_design) is not list:
        raise BridgeFailure("policy-invalid")
    design = tuple(_relative_path(path) for path in raw_design)
    if (
        not design
        or len(design) != len(set(design))
        or _paths_overlap(design)
        or verdict == findings
    ):
        raise BridgeFailure("policy-invalid")
    _validate_lifecycle_paths("contract-author", (contract,))
    _validate_lifecycle_paths("design-author", design)
    _validate_lifecycle_paths("reviewer", (verdict, findings))
    return {
        "issue_contract_path": contract,
        "controller_design_paths": list(design),
        "review_verdict_path": verdict,
        "review_findings_path": findings,
    }


def _phase_writable_paths(
    value: object,
    *,
    policy: Mapping[str, Any],
    artifacts: Mapping[str, Any],
) -> dict[str, list[str]]:
    if not isinstance(value, Mapping) or set(value) != _SAFE_TURN_KINDS:
        raise BridgeFailure("policy-invalid")
    normalized: dict[str, list[str]] = {}
    all_paths: list[tuple[str, str]] = []
    for turn_kind in sorted(_SAFE_TURN_KINDS):
        raw_paths = value[turn_kind]
        if type(raw_paths) is not list:
            raise BridgeFailure("policy-invalid")
        paths = tuple(_relative_path(path, allow_subtree_glob=True) for path in raw_paths)
        if not paths or len(paths) != len(set(paths)) or _paths_overlap(paths):
            raise BridgeFailure("policy-invalid")
        _validate_lifecycle_paths(turn_kind, paths)
        normalized[turn_kind] = list(paths)
        all_paths.extend((turn_kind, path) for path in paths)
    implementation = normalized["implementation"]
    if implementation != policy["implementation_writable_paths"]:
        raise BridgeFailure("policy-invalid")
    semantic_paths = {
        "contract-author": [artifacts["issue_contract_path"]],
        "design-author": list(artifacts["controller_design_paths"]),
        "reviewer": [
            artifacts["review_verdict_path"],
            artifacts["review_findings_path"],
        ],
    }
    if any(normalized[turn_kind] != paths for turn_kind, paths in semantic_paths.items()):
        raise BridgeFailure("policy-invalid")
    for index, (left_kind, left) in enumerate(all_paths):
        for right_kind, right in all_paths[index + 1 :]:
            if left_kind != right_kind and (
                _scope_contains(left, right) or _scope_contains(right, left)
            ):
                raise BridgeFailure("policy-invalid")
    return normalized


def validate_bridge_authority_policy(manifest: Mapping[str, Any]) -> None:
    """Validate controller-supplied policy before guest state is consumed."""
    policy = _execution_policy(manifest.get("execution_policy"))
    artifacts = _phase_artifacts(manifest.get("phase_artifacts"))
    _phase_writable_paths(
        manifest.get("phase_writable_paths"),
        policy=policy,
        artifacts=artifacts,
    )


def _model_auth_volume(config: BridgeConfig) -> str:
    """Return the fixed Claude credential-directory mount."""
    source = _private_automation_directory(
        config, _MODEL_AUTH_DIR, reason="model-auth-invalid", require_empty=False
    )
    return f"{source}:{_MODEL_AUTH_TARGET}"


def _model_auth_volumes(config: BridgeConfig) -> tuple[str, str]:
    """Return the complete fixed Claude credential mounts."""
    directory = _model_auth_volume(config)
    _read_regular_path(
        _MODEL_AUTH_FILE,
        max_bytes=1024 * 1024,
        expected_uid=config.root_uid,
        exact_mode=0o600,
        reason="model-auth-invalid",
    )
    return directory, f"{_MODEL_AUTH_FILE}:{_MODEL_AUTH_FILE_TARGET}"


def _automated_leash_environment(config: BridgeConfig) -> dict[str, str]:
    """Prevent persisted Leash settings from contributing implicit container mounts."""
    leash_home = _private_automation_directory(
        config, _LEASH_HOME, reason="leash-home-invalid", require_empty=True
    )
    environment = _bounded_environment()
    environment["HOME"] = str(leash_home)
    environment["LEASH_HOME"] = str(leash_home)
    environment["LEASH_DISABLE_TELEMETRY"] = "1"
    return environment


def _compile_probe_policy(
    config: BridgeConfig, *, workspace: Path, control: Path
) -> bytes:
    """Add only the fixed probe grants/denials to the installed policy."""
    if (
        not isinstance(workspace, Path)
        or not isinstance(control, Path)
        or not workspace.is_absolute()
        or control.parent != workspace
        or re.fullmatch(r"\.aifactory-probe-[0-9a-f]{16}", control.name) is None
    ):
        raise BridgeFailure("probe-policy-invalid")
    base = _root_owned_regular_bytes(config.policy_path, config.root_uid)
    if config.policy_path != config.leash_policy_path:
        raise BridgeFailure("policy-inode-mismatch")
    denials = [
        'forbid(principal, action == Action::"ProcessExec", '
        f"resource == File::{json.dumps(path)});"
        for path in _PROBE_PROCESS_PATHS.values()
    ]
    denials.extend(
        'forbid(principal, action in [Action::"FileOpen", '
        'Action::"FileOpenReadOnly", Action::"FileOpenReadWrite"], '
        f"resource == File::{json.dumps(path)});"
        for path in sorted(set(_PROBE_FIXED_FILE_PATHS.values()))
    )
    grants = [
        'permit(principal, action in [Action::"FileOpen", Action::"FileOpenReadOnly"], '
        f"resource) when {{ resource in [Dir::{json.dumps(str(workspace) + '/')}] }};",
        'permit(principal, action == Action::"FileOpenReadWrite", resource) when { '
        f"resource in [Dir::{json.dumps(str(control) + '/')}] }};",
        'permit(principal, action == Action::"NetworkConnect", resource) when { resource in [ '
        + ", ".join(
            f'Host::{json.dumps(host + ":443")}'
            for host in (*_MODEL_ENDPOINTS, "192.0.2.1")
        )
        + " ] };",
    ]
    return (
        ("\n".join(denials) + "\n").encode("utf-8")
        + base
        + b"\n"
        + ("\n".join(grants) + "\n").encode("utf-8")
    )


def _event_timestamp(value: object) -> float:
    if type(value) is not str or len(value) > 64 or not value.endswith("Z"):
        raise BridgeFailure("probe-events-invalid")
    try:
        parsed = datetime.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise BridgeFailure("probe-events-invalid") from None
    if parsed.tzinfo is None:
        raise BridgeFailure("probe-events-invalid")
    return parsed.timestamp()


def _authenticate_probe_boundary_items(
    items: object,
    *,
    expected_ids: tuple[str, ...],
    manager_events: object,
    expected_paths: Mapping[str, str] | None = None,
    expected_pid: str | None = None,
    expected_cgroup: str | None = None,
    expected_exe: str | None = None,
    expected_not_before: float | None = None,
) -> tuple[dict[str, str], ...]:
    """Authenticate non-network denials; child errno is never denial evidence."""
    normalized = _normalize_probe_items(items, expected_ids)
    if type(manager_events) not in {list, tuple}:
        raise BridgeFailure("probe-events-invalid")
    paths = {**_PROBE_PROCESS_PATHS, **_PROBE_FIXED_FILE_PATHS}
    if expected_paths is not None:
        paths.update(expected_paths)

    def expected_events(item: Mapping[str, str]) -> set[str]:
        if item["category"] == "process":
            return {"proc.exec"}
        if item["category"] == "tamper":
            return {"file.open:rw", "file.open"}
        return {"file.open:ro", "file.open"}

    relevant = {
        (event, paths[item["id"]])
        for item in normalized
        if item["expectation"] != "allowed" and item["id"] in paths
        for event in expected_events(item)
    }
    events: list[Mapping[str, Any]] = []
    consumed: set[int] = set()
    for event in manager_events:
        if (
            not isinstance(event, Mapping)
            or not {"event", "path", "decision"}.issubset(event)
            or event.get("event") not in {"proc.exec", "file.open", "file.open:ro", "file.open:rw"}
            or event.get("decision") not in {"allowed", "denied"}
            or type(event.get("path")) is not str
        ):
            raise BridgeFailure("probe-events-invalid")
        if expected_pid is not None and (
            not str(event.get("pid", "")).isdigit()
            or event.get("cgroup") != expected_cgroup
            or event.get("exe") != expected_exe
            or type(event.get("time")) is not str
            or (
                expected_not_before is not None
                and not expected_not_before <= _event_timestamp(event["time"]) <= time.time() + 5
            )
        ):
            raise BridgeFailure("probe-events-invalid")
        if (
            expected_pid is not None
            and (event["event"], event["path"]) in relevant
            and event["event"] != "proc.exec"
            and event.get("pid") != expected_pid
        ):
            raise BridgeFailure("probe-events-invalid")
        events.append(event)
    for item in normalized:
        if item["expectation"] == "allowed":
            if item["observed"] != "succeeded":
                raise BridgeFailure("probe-positive-failed")
            continue
        if item["observed"] == "succeeded":
            raise BridgeFailure("probe-boundary-failed")
        if item["observed"] == "absent":
            continue
        expected_path = paths.get(item["id"])
        item_events = expected_events(item)
        matches = [
            event for event in events
            if event.get("event") in item_events and event.get("path") == expected_path
        ]
        if expected_path is None or len(matches) != 1 or matches[0].get("decision") != "denied":
            raise BridgeFailure("probe-evidence-ambiguous")
        consumed.add(id(matches[0]))
    if any(
        (event["event"], event["path"]) in relevant and id(event) not in consumed
        for event in events
    ):
        raise BridgeFailure("probe-evidence-ambiguous")
    return normalized


def _compile_probe_firewall(
    *,
    table: object,
    bridge_interface: object,
    source_ipv4: object,
    source_mac: object,
    dns_ipv4: object,
    model_ipv4: object,
) -> bytes:
    """Compile the only accepted nftables program for one probe namespace."""
    try:
        if type(table) is not str or _PROBE_TABLE.fullmatch(table) is None:
            raise ValueError
        if (
            type(bridge_interface) is not str
            or _NETWORK_INTERFACE.fullmatch(bridge_interface) is None
        ):
            raise ValueError
        if type(source_ipv4) is not str:
            raise ValueError
        source = ipaddress.IPv4Address(source_ipv4)
        if not source.is_private or source.is_loopback or source.is_link_local:
            raise ValueError
        if type(source_mac) is not str or _MAC_ADDRESS.fullmatch(source_mac) is None:
            raise ValueError
        if type(dns_ipv4) is not tuple or not dns_ipv4 or len(dns_ipv4) > 4:
            raise ValueError
        dns = tuple(str(ipaddress.IPv4Address(value)) for value in dns_ipv4)
        if len(dns) != len(set(dns)):
            raise ValueError
        if type(model_ipv4) is not tuple or not model_ipv4 or len(model_ipv4) > 32:
            raise ValueError
        models = tuple(str(ipaddress.IPv4Address(value)) for value in model_ipv4)
        if len(models) != len(set(models)) or any(
            not ipaddress.IPv4Address(value).is_global for value in models
        ):
            raise ValueError
    except (ipaddress.AddressValueError, ValueError, TypeError):
        raise BridgeFailure("probe-network-shape-invalid") from None
    prefix = (
        f'  iifname "{bridge_interface}" ether saddr {source_mac} '
        f"ip saddr {source_ipv4} "
    )
    lines = [
        f"delete table inet {table}",
        f"table inet {table} {{",
        " counter probe_drop {}",
        " chain probe_forward {",
        "  type filter hook forward priority -200; policy accept;",
    ]
    for index, destination in enumerate(dns):
        lines.append(
            prefix
            + f'ip daddr {destination} udp dport 53 counter accept comment "aifp:dns-udp:{index}"'
        )
        lines.append(
            prefix
            + f'ip daddr {destination} tcp dport 53 counter accept comment "aifp:dns-tcp:{index}"'
        )
    lines.extend(
        (
            prefix
            + "ip daddr { "
            + ", ".join(models)
            + ' } tcp dport 443 counter accept comment "aifp:model-443"',
            prefix
            + 'meta nfproto ipv4 counter name probe_drop drop comment "aifp:drop-v4"',
            f'  iifname "{bridge_interface}" ether saddr {source_mac} '
            'meta nfproto ipv6 counter name probe_drop drop comment "aifp:drop-v6"',
            " }",
            " chain probe_input {",
            "  type filter hook input priority -200; policy accept;",
        )
    )
    for index, destination in enumerate(dns):
        lines.append(
            prefix
            + f'ip daddr {destination} udp dport 53 counter accept comment '
            f'"aifp:input-dns-udp:{index}"'
        )
        lines.append(
            prefix
            + f'ip daddr {destination} tcp dport 53 counter accept comment '
            f'"aifp:input-dns-tcp:{index}"'
        )
    lines.extend(
        (
            prefix
            + 'meta nfproto ipv4 counter name probe_drop drop comment "aifp:input-drop-v4"',
            f'  iifname "{bridge_interface}" ether saddr {source_mac} '
            'meta nfproto ipv6 counter name probe_drop drop comment "aifp:input-drop-v6"',
            " }",
            "}",
        )
    )
    return ("\n".join(lines) + "\n").encode("ascii")


def _compile_probe_bootstrap_firewall(*, table: object, bridge_interface: object) -> bytes:
    """Quarantine all forwarding from the authenticated Docker bridge pre-launch."""
    if (
        type(table) is not str
        or _PROBE_TABLE.fullmatch(table) is None
        or type(bridge_interface) is not str
        or _NETWORK_INTERFACE.fullmatch(bridge_interface) is None
    ):
        raise BridgeFailure("probe-network-shape-invalid")
    return (
        f"table inet {table} {{\n"
        " chain probe_forward {\n"
        "  type filter hook forward priority -300; policy accept;\n"
        f'  iifname "{bridge_interface}" meta nfproto ipv4 counter drop '
        'comment "aifp:bootstrap-v4"\n'
        f'  iifname "{bridge_interface}" meta nfproto ipv6 counter drop '
        'comment "aifp:bootstrap-v6"\n'
        " }\n"
        " chain probe_input {\n"
        "  type filter hook input priority -300; policy accept;\n"
        f'  iifname "{bridge_interface}" meta nfproto ipv4 counter drop '
        'comment "aifp:input-bootstrap-v4"\n'
        f'  iifname "{bridge_interface}" meta nfproto ipv6 counter drop '
        'comment "aifp:input-bootstrap-v6"\n'
        " }\n"
        "}\n"
    ).encode("ascii")


def _compile_probe_dns_bootstrap_firewall(
    *, table: object, bridge_interface: object, dns_ipv4: object
) -> bytes:
    """Atomically upgrade quarantine to DNS-only egress before Leash launch."""
    try:
        if (
            type(table) is not str
            or _PROBE_TABLE.fullmatch(table) is None
            or type(bridge_interface) is not str
            or _NETWORK_INTERFACE.fullmatch(bridge_interface) is None
            or type(dns_ipv4) is not tuple
            or not 1 <= len(dns_ipv4) <= 4
        ):
            raise ValueError
        dns = tuple(str(ipaddress.IPv4Address(value)) for value in dns_ipv4)
        if len(dns) != len(set(dns)) or any(
            ipaddress.IPv4Address(value).is_loopback for value in dns
        ):
            raise ValueError
    except (ipaddress.AddressValueError, TypeError, ValueError):
        raise BridgeFailure("probe-dns-shape-invalid") from None
    lines = [
        f"delete table inet {table}",
        f"table inet {table} {{",
        " chain probe_forward {",
        "  type filter hook forward priority -300; policy accept;",
    ]
    for index, destination in enumerate(dns):
        for protocol in ("udp", "tcp"):
            lines.append(
                f'  iifname "{bridge_interface}" ip daddr {destination} '
                f'{protocol} dport 53 counter accept comment '
                f'"aifp:bootstrap-dns-{protocol}:{index}"'
            )
    lines.extend(
        (
            f'  iifname "{bridge_interface}" meta nfproto ipv4 counter drop '
            'comment "aifp:bootstrap-v4"',
            f'  iifname "{bridge_interface}" meta nfproto ipv6 counter drop '
            'comment "aifp:bootstrap-v6"',
            " }",
            " chain probe_input {",
            "  type filter hook input priority -300; policy accept;",
        )
    )
    for index, destination in enumerate(dns):
        for protocol in ("udp", "tcp"):
            lines.append(
                f'  iifname "{bridge_interface}" ip daddr {destination} '
                f'{protocol} dport 53 counter accept comment '
                f'"aifp:input-bootstrap-dns-{protocol}:{index}"'
            )
    lines.extend(
        (
            f'  iifname "{bridge_interface}" meta nfproto ipv4 counter drop '
            'comment "aifp:input-bootstrap-v4"',
            f'  iifname "{bridge_interface}" meta nfproto ipv6 counter drop '
            'comment "aifp:input-bootstrap-v6"',
            " }",
            "}",
        )
    )
    return ("\n".join(lines) + "\n").encode("ascii")


def _parse_manager_network_events(raw: bytes) -> tuple[dict[str, str], ...]:
    """Parse only manager-owned Leash 1.1.7 net.send decisions."""
    if type(raw) is not bytes or len(raw) > _MAX_PROBE_LOG_BYTES:
        raise BridgeFailure("probe-events-invalid")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise BridgeFailure("probe-events-invalid") from None
    events: list[dict[str, str]] = []
    for line in text.splitlines():
        if "event=net.send" not in line:
            continue
        if not line or len(line.encode("utf-8")) > 4096:
            raise BridgeFailure("probe-events-invalid")
        try:
            tokens = shlex.split(line, comments=False, posix=True)
        except ValueError:
            raise BridgeFailure("probe-events-invalid") from None
        fields: dict[str, str] = {}
        for token in tokens:
            if "=" not in token:
                raise BridgeFailure("probe-events-invalid")
            key, value = token.split("=", 1)
            if not key or key in fields:
                raise BridgeFailure("probe-events-invalid")
            fields[key] = value
        required = {"time", "event", "pid", "cgroup", "exe", "protocol", "addr", "decision"}
        _event_timestamp(fields.get("time"))
        if (
            set(fields) not in {frozenset(required), frozenset(required | {"hostname"})}
            or fields["event"] != "net.send"
            or not fields["pid"].isascii()
            or not fields["pid"].isdigit()
            or not fields["cgroup"].isascii()
            or not fields["cgroup"].isdigit()
            or not fields["exe"]
            or len(fields["exe"]) > 128
            or contains_control_characters(fields["exe"])
            or fields["protocol"] != "tcp"
            or fields["decision"] not in {"allowed", "denied"}
        ):
            raise BridgeFailure("probe-events-invalid")
        try:
            address, port = fields["addr"].rsplit(":", 1)
            ipaddress.IPv4Address(address)
            if not port.isascii() or not port.isdigit() or not 1 <= int(port) <= 65535:
                raise ValueError
        except (ipaddress.AddressValueError, ValueError):
            raise BridgeFailure("probe-events-invalid") from None
        hostname = fields.get("hostname", "")
        if hostname and (
            len(hostname) > 253 or any(ord(character) < 33 for character in hostname)
        ):
            raise BridgeFailure("probe-events-invalid")
        event = {
            "time": fields["time"],
            "pid": fields["pid"],
            "cgroup": fields["cgroup"],
            "exe": fields["exe"],
            "addr": fields["addr"],
            "decision": fields["decision"],
            "hostname": hostname,
            "protocol": "tcp",
        }
        events.append(event)
    return tuple(events)


def _nft_document(raw: bytes, reason: str) -> list[dict[str, Any]]:
    if type(raw) is not bytes or not raw or len(raw) > 256 * 1024:
        raise BridgeFailure(reason)
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise BridgeFailure(reason) from None
    if type(document) is not dict or set(document) != {"nftables"}:
        raise BridgeFailure(reason)
    entries = document["nftables"]
    if type(entries) is not list or not entries or len(entries) > 128:
        raise BridgeFailure(reason)
    if any(type(entry) is not dict or len(entry) != 1 for entry in entries):
        raise BridgeFailure(reason)
    return entries


def _authenticate_nft_table(
    raw: bytes,
    *,
    table: str,
    bridge_interface: str,
    source_ipv4: str,
    source_mac: str,
    dns_ipv4: tuple[str, ...],
    model_ipv4: tuple[str, ...],
) -> None:
    dns_count = len(dns_ipv4)
    if (
        _PROBE_TABLE.fullmatch(table) is None
        or _NETWORK_INTERFACE.fullmatch(bridge_interface) is None
        or _MAC_ADDRESS.fullmatch(source_mac) is None
        or type(dns_ipv4) is not tuple
        or not 1 <= dns_count <= 4
        or type(model_ipv4) is not tuple
        or not model_ipv4
    ):
        raise BridgeFailure("probe-firewall-invalid")
    entries = _nft_document(raw, "probe-firewall-invalid")
    tables: list[Mapping[str, Any]] = []
    chains: list[Mapping[str, Any]] = []
    counters: list[Mapping[str, Any]] = []
    rules: list[Mapping[str, Any]] = []
    for entry in entries:
        kind, body = next(iter(entry.items()))
        if kind == "metainfo":
            if not isinstance(body, Mapping):
                raise BridgeFailure("probe-firewall-invalid")
            continue
        if not isinstance(body, Mapping):
            raise BridgeFailure("probe-firewall-invalid")
        if "handle" in body and (type(body["handle"]) is not int or body["handle"] <= 0):
            raise BridgeFailure("probe-firewall-invalid")
        if kind == "table":
            if not set(body).issubset({"family", "name", "handle"}):
                raise BridgeFailure("probe-firewall-invalid")
            tables.append(body)
        elif kind == "chain":
            if not set(body).issubset(
                {"family", "table", "name", "type", "hook", "prio", "policy", "handle"}
            ):
                raise BridgeFailure("probe-firewall-invalid")
            chains.append(body)
        elif kind == "counter":
            if not set(body).issubset(
                {"family", "table", "name", "packets", "bytes", "handle"}
            ):
                raise BridgeFailure("probe-firewall-invalid")
            counters.append(body)
        elif kind == "rule":
            if not set(body).issubset(
                {"family", "table", "chain", "comment", "expr", "handle"}
            ):
                raise BridgeFailure("probe-firewall-invalid")
            rules.append(body)
        else:
            raise BridgeFailure("probe-firewall-invalid")
    expected_comments = {
        *(f"aifp:dns-udp:{index}" for index in range(dns_count)),
        *(f"aifp:dns-tcp:{index}" for index in range(dns_count)),
        "aifp:model-443",
        "aifp:drop-v4",
        "aifp:drop-v6",
        *(f"aifp:input-dns-udp:{index}" for index in range(dns_count)),
        *(f"aifp:input-dns-tcp:{index}" for index in range(dns_count)),
        "aifp:input-drop-v4",
        "aifp:input-drop-v6",
    }
    expected_chains = {
        "probe_forward": ("forward", -200),
        "probe_input": ("input", -200),
    }
    if (
        len(tables) != 1
        or tables[0].get("family") != "inet"
        or tables[0].get("name") != table
        or len(chains) != 2
        or {
            chain.get("name"): (chain.get("hook"), chain.get("prio")) for chain in chains
        } != expected_chains
        or any(
            chain.get("family") != "inet"
            or chain.get("table") != table
            or chain.get("type") != "filter"
            or chain.get("policy") != "accept"
            for chain in chains
        )
        or len(counters) != 1
        or any(
            counters[0].get(key) != value
            for key, value in {
                "family": "inet",
                "table": table,
                "name": "probe_drop",
            }.items()
        )
        or len(rules) != len(expected_comments)
        or {rule.get("comment") for rule in rules} != expected_comments
        or any(
            rule.get("family") != "inet"
            or rule.get("table") != table
            or rule.get("chain") != (
                "probe_input"
                if str(rule.get("comment", "")).startswith("aifp:input-")
                else "probe_forward"
            )
            or not _valid_probe_nft_expression(
                rule.get("comment"),
                rule.get("expr"),
                bridge_interface=bridge_interface,
                source_ipv4=source_ipv4,
                source_mac=source_mac,
                dns_ipv4=dns_ipv4,
                model_ipv4=model_ipv4,
            )
            for rule in rules
        )
    ):
        raise BridgeFailure("probe-firewall-invalid")


def _authenticate_probe_bootstrap_firewall(
    raw: bytes, *, table: str, bridge_interface: str
) -> None:
    _authenticate_probe_quarantine_firewall(
        raw, table=table, bridge_interface=bridge_interface, dns_ipv4=None
    )


def _authenticate_probe_dns_bootstrap_firewall(
    raw: bytes,
    *,
    table: str,
    bridge_interface: str,
    dns_ipv4: tuple[str, ...],
) -> None:
    _authenticate_probe_quarantine_firewall(
        raw, table=table, bridge_interface=bridge_interface, dns_ipv4=dns_ipv4
    )


def _authenticate_probe_quarantine_firewall(
    raw: bytes,
    *,
    table: str,
    bridge_interface: str,
    dns_ipv4: tuple[str, ...] | None,
) -> None:
    try:
        if (
            _PROBE_TABLE.fullmatch(table) is None
            or _NETWORK_INTERFACE.fullmatch(bridge_interface) is None
            or (
                dns_ipv4 is not None
                and (
                    type(dns_ipv4) is not tuple
                    or not 1 <= len(dns_ipv4) <= 4
                )
            )
        ):
            raise ValueError
        dns = (
            ()
            if dns_ipv4 is None
            else tuple(str(ipaddress.IPv4Address(value)) for value in dns_ipv4)
        )
        if len(dns) != len(set(dns)):
            raise ValueError
    except (TypeError, ValueError, ipaddress.AddressValueError):
        raise BridgeFailure("probe-firewall-invalid") from None

    objects: dict[str, list[dict[str, Any]]] = {"table": [], "chain": [], "rule": []}
    for entry in _nft_document(raw, "probe-firewall-invalid"):
        kind, body = next(iter(entry.items()))
        if kind == "metainfo":
            if not isinstance(body, Mapping):
                raise BridgeFailure("probe-firewall-invalid")
            continue
        if kind not in objects or not isinstance(body, Mapping):
            raise BridgeFailure("probe-firewall-invalid")
        normalized = dict(body)
        handle = normalized.pop("handle", None)
        if handle is not None and (type(handle) is not int or handle <= 0):
            raise BridgeFailure("probe-firewall-invalid")
        objects[kind].append(normalized)
    expected_chains = [
        {
            "family": "inet", "table": table, "name": "probe_forward",
            "type": "filter", "hook": "forward", "prio": -300, "policy": "accept",
        },
        {
            "family": "inet", "table": table, "name": "probe_input",
            "type": "filter", "hook": "input", "prio": -300, "policy": "accept",
        },
    ]
    if (
        objects["table"] != [{"family": "inet", "name": table}]
        or objects["chain"] != expected_chains
        or len(objects["rule"]) != 4 * len(dns) + 4
    ):
        raise BridgeFailure("probe-firewall-invalid")

    expected_comments = {
        "aifp:bootstrap-v4",
        "aifp:bootstrap-v6",
        *(f"aifp:bootstrap-dns-{protocol}:{index}"
          for index in range(len(dns)) for protocol in ("udp", "tcp")),
        "aifp:input-bootstrap-v4",
        "aifp:input-bootstrap-v6",
        *(f"aifp:input-bootstrap-dns-{protocol}:{index}"
          for index in range(len(dns)) for protocol in ("udp", "tcp")),
    }
    by_comment = {rule.get("comment"): rule for rule in objects["rule"]}
    if set(by_comment) != expected_comments or len(by_comment) != len(objects["rule"]):
        raise BridgeFailure("probe-firewall-invalid")

    def match(protocol: str, field: str, right: object) -> dict[str, Any]:
        left = (
            {"meta": {"key": field}}
            if protocol == "meta"
            else {"payload": {"protocol": protocol, "field": field}}
        )
        return {"match": {"op": "==", "left": left, "right": right}}

    for comment, rule in by_comment.items():
        input_rule = str(comment).startswith("aifp:input-")
        normalized_comment = str(comment).replace("aifp:input-", "aifp:", 1)
        if any(
            rule.get(key) != value
            for key, value in {
                "family": "inet",
                "table": table,
                "chain": "probe_input" if input_rule else "probe_forward",
            }.items()
        ):
            raise BridgeFailure("probe-firewall-invalid")
        if normalized_comment.startswith("aifp:bootstrap-dns-"):
            try:
                protocol = "udp" if "-udp:" in normalized_comment else "tcp"
                index = int(normalized_comment.rsplit(":", 1)[1])
                expected = [
                    match("meta", "iifname", bridge_interface),
                    match("ip", "daddr", dns[index]),
                    match(protocol, "dport", 53),
                ]
                terminal = {"accept": None}
            except (IndexError, ValueError):
                raise BridgeFailure("probe-firewall-invalid") from None
        else:
            expected = [
                match("meta", "iifname", bridge_interface),
                match(
                    "meta", "nfproto",
                    "ipv4" if normalized_comment.endswith("v4") else "ipv6",
                ),
            ]
            terminal = {"drop": None}
        expression = rule.get("expr")
        if (
            type(expression) is not list
            or len(expression) != len(expected) + 2
            or expression[:len(expected)] != expected
        ):
            raise BridgeFailure("probe-firewall-invalid")
        counter = expression[-2].get("counter") if isinstance(expression[-2], Mapping) else None
        if (
            not isinstance(counter, Mapping)
            or set(counter) != {"packets", "bytes"}
            or any(type(counter[key]) is not int or counter[key] < 0 for key in counter)
            or expression[-1] != terminal
        ):
            raise BridgeFailure("probe-firewall-invalid")

def _valid_probe_nft_expression(
    comment: object,
    expression: object,
    *,
    bridge_interface: str,
    source_ipv4: str,
    source_mac: str,
    dns_ipv4: tuple[str, ...],
    model_ipv4: tuple[str, ...],
) -> bool:
    if type(comment) is not str or type(expression) is not list:
        return False
    normalized_comment = comment.replace("aifp:input-", "aifp:", 1)
    if normalized_comment == "aifp:model-443" and comment.startswith("aifp:input-"):
        return False
    expected_matches = (
        5
        if normalized_comment.startswith("aifp:dns-")
        or normalized_comment == "aifp:model-443"
        else (4 if normalized_comment == "aifp:drop-v4" else 3)
    )
    expected_length = expected_matches + 2
    if len(expression) != expected_length or any(
        type(item) is not dict or len(item) != 1 for item in expression
    ):
        return False
    matches = expression[:expected_matches]
    selectors: list[tuple[str, str, object]] = []
    for item in matches:
        body = item.get("match")
        if not isinstance(body, Mapping) or set(body) != {"op", "left", "right"}:
            return False
        if body.get("op") != "==" or not isinstance(body.get("left"), Mapping):
            return False
        left = body["left"]
        if set(left) not in ({"meta"}, {"payload"}):
            return False
        selector = left.get("meta", left.get("payload"))
        if not isinstance(selector, Mapping):
            return False
        if set(left) == {"meta"}:
            if set(selector) != {"key"} or selector.get("key") not in {"iifname", "nfproto"}:
                return False
            selectors.append(("meta", selector["key"], body["right"]))
        elif (
            set(selector) != {"protocol", "field"}
            or (selector.get("protocol"), selector.get("field"))
            not in {
                ("ether", "saddr"),
                ("ip", "saddr"),
                ("ip", "daddr"),
                ("udp", "dport"),
                ("tcp", "dport"),
            }
        ):
            return False
        else:
            selectors.append((selector["protocol"], selector["field"], body["right"]))
    protocol = "udp" if normalized_comment.startswith("aifp:dns-udp:") else "tcp"
    expected_selectors = (
        [("meta", "iifname"), ("ether", "saddr"), ("ip", "saddr"), ("ip", "daddr"), (protocol, "dport")]
        if normalized_comment.startswith("aifp:dns-")
        or normalized_comment == "aifp:model-443"
        else (
            [("meta", "iifname"), ("ether", "saddr"), ("ip", "saddr"), ("meta", "nfproto")]
            if normalized_comment == "aifp:drop-v4"
            else [("meta", "iifname"), ("ether", "saddr"), ("meta", "nfproto")]
        )
    )
    if [(kind, field) for kind, field, _right in selectors] != expected_selectors:
        return False
    try:
        if selectors[0][2] != bridge_interface:
            return False
        if selectors[1][2] != source_mac:
            return False
        offset = 2
        if normalized_comment != "aifp:drop-v6":
            if selectors[offset][2] != source_ipv4:
                return False
            offset += 1
        if normalized_comment.startswith("aifp:dns-"):
            index = int(normalized_comment.rsplit(":", 1)[1])
            if selectors[offset][2] != dns_ipv4[index] or selectors[offset + 1][2] != 53:
                return False
        elif normalized_comment == "aifp:model-443":
            destinations = selectors[offset][2]
            if (
                (
                    destinations != {"set": list(model_ipv4)}
                    and not (len(model_ipv4) == 1 and destinations == model_ipv4[0])
                )
                or selectors[offset + 1][2] != 443
            ):
                return False
        elif selectors[offset][2] != (
            "ipv4" if normalized_comment == "aifp:drop-v4" else "ipv6"
        ):
            return False
    except (IndexError, TypeError, ValueError, ipaddress.AddressValueError):
        return False
    terminal = expression[expected_matches:]
    if normalized_comment in {"aifp:drop-v4", "aifp:drop-v6"}:
        return terminal[-1] == {"drop": None} and terminal[0] in (
            {"counter": {"name": "probe_drop"}},
            {"counter": "probe_drop"},
        )
    if terminal[-1] != {"accept": None} or set(terminal[0]) != {"counter"}:
        return False
    counter = terminal[0]["counter"]
    return counter is None or (
        isinstance(counter, Mapping)
        and set(counter) == {"packets", "bytes"}
        and all(type(counter[key]) is int and 0 <= counter[key] <= 2**63 - 1 for key in counter)
    )


def _parse_nft_drop_counter(raw: bytes, *, table: str) -> int:
    if _PROBE_TABLE.fullmatch(table) is None:
        raise BridgeFailure("probe-firewall-counter-invalid")
    entries = _nft_document(raw, "probe-firewall-counter-invalid")
    counters = [entry["counter"] for entry in entries if "counter" in entry]
    if len(counters) != 1 or any(
        key in entry for entry in entries for key in entry if key not in {"metainfo", "counter"}
    ):
        raise BridgeFailure("probe-firewall-counter-invalid")
    counter = counters[0]
    if (
        not isinstance(counter, Mapping)
        or counter.get("family") != "inet"
        or counter.get("table") != table
        or counter.get("name") != "probe_drop"
        or type(counter.get("packets")) is not int
        or isinstance(counter.get("packets"), bool)
        or not 0 <= counter["packets"] <= 2**63 - 1
        or type(counter.get("bytes")) is not int
        or isinstance(counter.get("bytes"), bool)
        or not 0 <= counter["bytes"] <= 2**63 - 1
    ):
        raise BridgeFailure("probe-firewall-counter-invalid")
    return counter["packets"]


def _normalize_probe_items(
    value: object, expected_ids: tuple[str, ...]
) -> tuple[dict[str, str], ...]:
    """Authenticate a closed, ordered child-evidence schema."""
    if (
        type(value) not in {list, tuple}
        or type(expected_ids) is not tuple
        or not expected_ids
        or len(value) != len(expected_ids)
    ):
        raise BridgeFailure("probe-evidence-invalid")
    normalized: list[dict[str, str]] = []
    for expected_id, raw in zip(expected_ids, value, strict=True):
        if not isinstance(raw, Mapping) or set(raw) != {
            "id",
            "category",
            "expectation",
            "observed",
            "reason",
        }:
            raise BridgeFailure("probe-evidence-invalid")
        item = dict(raw)
        if (
            item.get("id") != expected_id
            or item.get("category") not in {"filesystem", "network", "process", "tamper"}
            or item.get("expectation") not in {"allowed", "denied", "denied-or-absent", "outer-denied"}
            or item.get("observed") not in {"succeeded", "failed", "absent"}
            or item.get("reason")
            not in {
                "none",
                "not-found",
                "permission-error",
                "os-error",
                "timeout",
                "nonzero-exit",
                "network-error",
                "content-mismatch",
            }
            or any(type(child) is not str for child in item.values())
        ):
            raise BridgeFailure("probe-evidence-invalid")
        normalized.append(item)  # type: ignore[arg-type]
    try:
        encoded = json.dumps(
            normalized, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise BridgeFailure("probe-evidence-invalid") from None
    if len(encoded) > _MAX_NORMALIZED_PROBE_BYTES:
        raise BridgeFailure("probe-evidence-invalid")
    return tuple(normalized)


def _probe_expected_addresses(
    endpoint_ipv4: Mapping[str, object], probe_ids: tuple[str, ...]
) -> dict[str, str]:
    if (
        not isinstance(endpoint_ipv4, Mapping)
        or type(probe_ids) is not tuple
        or not probe_ids
        or len(probe_ids) != len(set(probe_ids))
        or any(probe_id not in _NETWORK_PROBE_TARGETS for probe_id in probe_ids)
    ):
        raise BridgeFailure("probe-network-evidence-invalid")
    result: dict[str, str] = {}
    for probe_id in probe_ids:
        mode, target, _port, _decision = _NETWORK_PROBE_TARGETS[probe_id]
        if mode == "hostname":
            candidates = endpoint_ipv4.get(target)
            if type(candidates) not in {list, tuple} or not candidates:
                raise BridgeFailure("probe-network-evidence-invalid")
            address = candidates[0]
        else:
            address = target
        if type(address) is not str:
            raise BridgeFailure("probe-network-evidence-invalid")
        try:
            parsed = ipaddress.IPv4Address(address)
        except ipaddress.AddressValueError:
            raise BridgeFailure("probe-network-evidence-invalid") from None
        if mode == "hostname" and not parsed.is_global:
            raise BridgeFailure("probe-network-evidence-invalid")
        result[probe_id] = address
    return result


def _authenticate_network_evidence(
    items: object,
    events: object,
    *,
    drop_before: object,
    drop_after: object,
    expected_addresses: Mapping[str, str],
    expected_ids: tuple[str, ...] | None = None,
    expected_pid: str | None = None,
    expected_cgroup: str | None = None,
    expected_exe: str | None = None,
    expected_not_before: float | None = None,
) -> tuple[dict[str, str], ...]:
    """Bind child outcomes to exact Leash decisions and the independent drop counter."""
    expected_ids = tuple(_NETWORK_PROBE_TARGETS) if expected_ids is None else expected_ids
    if not expected_ids or any(probe_id not in _NETWORK_PROBE_TARGETS for probe_id in expected_ids):
        raise BridgeFailure("probe-network-evidence-invalid")
    normalized = _normalize_probe_items(items, expected_ids)
    if (
        type(events) not in {list, tuple}
        or len(events) != len(expected_ids)
        or type(drop_before) is not int
        or isinstance(drop_before, bool)
        or type(drop_after) is not int
        or isinstance(drop_after, bool)
        or not 0 <= drop_before <= drop_after <= 2**63 - 1
        or not isinstance(expected_addresses, Mapping)
        or set(expected_addresses) != set(expected_ids)
    ):
        raise BridgeFailure("probe-network-evidence-invalid")
    for item, event in zip(normalized, events, strict=True):
        mode, target, port, decision = _NETWORK_PROBE_TARGETS[item["id"]]
        expected_address = expected_addresses[item["id"]]
        try:
            expected_ip = ipaddress.IPv4Address(expected_address)
        except (ipaddress.AddressValueError, ValueError):
            raise BridgeFailure("probe-network-evidence-invalid") from None
        if (mode == "address" and expected_address != target) or (
            mode == "hostname" and not expected_ip.is_global
        ):
            raise BridgeFailure("probe-network-evidence-invalid")
        if not isinstance(event, Mapping) or not {
            "protocol", "addr", "hostname", "decision"
        }.issubset(event):
            raise BridgeFailure("probe-network-evidence-invalid")
        if expected_pid is not None and (
            event.get("pid") != expected_pid
            or event.get("cgroup") != expected_cgroup
            or event.get("exe") != expected_exe
            or type(event.get("time")) is not str
            or (
                expected_not_before is not None
                and not expected_not_before
                <= _event_timestamp(event["time"])
                <= time.time() + 5
            )
        ):
            raise BridgeFailure("probe-network-evidence-invalid")
        try:
            address, raw_port = event["addr"].rsplit(":", 1)
            ipaddress.IPv4Address(address)
            event_port = int(raw_port)
        except (AttributeError, ipaddress.AddressValueError, ValueError):
            raise BridgeFailure("probe-network-evidence-invalid") from None
        if (
            event.get("protocol") != "tcp"
            or event_port != port
            or address != expected_address
            or type(event.get("hostname")) is not str
            or contains_control_characters(event["hostname"])
        ):
            raise BridgeFailure("probe-network-evidence-invalid")
        if item["id"] == "network-firewall-control":
            if (
                event["decision"] != "allowed"
                or item["observed"] != "failed"
                or drop_after <= drop_before
            ):
                raise BridgeFailure("probe-firewall-control-failed")
        elif decision == "allowed":
            if event["decision"] != "allowed" or item["observed"] != "succeeded":
                raise BridgeFailure("probe-network-positive-failed")
        elif event["decision"] != "denied" or item["observed"] == "succeeded":
            raise BridgeFailure("probe-network-policy-failed")
    return normalized


def _probe_runtime_names(request_id: object) -> dict[str, str]:
    if type(request_id) is not str or not request_id or contains_control_characters(request_id):
        raise BridgeFailure("probe-identity-invalid")
    token = hashlib.sha256(request_id.encode("utf-8")).hexdigest()[:16]
    return {
        "manager": f"aifp-{token}-leash",
        "resolver": f"aifp-{token}-resolver",
        "table": f"aifp_{token}",
        "target": f"aifp-{token}-target",
        "token": token,
    }


def _probe_leash_argv(
    config: BridgeConfig,
    *,
    workspace: Path,
    control: Path,
    policy: Path,
) -> list[str]:
    if not all(isinstance(path, Path) and path.is_absolute() for path in (workspace, control, policy)):
        raise BridgeFailure("probe-path-invalid")
    sealed = ExecutionBridge(config)._sealed_runtime()
    return [
        str(_LEASH_ENTRY),
        "--policy",
        str(policy),
        "--no-interactive",
        "--listen",
        "",
        "--leash-image",
        str(sealed["leash_image_reference"]),
        "--image",
        str(sealed["image_reference"]),
        "--env",
        "LEASH_DISABLE_TELEMETRY=1",
        *_probe_child_argv(control=control, workspace=workspace),
    ]


def _probe_child_argv(*, control: Path, workspace: Path) -> list[str]:
    if not all(isinstance(path, Path) and path.is_absolute() for path in (control, workspace)):
        raise BridgeFailure("probe-path-invalid")
    return [
        _PROBE_NODE,
        "--input-type=commonjs",
        "--eval",
        _PROBE_PROGRAM,
        str(control),
        str(workspace),
    ]


def _probe_resolver_argv(config: BridgeConfig, *, names: Mapping[str, str]) -> list[str]:
    if (
        set(names) != {"manager", "resolver", "table", "target", "token"}
        or any(type(value) is not str for value in names.values())
    ):
        raise BridgeFailure("probe-identity-invalid")
    image = ExecutionBridge(config)._sealed_runtime()["image_reference"]
    return [
        "docker",
        "run",
        "-d",
        "--pull=never",
        "--name",
        names["resolver"],
        "--network",
        "bridge",
        "--entrypoint",
        "/bin/cat",
        "--user",
        "65534:65534",
        "--read-only",
        "--cgroupns",
        "private",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        str(image),
        "/etc/resolv.conf",
    ]


def _probe_leash_environment(
    config: BridgeConfig, *, work_dir: Path, names: Mapping[str, str]
) -> dict[str, str]:
    if (
        not isinstance(work_dir, Path)
        or not work_dir.is_absolute()
        or set(names) != {"manager", "resolver", "table", "target", "token"}
        or any(type(value) is not str for value in names.values())
    ):
        raise BridgeFailure("probe-environment-invalid")
    environment = _automated_leash_environment(config)
    environment.update(
        {
            "LEASH_CONTAINER": names["manager"],
            "LEASH_WORK_DIR": str(work_dir),
            "TARGET_CONTAINER": names["target"],
        }
    )
    return environment


def _authenticate_probe_network_shape(
    target: object,
    manager: object,
    network: object,
    names: Mapping[str, str],
) -> dict[str, str]:
    try:
        if (
            not isinstance(target, Mapping)
            or not {"id", "name", "running", "network_mode", "ports", "networks"}.issubset(target)
            or not isinstance(manager, Mapping)
            or not {"id", "name", "running", "network_mode", "ports", "networks"}.issubset(manager)
            or not isinstance(network, Mapping)
            or set(network) != {
                "id", "name", "driver", "internal", "options", "subnets", "containers"
            }
            or set(names) != {"manager", "resolver", "table", "target", "token"}
        ):
            raise ValueError
        target_id = target["id"]
        manager_id = manager["id"]
        if (
            type(target_id) is not str
            or re.fullmatch(r"[0-9a-f]{64}", target_id) is None
            or type(manager_id) is not str
            or re.fullmatch(r"[0-9a-f]{64}", manager_id) is None
            or target["name"] != "/" + names["target"]
            or manager["name"] != "/" + names["manager"]
            or target["running"] is not True
            or manager["running"] is not True
            or target["network_mode"] not in {"default", "bridge"}
            or manager["network_mode"] not in {
                "container:" + target_id,
                "container:" + names["target"],
            }
            or target["ports"] != {}
            or manager["ports"] != {}
            or manager["networks"] != {}
            or not isinstance(target["networks"], Mapping)
            or set(target["networks"]) != {"bridge"}
            or network["id"] != target["networks"]["bridge"].get("NetworkID")
            or network["name"] != "bridge"
            or network["driver"] != "bridge"
            or network["internal"] is not False
            or not isinstance(network["options"], Mapping)
            or network["options"].get("com.docker.network.bridge.name") != "docker0"
            or not isinstance(network["subnets"], list)
            or len(network["subnets"]) != 1
        ):
            raise ValueError
        attachment = target["networks"]["bridge"]
        if not isinstance(attachment, Mapping) or set(attachment) != {
            "IPAddress",
            "GlobalIPv6Address",
            "MacAddress",
            "NetworkID",
        }:
            raise ValueError
        source = ipaddress.IPv4Address(attachment["IPAddress"])
        subnet = ipaddress.IPv4Network(network["subnets"][0], strict=True)
        mac = attachment["MacAddress"]
        if (
            source not in subnet
            or not source.is_private
            or attachment["GlobalIPv6Address"] != ""
            or type(mac) is not str
            or _MAC_ADDRESS.fullmatch(mac) is None
        ):
            raise ValueError
        membership = network["containers"]
        expected_membership = {
            target_id: {
                "name": names["target"],
                "endpoint_id": membership.get(target_id, {}).get("endpoint_id"),
                "mac_address": mac,
                "ipv4_address": f"{source}/{subnet.prefixlen}",
                "ipv6_address": "",
            }
        }
        endpoint_id = expected_membership[target_id]["endpoint_id"]
        if (
            not isinstance(membership, Mapping)
            or set(membership) != {target_id}
            or type(endpoint_id) is not str
            or re.fullmatch(r"[0-9a-f]{64}", endpoint_id) is None
            or membership != expected_membership
        ):
            raise ValueError
    except (AttributeError, KeyError, TypeError, ValueError, ipaddress.AddressValueError):
        raise BridgeFailure("probe-network-shape-invalid") from None
    return {
        "bridge_interface": "docker0",
        "source_ipv4": str(source),
        "source_mac": mac,
        "target_id": target_id,
        "manager_id": manager_id,
    }


def _resolve_model_ipv4s(
    *, resolve: Callable[..., list[tuple[Any, ...]]] = socket.getaddrinfo
) -> tuple[str, ...]:
    addresses: set[str] = set()
    try:
        for endpoint in _MODEL_ENDPOINTS:
            current: set[str] = set()
            for answer in resolve(
                endpoint,
                443,
                family=socket.AF_INET,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            ):
                if not isinstance(answer, tuple) or len(answer) != 5:
                    raise ValueError
                sockaddr = answer[4]
                if not isinstance(sockaddr, tuple) or len(sockaddr) < 2:
                    raise ValueError
                address = ipaddress.IPv4Address(sockaddr[0])
                if not address.is_global or sockaddr[1] != 443:
                    raise ValueError
                current.add(str(address))
            if not current:
                raise ValueError
            addresses.update(current)
    except subprocess.TimeoutExpired:
        raise BridgeFailure("probe-timeout") from None
    except (OSError, TypeError, ValueError, ipaddress.AddressValueError):
        raise BridgeFailure("probe-model-resolution-failed") from None
    if not addresses or len(addresses) > 32:
        raise BridgeFailure("probe-model-resolution-failed")
    return tuple(sorted(addresses, key=lambda value: int(ipaddress.IPv4Address(value))))


def _resolve_probe_ipv4s(
    *,
    deadline: float | None = None,
    resolve: Callable[..., list[tuple[Any, ...]]] | None = None,
) -> dict[str, tuple[str, ...]]:
    """Resolve the fixed map in an independently killable process in production."""
    if resolve is None:
        if deadline is None:
            raise BridgeFailure("probe-model-resolution-failed")
        try:
            completed = _run_bounded_process(
                [sys.executable, "-I", "-c", _RESOLVER_PROGRAM],
                timeout=_probe_timeout(deadline, 30),
                text=False,
                max_output_bytes=16 * 1024,
            )
        except subprocess.TimeoutExpired:
            raise BridgeFailure("probe-timeout") from None
        except BridgeFailure as error:
            if error.reason == "probe-timeout":
                raise
            raise BridgeFailure("probe-model-resolution-failed") from None
        except OSError:
            raise BridgeFailure("probe-model-resolution-failed") from None
        if completed.returncode != 0 or completed.stderr != b"":
            raise BridgeFailure("probe-model-resolution-failed")
        try:
            document = json.loads(completed.stdout.decode("ascii"))
        except (AttributeError, UnicodeDecodeError, json.JSONDecodeError):
            raise BridgeFailure("probe-model-resolution-failed") from None
        if not isinstance(document, Mapping) or set(document) != {
            *_MODEL_ENDPOINTS,
            "github.com",
        }:
            raise BridgeFailure("probe-model-resolution-failed")

        def captured(endpoint: str, port: int, **_kwargs: object) -> list[tuple[Any, ...]]:
            values = document.get(endpoint)
            if type(values) is not list:
                raise ValueError
            return [
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (value, port))
                for value in values
            ]

        resolve = captured
    mapping: dict[str, tuple[str, ...]] = {}
    try:
        for endpoint in (*_MODEL_ENDPOINTS, "github.com"):
            addresses: set[str] = set()
            for answer in resolve(
                endpoint,
                443,
                family=socket.AF_INET,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            ):
                if not isinstance(answer, tuple) or len(answer) != 5:
                    raise ValueError
                sockaddr = answer[4]
                if not isinstance(sockaddr, tuple) or len(sockaddr) < 2 or sockaddr[1] != 443:
                    raise ValueError
                address = ipaddress.IPv4Address(sockaddr[0])
                if not address.is_global:
                    raise ValueError
                addresses.add(str(address))
            if not addresses or len(addresses) > 16:
                raise ValueError
            mapping[endpoint] = tuple(
                sorted(addresses, key=lambda value: int(ipaddress.IPv4Address(value)))
            )
    except subprocess.TimeoutExpired:
        raise BridgeFailure("probe-timeout") from None
    except (OSError, TypeError, ValueError, ipaddress.AddressValueError):
        raise BridgeFailure("probe-model-resolution-failed") from None
    models = {address for endpoint in _MODEL_ENDPOINTS for address in mapping[endpoint]}
    if models.intersection(mapping["github.com"]):
        raise BridgeFailure("probe-endpoint-overlap")
    return mapping


def _parse_manager_boundary_events(raw: bytes) -> tuple[dict[str, str], ...]:
    if type(raw) is not bytes or len(raw) > _MAX_PROBE_LOG_BYTES:
        raise BridgeFailure("probe-events-invalid")
    try:
        lines = raw.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError:
        raise BridgeFailure("probe-events-invalid") from None
    result: list[dict[str, str]] = []
    for line in lines:
        if not any(f"event={name}" in line for name in ("proc.exec", "file.open")):
            continue
        try:
            tokens = shlex.split(line, comments=False, posix=True)
            fields = dict(token.split("=", 1) for token in tokens)
        except (ValueError, TypeError):
            raise BridgeFailure("probe-events-invalid") from None
        if len(fields) != len(tokens):
            raise BridgeFailure("probe-events-invalid")
        event = fields.get("event", "")
        if event not in {"proc.exec", "file.open", "file.open:ro", "file.open:rw"}:
            continue
        base_fields = {"time", "event", "pid", "cgroup", "exe", "path", "decision"}
        if (
            (event == "proc.exec" and set(fields) not in {
                frozenset(base_fields | {"argc"}), frozenset(base_fields | {"argc", "argv"})
            })
            or (event != "proc.exec" and set(fields) != base_fields)
        ):
            raise BridgeFailure("probe-events-invalid")
        if (
            fields.get("decision") not in {"allowed", "denied"}
            or type(fields.get("path")) is not str
            or not fields["path"].startswith("/")
            or contains_control_characters(fields["path"])
            or type(fields.get("time")) is not str
            or not fields.get("pid", "").isascii()
            or not fields.get("pid", "").isdigit()
            or not fields.get("cgroup", "").isascii()
            or not fields.get("cgroup", "").isdigit()
            or type(fields.get("exe")) is not str
            or not fields["exe"]
        ):
            raise BridgeFailure("probe-events-invalid")
        _event_timestamp(fields["time"])
        result.append({
            "time": fields["time"], "pid": fields["pid"], "cgroup": fields["cgroup"],
            "exe": fields["exe"], "event": event, "path": fields["path"],
            "decision": fields["decision"],
        })
    return tuple(result)


def _authenticate_probe_http_events(raw: bytes) -> tuple[dict[str, str], ...]:
    events: list[dict[str, str]] = []
    for line in raw.decode("utf-8", "strict").splitlines():
        if "event=http.request" not in line:
            continue
        try:
            tokens = shlex.split(line, comments=False, posix=True)
        except ValueError:
            raise BridgeFailure("probe-events-invalid") from None
        fields: dict[str, str] = {}
        for token in tokens:
            if "=" not in token:
                raise BridgeFailure("probe-events-invalid")
            key, value = token.split("=", 1)
            if not key or key in fields:
                raise BridgeFailure("probe-events-invalid")
            fields[key] = value
        if (
            set(fields)
            != {"time", "event", "protocol", "addr", "path", "decision", "status"}
            or fields["event"] != "http.request"
            or fields["protocol"] != "https"
            or fields["path"] != "/"
            or fields["decision"] != "allowed"
            or not fields["status"].isascii()
            or not fields["status"].isdigit()
            or not 200 <= int(fields["status"]) < 500
        ):
            raise BridgeFailure("probe-events-invalid")
        _event_timestamp(fields["time"])
        events.append(fields)
    if tuple(event["addr"] for event in events) != _MODEL_ENDPOINTS:
        raise BridgeFailure("probe-events-invalid")
    return tuple(events)


def _authenticate_probe_log_suffix(
    raw: bytes,
) -> tuple[tuple[dict[str, str], ...], tuple[dict[str, str], ...]]:
    """Require every complete post-baseline manager line to use pinned event grammar."""
    if type(raw) is not bytes or len(raw) > _MAX_PROBE_LOG_BYTES:
        raise BridgeFailure("probe-events-invalid")
    try:
        lines = raw.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError:
        raise BridgeFailure("probe-events-invalid") from None
    recognized = (
        "event=net.send",
        "event=proc.exec",
        "event=file.open ",
        "event=file.open:ro",
        "event=file.open:rw",
        "event=http.request",
    )
    if any(not line or not any(token in line for token in recognized) for line in lines):
        raise BridgeFailure("probe-events-invalid")
    _authenticate_probe_http_events(raw)
    return _parse_manager_network_events(raw), _parse_manager_boundary_events(raw)


def _network_events_for(
    events: tuple[dict[str, str], ...], probe_ids: tuple[str, ...]
) -> tuple[dict[str, str], ...]:
    all_ids = tuple(_NETWORK_PROBE_TARGETS)
    if (
        type(events) is not tuple
        or type(probe_ids) is not tuple
        or not probe_ids
        or probe_ids != all_ids[: len(probe_ids)]
        or len(events) != len(probe_ids)
    ):
        raise BridgeFailure("probe-network-evidence-invalid")
    return events


def _read_probe_document(path: Path, *, phase: str) -> list[dict[str, str]]:
    raw = _read_regular_path(
        path,
        max_bytes=_MAX_NORMALIZED_PROBE_BYTES,
        exact_mode=0o600,
        reason="probe-evidence-invalid",
    )
    document = _canonical_document(raw)
    if (
        set(document) != {"schema_version", "phase", "probes"}
        or document.get("schema_version") != "containment-probe-child-v1"
        or document.get("phase") != phase
        or type(document.get("probes")) is not list
    ):
        raise BridgeFailure("probe-evidence-invalid")
    return document["probes"]


@dataclass
class _ProbeLogBaseline:
    descriptor: int
    path: Path
    device: int
    inode: int
    owner_uid: int
    mode: int
    offset: int
    wall_not_before: float

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


def _open_probe_log_baseline(
    path: Path, *, expected_uid: int, deadline: float
) -> _ProbeLogBaseline:
    """Open the manager log once and establish a quiescent append-only cursor."""
    _secure_descriptor_primitives()
    parent: int | None = None
    descriptor: int | None = None
    try:
        parent = os.open(os.fspath(path.parent), os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
        descriptor = os.open(path.name, os.O_RDONLY | _NOFOLLOW | _NONBLOCK, dir_fd=parent)
        stable: tuple[int, int, int] | None = None
        stable_count = 0
        while stable_count < 3:
            _require_probe_deadline(deadline)
            opened = os.fstat(descriptor)
            named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != expected_uid
                or opened.st_nlink != 1
                or stat.S_IMODE(opened.st_mode) != _PROBE_LOG_MODE
                or not _same_inode(opened, named)
                or opened.st_size < 0
                or opened.st_size > _MAX_PROBE_LOG_BYTES
            ):
                raise BridgeFailure("probe-events-invalid")
            current = (opened.st_dev, opened.st_ino, opened.st_size)
            content = os.pread(descriptor, opened.st_size, 0)
            after = os.fstat(descriptor)
            if len(content) != opened.st_size or current != (
                after.st_dev, after.st_ino, after.st_size
            ) or (content and not content.endswith(b"\n")):
                stable = None
                stable_count = 0
            elif stable == current:
                stable_count += 1
            else:
                stable = current
                stable_count = 1
            if stable_count < 3:
                time.sleep(min(0.05, _probe_timeout(deadline, 0.05)))
        assert stable is not None
        baseline = _ProbeLogBaseline(
            descriptor=descriptor,
            path=path,
            device=stable[0],
            inode=stable[1],
            owner_uid=expected_uid,
            mode=_PROBE_LOG_MODE,
            offset=stable[2],
            wall_not_before=float(int(time.time())),
        )
        descriptor = None
        return baseline
    except BridgeFailure:
        raise
    except OSError as error:
        raise BridgeFailure("probe-events-invalid") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent is not None:
            os.close(parent)


def _read_probe_log_suffix(baseline: _ProbeLogBaseline, path: Path) -> bytes:
    """Read a complete stable suffix from the originally opened manager log inode."""
    if (
        not isinstance(baseline, _ProbeLogBaseline)
        or baseline.descriptor < 0
        or path != baseline.path
    ):
        raise BridgeFailure("probe-events-invalid")
    parent: int | None = None
    try:
        parent = os.open(os.fspath(path.parent), os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
        deadline = time.monotonic() + 1.0
        while True:
            before = os.fstat(baseline.descriptor)
            named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            suffix_size = before.st_size - baseline.offset
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != baseline.owner_uid
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != baseline.mode
                or (before.st_dev, before.st_ino) != (baseline.device, baseline.inode)
                or not _same_inode(before, named)
                or named.st_uid != baseline.owner_uid
                or named.st_nlink != 1
                or stat.S_IMODE(named.st_mode) != baseline.mode
                or suffix_size < 0
                or suffix_size > _MAX_PROBE_LOG_BYTES
            ):
                raise BridgeFailure("probe-events-invalid")
            suffix = os.pread(baseline.descriptor, suffix_size, baseline.offset)
            after = os.fstat(baseline.descriptor)
            current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if (
                len(suffix) != suffix_size
                or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
                or after.st_size < before.st_size
                or after.st_uid != baseline.owner_uid
                or after.st_nlink != 1
                or stat.S_IMODE(after.st_mode) != baseline.mode
                or not _same_inode(after, current)
                or current.st_uid != baseline.owner_uid
                or current.st_nlink != 1
                or stat.S_IMODE(current.st_mode) != baseline.mode
            ):
                raise BridgeFailure("probe-events-invalid")
            if not suffix or suffix.endswith(b"\n"):
                return suffix
            if time.monotonic() >= deadline:
                raise BridgeFailure("probe-events-invalid")
            time.sleep(0.01)
    except BridgeFailure:
        raise
    except OSError as error:
        raise BridgeFailure("probe-events-invalid") from error
    finally:
        if parent is not None:
            os.close(parent)


def _wait_for_regular(path: Path, *, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if path.is_file() and not path.is_symlink():
                return
        except OSError:
            pass
        time.sleep(0.05)
    raise BridgeFailure("probe-timeout")


def _require_probe_deadline(deadline: float) -> None:
    if type(deadline) not in {int, float} or not math.isfinite(deadline) or time.monotonic() >= deadline:
        raise BridgeFailure("probe-timeout")


def _probe_timeout(deadline: float, cap: float) -> float:
    if type(cap) not in {int, float} or not math.isfinite(cap) or cap <= 0:
        raise BridgeFailure("probe-timeout")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise BridgeFailure("probe-timeout")
    return min(float(cap), remaining)


def _write_probe_file(path: Path, content: bytes) -> None:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600)
        try:
            view = memoryview(content)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        raise BridgeFailure("probe-state-unsafe") from None


def _decode_single_json(raw: bytes, reason: str) -> Mapping[str, Any]:
    if not raw or len(raw) > 256 * 1024:
        raise BridgeFailure(reason)
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise BridgeFailure(reason) from None
    if not isinstance(document, Mapping):
        raise BridgeFailure(reason)
    return document


def _container_shape(raw: bytes) -> dict[str, Any]:
    document = _decode_single_json(raw, "probe-network-shape-invalid")
    try:
        networks = document["NetworkSettings"]["Networks"]
        normalized_networks: dict[str, Any] = {}
        for name, attachment in networks.items():
            normalized_networks[name] = {
                "IPAddress": attachment["IPAddress"],
                "GlobalIPv6Address": attachment["GlobalIPv6Address"],
                "MacAddress": attachment["MacAddress"],
                "NetworkID": attachment["NetworkID"],
            }
        environment = document["Config"]["Env"] or []
        if type(environment) is not list or any(type(value) is not str for value in environment):
            raise TypeError
        mounts = []
        for mount in document["Mounts"]:
            mounts.append(
                {
                    "type": mount["Type"],
                    "source": mount["Source"],
                    "destination": mount["Destination"],
                    "mode": mount["Mode"],
                    "rw": mount["RW"],
                    "propagation": mount["Propagation"],
                }
            )
        cap_add = document["HostConfig"]["CapAdd"] or []
        cap_drop = document["HostConfig"]["CapDrop"] or []
        security_opt = document["HostConfig"]["SecurityOpt"] or []
        exec_ids = document["ExecIDs"] or []
        if any(type(value) is not list for value in (cap_add, cap_drop, security_opt, exec_ids)):
            raise TypeError
        return {
            "id": document["Id"],
            "name": document["Name"],
            "image_id": document["Image"],
            "image_reference": document["Config"]["Image"],
            "path": document["Path"],
            "args": document["Args"],
            "user": document["Config"]["User"],
            "working_dir": document["Config"]["WorkingDir"],
            "env": sorted(environment),
            "mounts": mounts,
            "privileged": document["HostConfig"]["Privileged"],
            "cap_add": sorted(cap_add),
            "cap_drop": sorted(cap_drop),
            "security_opt": sorted(security_opt),
            "cgroupns_mode": document["HostConfig"]["CgroupnsMode"],
            "exec_ids": sorted(exec_ids),
            "running": document["State"]["Running"],
            "exit_code": document["State"].get("ExitCode", 0),
            "state_pid": document["State"]["Pid"],
            "network_mode": document["HostConfig"]["NetworkMode"],
            "ports": document["NetworkSettings"]["Ports"],
            "networks": normalized_networks,
            "read_only": document["HostConfig"].get("ReadonlyRootfs", False),
        }
    except (AttributeError, KeyError, TypeError):
        raise BridgeFailure("probe-network-shape-invalid") from None


def _authenticate_probe_resolver_container(
    shape: object,
    *,
    config: BridgeConfig,
    names: Mapping[str, str],
    expected_container_id: str,
    expected_network_id: str,
) -> None:
    """Authenticate the short-lived credential-free resolver discovery container."""
    try:
        if (
            not isinstance(shape, Mapping)
            or set(names) != {"manager", "resolver", "table", "target", "token"}
            or re.fullmatch(r"[0-9a-f]{64}", expected_container_id) is None
            or re.fullmatch(r"[0-9a-f]{64}", expected_network_id) is None
        ):
            raise ValueError
        sealed = ExecutionBridge(config)._sealed_runtime()
        environment = _probe_environment_values(shape["env"])
        if environment != {
            "DEBIAN_FRONTEND": "noninteractive",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        }:
            raise ValueError
        networks = shape["networks"]
        if not isinstance(networks, Mapping) or set(networks) != {"bridge"}:
            raise ValueError
        attachment = networks["bridge"]
        if (
            not isinstance(attachment, Mapping)
            or attachment
            != {
                "IPAddress": "",
                "GlobalIPv6Address": "",
                "MacAddress": "",
                "NetworkID": expected_network_id,
            }
        ):
            raise ValueError
        if (
            shape["id"] != expected_container_id
            or shape["name"] != "/" + names["resolver"]
            or shape["image_id"] != "sha256:" + sealed["image_digest"]
            or shape["image_reference"] != sealed["image_reference"]
            or shape["path"] != "/bin/cat"
            or shape["args"] != ["/etc/resolv.conf"]
            or shape["user"] != "65534:65534"
            or shape["working_dir"] != ""
            or shape["mounts"] != []
            or shape["privileged"] is not False
            or shape["cap_add"] != []
            or shape["cap_drop"] != ["ALL"]
            or shape["security_opt"] != ["no-new-privileges:true"]
            or shape["cgroupns_mode"] != "private"
            or shape["exec_ids"] != []
            or shape["running"] is not False
            or shape["exit_code"] != 0
            or shape["state_pid"] != 0
            or shape["network_mode"] != "bridge"
            or shape["ports"] != {}
            or shape["read_only"] is not True
        ):
            raise ValueError
    except (BridgeFailure, KeyError, TypeError, ValueError):
        raise BridgeFailure("probe-resolver-container-invalid") from None


def _parse_probe_resolvers(raw: bytes) -> tuple[str, ...]:
    if type(raw) is not bytes or not raw or len(raw) > 16 * 1024:
        raise BridgeFailure("probe-dns-shape-invalid")
    try:
        text = raw.decode("ascii", "strict")
        addresses: list[str] = []
        for line in text.splitlines():
            fields = line.split()
            if not fields or fields[0].startswith("#") or fields[0] != "nameserver":
                continue
            if len(fields) != 2:
                raise ValueError
            address = ipaddress.IPv4Address(fields[1])
            if address.is_loopback or address.is_unspecified or address.is_multicast:
                raise ValueError
            addresses.append(str(address))
        result = tuple(dict.fromkeys(addresses))
        if not 1 <= len(result) <= 4:
            raise ValueError
        return result
    except (UnicodeDecodeError, ValueError, ipaddress.AddressValueError):
        raise BridgeFailure("probe-dns-shape-invalid") from None


def _exec_shape(raw: bytes) -> dict[str, Any]:
    document = _decode_single_json(raw, "probe-container-authority-invalid")
    try:
        process = document["ProcessConfig"]
        result = {
            "id": document["ID"],
            "running": document["Running"],
            "exit_code": document["ExitCode"],
            "pid": document["Pid"],
            "privileged": process["privileged"],
            "user": process["user"],
            "tty": process["tty"],
            "entrypoint": process["entrypoint"],
            "arguments": process["arguments"],
        }
    except (KeyError, TypeError):
        raise BridgeFailure("probe-container-authority-invalid") from None
    return result


def _probe_active_process_shape(
    *, cgroup_path: str, exec_id: str, expected_argv: list[str]
) -> dict[str, Any]:
    """Read the exact blocked probe process from its authenticated cgroup."""
    try:
        if (
            type(cgroup_path) is not str
            or not cgroup_path.startswith("/")
            or contains_control_characters(cgroup_path)
            or re.fullmatch(r"[0-9a-f]{64}", exec_id) is None
        ):
            raise ValueError
        cgroup_root = Path("/sys/fs/cgroup")
        declared = Path(cgroup_path)
        group = declared if declared.is_relative_to(cgroup_root) else cgroup_root / cgroup_path[1:]
        resolved = group.resolve(strict=True)
        if not resolved.is_relative_to(cgroup_root.resolve(strict=True)):
            raise ValueError
        pids = (resolved / "cgroup.procs").read_text(encoding="ascii").splitlines()
        if not pids or len(pids) > 64 or any(not pid.isascii() or not pid.isdigit() for pid in pids):
            raise ValueError
        matches: list[dict[str, Any]] = []
        for raw_pid in pids:
            pid = int(raw_pid)
            raw = Path(f"/proc/{pid}/cmdline").read_bytes()
            argv = [part.decode("utf-8", "strict") for part in raw.rstrip(b"\0").split(b"\0")]
            if argv != expected_argv:
                continue
            status = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
            uid_line = next(line for line in status.splitlines() if line.startswith("Uid:"))
            uids = uid_line.split()[1:]
            if uids != ["0", "0", "0", "0"]:
                raise ValueError
            executable = os.readlink(f"/proc/{pid}/exe")
            comm = Path(f"/proc/{pid}/comm").read_text(encoding="ascii").rstrip("\n")
            matches.append(
                {
                    "id": exec_id,
                    "running": True,
                    "exit_code": 0,
                    "pid": pid,
                    "privileged": False,
                    "user": "",
                    "tty": False,
                    "entrypoint": "bash",
                    "arguments": ["-lc", "exec " + shlex.join(expected_argv)],
                    "exe": executable,
                    "comm": comm,
                    "cgroup_id": str(resolved.stat().st_ino),
                }
            )
        if len(matches) != 1:
            raise ValueError
    except (OSError, StopIteration, TypeError, UnicodeError, ValueError):
        raise BridgeFailure("probe-container-authority-invalid") from None
    return matches[0]


def _probe_environment_values(values: object) -> dict[str, str]:
    if type(values) is not list:
        raise BridgeFailure("probe-container-authority-invalid")
    result: dict[str, str] = {}
    for item in values:
        if type(item) is not str or "=" not in item:
            raise BridgeFailure("probe-container-authority-invalid")
        key, value = item.split("=", 1)
        if not key or key in result or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) is None:
            raise BridgeFailure("probe-container-authority-invalid")
        result[key] = value
    forbidden = ("ANTHROPIC", "CLAUDE", "OPENAI", "API_KEY", "TOKEN", "PASSWORD", "SECRET")
    if any(any(marker in key.upper() for marker in forbidden) for key in result):
        raise BridgeFailure("probe-container-authority-invalid")
    return result


def _authenticate_probe_container_authority(
    target: object,
    manager: object,
    active_exec: object,
    *,
    config: BridgeConfig,
    names: Mapping[str, str],
    workspace: Path,
    control: Path,
    work_dir: Path,
) -> dict[str, str]:
    """Authenticate fixed Leash 1.1.7 Docker authority before releasing the child."""
    try:
        if (
            not isinstance(target, Mapping)
            or not isinstance(manager, Mapping)
            or not isinstance(active_exec, Mapping)
            or set(names) != {"manager", "resolver", "table", "target", "token"}
        ):
            raise ValueError
        sealed = ExecutionBridge(config)._sealed_runtime()
        target_id = target["id"]
        manager_id = manager["id"]
        exec_id = active_exec["id"]
        if any(type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None
               for value in (target_id, manager_id, exec_id)):
            raise ValueError
        command = _probe_child_argv(control=control, workspace=workspace)
        if (
            target["name"] != "/" + names["target"]
            or manager["name"] != "/" + names["manager"]
            or target["image_id"] != "sha256:" + sealed["image_digest"]
            or target["image_reference"] != sealed["image_reference"]
            or manager["image_id"] != "sha256:" + sealed["leash_image_digest"]
            or manager["image_reference"] != sealed["leash_image_reference"]
            or target["path"] != "/leash/leash-entry-linux-arm64"
            or target["args"] != []
            or target["user"] != ""
            or target["working_dir"] != str(workspace)
            or target["privileged"] is not False
            or target["cap_add"] != []
            or target["cap_drop"] != []
            or target["security_opt"] != []
            or target["cgroupns_mode"] != "host"
            or target["ports"] != {}
            or target["running"] is not True
            or type(target["state_pid"]) is not int
            or target["state_pid"] <= 0
            or target["exec_ids"] != [exec_id]
            or manager["path"] != "/usr/bin/tini"
            or manager["user"] != ""
            or manager["working_dir"] != ""
            or manager["privileged"] is not True
            # Docker 29 canonicalizes the requested NET_ADMIN capability and
            # reports its automatic privileged-container SELinux label option
            # in the inspect response.  These are the only accepted equivalent
            # representations; the target remains exact and unprivileged.
            or manager["cap_add"] not in (["NET_ADMIN"], ["CAP_NET_ADMIN"])
            or manager["cap_drop"] != []
            or manager["security_opt"] not in ([], ["label=disable"])
            or manager["cgroupns_mode"] != "host"
            or manager["ports"] != {}
            or manager["running"] is not True
            or type(manager["state_pid"]) is not int
            or manager["state_pid"] <= 0
            or manager["exec_ids"] != []
            or manager["network_mode"] not in {"container:" + target_id, "container:" + names["target"]}
            or active_exec["running"] is not True
            or active_exec["exit_code"] != 0
            or type(active_exec["pid"]) is not int
            or active_exec["pid"] <= 0
            or active_exec["privileged"] is not False
            or active_exec["user"] != ""
            or active_exec["tty"] is not False
            or active_exec["entrypoint"] != "bash"
            or active_exec.get("exe") != _PROBE_NODE
            or active_exec.get("comm") != "node"
        ):
            raise ValueError
        if active_exec["arguments"] != ["-lc", "exec " + shlex.join(command)]:
            raise ValueError
        manager_args = manager["args"]
        if (
            type(manager_args) is not list
            or len(manager_args) != 5
            or manager_args[:4] != ["--", "/usr/local/bin/leash", "--daemon", "--cgroup"]
            or type(manager_args[4]) is not str
            or not manager_args[4].startswith("/")
            or contains_control_characters(manager_args[4])
            or target_id not in manager_args[4]
        ):
            raise ValueError
        cgroup_path = manager_args[4]
        target_env = _probe_environment_values(target["env"])
        manager_env = _probe_environment_values(manager["env"])
        expected_target = {
            "LEASH_DIR": "/leash",
            "LEASH_ENTRY_READY_FILE": "/leash/leash-entry.ready",
            "LEASH_ENTRY_STOP_SIGNAL": "SIGTERM",
            "LEASH_ENTRY_KILL_SIGNAL": "SIGKILL",
            "LEASH_DISABLE_TELEMETRY": "1",
            "NODE_OPTIONS": "--use-openssl-ca",
        }
        expected_manager = {
            "LEASH_LOG_DIR": "/log",
            "LEASH_CFG_DIR": "/cfg",
            "LEASH_LOG": "/log/events.log",
            "LEASH_POLICY": "/cfg/leash.cedar",
            "LEASH_PROXY_PORT": "18000",
            "LEASH_LISTEN": "",
            "LEASH_CGROUP_PATH": cgroup_path,
            "LEASH_BOOTSTRAP_TIMEOUT": "2m0s",
            "LEASH_DIR": "/leash",
            "LEASH_PRIVATE_DIR": "/leash-private",
            "LEASH_PROJECT": workspace.name,
            "LEASH_COMMAND": " ".join(command),
            "LEASH_DISABLE_TELEMETRY": "1",
        }
        base_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        workspace_hash = hashlib.sha256(str(workspace).encode("utf-8")).hexdigest()[:32]
        session_id = target_env.get("LEASH_SESSION_ID")
        try:
            parsed_session = uuid.UUID(str(session_id))
        except (ValueError, AttributeError):
            raise ValueError from None
        if parsed_session.version != 4 or str(parsed_session) != session_id:
            raise ValueError
        dynamic = {"LEASH_WORKSPACE_HASH": workspace_hash, "LEASH_SESSION_ID": session_id}
        expected_target.update(
            {"PATH": base_path, "DEBIAN_FRONTEND": "noninteractive", **dynamic}
        )
        expected_manager.update({"PATH": base_path, **dynamic})
        if (
            target_env != expected_target
            or manager_env != expected_manager
        ):
            raise ValueError
        target_mounts = target["mounts"]
        manager_mounts = manager["mounts"]
        if type(target_mounts) is not list or type(manager_mounts) is not list:
            raise ValueError
        by_target = {mount["destination"]: mount for mount in target_mounts}
        by_manager = {mount["destination"]: mount for mount in manager_mounts}
        if len(by_target) != len(target_mounts) or len(by_manager) != len(manager_mounts):
            raise ValueError
        if set(by_target) != {"/leash", str(workspace)} or set(by_manager) != {
            "/sys/fs/cgroup", "/log", "/cfg", "/leash", "/leash-private"
        }:
            raise ValueError
        share = Path(by_target["/leash"]["source"])
        if share.parent != work_dir or not share.name.startswith("leash-"):
            raise ValueError
        expected_mounts = {
            str(workspace): (str(workspace), True, ""),
            "/leash": (str(share), True, ""),
        }
        expected_manager_mounts = {
            "/sys/fs/cgroup": ("/sys/fs/cgroup", False, "ro"),
            "/log": (str(work_dir / "log"), True, ""),
            "/cfg": (str(work_dir / "cfg"), True, ""),
            "/leash": (str(share), True, ""),
            "/leash-private": (str(work_dir / "private"), True, ""),
        }
        for mounts, expected in ((by_target, expected_mounts), (by_manager, expected_manager_mounts)):
            for destination, (source, rw, mode) in expected.items():
                mount = mounts[destination]
                if (
                    set(mount) != {"type", "source", "destination", "mode", "rw", "propagation"}
                    or mount != {"type": "bind", "source": source, "destination": destination,
                                 "mode": mode, "rw": rw, "propagation": "rprivate"}
                ):
                    raise ValueError
    except (BridgeFailure, KeyError, TypeError, ValueError):
        raise BridgeFailure("probe-container-authority-invalid") from None
    return {
        "cgroup_path": cgroup_path,
        "cgroup_id": str(active_exec.get("cgroup_id", "22")),
        "exec_pid": str(active_exec["pid"]),
        "exec_exe": str(active_exec["comm"]),
        "exec_id": exec_id,
    }


def _bridge_network_shape(raw: bytes) -> dict[str, Any]:
    document = _decode_single_json(raw, "probe-network-shape-invalid")
    try:
        configs = document["IPAM"]["Config"]
        containers = document["Containers"]
        if not isinstance(containers, Mapping):
            raise TypeError
        normalized_containers: dict[str, dict[str, str]] = {}
        for container_id, attachment in containers.items():
            if type(container_id) is not str or not isinstance(attachment, Mapping):
                raise TypeError
            normalized_containers[container_id] = {
                "name": attachment["Name"],
                "endpoint_id": attachment["EndpointID"],
                "mac_address": attachment["MacAddress"],
                "ipv4_address": attachment["IPv4Address"],
                "ipv6_address": attachment["IPv6Address"],
            }
        return {
            "id": document["Id"],
            "name": document["Name"],
            "driver": document["Driver"],
            "internal": document["Internal"],
            "options": document["Options"],
            "subnets": [entry["Subnet"] for entry in configs],
            "containers": normalized_containers,
        }
    except (KeyError, TypeError):
        raise BridgeFailure("probe-network-shape-invalid") from None


def _authenticate_builtin_bridge(network: object) -> str:
    if (
        not isinstance(network, Mapping)
        or set(network) != {
            "id", "name", "driver", "internal", "options", "subnets", "containers"
        }
        or type(network.get("id")) is not str
        or re.fullmatch(r"[0-9a-f]{64}", network["id"]) is None
        or network.get("name") != "bridge"
        or network.get("driver") != "bridge"
        or network.get("internal") is not False
        or not isinstance(network.get("options"), Mapping)
        or network["options"].get("com.docker.network.bridge.name") != "docker0"
        or type(network.get("subnets")) is not list
        or len(network["subnets"]) != 1
        or network.get("containers") != {}
    ):
        raise BridgeFailure("probe-network-shape-invalid")
    try:
        subnet = ipaddress.IPv4Network(network["subnets"][0], strict=True)
    except (TypeError, ValueError, ipaddress.AddressValueError):
        raise BridgeFailure("probe-network-shape-invalid") from None
    if not subnet.is_private:
        raise BridgeFailure("probe-network-shape-invalid")
    return "docker0"


def _authenticate_linux_bridge(raw: bytes, *, expected_interface: str) -> dict[str, Any]:
    try:
        document = json.loads(raw.decode("utf-8", "strict"))
        if type(document) is not list or len(document) != 1 or type(document[0]) is not dict:
            raise ValueError
        link = document[0]
        if (
            link.get("ifname") != expected_interface
            or type(link.get("ifindex")) is not int
            or link["ifindex"] <= 0
            or link.get("link_type") != "ether"
            or type(link.get("mtu")) is not int
            or link["mtu"] < 576
            or type(link.get("flags")) is not list
            or "UP" not in link["flags"]
            or "LOOPBACK" in link["flags"]
            or type(link.get("address")) is not str
            or _MAC_ADDRESS.fullmatch(link["address"]) is None
        ):
            raise ValueError
    except (KeyError, TypeError, UnicodeError, ValueError, json.JSONDecodeError):
        raise BridgeFailure("probe-network-shape-invalid") from None
    return {"ifindex": link["ifindex"], "ifname": expected_interface, "address": link["address"]}


def _nft_table_names(raw: bytes) -> set[tuple[str, str]]:
    entries = _nft_document(raw, "probe-firewall-invalid")
    names: set[tuple[str, str]] = set()
    for entry in entries:
        if "metainfo" in entry:
            if not isinstance(entry["metainfo"], Mapping):
                raise BridgeFailure("probe-firewall-invalid")
            continue
        table = entry.get("table")
        if (
            not isinstance(table, Mapping)
            or table.get("family") not in {"ip", "ip6", "inet", "arp", "bridge", "netdev"}
            or type(table.get("name")) is not str
            or not table["name"]
            or contains_control_characters(table["name"])
        ):
            raise BridgeFailure("probe-firewall-invalid")
        names.add((table["family"], table["name"]))
    return names


def _private_automation_directory(
    config: BridgeConfig, path: Path, *, reason: str, require_empty: bool
) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise BridgeFailure(reason)
    try:
        named = path.lstat()
        resolved = path.resolve(strict=True)
        opened = resolved.stat()
        has_entries = False
        if require_empty:
            with os.scandir(resolved) as entries:
                has_entries = next(entries, None) is not None
    except OSError:
        raise BridgeFailure(reason) from None
    if (
        resolved != path
        or not stat.S_ISDIR(named.st_mode)
        or stat.S_ISLNK(named.st_mode)
        or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
        or named.st_uid != config.root_uid
        or stat.S_IMODE(named.st_mode) != 0o700
        or (require_empty and has_entries)
        or any(
            path == surface
            or path.is_relative_to(surface)
            or surface.is_relative_to(path)
            for surface in (
                config.workspace_root,
                config.export_root,
                config.import_root,
                config.state_root,
            )
        )
    ):
        raise BridgeFailure(reason)
    return path


def _safe_root(root: Path, *, create: bool) -> Path:
    if create:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not root.is_dir() or root.is_symlink():
        raise BridgeFailure("workspace-root-unsafe")
    return root.resolve(strict=True)


def _owned_workspace(root: Path, context: str) -> Path:
    context = _digest(context)
    resolved_root = _safe_root(root, create=False)
    candidate = resolved_root / context
    if candidate.is_symlink() or not candidate.is_dir():
        raise BridgeFailure("workspace-unsafe")
    resolved = candidate.resolve(strict=True)
    if resolved.parent != resolved_root or resolved.name != context:
        raise BridgeFailure("workspace-unsafe")
    return resolved


def _child_directory(root: Path, child: str, *, create: bool) -> Path:
    parent = _safe_root(root, create=create)
    candidate = parent / child
    if create:
        candidate.mkdir(mode=0o700, exist_ok=True)
    if (
        candidate.is_symlink()
        or not candidate.is_dir()
        or candidate.resolve(strict=True).parent != parent
    ):
        raise BridgeFailure("guest-path-unsafe")
    return candidate.resolve(strict=True)


def _remove_directory_contents(descriptor: int, *, deadline: float | None = None) -> None:
    if deadline is not None:
        _require_probe_deadline(deadline)
    for name in os.listdir(descriptor):
        if deadline is not None:
            _require_probe_deadline(deadline)
        before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if stat.S_ISDIR(before.st_mode):
            child = os.open(
                name,
                os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                dir_fd=descriptor,
            )
            try:
                opened = os.fstat(child)
                if not _same_inode(before, opened):
                    raise BridgeFailure("workspace-unsafe")
                _remove_directory_contents(child, deadline=deadline)
                if deadline is not None:
                    _require_probe_deadline(deadline)
                current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if not _same_inode(opened, current):
                    raise BridgeFailure("workspace-unsafe")
            finally:
                os.close(child)
            if deadline is not None:
                _require_probe_deadline(deadline)
            os.rmdir(name, dir_fd=descriptor)
        else:
            if deadline is not None:
                _require_probe_deadline(deadline)
            current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if not _same_inode(before, current):
                raise BridgeFailure("workspace-unsafe")
            os.unlink(name, dir_fd=descriptor)


def _remove_owned_tree(root: Path, child: str) -> None:
    _secure_descriptor_primitives()
    child = _digest(child)
    parent = os.open(os.fspath(root), os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
    directory: int | None = None
    try:
        before = os.stat(child, dir_fd=parent, follow_symlinks=False)
        directory = os.open(
            child,
            os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
            dir_fd=parent,
        )
        opened = os.fstat(directory)
        if not stat.S_ISDIR(opened.st_mode) or not _same_inode(before, opened):
            raise BridgeFailure("workspace-unsafe")
        _remove_directory_contents(directory)
        current = os.stat(child, dir_fd=parent, follow_symlinks=False)
        if not _same_inode(opened, current):
            raise BridgeFailure("workspace-unsafe")
        os.close(directory)
        directory = None
        os.rmdir(child, dir_fd=parent)
        os.fsync(parent)
    except BridgeFailure:
        raise
    except OSError as error:
        raise BridgeFailure("workspace-unsafe") from error
    finally:
        if directory is not None:
            os.close(directory)
        os.close(parent)


def _regular_child(root: Path, name: str) -> Path:
    candidate = root / name
    if candidate.is_symlink() or not candidate.is_file():
        raise BridgeFailure("import-missing")
    return candidate


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _secure_descriptor_primitives() -> None:
    if not (
        _NOFOLLOW
        and _DIRECTORY
        and _OPEN_SUPPORTS_DIR_FD
        and _STAT_SUPPORTS_DIR_FD
        and _STAT_SUPPORTS_NOFOLLOW
        and _RENAME_SUPPORTS_DIR_FD
        and _LINK_SUPPORTS_DIR_FD
    ):
        raise BridgeFailure("guest-state-unsafe")


def _read_regular_path(
    path: Path,
    *,
    max_bytes: int,
    expected_uid: int | None = None,
    exact_mode: int | None = None,
    reject_group_world_write: bool = False,
    reason: str = "guest-file-unsafe",
) -> bytes:
    _secure_descriptor_primitives()
    parent: int | None = None
    descriptor: int | None = None
    try:
        parent = os.open(os.fspath(path.parent), os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
        parent_info = os.fstat(parent)
        if not stat.S_ISDIR(parent_info.st_mode):
            raise BridgeFailure(reason)
        descriptor = os.open(
            path.name,
            os.O_RDONLY | _NOFOLLOW | _NONBLOCK,
            dir_fd=parent,
        )
        opened = os.fstat(descriptor)
        named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or not _same_inode(opened, named)
            or (expected_uid is not None and opened.st_uid != expected_uid)
            or (exact_mode is not None and stat.S_IMODE(opened.st_mode) != exact_mode)
            or (reject_group_world_write and bool(opened.st_mode & 0o022))
            or opened.st_size < 0
            or opened.st_size > max_bytes
        ):
            raise BridgeFailure(reason)
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        after = os.fstat(descriptor)
        current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (
            len(content) > max_bytes
            or not _same_inode(opened, after)
            or not _same_inode(after, current)
            or opened.st_size != after.st_size
            or len(content) != after.st_size
        ):
            raise BridgeFailure(reason)
        return content
    except BridgeFailure:
        raise
    except OSError as error:
        raise BridgeFailure(reason) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent is not None:
            os.close(parent)


def _read_dynamic_regular_path(path: Path, *, max_bytes: int) -> bytes:
    """Read a bounded regular pseudo-file without trusting its reported size."""
    _secure_descriptor_primitives()
    if max_bytes < 0:
        raise BridgeFailure("guest-file-unsafe")
    parent: int | None = None
    descriptor: int | None = None
    try:
        if path == _PROC_MOUNTINFO:
            descriptor = os.open(os.fspath(path), os.O_RDONLY | _NOFOLLOW | _NONBLOCK)
            named = os.stat(path, follow_symlinks=False)
        else:
            parent = os.open(os.fspath(path.parent), os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
            parent_info = os.fstat(parent)
            if not stat.S_ISDIR(parent_info.st_mode):
                raise BridgeFailure("guest-file-unsafe")
            descriptor = os.open(
                path.name,
                os.O_RDONLY | _NOFOLLOW | _NONBLOCK,
                dir_fd=parent,
            )
            named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not _same_inode(opened, named):
            raise BridgeFailure("guest-file-unsafe")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        after = os.fstat(descriptor)
        if path == _PROC_MOUNTINFO:
            current = os.stat(path, follow_symlinks=False)
        else:
            assert parent is not None
            current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (
            len(content) > max_bytes
            or not _same_inode(opened, after)
            or not _same_inode(after, current)
        ):
            raise BridgeFailure("guest-file-unsafe")
        return content
    except BridgeFailure:
        raise
    except OSError as error:
        raise BridgeFailure("guest-file-unsafe") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent is not None:
            os.close(parent)


def _regular_bytes(path: Path) -> bytes:
    return _read_regular_path(path, max_bytes=128 * 1024 * 1024)


def _root_owned_regular_bytes(path: Path, root_uid: int) -> bytes:
    return _read_regular_path(
        path,
        max_bytes=16 * 1024 * 1024,
        expected_uid=root_uid,
        reject_group_world_write=True,
    )


def _root_owned_regular_text(
    path: Path,
    root_uid: int,
    *,
    root_owned: bool = True,
    strip: bool = True,
) -> str:
    raw = _read_regular_path(
        path,
        max_bytes=16 * 1024 * 1024,
        expected_uid=(root_uid if root_owned else None),
        reject_group_world_write=root_owned,
    )
    text = raw.decode("utf-8")
    return text.strip() if strip else text


def _has_host_mount(mountinfo: str) -> bool:
    if not mountinfo or not mountinfo.endswith("\n"):
        raise BridgeFailure("mountinfo-invalid")
    root_present = False
    for line in mountinfo.splitlines():
        if not line or line.count(" - ") != 1:
            raise BridgeFailure("mountinfo-invalid")
        parts = line.split(" - ", 1)
        before, after = parts
        fields = before.split()
        post = after.split()
        if (
            len(fields) < 6
            or len(post) != 3
            or not fields[0].isascii()
            or not fields[0].isdigit()
            or not fields[1].isascii()
            or not fields[1].isdigit()
            or re.fullmatch(r"[0-9]+:[0-9]+", fields[2]) is None
            or not fields[5]
            or any(not option for option in fields[5].split(","))
            or any(
                re.fullmatch(r"[A-Za-z0-9_.-]+(?::[A-Za-z0-9_.-]+)?", optional) is None
                for optional in fields[6:]
            )
            or re.fullmatch(r"[A-Za-z0-9_.+-]+", post[0]) is None
            or not post[1]
            or not post[2]
            or any(not option for option in post[2].split(","))
        ):
            raise BridgeFailure("mountinfo-invalid")
        root = _mountinfo_path(fields[3])
        target = _mountinfo_path(fields[4])
        if not root.startswith("/") or not target.startswith("/"):
            raise BridgeFailure("mountinfo-invalid")
        root_present = root_present or target == "/"
        filesystem = post[0]
        source = _mountinfo_field(post[1])
        if (
            filesystem in {"virtiofs", "9p", "fuse.osxfs", "fuse.lima", "fuse.sshfs"}
            or target.startswith(("/Users", "/Volumes", "/mnt/host"))
            or source.startswith(("/Users", "/Volumes", "host:"))
        ):
            return True
    if not root_present:
        raise BridgeFailure("mountinfo-invalid")
    return False


def _mountinfo_field(value: str) -> str:
    if not value or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise BridgeFailure("mountinfo-invalid")
    output: list[str] = []
    index = 0
    escapes = {"040": " ", "011": "\t", "012": "\n", "134": "\\"}
    while index < len(value):
        if value[index] != "\\":
            output.append(value[index])
            index += 1
            continue
        code = value[index + 1 : index + 4]
        if len(code) != 3 or code not in escapes:
            raise BridgeFailure("mountinfo-invalid")
        output.append(escapes[code])
        index += 4
    return "".join(output)


def _mountinfo_path(value: str) -> str:
    decoded = _mountinfo_field(value)
    if not decoded.startswith("/") or "\0" in decoded or "\n" in decoded:
        raise BridgeFailure("mountinfo-invalid")
    return decoded


def _canonical_document(raw: bytes) -> dict[str, Any]:
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BridgeFailure("manifest-invalid") from error
    if type(document) is not dict:
        raise BridgeFailure("manifest-invalid")
    encoded = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    if encoded != raw:
        raise BridgeFailure("manifest-invalid")
    return document


def _execution_policy(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != {
        "implementation_writable_paths",
        "verification_commands",
        "network_profile",
    }:
        raise BridgeFailure("policy-invalid")
    paths = value["implementation_writable_paths"]
    commands = value["verification_commands"]
    profile = value["network_profile"]
    if (
        type(paths) is not list
        or type(commands) is not list
        or profile not in _SAFE_NETWORK_PROFILES
    ):
        raise BridgeFailure("policy-invalid")
    normalized_paths = [_relative_path(item, allow_subtree_glob=True) for item in paths]
    if len(normalized_paths) != len(set(normalized_paths)):
        raise BridgeFailure("policy-invalid")
    result_commands: list[dict[str, Any]] = []
    names: set[str] = set()
    for command in commands:
        if not isinstance(command, Mapping) or set(command) != {
            "name",
            "argv",
            "expected_exit",
            "environment_profile",
        }:
            raise BridgeFailure("policy-invalid")
        name, argv, expected, environment = (
            command["name"],
            command["argv"],
            command["expected_exit"],
            command["environment_profile"],
        )
        if (
            type(name) is not str
            or not name.replace("-", "").replace("_", "").isalnum()
            or name in names
            or type(argv) is not list
            or not argv
            or any(
                type(argument) is not str or not argument or "\0" in argument for argument in argv
            )
            or expected not in {"zero", "nonzero"}
            or environment != "default"
            or is_indirect_verification_command(argv)
        ):
            raise BridgeFailure("policy-invalid")
        names.add(name)
        result_commands.append(
            {
                "name": name,
                "argv": list(argv),
                "expected_exit": expected,
                "environment_profile": environment,
            }
        )
    return {
        "implementation_writable_paths": normalized_paths,
        "verification_commands": result_commands,
        "network_profile": profile,
    }


def is_indirect_verification_command(argv: Sequence[object]) -> bool:
    """Return whether an argv delegates command selection to another program."""

    if not argv or type(argv[0]) is not str:
        return True
    executable = argv[0]
    path = Path(executable)
    name = path.name.lower()
    if "/" in executable and not path.is_absolute():
        return True
    if name in {
        "sh",
        "bash",
        "zsh",
        "dash",
        "fish",
        "csh",
        "tcsh",
        "ksh",
        "env",
        "sudo",
        "doas",
        "xargs",
        "find",
        "nice",
        "nohup",
        "timeout",
        "setsid",
        "busybox",
    }:
        return True
    options = tuple(argument for argument in argv[1:] if type(argument) is str)
    if name == _VERIFIER_LAUNCHER.name and "--verifier-launch" in options:
        return True
    return _DIRECT_INTERPRETER.fullmatch(name) is not None


def _validate_state_directory(descriptor: int, named: os.stat_result, *, root_uid: int) -> None:
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or not _same_inode(opened, named)
        or opened.st_uid != root_uid
        or stat.S_IMODE(opened.st_mode) != 0o700
    ):
        raise BridgeFailure("guest-state-unsafe")


def _open_state_context(
    root: Path, context: str, *, create: bool, root_uid: int
) -> tuple[int, int]:
    _secure_descriptor_primitives()
    context = _digest(context)
    if create:
        try:
            root.mkdir(mode=0o700, parents=True, exist_ok=False)
        except FileExistsError:
            pass
        except OSError as error:
            raise BridgeFailure("guest-state-unsafe") from error
    root_descriptor: int | None = None
    context_descriptor: int | None = None
    try:
        root_descriptor = os.open(os.fspath(root), os.O_RDONLY | _DIRECTORY | _NOFOLLOW)
        root_named = root.lstat()
        _validate_state_directory(root_descriptor, root_named, root_uid=root_uid)
        if create:
            try:
                os.mkdir(context, 0o700, dir_fd=root_descriptor)
            except FileExistsError:
                pass
        context_descriptor = os.open(
            context,
            os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
            dir_fd=root_descriptor,
        )
        context_named = os.stat(context, dir_fd=root_descriptor, follow_symlinks=False)
        _validate_state_directory(context_descriptor, context_named, root_uid=root_uid)
        return root_descriptor, context_descriptor
    except BridgeFailure:
        if context_descriptor is not None:
            os.close(context_descriptor)
        if root_descriptor is not None:
            os.close(root_descriptor)
        raise
    except OSError as error:
        if context_descriptor is not None:
            os.close(context_descriptor)
        if root_descriptor is not None:
            os.close(root_descriptor)
        raise BridgeFailure("guest-state-unsafe") from error


def _read_state_file(
    root: Path,
    context: str,
    name: str,
    *,
    root_uid: int,
    max_bytes: int,
) -> bytes:
    root_descriptor, context_descriptor = _open_state_context(
        root, context, create=False, root_uid=root_uid
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | _NOFOLLOW | _NONBLOCK,
            dir_fd=context_descriptor,
        )
        opened = os.fstat(descriptor)
        named = os.stat(name, dir_fd=context_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or not _same_inode(opened, named)
            or opened.st_uid != root_uid
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_size < 0
            or opened.st_size > max_bytes
        ):
            raise BridgeFailure("guest-state-unsafe")
        content = b""
        while len(content) <= max_bytes:
            chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - len(content)))
            if not chunk:
                break
            content += chunk
        after = os.fstat(descriptor)
        current = os.stat(name, dir_fd=context_descriptor, follow_symlinks=False)
        if (
            len(content) > max_bytes
            or len(content) != after.st_size
            or not _same_inode(opened, after)
            or not _same_inode(after, current)
        ):
            raise BridgeFailure("guest-state-unsafe")
        return content
    except BridgeFailure:
        raise
    except OSError as error:
        raise BridgeFailure("guest-state-unsafe") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(context_descriptor)
        os.close(root_descriptor)


def _write_state_file(
    root: Path,
    context: str,
    name: str,
    content: bytes,
    *,
    root_uid: int,
) -> Path:
    root_descriptor, context_descriptor = _open_state_context(
        root, context, create=True, root_uid=root_uid
    )
    descriptor: int | None = None
    temporary: str | None = None
    try:
        for _ in range(20):
            candidate = f".{name}.{secrets.token_hex(16)}.tmp"
            try:
                descriptor = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW,
                    0o600,
                    dir_fd=context_descriptor,
                )
            except FileExistsError:
                continue
            temporary = candidate
            break
        if descriptor is None or temporary is None:
            raise BridgeFailure("guest-state-unsafe")
        created = os.fstat(descriptor)
        if created.st_uid != root_uid or stat.S_IMODE(created.st_mode) != 0o600:
            raise BridgeFailure("guest-state-unsafe")
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise BridgeFailure("guest-state-unsafe")
            view = view[written:]
        os.fsync(descriptor)
        try:
            os.link(
                temporary,
                name,
                src_dir_fd=context_descriptor,
                dst_dir_fd=context_descriptor,
                follow_symlinks=False,
            )
        except FileExistsError:
            existing = os.open(
                name,
                os.O_RDONLY | _NOFOLLOW | _NONBLOCK,
                dir_fd=context_descriptor,
            )
            try:
                existing_info = os.fstat(existing)
                named = os.stat(name, dir_fd=context_descriptor, follow_symlinks=False)
                if (
                    not stat.S_ISREG(existing_info.st_mode)
                    or not _same_inode(existing_info, named)
                    or existing_info.st_uid != root_uid
                    or stat.S_IMODE(existing_info.st_mode) != 0o600
                    or existing_info.st_size != len(content)
                ):
                    raise BridgeFailure("guest-state-unsafe")
                existing_content = b""
                while len(existing_content) < len(content):
                    chunk = os.read(existing, len(content) - len(existing_content))
                    if not chunk:
                        break
                    existing_content += chunk
                if existing_content != content:
                    raise BridgeFailure("guest-state-unsafe")
            finally:
                os.close(existing)
        else:
            published = os.stat(name, dir_fd=context_descriptor, follow_symlinks=False)
            if not _same_inode(created, published):
                raise BridgeFailure("guest-state-unsafe")
        os.unlink(temporary, dir_fd=context_descriptor)
        temporary = None
        published = os.stat(name, dir_fd=context_descriptor, follow_symlinks=False)
        if published.st_uid != root_uid or stat.S_IMODE(published.st_mode) != 0o600:
            raise BridgeFailure("guest-state-unsafe")
        os.fsync(context_descriptor)
    except BridgeFailure:
        raise
    except OSError as error:
        raise BridgeFailure("guest-state-unsafe") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=context_descriptor)
            except OSError:
                pass
        os.close(context_descriptor)
        os.close(root_descriptor)
    return root / context / name


def _read_authority(root: Path, context: str, root_uid: int | None = None) -> dict[str, Any]:
    trusted_uid = os.geteuid() if root_uid is None else root_uid
    document = _canonical_document(
        _read_state_file(
            root,
            context,
            "authority.json",
            root_uid=trusted_uid,
            max_bytes=4 * 1024 * 1024,
        )
    )
    expected = {
        "context_digest",
        "base_revision",
        "bundle_digest",
        "manifest_digest",
        "execution_policy",
        "phase_artifacts",
        "phase_writable_paths",
        "prepared_head",
        "prepared_tree",
        "prepared_surface_fingerprint",
        "prepared_clean",
        "git_policy_fingerprint",
    }
    try:
        if set(document) != expected or document.get("context_digest") != context:
            raise BridgeFailure("authority-invalid")
        base = _revision(document.get("base_revision"))
        _digest(document.get("bundle_digest"))
        _digest(document.get("manifest_digest"))
        prepared_head = _revision(document.get("prepared_head"))
        _revision(document.get("prepared_tree"))
        _digest(document.get("prepared_surface_fingerprint"))
        _digest(document.get("git_policy_fingerprint"))
        if prepared_head != base or document.get("prepared_clean") is not True:
            raise BridgeFailure("authority-invalid")
        policy = _execution_policy(document.get("execution_policy"))
        artifacts = _phase_artifacts(document.get("phase_artifacts"))
        _phase_writable_paths(
            document.get("phase_writable_paths"),
            policy=policy,
            artifacts=artifacts,
        )
    except BridgeFailure as error:
        if error.reason in {"authority-invalid", "policy-invalid"}:
            raise
        raise BridgeFailure("authority-invalid") from error
    return document


def _write_authority(
    root: Path,
    context: str,
    document: dict[str, Any],
    root_uid: int | None = None,
) -> None:
    trusted_uid = os.geteuid() if root_uid is None else root_uid
    encoded = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    _write_state_file(
        root,
        context,
        "authority.json",
        encoded,
        root_uid=trusted_uid,
    )


def _workspace_context(root: Path, workspace: Path) -> str:
    resolved_root = _safe_root(root, create=False)
    if workspace.parent != resolved_root:
        raise BridgeFailure("workspace-unsafe")
    return _digest(workspace.name)


def _path_within(path: str, approved: tuple[str, ...]) -> bool:
    if path == ".git" or path.startswith((".git/", ".aifactory-")):
        return False
    return any(
        path.startswith(f"{root[:-3]}/") if root.endswith("/**") else path == root
        for root in approved
    )


def _write_effective_policy(
    config: BridgeConfig,
    request_id: str,
    workspace: Path,
    scope: ExecutionScope,
    authority: Mapping[str, Any],
) -> Path:
    base = _root_owned_regular_bytes(config.policy_path, config.root_uid)
    if config.policy_path != config.leash_policy_path:
        raise BridgeFailure("policy-inode-mismatch")
    if authority.get("execution_policy", {}).get("network_profile") != scope.network_profile:
        raise BridgeFailure("scope-authority-mismatch")
    reads = (
        'permit(principal, action in [Action::"FileOpen", Action::"FileOpenReadOnly"], '
        "resource) when { resource in ["
        f"File::{json.dumps(str(workspace))}, "
        f"Dir::{json.dumps(str(workspace) + '/')}] }};\n"
    )
    writes: list[str] = []
    for path in scope.writable_paths:
        absolute = str(workspace / path.removesuffix("/**"))
        if path.endswith("/**"):
            writes.append(
                'permit(principal, action == Action::"FileOpenReadWrite", resource) '
                f"when {{ resource in [Dir::{json.dumps(absolute + '/')}] }};\n"
            )
        else:
            writes.append(
                'permit(principal, action == Action::"FileOpenReadWrite", '
                f"resource == File::{json.dumps(absolute)});\n"
            )
    if not writes:
        raise BridgeFailure("scope-not-representable")
    content = base + b"\n" + (reads + "".join(writes)).encode("utf-8")
    filename = hashlib.sha256(request_id.encode("utf-8")).hexdigest() + ".cedar"
    return _write_state_file(
        config.state_root,
        scope.context_digest,
        filename,
        content,
        root_uid=config.root_uid,
    )


def _git_policy_fingerprint(
    bridge: ExecutionBridge, workspace: Path, *, deadline: float | None = None
) -> str:
    configured = bridge._command(
        ["git", "config", "--local", "--no-includes", "--null", "--list"],
        cwd=workspace,
        timeout=20 if deadline is None else _probe_timeout(deadline, 20),
        env=_sanitized_bridge_git_environment(),
    ).stdout
    return hashlib.sha256(
        b"aifactory-sanitized-git-v1\0"
        + json.dumps(
            _FIXED_GIT_CONFIG,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\0"
        + configured.encode("utf-8")
    ).hexdigest()


def _containment_surface_fingerprint(workspace: Path, *, deadline: float) -> str:
    try:
        completed = _run_bounded_process(
            [sys.executable, "-I", "-c", _FINGERPRINT_PROGRAM, str(workspace)],
            timeout=_probe_timeout(deadline, 120),
            text=False,
            max_output_bytes=128,
        )
        value = completed.stdout.decode("ascii", "strict").strip()
    except subprocess.TimeoutExpired:
        raise BridgeFailure("probe-timeout") from None
    except BridgeFailure as error:
        if error.reason == "probe-timeout":
            raise
        raise BridgeFailure("fingerprint-unavailable") from None
    except (OSError, UnicodeDecodeError):
        raise BridgeFailure("fingerprint-unavailable") from None
    if completed.returncode != 0 or completed.stderr or not _is_digest(value):
        raise BridgeFailure("fingerprint-unavailable")
    return value


def _prepared_workspace_identity(
    bridge: ExecutionBridge, workspace: Path, *, deadline: float | None = None
) -> dict[str, JsonValue]:
    def git_stdout(args: list[str]) -> str:
        if deadline is None:
            return bridge._git_stdout(workspace, args)
        return bridge._command(
            ["git", *args],
            cwd=workspace,
            timeout=_probe_timeout(deadline, 30),
            env=_sanitized_bridge_git_environment(),
        ).stdout.strip()

    head = git_stdout(["rev-parse", "HEAD"])
    tree = git_stdout(["rev-parse", "HEAD^{tree}"])
    status = bridge._command(
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        cwd=workspace,
        timeout=60 if deadline is None else _probe_timeout(deadline, 60),
        env=_sanitized_bridge_git_environment(),
    ).stdout
    if status:
        raise BridgeFailure("workspace-dirty")
    return {
        "prepared_head": head,
        "prepared_tree": tree,
        "prepared_surface_fingerprint": (
            fingerprint_repository_surface(workspace)
            if deadline is None
            else _containment_surface_fingerprint(workspace, deadline=deadline)
        ),
        "prepared_clean": True,
        "git_policy_fingerprint": _git_policy_fingerprint(
            bridge, workspace, deadline=deadline
        ),
    }


def _prepared_workspace_matches(workspace: Path, authority: Mapping[str, Any]) -> bool:
    try:
        bridge = ExecutionBridge()
        observed = _prepared_workspace_identity(bridge, workspace)
        return all(authority.get(key) == value for key, value in observed.items())
    except (OSError, KeyError, BridgeFailure, RuntimeError):
        return False


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(_regular_bytes(path)).hexdigest()


def _bounded_environment() -> dict[str, str]:
    environment = {key: os.environ[key] for key in _ENVIRONMENT_ALLOWLIST if key in os.environ}
    environment["PATH"] = _SAFE_PATH
    return environment


def _sanitized_bridge_git_environment(
    extra: Mapping[str, str] | None = None,
) -> dict[str, str]:
    environment = sanitized_git_environment()
    environment["GIT_CONFIG_COUNT"] = str(len(_FIXED_GIT_CONFIG))
    for index, (key, value) in enumerate(_FIXED_GIT_CONFIG):
        environment[f"GIT_CONFIG_KEY_{index}"] = key
        environment[f"GIT_CONFIG_VALUE_{index}"] = value
    if extra is not None:
        if any(not key.startswith("GIT_") for key in extra):
            raise BridgeFailure("git-environment-invalid")
        environment.update(extra)
    return environment


def _command_environment(profile: object) -> dict[str, str]:
    if profile != "default":
        raise BridgeFailure("policy-invalid")
    return _bounded_environment()


def _is_denial(output: str) -> bool:
    try:
        document = _terminal_json_record(output)
    except (TypeError, json.JSONDecodeError):
        return False
    return isinstance(document, Mapping) and document.get("decision") in {"deny", "denied"}


def _normalized_denial(output: str, *, workspace: Path, state_root: Path) -> dict[str, JsonValue]:
    try:
        document = _terminal_json_record(output)
    except (TypeError, json.JSONDecodeError):
        return {"action": "process.exec", "resource": "unknown"}
    action = document.get("action") if isinstance(document, Mapping) else None
    if action not in _SAFE_DENIAL_ACTIONS:
        action = "process.exec"
    resource = document.get("resource") if isinstance(document, Mapping) else None
    if type(resource) is str and "://" in resource:
        category = "network-endpoint"
    elif type(resource) is str and _valid_relative_path(resource):
        category = "repository-path"
    elif type(resource) is str and resource.startswith("/"):
        parsed = PurePosixPath(resource)
        workspace_path = PurePosixPath(str(workspace))
        state_path = PurePosixPath(str(state_root))
        if parsed == workspace_path or parsed.is_relative_to(workspace_path):
            category = "repository-path"
        elif parsed == state_path or parsed.is_relative_to(state_path):
            category = "controller-state"
        else:
            category = "system-path"
    else:
        category = "unknown"
    return {"action": action, "resource": category}


def _terminal_json_record(output: str) -> Any:
    """Decode the final machine record after Leash's human-readable prelude."""
    if type(output) is not str:
        raise TypeError("command output is not text")
    stripped = output.rstrip()
    if not stripped:
        raise json.JSONDecodeError("empty command output", output, 0)
    return json.loads(stripped.rsplit("\n", 1)[-1].strip())


def _claude_nonzero_reason(output: str) -> str:
    """Preserve only fixed Claude result subtypes from a failed author turn."""
    reasons = {
        "error_during_execution": "claude-error-during-execution",
        "error_max_turns": "claude-error-max-turns",
        "error_max_budget_usd": "claude-error-max-budget",
    }
    try:
        record = _terminal_json_record(output)
    except (ValueError, TypeError, json.JSONDecodeError):
        return "agent-exit-nonzero"
    if (
        not isinstance(record, dict)
        or record.get("type") != "result"
        or record.get("is_error") is not True
    ):
        return "agent-exit-nonzero"
    return reasons.get(record.get("subtype"), "agent-exit-nonzero")


def _verifier_launch_status(
    output: str,
) -> tuple[bool, Literal["exit", "signal"] | None, int | None] | None:
    try:
        document = json.loads(output)
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(document, Mapping) or document.get("protocol") != _VERIFIER_LAUNCH_PROTOCOL:
        return None
    if (
        document.get("launched") is True
        and set(document)
        == {
            "protocol",
            "launched",
            "termination",
            "exit_code",
        }
        and document.get("termination") == "exit"
    ):
        exit_code = document.get("exit_code")
        if type(exit_code) is int and 0 <= exit_code <= 255:
            return True, "exit", exit_code
        return None
    if (
        document.get("launched") is True
        and set(document)
        == {
            "protocol",
            "launched",
            "termination",
            "signal",
        }
        and document.get("termination") == "signal"
    ):
        signum = document.get("signal")
        if type(signum) is int and 1 <= signum <= 255:
            return True, "signal", signum
        return None
    if (
        document.get("launched") is False
        and set(document) == {"protocol", "launched", "reason"}
        and document.get("reason") == "executable-unavailable"
    ):
        return False, None, None
    return None


def verifier_launcher_main(argv: list[str] | None = None) -> int:
    """Run one verifier child and emit only the fixed launch-attestation protocol."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    if (
        len(arguments) < 2
        or arguments[0] != "--verifier-launch"
        or any(
            type(argument) is not str or not argument or "\0" in argument
            for argument in arguments[1:]
        )
    ):
        document: dict[str, JsonValue] = {
            "protocol": _VERIFIER_LAUNCH_PROTOCOL,
            "launched": False,
            "reason": "executable-unavailable",
        }
    else:
        try:
            child = subprocess.Popen(
                arguments[1:],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=_bounded_environment(),
                close_fds=True,
                shell=False,
            )
            exit_code = child.wait()
        except OSError:
            document = {
                "protocol": _VERIFIER_LAUNCH_PROTOCOL,
                "launched": False,
                "reason": "executable-unavailable",
            }
        else:
            if exit_code < 0:
                document = {
                    "protocol": _VERIFIER_LAUNCH_PROTOCOL,
                    "launched": True,
                    "termination": "signal",
                    "signal": -exit_code,
                }
            elif exit_code <= 255:
                document = {
                    "protocol": _VERIFIER_LAUNCH_PROTOCOL,
                    "launched": True,
                    "termination": "exit",
                    "exit_code": exit_code,
                }
            else:
                document = {
                    "protocol": _VERIFIER_LAUNCH_PROTOCOL,
                    "launched": False,
                    "reason": "executable-unavailable",
                }
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    sys.stdout.write(encoded)
    sys.stdout.flush()
    return 0


def main() -> int:
    """Read one canonical request from stdin and write one canonical response to stdout."""
    if sys.argv[1:2] == ["--verifier-launch"]:
        return verifier_launcher_main()
    request: BridgeRequest | None = None
    try:
        request = decode_request(sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1))
    except BridgeProtocolError:
        response = BridgeResponse(
            SCHEMA_VERSION, "bridge-error", "failed", {"reason": "invalid-request"}, ()
        )
    else:
        response = ExecutionBridge().handle(request)
    try:
        encoded = encode_response(response)
    except Exception as error:
        _emit_internal_diagnostic(error)
        fallback_request_id = "bridge-error" if request is None else request.request_id
        encoded = encode_response(
            BridgeResponse(
                SCHEMA_VERSION,
                fallback_request_id,
                "failed",
                {"reason": "response-encoding-failed"},
                (),
            )
        )
    sys.stdout.buffer.write(encoded)
    return 0


__all__ = [
    "BridgeConfig",
    "BridgeFailure",
    "ExecutionBridge",
    "ExecutionScope",
    "default_config",
    "main",
    "verifier_launcher_main",
]
