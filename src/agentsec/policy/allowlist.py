"""Target allowlist loading, with the network guard.

Two properties this module is responsible for:

* ``production`` is not a valid environment anywhere in the type system, so
  there is no runtime flag that lets a caller opt into it.
* A target's ``base_url`` must point at loopback or RFC1918 space unless the
  operator has explicitly recorded that they meant otherwise. A purple harness
  that can be pointed at ``api.stripe.com`` by editing one YAML line is a
  liability.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

import yaml
from jsonschema import Draft202012Validator

from agentsec.config import package_schema_dir
from agentsec.errors import ConfigError
from agentsec.models.target import Target, TargetAllowlist

#: Operators who genuinely need a public endpoint set this to a comma-separated
#: list of hostnames. Anything not listed is refused.
ENV_EXTERNAL_ALLOW = "AGENTSEC_ALLOW_EXTERNAL_HOSTS"


@lru_cache(maxsize=1)
def _schema() -> Draft202012Validator:
    schema = json.loads(
        (package_schema_dir() / "target.schema.json").read_text(encoding="utf-8")
    )
    return Draft202012Validator(schema)


def load_allowlist(path: Path, *, check_network: bool = True) -> TargetAllowlist:
    if not path.is_file():
        raise ConfigError(f"target allowlist not found: {path}")

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path.name}: invalid YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError(f"{path.name}: expected a mapping at the document root")

    errors = sorted(_schema().iter_errors(data), key=str)
    if errors:
        detail = "; ".join(
            f"{'/'.join(str(p) for p in e.absolute_path) or '(root)'}: {e.message}"
            for e in errors[:5]
        )
        raise ConfigError(f"{path.name}: allowlist schema errors: {detail}")

    try:
        allowlist = TargetAllowlist.model_validate(data)
    except Exception as exc:
        raise ConfigError(f"{path.name}: {exc}") from exc

    if check_network:
        for target in allowlist.targets:
            _check_endpoint(target)

    return allowlist


def assert_private_url(url: str, *, what: str) -> None:
    """Re-assert the private-address rule at the moment of dialling.

    ``_is_private_host`` treats an unresolvable name as private, because compose
    service names and CI DNS legitimately do not resolve when the allowlist is
    loaded. That leniency is only safe if something checks again later — otherwise
    a name that fails to resolve at load time and resolves publicly at run time is
    never caught at all.

    Raises ``EvidenceUnavailable`` rather than ``ConfigError``: at collection time
    the caller is a collector, and a refusal has to degrade its axis to ``error``
    rather than abort the batch.
    """
    from agentsec.errors import EvidenceUnavailable

    host = urlparse(url).hostname
    if not host:
        raise EvidenceUnavailable(f"{what} has no host")
    if host.lower() in _external_allowlist():
        return
    if not _is_private_host(host):
        raise EvidenceUnavailable(
            f"refusing to contact {what}: host '{host}' resolves outside private "
            f"address space. If this is intentional, add it to {ENV_EXTERNAL_ALLOW}."
        )


def _external_allowlist() -> set[str]:
    raw = os.environ.get(ENV_EXTERNAL_ALLOW, "")
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def _check_endpoint(target: Target) -> None:
    """Every URL the target can make the harness dial, not only the agent's.

    The adapter's ``base_url`` is the obvious one, but the evidence backends dial
    out too — and the Wazuh collector carries HTTP basic auth from the environment
    when it does, so a public URL there leaks the SIEM credentials rather than just
    reaching the wrong host.
    """
    for label, url in _target_urls(target):
        _check_url(target, label, url)


def _target_urls(target: Target) -> list[tuple[str, str]]:
    urls: list[tuple[str, str]] = []
    if target.adapter.kind == "http" and target.adapter.base_url:
        urls.append(("adapter.base_url", target.adapter.base_url))
    for name in ("otel", "wazuh", "tool_audit", "state_diff"):
        backend = getattr(target.evidence, name, None)
        if backend is None or backend.kind == "none" or not getattr(backend, "url", None):
            continue
        urls.append((f"evidence.{name}.url", backend.url))
    return urls


def _check_url(target: Target, label: str, raw: str) -> None:
    parsed = urlparse(raw)
    host = parsed.hostname
    if not host:
        raise ConfigError(f"target '{target.id}': {label} has no host")

    if host.lower() in _external_allowlist():
        return

    if not _is_private_host(host):
        raise ConfigError(
            f"target '{target.id}': {label} host '{host}' is not a private or "
            f"loopback address. If this is intentional, add it to "
            f"{ENV_EXTERNAL_ALLOW}.",
            details={"target_id": target.id, "host": host, "field": label},
        )


def _is_private_host(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
            return True
        try:
            # Resolve so that a hostname pointing at a public IP is caught too.
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror:
            # Unresolvable at config-load time (compose service names, CI DNS).
            # Treat as private; the run itself will fail loudly if it is not.
            return True
        return all(
            _addr_is_private(info[4][0]) for info in infos if isinstance(info[4][0], str)
        )
    return _addr_is_private(str(ip))


def _addr_is_private(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local
