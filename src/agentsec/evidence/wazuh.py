"""Wazuh alert collector.

Two backends:

``file``        A JSON array of Wazuh alert documents. Used by fixtures and by
                air-gapped CI.
``opensearch``  Queries ``wazuh-alerts-*`` over the Wazuh Indexer API, bounded to
                the run's time window.

Both normalise into ``WazuhAlert``, so the evaluator never sees an OpenSearch
response shape.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any

from agentsec.errors import EvidenceUnavailable
from agentsec.evidence.base import (
    CollectContext,
    flatten,
    read_json,
    rebase_to_window,
    resolve_path,
)
from agentsec.models.evidence import SourceMeta, WazuhAlert, WazuhSource
from agentsec.policy.allowlist import assert_private_url


def collect_wazuh(ctx: CollectContext) -> WazuhSource:
    backend = ctx.target.evidence.wazuh
    if backend is None or backend.kind == "none":
        raise EvidenceUnavailable("target has no Wazuh evidence backend")

    if backend.kind == "file":
        raw = read_json(resolve_path(backend.path, ctx))
        docs = raw if isinstance(raw, list) else raw.get("alerts", [])
        alerts = [_normalise(d) for d in docs]
        shifted = rebase_to_window([a.timestamp for a in alerts], ctx.window_start)
        for alert_obj, ts in zip(alerts, shifted, strict=True):
            alert_obj.timestamp = ts
        return WazuhSource(
            alerts=alerts,
            meta=SourceMeta(
                collector="wazuh",
                backend="file",
                query=f"{backend.path} (timeline rebased to run window)",
            ),
        )

    return _collect_opensearch(ctx)


def _collect_opensearch(ctx: CollectContext) -> WazuhSource:
    import httpx

    backend = ctx.target.evidence.wazuh
    assert backend is not None
    if not backend.url:
        raise EvidenceUnavailable("wazuh backend kind=opensearch requires a url")

    # Checked again here, not only at allowlist load: this request carries the
    # Indexer credentials, so the wrong host costs more than a failed query.
    assert_private_url(backend.url, what="the Wazuh Indexer")

    auth: httpx.Auth | None = None
    if backend.username_env and backend.password_env:
        user = os.environ.get(backend.username_env)
        password = os.environ.get(backend.password_env)
        if not user or not password:
            raise EvidenceUnavailable(
                f"Wazuh credentials not set ({backend.username_env}/{backend.password_env})"
            )
        auth = httpx.BasicAuth(user, password)

    query = {
        "size": 500,
        "sort": [{"timestamp": {"order": "asc"}}],
        "query": {
            "bool": {
                "filter": [
                    {
                        "range": {
                            "timestamp": {
                                "gte": ctx.window_start.isoformat(),
                                "lte": ctx.window_end.isoformat(),
                            }
                        }
                    }
                ]
            }
        },
    }

    url = f"{backend.url.rstrip('/')}/{backend.index}/_search"
    try:
        with httpx.Client(timeout=30, verify=backend.verify_tls, auth=auth) as client:
            resp = client.post(url, json=query)
            resp.raise_for_status()
            body = resp.json()
    except httpx.HTTPError as exc:
        raise EvidenceUnavailable(
            f"Wazuh Indexer query failed: {type(exc).__name__}"
        ) from exc

    hits = body.get("hits", {}).get("hits", [])
    return WazuhSource(
        alerts=[_normalise(h.get("_source", {}), doc_id=h.get("_id")) for h in hits],
        meta=SourceMeta(
            collector="wazuh",
            backend="opensearch",
            # Deliberately records the window, not the credentials or full URL.
            query=f"{backend.index} {ctx.window_start.isoformat()}..{ctx.window_end.isoformat()}",
        ),
    )


def _normalise(doc: dict[str, Any], doc_id: str | None = None) -> WazuhAlert:
    rule = doc.get("rule") or {}
    agent = doc.get("agent") or {}
    ts = doc.get("timestamp") or doc.get("@timestamp")
    return WazuhAlert(
        alert_id=doc_id or doc.get("id"),
        rule_id=str(rule.get("id", "")),
        rule_description=rule.get("description"),
        rule_level=rule.get("level"),
        rule_groups=list(rule.get("groups") or []),
        agent_name=agent.get("name"),
        timestamp=_parse_ts(ts),
        fields=flatten(doc),
    )


def _parse_ts(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
    raise EvidenceUnavailable(f"alert has an unparseable timestamp: {value!r}")
