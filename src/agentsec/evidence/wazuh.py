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
    canonical_run_id,
    flatten,
    read_json,
    rebase_to_window,
    require_run_id_value,
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
        if isinstance(raw, list):
            docs = raw
        elif isinstance(raw, dict) and isinstance(raw.get("alerts"), list):
            docs = raw["alerts"]
        else:
            raise EvidenceUnavailable("unrecognised Wazuh payload shape")
        if not all(isinstance(d, dict) for d in docs):
            raise EvidenceUnavailable("Wazuh alert payload contains a non-object record")
        alerts = [
            _normalise(d, ctx=ctx, trusted_fixture=ctx.trusted_fixture) for d in docs
        ]
        shifted = rebase_to_window([a.timestamp for a in alerts], ctx.window_start)
        for alert_obj, ts in zip(alerts, shifted, strict=True):
            alert_obj.timestamp = ts
        return WazuhSource(
            alerts=alerts,
            meta=SourceMeta(
                collector="wazuh",
                backend="file",
                query=f"{backend.path} (timeline rebased to run window)",
                correlation="trusted_fixture" if ctx.trusted_fixture else "verified",
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

    page_size = 500
    scroll_keep_alive = "1m"
    query = {
        "size": page_size,
        # Scroll freezes the result set; _doc is the mapping-independent,
        # efficient traversal order recommended for consuming every hit.
        "sort": ["_doc"],
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
                    },
                    {"term": {"agentsec.run_id": ctx.run_id}},
                ]
            }
        },
    }

    base_url = backend.url.rstrip("/")
    initial_url = f"{base_url}/{backend.index}/_search?scroll={scroll_keep_alive}"
    scroll_url = f"{base_url}/_search/scroll"
    hits: list[dict[str, Any]] = []
    seen_hits: set[tuple[str, str]] = set()
    scroll_id: str | None = None
    max_pages = 1000
    try:
        with httpx.Client(timeout=30, verify=backend.verify_tls, auth=auth) as client:
            collection_failed = False
            try:
                request_url = initial_url
                payload = query
                for _ in range(max_pages):
                    resp = client.post(request_url, json=payload)
                    resp.raise_for_status()
                    body = resp.json()
                    scroll_id = _response_scroll_id(body)
                    page = _page_hits(body)
                    if not page:
                        break
                    for hit in page:
                        index_name = hit.get("_index")
                        doc_id = hit.get("_id")
                        if not isinstance(index_name, str) or not index_name:
                            raise EvidenceUnavailable("Wazuh response hit is missing _index")
                        if not isinstance(doc_id, str) or not doc_id:
                            raise EvidenceUnavailable("Wazuh response hit is missing _id")
                        identity = (index_name, doc_id)
                        if identity in seen_hits:
                            raise EvidenceUnavailable(
                                "Wazuh pagination returned a duplicate hit"
                            )
                        seen_hits.add(identity)
                    hits.extend(page)
                    request_url = scroll_url
                    payload = {"scroll": scroll_keep_alive, "scroll_id": scroll_id}
                else:
                    raise EvidenceUnavailable(
                        "Wazuh pagination exceeded the bounded page limit"
                    )
            except Exception:
                collection_failed = True
                raise
            finally:
                if scroll_id is not None:
                    try:
                        clear = client.request(
                            "DELETE", scroll_url, json={"scroll_id": scroll_id}
                        )
                        clear.raise_for_status()
                    except httpx.HTTPError:
                        # Preserve the primary collection error if one already
                        # occurred. Otherwise a leaked scroll context is itself
                        # a backend failure (the context also expires after 1m).
                        if not collection_failed:
                            raise
    except httpx.HTTPError as exc:
        raise EvidenceUnavailable(
            f"Wazuh Indexer query failed: {type(exc).__name__}"
        ) from exc
    except (TypeError, ValueError) as exc:
        raise EvidenceUnavailable("Wazuh Indexer returned malformed JSON") from exc

    alerts = [_normalise(h["_source"], doc_id=h["_id"], ctx=ctx) for h in hits]
    alerts.sort(key=lambda alert: (alert.timestamp, alert.alert_id or ""))
    return WazuhSource(
        alerts=alerts,
        meta=SourceMeta(
            collector="wazuh",
            backend="opensearch",
            # Deliberately records the window, not the credentials or full URL.
            query=f"{backend.index} {ctx.window_start.isoformat()}..{ctx.window_end.isoformat()}",
            correlation="verified",
        ),
    )


def _response_scroll_id(body: Any) -> str:
    if not isinstance(body, dict):
        raise EvidenceUnavailable("Wazuh response is not an object")
    scroll_id = body.get("_scroll_id")
    if not isinstance(scroll_id, str) or not scroll_id:
        raise EvidenceUnavailable("Wazuh response is missing _scroll_id")
    return scroll_id


def _page_hits(body: Any) -> list[dict[str, Any]]:
    if not isinstance(body, dict) or not isinstance(body.get("hits"), dict):
        raise EvidenceUnavailable("Wazuh response is missing hits")
    raw_hits = body["hits"].get("hits")
    if not isinstance(raw_hits, list) or not all(isinstance(h, dict) for h in raw_hits):
        raise EvidenceUnavailable("Wazuh response has an invalid hits list")
    for hit in raw_hits:
        if not isinstance(hit.get("_source"), dict):
            raise EvidenceUnavailable("Wazuh response hit is missing _source")
    return raw_hits


def _normalise(
    doc: dict[str, Any],
    doc_id: str | None = None,
    *,
    ctx: CollectContext | None = None,
    trusted_fixture: bool = False,
) -> WazuhAlert:
    rule = doc.get("rule") or {}
    agent = doc.get("agent") or {}
    ts = doc.get("timestamp") or doc.get("@timestamp")
    run_id = canonical_run_id(doc)
    if ctx is not None:
        run_id = require_run_id_value(
            run_id,
            ctx.run_id,
            trusted_fixture=trusted_fixture,
            what="Wazuh alert",
        )
    return WazuhAlert(
        alert_id=doc_id or doc.get("id"),
        rule_id=str(rule.get("id", "")),
        rule_description=rule.get("description"),
        rule_level=rule.get("level"),
        rule_groups=list(rule.get("groups") or []),
        agent_name=agent.get("name"),
        timestamp=_parse_ts(ts),
        fields=flatten(doc),
        run_id=run_id,
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
