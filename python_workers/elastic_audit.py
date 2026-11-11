"""
SENTINEL Elasticsearch SIEM & Vector Search Client.

Streams every SENTINEL governance decision and PayPal Sandbox execution event into
an Elasticsearch index (`sentinel-audit-events` by default) with a 6-dimensional
`dense_vector` (`feature_vector`) so operators and judges can run both:
  1. Full-text & structured SIEM filtering (`_search` bool + multi_match)
  2. Nearest-neighbor behavioral attack matching (`_search` kNN cosine similarity)

Supports Elasticsearch 8.x/9.x / Elastic Cloud / Serverless using HTTPS REST (`ApiKey`
or Basic Auth) and degrades gracefully to in-memory ring-buffer search when unconfigured.
"""

import logging
import math
import os
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence

import requests

DEFAULT_ELASTIC_INDEX = "sentinel-audit-events"
_INDEX_LOCK = threading.Lock()
_ENSURED_INDEX_KEYS = set()


class ElasticAuditClient:
    """Lightweight REST client for Elasticsearch SIEM & kNN dense_vector indexing/search."""

    def __init__(
        self,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        index_name: Optional[str] = None,
        timeout: Optional[float] = None,
    ):
        self.url = (url if url is not None else os.getenv("ELASTICSEARCH_URL", "")).strip().rstrip("/")
        self.api_key = (api_key if api_key is not None else os.getenv("ELASTICSEARCH_API_KEY", "")).strip()
        self.username = (username if username is not None else os.getenv("ELASTICSEARCH_USERNAME", "")).strip()
        self.password = (password if password is not None else os.getenv("ELASTICSEARCH_PASSWORD", "")).strip()
        self.index_name = (
            index_name if index_name is not None else os.getenv("ELASTICSEARCH_INDEX", DEFAULT_ELASTIC_INDEX)
        ).strip() or DEFAULT_ELASTIC_INDEX
        try:
            self.timeout = float(timeout if timeout is not None else os.getenv("ELASTICSEARCH_TIMEOUT", "1.5"))
        except (TypeError, ValueError):
            self.timeout = 1.5

    def is_configured(self) -> bool:
        return bool(self.url)

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"
        return headers

    def _auth(self):
        if not self.api_key and self.username:
            return (self.username, self.password)
        return None

    def ensure_index(self) -> bool:
        """Creates the `sentinel-audit-events` index with 6-D cosine `dense_vector` mapping if missing."""
        if not self.is_configured():
            return False

        cache_key = f"{self.url}|{self.index_name}"
        with _INDEX_LOCK:
            if cache_key in _ENSURED_INDEX_KEYS:
                return True

        try:
            head_resp = requests.head(
                f"{self.url}/{self.index_name}",
                headers=self._headers(),
                auth=self._auth(),
                timeout=self.timeout,
            )
            if head_resp.status_code == 200:
                with _INDEX_LOCK:
                    _ENSURED_INDEX_KEYS.add(cache_key)
                return True

            if head_resp.status_code not in (404, 400):
                logging.debug(f"Elasticsearch index check returned HTTP {head_resp.status_code}")
                return False

            mapping = {
                "mappings": {
                    "properties": {
                        "event_id": {"type": "keyword"},
                        "timestamp": {"type": "date"},
                        "display_time": {"type": "keyword"},
                        "agent_id": {"type": "keyword"},
                        "action": {"type": "keyword"},
                        "decision": {"type": "keyword"},
                        "amount": {"type": "keyword"},
                        "amount_usd": {"type": "double"},
                        "wal_hash": {"type": "keyword"},
                        "paypal_id": {"type": "keyword"},
                        "prompt": {
                            "type": "text",
                            "fields": {"keyword": {"type": "keyword", "ignore_above": 256}},
                        },
                        "message": {"type": "text"},
                        "payload": {"type": "object", "enabled": True},
                        "feature_vector": {
                            "type": "dense_vector",
                            "dims": 6,
                            "index": True,
                            "similarity": "cosine",
                        },
                    }
                }
            }
            put_resp = requests.put(
                f"{self.url}/{self.index_name}",
                headers=self._headers(),
                auth=self._auth(),
                json=mapping,
                timeout=self.timeout,
            )
            if put_resp.status_code in (200, 201):
                with _INDEX_LOCK:
                    _ENSURED_INDEX_KEYS.add(cache_key)
                logging.info(f"Initialized Elasticsearch index `{self.index_name}` with 6D dense_vector mapping.")
                return True
            # Handle race condition when two workers create the index concurrently
            if put_resp.status_code == 400 and "resource_already_exists_exception" in put_resp.text:
                with _INDEX_LOCK:
                    _ENSURED_INDEX_KEYS.add(cache_key)
                return True
            logging.warning(f"Failed to create Elasticsearch index ({put_resp.status_code}): {put_resp.text[:200]}")
            return False
        except Exception as exc:
            logging.debug(f"Elasticsearch ensure_index skipped: {exc}")
            return False

    def check_health(self) -> Dict[str, Any]:
        """Checks live connectivity to the configured Elasticsearch cluster or Elastic Cloud endpoint."""
        if not self.is_configured():
            return {
                "configured": False,
                "reachable": False,
                "index": self.index_name,
                "message": "Optional: set ELASTICSEARCH_URL (and ELASTICSEARCH_API_KEY) to stream SIEM & kNN vectors.",
            }

        try:
            resp = requests.get(
                f"{self.url}/",
                headers=self._headers(),
                auth=self._auth(),
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                info = resp.json()
                return {
                    "configured": True,
                    "reachable": True,
                    "index": self.index_name,
                    "cluster_name": info.get("cluster_name", "elastic"),
                    "version": (info.get("version") or {}).get("number"),
                    "message": f"Connected to {info.get('cluster_name', 'Elasticsearch')}",
                }
            return {
                "configured": True,
                "reachable": False,
                "index": self.index_name,
                "message": f"HTTP {resp.status_code}: {resp.text[:160]}",
            }
        except Exception as exc:
            return {
                "configured": True,
                "reachable": False,
                "index": self.index_name,
                "message": str(exc),
            }

    def index_audit_event(self, doc: Dict[str, Any]) -> Dict[str, Any]:
        """Indexes one audit log event + optional 6D feature_vector into Elasticsearch."""
        if not self.is_configured():
            return {"indexed": False, "reason": "ELASTICSEARCH_URL not configured"}

        if not self.ensure_index():
            return {"indexed": False, "reason": "Could not verify/create Elasticsearch index"}

        record = dict(doc)
        if not record.get("timestamp"):
            record["timestamp"] = datetime.now(timezone.utc).isoformat()
        event_id = record.get("event_id")

        endpoint = (
            f"{self.url}/{self.index_name}/_doc/{event_id}"
            if event_id
            else f"{self.url}/{self.index_name}/_doc"
        )
        method = requests.put if event_id else requests.post

        try:
            resp = method(
                endpoint,
                headers=self._headers(),
                auth=self._auth(),
                json=record,
                timeout=self.timeout,
            )
            if resp.status_code in (200, 201):
                body = resp.json()
                return {"indexed": True, "id": body.get("_id"), "index": self.index_name}
            return {"indexed": False, "reason": f"HTTP {resp.status_code}: {resp.text[:180]}"}
        except Exception as exc:
            logging.debug(f"Elasticsearch index_audit_event failed: {exc}")
            return {"indexed": False, "reason": str(exc)}

    def search_audit_events(
        self,
        query: str = "",
        decision: str = "",
        agent_id: str = "",
        query_vector: Optional[Sequence[float]] = None,
        size: int = 25,
    ) -> Dict[str, Any]:
        """Executes full-text SIEM filtering or 6D dense_vector kNN search in Elasticsearch."""
        if not self.is_configured():
            raise RuntimeError("ELASTICSEARCH_URL not configured")

        limit = max(1, min(100, int(size)))
        filter_clauses: List[Dict[str, Any]] = []
        if decision and decision.upper() in ("ALLOW", "DENY"):
            filter_clauses.append({"term": {"decision": decision.upper()}})
        if agent_id and agent_id.strip():
            filter_clauses.append({"term": {"agent_id": agent_id.strip()}})

        if query_vector is not None:
            vec = [float(x) for x in query_vector]
            knn_body: Dict[str, Any] = {
                "field": "feature_vector",
                "query_vector": vec,
                "k": limit,
                "num_candidates": max(25, limit * 4),
            }
            if filter_clauses:
                knn_body["filter"] = filter_clauses
            search_body: Dict[str, Any] = {
                "size": limit,
                "knn": knn_body,
            }
        else:
            must_clauses: List[Dict[str, Any]] = []
            q = (query or "").strip()
            if q:
                must_clauses.append(
                    {
                        "multi_match": {
                            "query": q,
                            "fields": [
                                "agent_id^2",
                                "action^2",
                                "paypal_id^2",
                                "wal_hash^2",
                                "message",
                                "prompt",
                                "amount",
                            ],
                            "type": "best_fields",
                            "fuzziness": "AUTO",
                        }
                    }
                )
            else:
                must_clauses.append({"match_all": {}})

            search_body = {
                "size": limit,
                "query": {
                    "bool": {
                        "must": must_clauses,
                        "filter": filter_clauses,
                    }
                },
                "sort": (
                    [{"_score": {"order": "desc"}}, {"timestamp": {"order": "desc"}}]
                    if q
                    else [{"timestamp": {"order": "desc"}}]
                ),
            }

        resp = requests.post(
            f"{self.url}/{self.index_name}/_search",
            headers=self._headers(),
            auth=self._auth(),
            json=search_body,
            timeout=self.timeout,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"Elasticsearch _search HTTP {resp.status_code}: {resp.text[:220]}")

        data = resp.json()
        hits_obj = data.get("hits") or {}
        raw_hits = hits_obj.get("hits") or []
        total_val = hits_obj.get("total")
        total = total_val.get("value", len(raw_hits)) if isinstance(total_val, dict) else int(total_val or len(raw_hits))

        items = []
        for idx, h in enumerate(raw_hits):
            src = h.get("_source") or {}
            wal_hash = src.get("wal_hash") or ""
            short_hash = wal_hash if str(wal_hash).endswith("...") else (str(wal_hash)[:12] + "..." if wal_hash else "ELASTIC...")
            item = {
                "id": src.get("event_id") or h.get("_id") or f"es-{idx}",
                "time": src.get("display_time") or src.get("timestamp", "--"),
                "agent": src.get("agent_id", "ag_Unknown"),
                "action": src.get("action", "UNKNOWN"),
                "amount": src.get("amount", "N/A"),
                "decision": src.get("decision", "DENY"),
                "hash": short_hash,
                "score": round(float(h.get("_score")), 4) if h.get("_score") is not None else None,
            }
            if src.get("paypal_id"):
                item["paypal_id"] = src["paypal_id"]
            if src.get("message"):
                item["message"] = src["message"]
            items.append(item)

        return {
            "source": "elasticsearch",
            "index": self.index_name,
            "mode": "knn" if query_vector is not None else "text",
            "total": total,
            "hits": items,
        }


def _cosine_similarity(vec_a: Sequence[float], vec_b: Sequence[float]) -> float:
    dot = sum(float(a) * float(b) for a, b in zip(vec_a, vec_b))
    norm_a = math.sqrt(sum(float(a) * float(a) for a in vec_a))
    norm_b = math.sqrt(sum(float(b) * float(b) for b in vec_b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


def search_in_memory_fallback(
    records: Sequence[Dict[str, Any]],
    query: str = "",
    decision: str = "",
    agent_id: str = "",
    query_vector: Optional[Sequence[float]] = None,
    vectorize_fn: Optional[Callable[[str, Dict[str, Any]], Sequence[float]]] = None,
    size: int = 25,
) -> Dict[str, Any]:
    """Searches live in-memory audit records when Elasticsearch is unconfigured or offline."""
    q = (query or "").strip().lower()
    dec_filter = (decision or "").strip().upper()
    agent_filter = (agent_id or "").strip()

    matched: List[Dict[str, Any]] = []
    for rec in records:
        if dec_filter in ("ALLOW", "DENY") and str(rec.get("decision", "")).upper() != dec_filter:
            continue
        if agent_filter and str(rec.get("agent", "")) != agent_filter:
            continue

        if q and query_vector is None:
            haystack = " ".join(
                str(rec.get(k, "") or "")
                for k in ("agent", "action", "amount", "decision", "hash", "paypal_id", "message")
            ).lower()
            normalized_haystack = haystack.replace(",", "").replace("$", "")
            normalized_q = q.replace(",", "").replace("$", "")
            if q not in haystack and normalized_q not in normalized_haystack:
                continue

        entry = dict(rec)
        if query_vector is not None and vectorize_fn is not None:
            stored_vec = rec.get("_vector")
            if stored_vec is None:
                raw_amt = rec.get("amount", "")
                stored_vec = vectorize_fn(rec.get("action", ""), {"amount": raw_amt})
            entry["score"] = round(_cosine_similarity(query_vector, stored_vec), 4)
        matched.append(entry)

    if query_vector is not None:
        matched.sort(key=lambda item: float(item.get("score") or 0.0), reverse=True)

    # Strip internal vector field before returning JSON
    clean_hits = []
    for item in matched[: max(1, min(100, int(size)))]:
        cleaned = {k: v for k, v in item.items() if k != "_vector"}
        clean_hits.append(cleaned)

    return {
        "source": "in_memory_fallback",
        "index": os.getenv("ELASTICSEARCH_INDEX", DEFAULT_ELASTIC_INDEX),
        "mode": "knn" if query_vector is not None else "text",
        "total": len(matched),
        "hits": clean_hits,
    }
