"""
Automated tests for SENTINEL Elasticsearch SIEM & 6D dense_vector kNN integration.

Verifies against a local mock Elasticsearch HTTP server AND offline fallback:
  - Index creation (`PUT /sentinel-audit-events`) with 6D cosine `dense_vector` mapping
  - Automatic event indexing (`PUT /_doc/...`) when SENTINEL logs governance events
  - Text SIEM `_search` (`multi_match` + filters) and 6D `knn` similarity search
  - FastAPI endpoints (`GET /health`, `GET /api/integrations/status`, `GET /api/audit/search`)
  - Never exposing `ELASTICSEARCH_API_KEY` or credentials in API responses
"""

import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

from fastapi.testclient import TestClient

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import case_law_engine  # noqa: E402
import elastic_audit  # noqa: E402


class _MockElasticState:
    def __init__(self):
        self.reset()

    def reset(self):
        self.index_created = False
        self.mapping_body = None
        self.docs = []
        self.search_requests = []
        self.last_auth_header = ""


_MOCK_ES_STATE = _MockElasticState()


class _MockElasticHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def _send(self, code: int, payload):
        body = json.dumps(payload).encode("utf-8") if payload is not None else b""
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_HEAD(self):
        _MOCK_ES_STATE.last_auth_header = self.headers.get("Authorization", "")
        if _MOCK_ES_STATE.index_created:
            self._send(200, None)
        else:
            self._send(404, None)

    def do_GET(self):
        _MOCK_ES_STATE.last_auth_header = self.headers.get("Authorization", "")
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send(
                200,
                {
                    "name": "mock-es-node",
                    "cluster_name": "sentinel-elastic-test",
                    "version": {"number": "8.15.0"},
                },
            )
            return
        self._send(404, {"error": "not_found"})

    def do_PUT(self):
        _MOCK_ES_STATE.last_auth_header = self.headers.get("Authorization", "")
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        body = json.loads(raw)
        parsed = urlparse(self.path)

        if parsed.path == "/sentinel-audit-events":
            _MOCK_ES_STATE.index_created = True
            _MOCK_ES_STATE.mapping_body = body
            self._send(200, {"acknowledged": True, "index": "sentinel-audit-events"})
            return

        if parsed.path.startswith("/sentinel-audit-events/_doc/"):
            doc_id = parsed.path.rsplit("/", 1)[-1]
            _MOCK_ES_STATE.docs.append({"_id": doc_id, "_source": body})
            self._send(201, {"_id": doc_id, "result": "created"})
            return

        self._send(404, {"error": "unknown_put"})

    def do_POST(self):
        _MOCK_ES_STATE.last_auth_header = self.headers.get("Authorization", "")
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        body = json.loads(raw)
        parsed = urlparse(self.path)

        if parsed.path == "/sentinel-audit-events/_doc":
            doc_id = f"auto-{len(_MOCK_ES_STATE.docs) + 1}"
            _MOCK_ES_STATE.docs.append({"_id": doc_id, "_source": body})
            self._send(201, {"_id": doc_id, "result": "created"})
            return

        if parsed.path == "/sentinel-audit-events/_search":
            _MOCK_ES_STATE.search_requests.append(body)
            hits = []
            for idx, doc in enumerate(reversed(_MOCK_ES_STATE.docs)):
                hits.append(
                    {
                        "_id": doc["_id"],
                        "_score": 0.9876 if "knn" in body else 1.5 - idx * 0.1,
                        "_source": doc["_source"],
                    }
                )
            self._send(
                200,
                {
                    "hits": {
                        "total": {"value": len(hits), "relation": "eq"},
                        "hits": hits,
                    }
                },
            )
            return

        self._send(404, {"error": "unknown_post"})


class TestElasticAuditIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), _MockElasticHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        _MOCK_ES_STATE.reset()
        elastic_audit._ENSURED_INDEX_KEYS.clear()
        self._orig_url = os.environ.get("ELASTICSEARCH_URL")
        self._orig_key = os.environ.get("ELASTICSEARCH_API_KEY")
        os.environ["ELASTICSEARCH_URL"] = f"http://127.0.0.1:{self.port}"
        os.environ["ELASTICSEARCH_API_KEY"] = "es-secret-api-key-999"

    def tearDown(self):
        elastic_audit._ENSURED_INDEX_KEYS.clear()
        if self._orig_url is None:
            os.environ.pop("ELASTICSEARCH_URL", None)
        else:
            os.environ["ELASTICSEARCH_URL"] = self._orig_url
        if self._orig_key is None:
            os.environ.pop("ELASTICSEARCH_API_KEY", None)
        else:
            os.environ["ELASTICSEARCH_API_KEY"] = self._orig_key

    def test_index_mapping_siem_ingestion_and_knn_search(self):
        client = TestClient(case_law_engine.app)

        # 1. Health endpoint for Render readiness probe
        h = client.get("/health")
        self.assertEqual(h.status_code, 200)
        self.assertEqual(h.json()["status"], "ok")

        # 2. Integration status reports Elastic reachable without leaking API key
        status_resp = client.get("/api/integrations/status")
        self.assertEqual(status_resp.status_code, 200)
        status_json = status_resp.json()
        self.assertTrue(status_json["elastic"]["configured"])
        self.assertTrue(status_json["elastic"]["reachable"])
        self.assertEqual(status_json["elastic"]["cluster_name"], "sentinel-elastic-test")
        self.assertNotIn("es-secret-api-key-999", json.dumps(status_json))
        self.assertEqual(_MOCK_ES_STATE.last_auth_header, "ApiKey es-secret-api-key-999")

        # 3. Recording a live audit log creates the 6D dense_vector mapping and indexes event
        case_law_engine.record_live_audit_log(
            {
                "agent": "ag_Travel_Bot",
                "action": "PAYPAL_PAYOUT",
                "payload": {"amount": 25.0, "recipient_email": "sb-buyer@personal.example.com"},
                "decision": "ALLOW",
                "paypal_id": "BATCH_ES_001",
                "message": "Approved PayPal Sandbox payout",
            }
        )
        self.assertTrue(_MOCK_ES_STATE.index_created)
        vec_prop = _MOCK_ES_STATE.mapping_body["mappings"]["properties"]["feature_vector"]
        self.assertEqual(vec_prop["type"], "dense_vector")
        self.assertEqual(vec_prop["dims"], 6)
        self.assertEqual(vec_prop["similarity"], "cosine")
        self.assertEqual(len(_MOCK_ES_STATE.docs), 1)
        self.assertEqual(len(_MOCK_ES_STATE.docs[0]["_source"]["feature_vector"]), 6)

        # 4. Full-text SIEM query hits Elasticsearch bool/multi_match
        txt_resp = client.get("/api/audit/search?q=BATCH_ES_001&decision=ALLOW&mode=text")
        self.assertEqual(txt_resp.status_code, 200)
        txt_data = txt_resp.json()
        self.assertEqual(txt_data["source"], "elasticsearch")
        self.assertEqual(txt_data["mode"], "text")
        self.assertEqual(len(txt_data["hits"]), 1)
        self.assertEqual(txt_data["hits"][0]["paypal_id"], "BATCH_ES_001")
        self.assertIn("query", _MOCK_ES_STATE.search_requests[0])

        # 5. 6D dense_vector kNN query hits Elasticsearch knn search
        knn_resp = client.get("/api/audit/search?q=PAYPAL_PAYOUT%20$25000&mode=knn")
        self.assertEqual(knn_resp.status_code, 200)
        knn_data = knn_resp.json()
        self.assertEqual(knn_data["source"], "elasticsearch")
        self.assertEqual(knn_data["mode"], "knn")
        self.assertEqual(len(knn_data["query_vector"]), 6)
        self.assertIn("knn", _MOCK_ES_STATE.search_requests[1])
        self.assertEqual(_MOCK_ES_STATE.search_requests[1]["knn"]["field"], "feature_vector")
        self.assertEqual(len(_MOCK_ES_STATE.search_requests[1]["knn"]["query_vector"]), 6)

    def test_in_memory_fallback_search_when_elastic_unconfigured(self):
        os.environ.pop("ELASTICSEARCH_URL", None)
        client = TestClient(case_law_engine.app)

        case_law_engine.record_live_audit_log(
            {
                "agent": "ag_Rogue_Sim",
                "action": "PAYPAL_PAYOUT",
                "payload": {"amount": 30000.0},
                "decision": "DENY",
                "message": "Ceiling exceeded fallback test",
            }
        )

        # Text fallback filter
        resp = client.get("/api/audit/search?q=ag_Rogue_Sim&decision=DENY&mode=text")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["source"], "in_memory_fallback")
        self.assertGreaterEqual(data["total"], 1)
        self.assertTrue(all(h["decision"] == "DENY" for h in data["hits"]))

        # Vector kNN fallback scoring
        knn_resp = client.get("/api/audit/search?q=30000&mode=knn")
        self.assertEqual(knn_resp.status_code, 200)
        knn_data = knn_resp.json()
        self.assertEqual(knn_data["source"], "in_memory_fallback")
        self.assertEqual(knn_data["mode"], "knn")
        self.assertGreaterEqual(len(knn_data["hits"]), 1)
        self.assertIn("score", knn_data["hits"][0])


if __name__ == "__main__":
    unittest.main()
