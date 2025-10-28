"""Tests for the audit WSGI application."""
from __future__ import annotations

import json
from io import BytesIO
from typing import Dict, Iterable, List, Tuple
from wsgiref.util import setup_testing_defaults

from audit_app.app import create_app


def call_app(
    path: str,
    method: str = "GET",
    body: str | bytes | None = None,
    headers: Dict[str, str] | None = None,
) -> Tuple[str, Dict[str, str], bytes]:
    app = create_app()
    environ: Dict[str, object] = {}
    setup_testing_defaults(environ)
    environ["PATH_INFO"] = path
    environ["REQUEST_METHOD"] = method

    payload_bytes = b""
    if body is not None:
        payload_bytes = body.encode("utf-8") if isinstance(body, str) else body
    environ["wsgi.input"] = BytesIO(payload_bytes)
    environ["CONTENT_LENGTH"] = str(len(payload_bytes))
    if headers:
        for key, value in headers.items():
            normalized = key.upper().replace("-", "_")
            if normalized == "CONTENT_TYPE":
                environ["CONTENT_TYPE"] = value
            else:
                environ[f"HTTP_{normalized}"] = value

    status_holder: List[str] = []
    headers_holder: List[List[Tuple[str, str]]] = []

    def start_response(status: str, response_headers: List[Tuple[str, str]], exc_info=None):
        status_holder.append(status)
        headers_holder.append(response_headers)

    body_iterable: Iterable[bytes] = app(environ, start_response)
    body = b"".join(body_iterable)
    headers_dict = {key: value for key, value in headers_holder[0]}
    return status_holder[0], headers_dict, body


def test_api_checklist_structure():
    status, headers, body = call_app("/api/checklist")
    assert status == "200 OK"
    assert headers["Content-Type"].startswith("application/json")
    assert b"sections" in body


def test_index_route_renders():
    status, headers, body = call_app("/")
    assert status == "200 OK"
    assert headers["Content-Type"].startswith("text/html")
    assert b"Dedaub-Style Smart Contract Analyzer" in body


def test_analyze_endpoint_accepts_post_payload():
    payload = {
        "address": "0xabc123",
        "source": (
            "pragma solidity ^0.8.0;"
            "contract Test {"
            "  function boom(address target) external {"
            "    target.delegatecall(\"\");"
            "  }"
            "}"
        ),
    }
    status, headers, body = call_app(
        "/api/analyze",
        method="POST",
        body=json.dumps(payload),
        headers={"Content-Type": "application/json"},
    )
    assert status == "200 OK"
    assert headers["Content-Type"].startswith("application/json")
    report = json.loads(body)
    assert report["address"] == payload["address"]
    finding_ids = {finding["id"] for finding in report["findings"]}
    assert "delegatecall" in finding_ids
    assert report["risk_rating"]["label"] in {"high", "medium"}


def test_analyze_endpoint_validates_method():
    status, headers, body = call_app("/api/analyze")
    assert status == "405 Method Not Allowed"
    assert headers["Allow"] == "POST"
    assert b"Method Not Allowed" in body


def test_analyze_endpoint_requires_fields():
    status, _, body = call_app(
        "/api/analyze",
        method="POST",
        body=json.dumps({"address": "0xabc"}),
        headers={"Content-Type": "application/json"},
    )
    assert status == "400 Bad Request"
    assert b"source" in body
