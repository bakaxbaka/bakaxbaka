"""WSGI application exposing the audit checklist and a Dedaub-style analyzer."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable, Iterable
from wsgiref.simple_server import make_server

from .analysis import analyze_contract
from .data import ANALYZER_FEATURES, CHECKLIST, SAMPLE_ANALYSIS_PAYLOAD

TEMPLATE_PATH = Path(__file__).with_name("templates").joinpath("index.html")


def render_index() -> str:
    """Render the HTML landing page using the static template."""
    template = TEMPLATE_PATH.read_text(encoding="utf-8")
    cards = []
    for section in CHECKLIST:
        items = "\n".join(f"          <li>{item}</li>" for item in section["items"])
        cards.append(
            "      <section class=\"card\">\n"
            f"        <h2>{section['title']}</h2>\n"
            f"        <p>{section['description']}</p>\n"
            "        <ul>\n"
            f"{items}\n"
            "        </ul>\n"
            "      </section>"
        )
    feature_list = "\n".join(f"          <li>{item}</li>" for item in ANALYZER_FEATURES)
    payload = json.dumps(SAMPLE_ANALYSIS_PAYLOAD, indent=2)
    return (
        template.replace("{{CARDS}}", "\n".join(cards))
        .replace("{{ANALYZER_FEATURES}}", feature_list)
        .replace("{{ANALYZER_SAMPLE_PAYLOAD}}", payload)
    )


def _response(
    start_response: Callable[..., None],
    status: str,
    body: bytes,
    content_type: str,
    extra_headers: Iterable[tuple[str, str]] | None = None,
) -> Iterable[bytes]:
    headers = [
        ("Content-Type", content_type),
        ("Content-Length", str(len(body))),
    ]
    if extra_headers:
        headers.extend(extra_headers)
    start_response(status, headers)
    return [body]


def _read_json_body(environ: dict) -> tuple[dict, list[bytes]]:
    """Read a JSON request body, returning the payload and raw fragments."""
    raw_chunks: list[bytes] = []
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except (TypeError, ValueError):
        length = 0
    if length < 0:
        length = 0
    body_bytes = environ["wsgi.input"].read(length)
    raw_chunks.append(body_bytes)
    text = body_bytes.decode("utf-8") if body_bytes else ""
    if not text:
        return {}, raw_chunks
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive guard
        raise ValueError(f"Invalid JSON payload: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("JSON payload must be an object")
    return payload, raw_chunks


def create_app() -> Callable[[dict, Callable[..., None]], Iterable[bytes]]:
    """Create a WSGI application callable."""

    def application(environ: dict, start_response: Callable[..., None]):
        path = environ.get("PATH_INFO", "/")
        method = environ.get("REQUEST_METHOD", "GET").upper()
        if path in {"", "/"} and method == "GET":
            body = render_index().encode("utf-8")
            return _response(start_response, "200 OK", body, "text/html; charset=utf-8")

        if path == "/api/checklist" and method == "GET":
            payload = json.dumps({"sections": CHECKLIST}).encode("utf-8")
            return _response(
                start_response,
                "200 OK",
                payload,
                "application/json; charset=utf-8",
            )

        if path == "/api/analyze":
            if method != "POST":
                return _response(
                    start_response,
                    "405 Method Not Allowed",
                    b"Method Not Allowed",
                    "text/plain; charset=utf-8",
                    extra_headers=[("Allow", "POST")],
                )
            try:
                payload, _ = _read_json_body(environ)
            except ValueError as exc:
                return _response(
                    start_response,
                    "400 Bad Request",
                    str(exc).encode("utf-8"),
                    "text/plain; charset=utf-8",
                )
            address = payload.get("address")
            source = payload.get("source")
            metadata = payload.get("metadata")
            if not address or not isinstance(address, str):
                return _response(
                    start_response,
                    "400 Bad Request",
                    b"'address' must be a non-empty string",
                    "text/plain; charset=utf-8",
                )
            if not source or not isinstance(source, str):
                return _response(
                    start_response,
                    "400 Bad Request",
                    b"'source' must be provided as Solidity text",
                    "text/plain; charset=utf-8",
                )
            if metadata is not None and not isinstance(metadata, dict):
                return _response(
                    start_response,
                    "400 Bad Request",
                    b"'metadata' must be an object when provided",
                    "text/plain; charset=utf-8",
                )
            report = analyze_contract(address=address, source=source, metadata=metadata or {})
            payload = json.dumps(report).encode("utf-8")
            return _response(
                start_response,
                "200 OK",
                payload,
                "application/json; charset=utf-8",
            )

        message = b"Not Found"
        return _response(start_response, "404 Not Found", message, "text/plain; charset=utf-8")

    return application


def run(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run the development server."""
    with make_server(host, port, create_app()) as httpd:
        print(f"Serving on http://{host}:{port}")
        httpd.serve_forever()


if __name__ == "__main__":
    run()
