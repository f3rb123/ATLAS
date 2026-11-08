"""Actual local SSE transport across every built-in protocol, including fragmented echoes."""

import json, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import pytest
from atlas.gateway import (
    ProviderInput,
    ModelRequest,
    Adapter,
    create_provider,
    ADAPTERS,
)
from atlas.config import settings


@pytest.mark.parametrize("protocol", list(ADAPTERS))
def test_real_protocol_stream_and_fragmented_secret_redaction(db, protocol):
    secret = "fixture-stream-credential-not-real"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            assert request.get("stream") or protocol == "gemini"
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            for part in ["Hello ", secret[:12], secret[12:], " world"]:
                if protocol == "anthropic_messages":
                    event = {
                        "type": "content_block_delta",
                        "delta": {"type": "text_delta", "text": part},
                    }
                elif protocol == "gemini":
                    event = {"candidates": [{"content": {"parts": [{"text": part}]}}]}
                elif protocol == "openai_responses":
                    event = {"type": "response.output_text.delta", "delta": part}
                else:
                    event = {"choices": [{"delta": {"content": part}}]}
                self.wfile.write(("data: " + json.dumps(event) + "\n\n").encode())
                self.wfile.flush()
            if protocol not in ("anthropic_messages", "gemini", "openai_responses"):
                for arg in ['{"token":"' + secret[:12], secret[12:] + '"}']:
                    event = {
                        "choices": [
                            {
                                "delta": {
                                    "tool_calls": [
                                        {"index": 0, "function": {"arguments": arg}}
                                    ]
                                }
                            }
                        ]
                    }
                    self.wfile.write(("data: " + json.dumps(event) + "\n\n").encode())
            self.wfile.write(b"data: [DONE]\n\n")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    settings().provider_local_allowlist = [f"127.0.0.1:{server.server_port}"]
    try:
        provider = create_provider(
            db,
            "owner",
            ProviderInput(
                display_name="Stream fixture",
                adapter_type=protocol,
                base_url=f"http://127.0.0.1:{server.server_port}/v1",
                api_key=secret,
            ),
        )
        events = list(
            Adapter(provider).stream(
                ModelRequest(
                    model="fixture",
                    messages=[{"role": "user", "content": "hello"}],
                    structured=False,
                )
            )
        )
        assert secret not in json.dumps(events)
        assert (
            "".join(e["text"] for e in events if e["type"] == "content_delta")
            == "Hello [REDACTED] world"
        )
        if protocol not in ("anthropic_messages", "gemini", "openai_responses"):
            assert events[-1]["tool_call"]["arguments"]["token"] == "[REDACTED]"
    finally:
        server.shutdown()
