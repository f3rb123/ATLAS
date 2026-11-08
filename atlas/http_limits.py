"""Count actual ASGI body bytes, including chunked requests without Content-Length."""

from fastapi import HTTPException
from atlas.config import settings


class BodyLimitMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        count = 0

        async def bounded_receive():
            nonlocal count
            message = await receive()
            if message["type"] == "http.request":
                count += len(message.get("body", b""))
                if count > settings().max_request_bytes:
                    raise HTTPException(413, "Request body exceeds limit")
            return message

        await self.app(scope, bounded_receive, send)
