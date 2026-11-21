from typing import Any, Awaitable, Callable

from fastapi.responses import JSONResponse

from app.core.logging import logger


class RequestBodyLimitMiddleware:
    def __init__(self, app: Callable[..., Awaitable[None]], max_body_bytes: int = 65_536):
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: dict[str, Any], receive: Callable, send: Callable) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        content_length = headers.get(b"content-length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError:
                await self._reject(scope, receive, send, 400, "INVALID_CONTENT_LENGTH")
                return
            if declared_length < 0:
                await self._reject(scope, receive, send, 400, "INVALID_CONTENT_LENGTH")
                return
            if declared_length > self.max_body_bytes:
                await self._reject(scope, receive, send, 413, "PAYLOAD_TOO_LARGE")
                return

        messages = []
        total_bytes = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            total_bytes += len(message.get("body", b""))
            if total_bytes > self.max_body_bytes:
                await self._reject(scope, receive, send, 413, "PAYLOAD_TOO_LARGE")
                return
            messages.append(message)
            if not message.get("more_body", False):
                break

        message_index = 0

        async def replay_receive():
            nonlocal message_index
            if message_index < len(messages):
                message = messages[message_index]
                message_index += 1
                return message
            return await receive()

        await self.app(scope, replay_receive, send)

    async def _reject(
        self,
        scope: dict[str, Any],
        receive: Callable,
        send: Callable,
        status_code: int,
        error_code: str,
    ) -> None:
        path = scope.get("path", "")
        logger.warning("Rejected request for %s (%s)", path, error_code)
        response = JSONResponse(
            status_code=status_code,
            content={
                "detail": {
                    "code": error_code,
                    "message": "Request body is invalid or exceeds the allowed size.",
                }
            },
            headers={
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "strict-origin-when-cross-origin",
            },
        )
        await response(scope, receive, send)
