"""Structured event logging; no request bodies, credentials, prompts or arbitrary extras."""

import logging, json
from .vault import redact
from .db import now


class SafeJSON(logging.Formatter):
    def format(self, record):
        result = {
            "time": now(),
            "level": record.levelname,
            "event": redact(record.getMessage()),
        }
        for key in [
            "correlation_id",
            "route",
            "method",
            "status",
            "duration_ms",
            "actor",
        ]:
            if hasattr(record, key):
                result[key] = getattr(record, key)
        if record.exc_info:
            import traceback

            result["exception_type"] = record.exc_info[0].__name__
            result["stack"] = [
                {
                    "file": __import__("pathlib").Path(f.filename).name,
                    "line": f.lineno,
                    "function": f.name,
                }
                for f in traceback.extract_tb(record.exc_info[2])
            ][-8:]
        return json.dumps(result)


def configure():
    logger = logging.getLogger("atlas")
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(SafeJSON())
    logger.handlers = [handler]
    logger.propagate = False
