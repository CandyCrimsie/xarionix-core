import json
import logging
import sys
from datetime import UTC, datetime


class SafeJSONFormatter(logging.Formatter):
    """An allowlist, not redaction after arbitrary secrets have been interpolated."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, object] = {
            "time": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "event": getattr(record, "event", "runtime"),
        }
        for field in ("request_id", "method", "status", "duration_ms"):
            if hasattr(record, field):
                entry[field] = getattr(record, field)
        # Do not serialize record.msg, args, exc_info, URLs, headers or bodies.
        return json.dumps(entry)


def configure_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(SafeJSONFormatter())
    logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "sqlalchemy", "httpx", "httpcore"):
        logger = logging.getLogger(name)
        logger.handlers = []
        logger.propagate = True
    logging.getLogger("uvicorn.access").disabled = True
