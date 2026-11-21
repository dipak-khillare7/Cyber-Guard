import logging
import sys
from app.core.config import settings


class SensitiveFilter(logging.Filter):
    """
    Filter to mask sensitive information (passwords, keys, tokens) in log outputs.
    """
    SENSITIVE_KEYS = ["password", "secret", "token", "api_key", "authorization"]

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            msg_lower = record.msg.lower()
            for key in self.SENSITIVE_KEYS:
                if key in msg_lower and "=" in record.msg:
                    record.msg = "[REDACTED SENSITIVE LOG ENTRY]"
                    break
        return True


def setup_logging() -> logging.Logger:
    """
    Initializes and configures structured logging for the application.
    """
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] [%(name)s:%(lineno)d] - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    handler.addFilter(SensitiveFilter())

    log_obj = logging.getLogger("cyber_threat_system")
    log_obj.setLevel(log_level)
    log_obj.handlers.clear()
    log_obj.addHandler(handler)
    log_obj.propagate = False

    return log_obj


logger = setup_logging()


def get_logger(name: str = "cyber_threat_system") -> logging.Logger:
    """
    Helper to get named child logger inheriting sensitive filter rules.
    """
    child_logger = logging.getLogger(f"cyber_threat_system.{name}")
    return child_logger
