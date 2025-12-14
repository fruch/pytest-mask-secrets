"""pytest plugin to mask/remove secrets from test reports."""
import os
import re
import logging
from typing import Optional

import pytest


mask_secrets_key = pytest.StashKey[set]()

_stash = None
_secret_values = set()
_secrets: Optional[re.Pattern[str]] = None
_mask: Optional[str] = None



def pytest_configure(config):
    """pytest stash as global variable to gain access."""
    global _stash, _secret_values, _secrets, _mask
    _stash = config.stash
    _stash[mask_secrets_key] = set()

    _mask = "*****"

    # discover secrets from environment and stash
    if os.environ.get("MASK_SECRETS_AUTO", "") not in ("0", ""):
        candidates = "(TOKEN|PASSWORD|PASSWD|SECRET)"
        candidates = re.compile(candidates)
        mine = re.compile(r"MASK_SECRETS(_AUTO)?\b")
        _secret_values |= {os.environ[k] for k in os.environ if candidates.search(k) and not mine.match(k)}

    if "MASK_SECRETS" in os.environ:
        vars_ = os.environ["MASK_SECRETS"].split(",")
        _secret_values |= {os.environ[k] for k in vars_ if k in os.environ}

    _secret_values |= _stash[mask_secrets_key]

    if len(_secret_values) == 0:
        # Still install the logging filter, but it will be a no-op
        _secrets = None
    else:
        # compile secrets into a single regex
        compiled = [re.escape(i) for i in _secret_values]
        _secrets = re.compile(f"({'|'.join(compiled)})")

    # Attach logging filter to redact secrets from logs
    _install_logging_filter()


class _MaskSecretsFilter(logging.Filter):
    """Logging filter that redacts any occurrence of secrets using `_secrets` and `_mask`."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            # Redact message and optionally args if present
            if hasattr(record, "msg") and isinstance(record.msg, str):
                record.msg = _redact(record.msg)
            # If the message uses formatting args, redact those too
            if hasattr(record, "args") and record.args:
                if isinstance(record.args, tuple):
                    record.args = tuple(_redact(a) if isinstance(a, str) else a for a in record.args)
                elif isinstance(record.args, dict):
                    record.args = {k: _redact(v) if isinstance(v, str) else v for k, v in record.args.items()}
            # Also redact extra fields commonly used
            if hasattr(record, "message") and isinstance(record.message, str):
                record.message = _redact(record.message)
        except Exception:
            # Be conservative: never block a log record
            pass
        return True


def _redact(text: str) -> str:
    """Redact secrets from the given text using the global `_secrets` regex and `_mask`.

    If `_secrets` has not been compiled or is None, returns text unchanged.
    """
    global _secrets, _mask
    if not isinstance(text, str):
        return text
    if _secrets is None or _mask is None:
        return text
    return _secrets.sub(_mask, text)


def _install_logging_filter():
    """Install the masking filter on the root logger once."""
    logger = logging.getLogger()
    # Avoid duplicate installation
    for f in logger.filters:
        if isinstance(f, _MaskSecretsFilter):
            return
    logger.addFilter(_MaskSecretsFilter())


def _remove_logging_filter():
    """Remove the masking filter from the root logger."""
    logger = logging.getLogger()
    to_remove = [f for f in logger.filters if isinstance(f, _MaskSecretsFilter)]
    for f in to_remove:
        logger.removeFilter(f)


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_logreport(report):
    """pytest hook to remove sensitive data aka secrets from report output."""

    if _secrets is not None and _mask is not None:
        report.sections = [(header, _secrets.sub(_mask, content)) for header, content in report.sections]
        if hasattr(report.longrepr, "chain"):
            for tracebacks, location, _ in report.longrepr.chain:
                for entry in getattr(tracebacks, "reprentries", []):
                    entry.lines = [_secrets.sub(_mask, l) for l in entry.lines]
                    if getattr(entry, "reprlocals", None) is not None:
                        entry.reprlocals.lines = [_secrets.sub(_mask, l) for l in entry.reprlocals.lines]
                if hasattr(location, "message"):
                    location.message = _secrets.sub(_mask, location.message)


def pytest_unconfigure(config):
    """Cleanup logging filter when pytest is done."""
    _remove_logging_filter()
