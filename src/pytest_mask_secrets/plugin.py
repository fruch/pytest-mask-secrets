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


def _refresh_secrets():
    """Refresh compiled secrets regex from current environment and stash.

    This allows masking secrets that are set during test collection or execution.
    """
    global _secrets, _secret_values
    current = set()
    # Auto-detect candidate names based on MASK_SECRETS_AUTO
    if os.environ.get("MASK_SECRETS_AUTO", "") not in ("0", ""):
        candidates = re.compile("(TOKEN|PASSWORD|PASSWD|SECRET)")
        mine = re.compile(r"MASK_SECRETS(_AUTO)?\b")
        current |= {os.environ[k] for k in os.environ if candidates.search(k) and not mine.match(k)}
    # Explicit list
    if "MASK_SECRETS" in os.environ:
        vars_ = os.environ["MASK_SECRETS"].split(",")
        current |= {os.environ[k] for k in vars_ if k in os.environ}
    # Include stashed values
    try:
        # Access stash safely
        if _stash is not None and mask_secrets_key in _stash:
            current |= _stash[mask_secrets_key]
    except Exception:
        pass

    # Merge into _secret_values so logging filter benefits too
    if current:
        _secret_values |= current
        compiled = [re.escape(i) for i in _secret_values]
        _secrets = re.compile(f"({'|'.join(compiled)})")


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

    # Ensure we have up-to-date secrets from env set by tests
    _refresh_secrets()

    if _secrets is not None and _mask is not None:
        # Redact captured sections
        report.sections = [(header, _secrets.sub(_mask, content)) for header, content in report.sections]

        # Redact string longrepr variants
        if isinstance(getattr(report, "longrepr", None), str):
            report.longrepr = _secrets.sub(_mask, report.longrepr)
        # Do not assign to longreprtext (read-only); just rely on other paths
        # Traverse structured longrepr objects (pytest internal types)
        lr = getattr(report, "longrepr", None)
        if lr and not isinstance(lr, str):
            # ReprCrash: message with assertion details often contains values
            if hasattr(lr, "reprcrash") and hasattr(lr.reprcrash, "message"):
                lr.reprcrash.message = _secrets.sub(_mask, lr.reprcrash.message)

            # ReprTraceback: entries with funcargs, locals, and lines
            if hasattr(lr, "reprtraceback"):
                rt = lr.reprtraceback
                # For each entry redact lines and locals
                for entry in getattr(rt, "reprentries", []):
                    if hasattr(entry, "lines"):
                        entry.lines = [_secrets.sub(_mask, l) for l in entry.lines]
                    # redact locals dump
                    if getattr(entry, "reprlocals", None) is not None and hasattr(entry.reprlocals, "lines"):
                        entry.reprlocals.lines = [_secrets.sub(_mask, l) for l in entry.reprlocals.lines]
                    # redact function arguments shown
                    if getattr(entry, "reprfuncargs", None) is not None:
                        try:
                            # reprfuncargs.args is typically a list of (name, value_repr)
                            args = getattr(entry.reprfuncargs, "args", None)
                            if isinstance(args, list):
                                redacted = []
                                for name, val in args:
                                    # val may be a repr string
                                    if isinstance(val, str):
                                        redacted.append((name, _secrets.sub(_mask, val)))
                                    else:
                                        redacted.append((name, val))
                                entry.reprfuncargs.args = redacted
                            # Some pytest versions store it as text lines
                            if hasattr(entry.reprfuncargs, "lines") and isinstance(entry.reprfuncargs.lines, list):
                                entry.reprfuncargs.lines = [_secrets.sub(_mask, l) for l in entry.reprfuncargs.lines]
                        except Exception:
                            # Be defensive across pytest versions
                            pass

        # Also handle the chained representation used when verbose chaining is enabled
        if hasattr(report.longrepr, "chain"):
            for tracebacks, location, _ in report.longrepr.chain:
                for entry in getattr(tracebacks, "reprentries", []):
                    if hasattr(entry, "lines"):
                        entry.lines = [_secrets.sub(_mask, l) for l in entry.lines]
                    if getattr(entry, "reprlocals", None) is not None and hasattr(entry.reprlocals, "lines"):
                        entry.reprlocals.lines = [_secrets.sub(_mask, l) for l in entry.reprlocals.lines]
                    if getattr(entry, "reprfuncargs", None) is not None:
                        try:
                            args = getattr(entry.reprfuncargs, "args", None)
                            if isinstance(args, list):
                                entry.reprfuncargs.args = [
                                    (name, _secrets.sub(_mask, val) if isinstance(val, str) else val)
                                    for name, val in args
                                ]
                            if hasattr(entry.reprfuncargs, "lines") and isinstance(entry.reprfuncargs.lines, list):
                                entry.reprfuncargs.lines = [_secrets.sub(_mask, l) for l in entry.reprfuncargs.lines]
                        except Exception:
                            pass
                if hasattr(location, "message"):
                    location.message = _secrets.sub(_mask, location.message)


def pytest_unconfigure(config):
    """Cleanup logging filter when pytest is done."""
    _remove_logging_filter()
