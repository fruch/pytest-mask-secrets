import pytest


@pytest.mark.parametrize("level", ["INFO", "WARNING", "ERROR"])
def test_logging_filter_redacts_output(pytester, level):
    # Create a test module that configures the plugin and emits a log message containing a secret
    test_code = f"""
import logging
import os
from pytest_mask_secrets import plugin


class FakeConfig:
    def __init__(self):
        self.stash = {{}}


def test_emit_secret_log(caplog):
    # Prepare plugin secrets directly and configure
    plugin._secret_values = {{"s3cr3t"}}
    plugin._mask = "*****"
    # compile regex and install filter
    plugin._secrets = None
    plugin.pytest_configure(FakeConfig())

    caplog.set_level(getattr(logging, "{level}"))

    # Ensure message formatting path is covered too
    logging.getLogger().log(getattr(logging, "{level}"), "Login with password %s", "s3cr3t")
    logging.getLogger().log(getattr(logging, "{level}"), "Also inline: secret s3cr3t")

    # The caplog should not contain the raw secret, but should contain mask
    assert "s3cr3t" not in caplog.text
    assert "*****" in caplog.text
"""
    pytester.makepyfile(test_code)

    result = pytester.runpytest_subprocess("-q")
    result.assert_outcomes(passed=1)


def test_filter_is_installed_once(pytester):
    # Create a test module that calls plugin.pytest_configure twice and inspects logger filters
    test_code = """
import logging
from pytest_mask_secrets import plugin

class FakeConfig:
    def __init__(self):
        self.stash = {}


def test_install_once():
    cfg = FakeConfig()
    plugin.pytest_unconfigure(cfg)  # ensure clean
    plugin._secret_values = {"abc123"}
    plugin._mask = "*****"
    plugin._secrets = None

    plugin.pytest_configure(cfg)
    plugin.pytest_configure(cfg)

    logger = logging.getLogger()
    count = sum(1 for f in logger.filters if isinstance(f, plugin._MaskSecretsFilter))
    assert count == 1
"""
    pytester.makepyfile(test_code)
    result = pytester.runpytest_subprocess("-q")
    result.assert_outcomes(passed=1)


def test_noop_when_no_secrets(pytester):
    # Without any secrets, the message should remain unchanged
    test_code = """
import logging
from pytest_mask_secrets import plugin

class FakeConfig:
    def __init__(self):
        self.stash = {}


def test_plain_message(caplog):
    # Ensure plugin is configured with no secrets
    plugin._secret_values = set()
    plugin._mask = "*****"
    plugin._secrets = None
    plugin.pytest_configure(FakeConfig())

    caplog.set_level(logging.INFO)
    logging.info("plain message")
    assert "plain message" in caplog.text
    assert "*****" not in caplog.text
"""
    pytester.makepyfile(test_code)
    result = pytester.runpytest_subprocess("-q")
    result.assert_outcomes(passed=1)
