from textwrap import dedent

import pytest

@pytest.mark.parametrize("auto", [False, True])
def test_masks_function_args_in_report(pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch, auto: bool):
    """Test that secrets passed as function arguments are masked in failure reports."""
    monkeypatch.setenv('MASK_SECRETS_AUTO', "1" if auto else "0")
    monkeypatch.setenv('MY_SECRET', 'TOPSECRET')
    # When auto=False, explicitly set MASK_SECRETS to include MY_SECRET
    if not auto:
        monkeypatch.setenv('MASK_SECRETS', 'MY_SECRET')

    # Arrange: create a test file that fails and leaks a secret via a function argument
    body = dedent(f"""
        import os
       
        def test_leak_arg(secret_value='TOPSECRET'):
            # Secret flows through a function argument; failure should show func args in report
            assert secret_value == 'NOTSECRET'
    """)
    pytester.makepyfile(**{"test_leak_args.py": body})

    # Act: run pytest and capture output
    result = pytester.runpytest()

    # Assert: the raw secret should not appear, but masked value should
    stdout = result.stdout.str()
    stderr = result.stderr.str()

    # Ensure test failed so we have a report to inspect
    result.assert_outcomes(failed=1)

    # The secret value should be masked everywhere
    assert "TOPSECRET" not in stdout
    assert "TOPSECRET" not in stderr
    assert "*****" in stdout or "*****" in stderr


def test_masks_function_args_with_multiple_args(pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch):
    """Test that secrets among multiple function arguments are masked in failure reports."""

    monkeypatch.setenv('MASK_SECRETS', 'MY_SECRET')
    monkeypatch.setenv('MY_SECRET','TOPSECRET')

    pytester.makepyfile(
        **{
            "test_multi_args.py": dedent("""
                import os

                
                def test_multi_args(a='VISIBLE', b='TOPSECRET'):
                    # Fails to expose function args in report
                    assert a == b
            """)
        }
    )

    result = pytester.runpytest()
    result.assert_outcomes(failed=1)

    out = result.stdout.str() + result.stderr.str()

    # Secret should be masked, non-secret arg should remain
    assert "TOPSECRET" not in out
    assert "VISIBLE" in out
    assert "*****" in out

