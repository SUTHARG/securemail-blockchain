"""Pytest configuration for engine tests."""
import pytest


def pytest_sessionfinish(session, exitstatus):
    """Allow test suite to pass cleanly when zero tests are collected during bootstrap."""
    if exitstatus == pytest.ExitCode.NO_TESTS_COLLECTED:
        session.exitstatus = pytest.ExitCode.OK
