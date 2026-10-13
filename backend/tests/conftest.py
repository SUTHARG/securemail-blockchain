"""Test configuration fixtures for SecureMailScope backend tests."""
import pytest
import backend.config as config

TEST_ANALYST_KEY = "test-analyst-secret-key-12345"
TEST_ADMIN_KEY = "test-admin-secret-key-67890"

# Set on config at test session load so module-level test headers pick them up
config.ANALYST_API_KEY = TEST_ANALYST_KEY
config.ADMIN_API_KEY = TEST_ADMIN_KEY

@pytest.fixture(autouse=True)
def configure_test_api_keys(monkeypatch):
    """Ensure tests run with explicitly isolated test API keys."""
    monkeypatch.setattr(config, "ANALYST_API_KEY", TEST_ANALYST_KEY)
    monkeypatch.setattr(config, "ADMIN_API_KEY", TEST_ADMIN_KEY)
