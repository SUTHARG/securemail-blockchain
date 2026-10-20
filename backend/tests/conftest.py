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


@pytest.fixture(autouse=True)
def isolate_test_data_dir(tmp_path, monkeypatch):
    """Ensure ALL backend tests run in isolated temporary database and case storage."""
    test_db = tmp_path / "test_conftest.db"
    test_cases_dir = tmp_path / "cases"
    test_cases_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(config, "DB_PATH", test_db)
    monkeypatch.setattr(config, "CASES_DIR", test_cases_dir)
    from backend.database import init_db
    init_db()
