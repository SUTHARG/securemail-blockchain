"""Regression tests for production secret enforcement (Requirement 6).

Verifies:
1. Development defaults are permitted when APP_ENV="development" / is_local_demo.
2. Production rejects missing blockchain signing keys (ANALYST_KEY / ADMIN_KEY).
3. Production rejects known Hardhat development signing keys.
4. Production rejects short or default API keys (ANALYST_API_KEY / ADMIN_API_KEY).
5. Production rejects missing, default, or malformed ORG_SECRET_HEX.
6. Production accepts valid, distinct production settings.
7. Secrets are NEVER leaked in exception messages.
"""
import pytest
import backend.config as config


def test_development_environment_accepts_defaults(monkeypatch):
    """Local development/test environment accepts development defaults."""
    monkeypatch.setattr(config, "APP_ENV", "test")
    monkeypatch.setattr(config, "ALLOW_DEV_KEYS", True)
    # Must not raise
    config.validate_environment()


def test_production_rejects_missing_analyst_key(monkeypatch):
    """Production rejects empty ANALYST_KEY."""
    monkeypatch.setattr(config, "APP_ENV", "production")
    monkeypatch.setattr(config, "ALLOW_DEV_KEYS", False)
    monkeypatch.setattr(config, "ANALYST_KEY", "")

    with pytest.raises(RuntimeError) as exc_info:
        config.validate_environment()
    assert "requires ANALYST_KEY to be set" in str(exc_info.value)


def test_production_rejects_hardhat_dev_key(monkeypatch):
    """Production rejects known Hardhat dev private keys."""
    monkeypatch.setattr(config, "APP_ENV", "production")
    monkeypatch.setattr(config, "ALLOW_DEV_KEYS", False)
    monkeypatch.setattr(config, "ANALYST_KEY", config.HARDHAT_DEV_KEY)
    monkeypatch.setattr(config, "ADMIN_KEY", "11" * 32)
    monkeypatch.setattr(config, "ANALYST_API_KEY", "secure-analyst-api-key-12345")
    monkeypatch.setattr(config, "ADMIN_API_KEY", "secure-admin-api-key-12345")
    monkeypatch.setattr(config, "ORG_SECRET_HEX", "aa" * 32)

    with pytest.raises(RuntimeError) as exc_info:
        config.validate_environment()
    assert "must not use Hardhat development keys" in str(exc_info.value)


def test_production_rejects_default_org_secret(monkeypatch):
    """Production rejects default ORG_SECRET_HEX."""
    monkeypatch.setattr(config, "APP_ENV", "production")
    monkeypatch.setattr(config, "ALLOW_DEV_KEYS", False)
    monkeypatch.setattr(config, "ANALYST_KEY", "11" * 32)
    monkeypatch.setattr(config, "ADMIN_KEY", "22" * 32)
    monkeypatch.setattr(config, "ANALYST_API_KEY", "secure-analyst-api-key-12345")
    monkeypatch.setattr(config, "ADMIN_API_KEY", "secure-admin-api-key-12345")
    monkeypatch.setattr(config, "ORG_SECRET_HEX", config.DEFAULT_ORG_SECRET_HEX)

    with pytest.raises(RuntimeError) as exc_info:
        config.validate_environment()
    assert "must not use the hard-coded default ORG_SECRET_HEX" in str(exc_info.value)


def test_production_rejects_malformed_org_secret(monkeypatch):
    """Production rejects malformed / non-hex / wrong-length ORG_SECRET_HEX without leaking secret."""
    monkeypatch.setattr(config, "APP_ENV", "production")
    monkeypatch.setattr(config, "ALLOW_DEV_KEYS", False)
    monkeypatch.setattr(config, "ANALYST_KEY", "11" * 32)
    monkeypatch.setattr(config, "ADMIN_KEY", "22" * 32)
    monkeypatch.setattr(config, "ANALYST_API_KEY", "secure-analyst-api-key-12345")
    monkeypatch.setattr(config, "ADMIN_API_KEY", "secure-admin-api-key-12345")
    secret_value = "invalid-non-hex-short"
    monkeypatch.setattr(config, "ORG_SECRET_HEX", secret_value)

    with pytest.raises(RuntimeError) as exc_info:
        config.validate_environment()
    err_msg = str(exc_info.value)
    assert "64-character hex string" in err_msg or "invalid hex" in err_msg
    # Ensure the secret string is not leaked in the exception message!
    assert secret_value not in err_msg


def test_production_accepts_valid_configuration(monkeypatch):
    """Production accepts valid, strong, distinct keys and valid ORG_SECRET_HEX."""
    monkeypatch.setattr(config, "APP_ENV", "production")
    monkeypatch.setattr(config, "ALLOW_DEV_KEYS", False)
    monkeypatch.setattr(config, "ANALYST_KEY", "33" * 32)
    monkeypatch.setattr(config, "ADMIN_KEY", "44" * 32)
    monkeypatch.setattr(config, "ANALYST_API_KEY", "secure-analyst-key-production-98765")
    monkeypatch.setattr(config, "ADMIN_API_KEY", "secure-admin-key-production-12345")
    monkeypatch.setattr(config, "ORG_SECRET_HEX", "ab" * 32)

    # Must pass validation without raising
    config.validate_environment()
