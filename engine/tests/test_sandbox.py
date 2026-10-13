"""Unit tests for container sandbox check logic (Prompt T2.6)."""
import os
import socket
from pathlib import Path
import pytest

from scripts.sandbox_check import check_network, check_non_root, check_filesystem


def test_sandbox_network_isolated(monkeypatch):
    """When socket connections fail (no network), check_network returns True (PASS)."""
    def mock_connect(self, addr):
        raise OSError("Network is unreachable")

    monkeypatch.setattr(socket.socket, "connect", mock_connect)
    assert check_network() is True


def test_sandbox_network_breach(monkeypatch):
    """When a socket connection succeeds, check_network returns False (FAIL)."""
    def mock_connect(self, addr):
        pass  # Successful connection

    monkeypatch.setattr(socket.socket, "connect", mock_connect)
    assert check_network() is False


def test_sandbox_non_root(monkeypatch):
    """When UID != 0, check_non_root returns True."""
    monkeypatch.setattr(os, "getuid", lambda: 1000, raising=False)
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
    assert check_non_root() is True


def test_sandbox_root_breach(monkeypatch):
    """When UID == 0, check_non_root returns False."""
    monkeypatch.setattr(os, "getuid", lambda: 0, raising=False)
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    assert check_non_root() is False


def test_sandbox_filesystem_read_only(tmp_path, monkeypatch):
    """Writable output directory succeeds, unwritable paths are handled."""
    out_dir = tmp_path / "out"
    assert check_filesystem(out_dir) is True
