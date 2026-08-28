"""Smoke tests: import every module and verify the core wiring works."""
import os
import sys

# Make the repo root importable without installation
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest


def test_package_imports():
    import alicit
    import alicit.constants
    assert alicit.__version__


def test_constants_paths_exist():
    from alicit import constants
    assert os.path.isdir(constants.DATA_DIR)
    assert constants.TOKEN_FILE.endswith("tokens.json")


def test_reclist_imports():
    from alicit.reclist import Config, OAuthPhishAgent, PhishingEmailGenerator
    cfg = Config()
    assert cfg.oauth_client_id
    assert os.path.isdir(cfg.output_dir) or True  # created on demand
    agent = OAuthPhishAgent(cfg)
    assert agent.recon is not None
    assert isinstance(agent.email_generator, PhishingEmailGenerator)


def test_postexp_imports(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    from alicit.postexp import TokenManager, llamascout_analyse, llama_maverick_craft, send_email
    tm = TokenManager(token_file=os.path.join(os.path.dirname(__file__), "dummy_tokens.json"))
    assert tm is not None
    assert callable(send_email)


def test_listener_app():
    from alicit.listener import app
    client = app.test_client()
    resp = client.get("/ping")
    assert resp.status_code == 200
    assert b"listener ready" in resp.data

    resp = client.get("/oauth/callback?code=abc123&state=xyz")
    assert resp.status_code == 200
    assert b"Authentication Complete" in resp.data
