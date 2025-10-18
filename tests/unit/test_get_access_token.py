"""Unit tests for get_access_token in QueueTrigger1 module.

These tests simulate KeyVault secrets and the token refresh HTTP call.
"""

import time
from unittest.mock import Mock


class FakeClient:
    """Simple fake SecretClient that stores secrets in a dict."""

    def __init__(self, secrets=None):
        self._secrets = dict(secrets or {})
        self.set_calls = []

    def get_secret(self, name):
        m = Mock()
        m.value = self._secrets.get(name, '')
        return m

    def set_secret(self, name, value):
        # record calls for assertions
        self.set_calls.append((name, value))
        self._secrets[name] = value
        return Mock()


def test_get_access_token_not_expired(monkeypatch):
    # prepare fake client with a future expiry
    future_ts = str(time.time() + 3600)
    fake = FakeClient({'StravaTokenExpires': future_ts, 'StravaAccessToken': 'existing_token'})

    # Patch the module-level SecretClient and credential class
    monkeypatch.setattr('QueueTrigger1.__init__.SecretClient', lambda vault_url, credential: fake)
    monkeypatch.setattr('QueueTrigger1.__init__.DefaultAzureCredential', lambda: None)

    # Import lazily and call
    from QueueTrigger1.__init__ import get_access_token
    token = get_access_token()

    assert token == 'existing_token'


def test_get_access_token_refresh(monkeypatch):
    # expired token triggers refresh
    past_ts = str(time.time() - 3600)
    fake = FakeClient({'StravaTokenExpires': past_ts, 'StravaRefreshToken': 'refresh_token_val'})

    # Prepare fake post response
    class FakeResp:
        status_code = 200

        def json(self):
            return {
                'access_token': 'new_access',
                'expires_at': int(time.time()) + 7200,
                'refresh_token': 'new_refresh',
            }

    def fake_post(url, data, timeout):
        assert 'refresh_token' in data
        return FakeResp()

    monkeypatch.setattr('QueueTrigger1.__init__.SecretClient', lambda vault_url, credential: fake)
    monkeypatch.setattr('QueueTrigger1.__init__.DefaultAzureCredential', lambda: None)
    monkeypatch.setattr('QueueTrigger1.__init__.requests.post', fake_post)

    from QueueTrigger1.__init__ import get_access_token
    token = get_access_token()

    assert token == 'new_access'
    # confirm that the fake client had its set_secret called for refresh token and access token
    names = [c[0] for c in fake.set_calls]
    assert 'StravaRefreshToken' in names
    assert 'StravaAccessToken' in names
