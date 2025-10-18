"""Test fixtures and lightweight shims for azure SDK used in tests.

This module provides small dummy classes so the production modules can be
imported without installing the full Azure SDK during unit tests.

Pylint is intentionally relaxed in this helper module because the classes are
very small and used only in tests.
"""

import os
import sys
import types
from unittest.mock import Mock

# pylint: disable=missing-module-docstring,missing-function-docstring,too-few-public-methods,unused-argument,import-outside-toplevel,broad-except,abstract-class-instantiated,C0305

# Ensure project root is on sys.path so top-level packages import properly
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Always use local shims rather than importing real azure functions classes.
class _DummyHttpResponse:
    """HTTP response shim used by tests."""

    def __init__(self, body=None, status_code=200, mimetype=None):
        self.body = body
        self.status_code = status_code
        self.mimetype = mimetype


class _DummyHttpRequest:
    """HTTP request shim used by tests."""

    def __init__(self, method='GET', params=None, json_body=None):
        self.method = method
        self.params = params or {}
        self._json = json_body

    def get_json(self):
        return self._json


class _DummyQueueMessage:
    """Queue message shim used by tests."""

    def __init__(self, body: str):
        self._body = body.encode('utf-8')

    def get_body(self):
        return self._body


class _DummyOut:
    """Out shim used by tests; supports subscription for annotations."""

    def __init__(self):
        self._set = Mock()

    def set(self, value):
        self._set(value)

    @classmethod
    def __class_getitem__(cls, item):
        return cls


keyvault_secrets_mod = types.ModuleType('azure.keyvault.secrets')
identity_mod = types.ModuleType('azure.identity')
data_tables_mod = types.ModuleType('azure.data.tables')
core_ex_mod = types.ModuleType('azure.core.exceptions')


class SecretClient:
    """Minimal SecretClient shim returning simple mocks."""

    def __init__(self, vault_url=None, credential=None):
        del vault_url, credential

    def get_secret(self, name):
        m = Mock()
        m.value = ''
        return m

    def set_secret(self, name, value):
        del name, value
        return Mock()


class DefaultAzureCredential:
    """Credential shim."""

    def __init__(self):
        return None


class TableClient:
    """TableClient shim with static factory."""

    @staticmethod
    def from_connection_string(conn_str=None, table_name=None):
        del conn_str, table_name
        return Mock()


class ResourceExistsError(Exception):
    """Placeholder for resource exists error."""


keyvault_secrets_mod.SecretClient = SecretClient
identity_mod.DefaultAzureCredential = DefaultAzureCredential
data_tables_mod.TableClient = TableClient
core_ex_mod.ResourceExistsError = ResourceExistsError

# Insert modules into sys.modules so production imports succeed
sys.modules['azure'] = types.ModuleType('azure')
sys.modules['azure.functions'] = types.ModuleType('azure.functions')
sys.modules['azure.keyvault.secrets'] = keyvault_secrets_mod
sys.modules['azure.identity'] = identity_mod
sys.modules['azure.data.tables'] = data_tables_mod
sys.modules['azure.core.exceptions'] = core_ex_mod


def dummy_http_request(method='GET', params=None, json_body=None):
    """Return a request-like object for tests (always local shim)."""

    class Req:
        """Request-like object used as a lightweight shim in tests."""
        def __init__(self, method, params, json_body):
            self.method = method
            self.params = params or {}
            self._json = json_body

        def get_json(self):
            return self._json

    return Req(method, params, json_body)


def dummy_queue_message(body: str):
    """Return a queue-message-like object for tests (always local shim)."""

    class QM:
        """QueueMessage-like object used as a lightweight shim in tests."""
        def __init__(self, body):
            self._body = body.encode('utf-8')

        def get_body(self):
            return self._body

    return QM(body)


def dummy_out():
    """Return an Out-like object for tests (always local shim)."""



    return _DummyOut()








