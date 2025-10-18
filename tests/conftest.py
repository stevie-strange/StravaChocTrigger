import os
import sys
import types
from unittest.mock import Mock

# Ensure project root is on sys.path so top-level packages (QueueTrigger1, StevieHttpTrigger) import properly
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Create minimal azure.* package placeholders to satisfy imports in functions
azure_mod = types.ModuleType('azure')
azure_functions_mod = types.ModuleType('azure.functions')

class _DummyHttpResponse:
    def __init__(self, body=None, status_code=200, mimetype=None):
        self.body = body
        self.status_code = status_code
        self.mimetype = mimetype

class _DummyHttpRequest:
    def __init__(self, method='GET', params=None, json_body=None):
        self.method = method
        self.params = params or {}
        self._json = json_body
    def get_json(self):
        return self._json

class _DummyQueueMessage:
    def __init__(self, body: str):
        self._body = body.encode('utf-8')
    def get_body(self):
        return self._body

class _DummyOut:
    def __init__(self):
        self._set = Mock()
    def set(self, value):
        self._set(value)
    @classmethod
    def __class_getitem__(cls, item):
        # allow subscription like Out[QueueMessage] used in annotations
        return cls

azure_functions_mod.HttpResponse = _DummyHttpResponse
azure_functions_mod.HttpRequest = _DummyHttpRequest
azure_functions_mod.QueueMessage = _DummyQueueMessage
azure_functions_mod.Out = _DummyOut

keyvault_secrets_mod = types.ModuleType('azure.keyvault.secrets')
identity_mod = types.ModuleType('azure.identity')
data_tables_mod = types.ModuleType('azure.data.tables')
core_ex_mod = types.ModuleType('azure.core.exceptions')

# Minimal placeholder classes
class SecretClient:
    def __init__(self, vault_url=None, credential=None):
        pass
    def get_secret(self, name):
        m = Mock()
        m.value = ''
        return m
    def set_secret(self, name, value):
        return Mock()

class DefaultAzureCredential:
    def __init__(self):
        pass

class TableClient:
    @staticmethod
    def from_connection_string(conn_str=None, table_name=None):
        return Mock()

class ResourceExistsError(Exception):
    pass

keyvault_secrets_mod.SecretClient = SecretClient
identity_mod.DefaultAzureCredential = DefaultAzureCredential
data_tables_mod.TableClient = TableClient
core_ex_mod.ResourceExistsError = ResourceExistsError

# Insert modules into sys.modules
sys.modules['azure'] = azure_mod
sys.modules['azure.functions'] = azure_functions_mod
sys.modules['azure.keyvault.secrets'] = keyvault_secrets_mod
sys.modules['azure.identity'] = identity_mod
sys.modules['azure.data.tables'] = data_tables_mod
sys.modules['azure.core.exceptions'] = core_ex_mod


def dummy_http_request(method='GET', params=None, json_body=None):
    try:
        from azure.functions import HttpRequest as Req
        return Req(method=method, params=params, json_body=json_body)
    except Exception:
        class Req:
            def __init__(self, method, params, json_body):
                self.method = method
                self.params = params or {}
                self._json = json_body
            def get_json(self):
                return self._json
        return Req(method, params, json_body)


def dummy_queue_message(body: str):
    try:
        from azure.functions import QueueMessage as QM
        return QM(body)
    except Exception:
        class QM:
            def __init__(self, body):
                self._body = body.encode('utf-8')
            def get_body(self):
                return self._body
        return QM(body)


def dummy_out():
    try:
        from azure.functions import Out as OutT
        return OutT()
    except Exception:
        return Mock()

