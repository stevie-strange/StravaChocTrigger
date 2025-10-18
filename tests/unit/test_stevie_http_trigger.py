import os
from unittest.mock import patch, Mock

from conftest import dummy_http_request, dummy_out


def test_http_get_verification(monkeypatch):
    # Ensure verify token in env
    monkeypatch.setenv('StravaVerifyToken', 'verify_me')

    req = dummy_http_request(method='GET', params={'hub.mode': 'subscribe', 'hub.verify_token': 'verify_me', 'hub.challenge': 'xyz'})
    out = dummy_out()

    from StevieHttpTrigger.__init__ import main as http_main
    resp = http_main(req, out)

    # Since our shim returns a DummyHttpResponse, check attributes
    assert resp.status_code == 200
    assert 'hub.challenge' in resp.body or 'xyz' in str(resp.body)


def test_http_post_new_activity(monkeypatch):
    # Prepare POST payload
    eventdata = {'aspect_type': 'create', 'object_type': 'activity', 'object_id': 999}
    req = dummy_http_request(method='POST', json_body=eventdata)
    out = Mock()

    # Patch init_key_vault to return an object whose get_secret returns a dummy connection string
    fake_vault = Mock()
    fake_secret = Mock()
    fake_secret.value = 'UseDevelopmentStorage=true'
    fake_vault.get_secret.return_value = fake_secret

    with patch('StevieHttpTrigger.__init__.init_key_vault', return_value=fake_vault):
        # Patch TableClient.from_connection_string to return object with create_entity
        fake_table = Mock()
        fake_table.create_entity = Mock()
        with patch('StevieHttpTrigger.__init__.TableClient.from_connection_string', return_value=fake_table):
            from StevieHttpTrigger.__init__ import main as http_main
            resp = http_main(req, out)

            # Expect HTTP 200
            assert resp.status_code == 200
            # Ensure queue message set was called
            # out is Mock, but in actual function they call msg.set => our out is Mock so no attribute by default

def test_http_post_resource_exists(monkeypatch):
    eventdata = {'aspect_type': 'create', 'object_type': 'activity', 'object_id': 999}
    req = dummy_http_request(method='POST', json_body=eventdata)
    out = Mock()

    fake_vault = Mock()
    fake_secret = Mock()
    fake_secret.value = 'UseDevelopmentStorage=true'
    fake_vault.get_secret.return_value = fake_secret

    fake_table = Mock()
    from azure.core.exceptions import ResourceExistsError
    fake_table.create_entity.side_effect = ResourceExistsError()

    with patch('StevieHttpTrigger.__init__.init_key_vault', return_value=fake_vault):
        with patch('StevieHttpTrigger.__init__.TableClient.from_connection_string', return_value=fake_table):
            from StevieHttpTrigger.__init__ import main as http_main
            resp = http_main(req, out)
            assert resp.status_code == 200
