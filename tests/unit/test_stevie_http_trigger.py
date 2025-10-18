"""Unit tests for StevieHttpTrigger.

Minimal coverage for webhook verification and new activity handling.
"""

# pylint: disable=import-outside-toplevel,missing-function-docstring,line-too-long
from unittest.mock import patch, Mock

from conftest import dummy_http_request, dummy_out


def test_http_get_verification():
    # set env var
    import os
    os.environ['StravaVerifyToken'] = 'verify_me'

    req = dummy_http_request(
        method='GET',
        params={'hub.mode': 'subscribe', 'hub.verify_token': 'verify_me', 'hub.challenge': 'xyz'},
    )
    out = dummy_out()

    from StevieHttpTrigger.__init__ import main as http_main
    resp = http_main(req, out)

    assert resp.status_code == 200
    # our shim may store the challenge in body or in the returned object representation
    body_val = getattr(resp, 'body', None)
    assert 'xyz' in str(body_val) or 'hub.challenge' in str(body_val)


def test_http_post_new_activity():
    eventdata = {'aspect_type': 'create', 'object_type': 'activity', 'object_id': 999}
    req = dummy_http_request(method='POST', json_body=eventdata)
    out = Mock()

    fake_vault = Mock()
    fake_secret = Mock()
    fake_secret.value = 'UseDevelopmentStorage=true'
    fake_vault.get_secret.return_value = fake_secret

    with patch('StevieHttpTrigger.__init__.init_key_vault', return_value=fake_vault):
        fake_table = Mock()
        fake_table.create_entity = Mock()
        with patch('StevieHttpTrigger.__init__.TableClient.from_connection_string', return_value=fake_table):
            from StevieHttpTrigger.__init__ import main as http_main
            resp = http_main(req, out)
            assert resp.status_code == 200

def test_http_post_resource_exists():
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
