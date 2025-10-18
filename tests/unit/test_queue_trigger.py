"""Unit tests for QueueTrigger1.

These are minimal smoke tests that exercise the main code paths.
"""

# pylint: disable=import-outside-toplevel,missing-function-docstring,line-too-long,import-error
from unittest.mock import patch, Mock

from conftest import dummy_queue_message


def test_calc_cho_and_fat_basic():
    # Import functions lazily to avoid import-time azure SDK requirements
    from QueueTrigger1.__init__ import calc_cho, calculate_fat

    power = [100, 200, None, 50]
    cho = calc_cho(power)
    fat = calculate_fat(power)

    assert cho >= 0
    assert fat >= 0


def test_queue_main_happy_path(monkeypatch):
    # Prepare a queue message with activity id
    msg = dummy_queue_message('12345')

    # Patch get_access_token to avoid KeyVault calls
    monkeypatch.setattr('QueueTrigger1.__init__.get_access_token', lambda: 'dummy_token')

    # Create fake responses for activity metadata and streams
    activity_resp = Mock()
    activity_resp.status_code = 200
    activity_resp.json.return_value = {'type': 'Ride', 'elapsed_time': 3600}

    streams_resp = Mock()
    streams_resp.status_code = 200
    streams_resp.json.return_value = {'watts': {'data': [100, 200, None, 0]}}

    put_resp = Mock()
    put_resp.status_code = 200

    with patch('QueueTrigger1.__init__.requests.get', side_effect=[activity_resp, streams_resp]):
        with patch('QueueTrigger1.__init__.requests.put', return_value=put_resp):
            # Call main
            from QueueTrigger1.__init__ import main
            main(msg)



def test_queue_main_non_ride(monkeypatch):
    # If activity type is not Ride, no PUT should be called
    msg = dummy_queue_message('12345')
    monkeypatch.setattr('QueueTrigger1.__init__.get_access_token', lambda: 'dummy_token')

    activity_resp = Mock()
    activity_resp.status_code = 200
    activity_resp.json.return_value = {'type': 'Run', 'elapsed_time': 100}

    with patch('QueueTrigger1.__init__.requests.get', return_value=activity_resp):
        with patch('QueueTrigger1.__init__.requests.put') as mock_put:
            from QueueTrigger1.__init__ import main
            main(msg)
            mock_put.assert_not_called()


def test_queue_main_requests_error(monkeypatch):
    # Simulate a non-200 response to trigger raise_for_status path
    msg = dummy_queue_message('12345')
    monkeypatch.setattr('QueueTrigger1.__init__.get_access_token', lambda: 'dummy_token')

    bad_resp = Mock()
    bad_resp.status_code = 500
    bad_resp.raise_for_status.side_effect = Exception('Server error')

    # import pytest locally to avoid import-time dependency for linters
    import pytest
    from QueueTrigger1.__init__ import main
    with patch('QueueTrigger1.__init__.requests.get', return_value=bad_resp):
        with pytest.raises(Exception):
            main(msg)
