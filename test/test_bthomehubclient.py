import json
from unittest import TestCase
from unittest.mock import ANY
from unittest.mock import patch

from bthomehubclient import BtHomeClient


def mocked_requests_post(*args, **kwargs):
    class MockResponse:
        def __init__(self, text, status_code):
            self.text = text
            self.status_code = status_code

    if 'xpath' in kwargs['data']:
        text = get_json_string_from_file('get_devices.json')
    else:
        text = get_json_string_from_file('authenticate_response.json')
    return MockResponse(text, 200)


class TestBtHomeClient(TestCase):
    @patch('requests.post', side_effect=mocked_requests_post)
    def test__authenticate(self, mock_post):
        client = BtHomeClient()
        client.authenticate()

        self.assertEqual(client._authentication.server_nonce, '2222222222')
        self.assertEqual(client._authentication.session_id, 11111111)
        self.assertEqual(client._authentication.user, 'guest')
        self.assertEqual(client._authentication.password, 'd41d8cd98f00b204e9800998ecf8427e')
        self.assertEqual(client._authentication.request_id, 0)
        self.assertIsNotNone(client._authentication.client_nonce)
        self.assertEqual(client._authentication.auth_hash, '4cdf1b280f5701f1ec21aab3a3dfaff8')

        mock_post.assert_called_with(
            'http://bthomehub.home/cgi/json-req',
            data=ANY,
            headers=ANY,
            timeout=10
        )

    @patch('requests.post', side_effect=mocked_requests_post)
    def test__get_devices_authenticate_first_if_not_done_before(self, mock_post):
        client = BtHomeClient()
        self.assertIsNone(client._authentication)
        client.get_devices()
        self.assertIsNotNone(client._authentication)
        mock_post.assert_called_with(
            url='http://bthomehub.home/cgi/json-req',
            data=ANY,
            headers=ANY,
            timeout=10
        )
        self.assertEqual(mock_post.call_count, 2)
        self.assertIsNotNone(client._authentication)

    @patch('requests.post', side_effect=mocked_requests_post)
    def test__get_devices(self, mock_post):
        client = BtHomeClient()
        devices = client.get_devices()
        self.assertEqual(devices, {'A1:27:A1:A1:40:A1': 'raspberrypi'})

    def test__is_successful_returns_true_when_call_is_successful(self):
        client = BtHomeClient()
        data = {
            'reply': {
                'error': {
                    'code': 16777216
                }
            }
        }
        self.assertTrue(client._is_successful(data))

    def test__is_successful_returns_false_when_call_is_failure(self):
        client = BtHomeClient()
        data = {
            'reply': {
                'error': {
                    'code': 1
                }
            }
        }
        self.assertFalse(client._is_successful(data))

    def test__parse_homehub_response(self):
        pass
        # self.fail()


def get_json_string_from_file(file_name):
    with open(file_name) as data_file:
        data = json.load(data_file)

    return json.dumps(data)
