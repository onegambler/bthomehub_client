import hashlib
import json
import math
import random
from collections import namedtuple
from urllib.parse import quote

import requests

from bthomehub.exception import AuthenticationException, ResponseException

Device = namedtuple(
    "Device", ["mac_address", "ip_address", "name", "address_source", "interface", "active",
               "user_friendly_name", "detected_device_type", "user_device_type"])


class BtHomeClient(object):
    BT_HOME_HOST = 'bthomehub.home'
    DEFAULT_TIMEOUT = 10

    AUTH_COOKIE_OBJ = {'req_id': 1,
                       'sess_id': 0,
                       'basic': False,
                       'user': 'guest',
                       'dataModel':
                           {'name': 'Internal',
                            'nss': [
                                {
                                    'name': 'gtw',
                                    'uri': 'http://sagemcom.com/gateway-data'
                                }
                            ]},
                       'ha1': 'ca6e4940afd41d8cd98f00b204e9800998ecf8427e830e7a046fd8d92ecec8e4',
                       'nonce': ''}

    AUTH_REQUEST_OBJ = {
        'request': {
            'id': 0,
            'session-id': 0,
            'priority': True,
            'actions': [
                {
                    'id': 0,
                    'method': 'logIn',
                    'parameters': {
                        'user': 'guest',
                        'persistent': True,
                        'session-options': {
                            'nss': [
                                {
                                    'name': 'gtw',
                                    'uri': 'http://sagemcom.com/gateway-data'
                                }
                            ],
                            'language': 'ident',
                            'context-flags': {
                                'get-content-name': True,
                                'local-time': True
                            },
                            'capability-depth': 2,
                            'capability-flags': {
                                'name': True,
                                'default-value': False,
                                'restriction': True,
                                'description': False
                            },
                            'time-format': 'ISO_8601'
                        }
                    }
                }
            ],
            'cnonce': 745670196,
            'auth-key': '06a19e589dc848a89675748aa2d509b3'
        }
    }

    def __init__(self, host=BT_HOME_HOST, timeout=DEFAULT_TIMEOUT):
        self._authentication = None
        self.url = 'http://{}/cgi/json-req'.format(host)
        self.timeout = timeout

    def authenticate(self):
        """
        Authenticates the client by creating a new session. The session is automatically renewed so
        there is no need to authenticate again, unless an explicit AuthenticationException is thrown.
        """

        headers = {
            "Cookie": "lang=en; session=" + quote(json.dumps(self.AUTH_COOKIE_OBJ).encode("utf-8"))
        }
        request = "req=" + quote(json.dumps(self.AUTH_REQUEST_OBJ, sort_keys=True).encode("utf-8"))

        response = requests.post(self.url, data=request, headers=headers, timeout=self.timeout)
        data = json.loads(response.text)
        if response.status_code != 200:
            raise AuthenticationException('Failed to authenticate. Status code: %s' % response.status_code)
        if not self._is_successful(data):
            raise AuthenticationException(
                'Failed to authenticate. Error: %s' % data['reply']['error']['description'])

        server_nonce = data['reply']['actions'][0]['callbacks'][0]['parameters']['nonce']
        session_id = data['reply']['actions'][0]['callbacks'][0]['parameters']['id']
        self._authentication = Auth(nonce=server_nonce, session_id=session_id)

    def get_devices(self, only_active=True) -> list:
        """
        Returns the list of connected devices

        :param only_active: a flag indicating whether only currently active (connected) devices should be returned.
        Default `True`
        :return: a dictionary containing all the devices connected to the bt home hub
        """

        if self._authentication is None:
            raise AuthenticationException('Client not authenticated. Please authenticate first, using "authenticated '
                                          'function')

        list_cookie_obj = {
            'req_id': self._authentication.request_id,
            'sess_id': self._authentication.session_id,
            'basic': False,
            'user': 'guest',
            'dataModel': {
                'name': 'Internal',
                'nss': [
                    {
                        'name': 'gtw',
                        'uri': 'http://sagemcom.com/gateway-data'
                    }
                ]
            },
            'ha1': '2d9a6f39b6d41d8cd98f00b204e9800998ecf8427eba8d73fbd3de28879da7dd',
            'nonce': self._authentication.server_nonce
        }

        self._authentication.request_id += 1

        list_req_obj = {
            'request': {
                'id': self._authentication.request_id,
                'session-id': self._authentication.session_id,
                'priority': False,
                'actions': [
                    {
                        'id': 1,
                        'method': 'getValue',
                        'xpath': 'Device/Hosts/Hosts',
                        'options': {
                            'capability-flags': {
                                'interface': True
                            }
                        }
                    }
                ],
                'cnonce': self._authentication.client_nonce,
                'auth-key': self._authentication.get_auth_key()
            }
        }

        headers = {
            "Cookie": "lang=en; session=" + quote(json.dumps(list_cookie_obj).encode("utf-8"))
        }

        request = "req=" + quote(json.dumps(list_req_obj, sort_keys=True).encode("utf-8"))
        response = requests.post(url=self.url, data=request, headers=headers, timeout=self.timeout)
        if response.status_code == 401:
            raise AuthenticationException('Failed to get list of devices. Session expired')
        elif response.status_code != 200:
            raise ResponseException('Failed to get list of devices. Got a %s' % response.status_code)

        data = json.loads(response.text)
        if not self._is_successful(data):
            if self._is_invalid_user_session(data):
                self.authenticate()
            raise ResponseException('Failed to get list of devices. Reason: %s' % data['reply']['error']['description'])

        # We don't let the request id grow exponentially
        if self._authentication.request_id > 100000:
            self.authenticate()
            self._authentication.request_id = 0

        return self._parse_homehub_response(data, only_active)

    @staticmethod
    def _is_successful(data):
        return data and data.get('reply', {}).get('error', {}).get('code', {}) == 16777216

    @staticmethod
    def _is_invalid_user_session(data):
        return data and data.get('reply', {}).get('error', {}).get('code', {}) == 16777219

    @staticmethod
    def _parse_homehub_response(data, only_active):
        """Parse the BT Home Hub data format."""
        known_devices = data['reply']['actions'][0]['callbacks'][0]['parameters']['value']

        devices = []

        for device in known_devices:
            if not only_active or device['Active']:
                device = Device(
                    mac_address=device['PhysAddress'].upper(),
                    ip_address=device['IPAddress'],
                    address_source=device['AddressSource'],
                    name=device['UserHostName'] or device['HostName'],
                    interface=device['InterfaceType'],
                    active=device['Active'],
                    user_friendly_name=device['UserFriendlyName'],
                    detected_device_type=device['DetectedDeviceType'],
                    user_device_type=device['UserDeviceType']
                )

                devices.append(device)

        return devices


class Auth:
    def __init__(self, nonce, session_id, request_id=0, user='guest', password='d41d8cd98f00b204e9800998ecf8427e'):
        self.server_nonce = nonce
        self.session_id = session_id
        self.request_id = request_id
        self.user = user
        self.password = password
        self.client_nonce = str(math.floor(4294967295 * (random.uniform(0, 1))))
        self.auth_hash = self._md5_hex(self.user + ':' + self.server_nonce + ':' + self.password)

    def get_auth_key(self):
        return self._md5_hex(
            self.auth_hash + ':' + str(self.request_id) + ':' + self.client_nonce + ':JSON:/cgi/json-req')

    @staticmethod
    def _md5_hex(string):
        return hashlib.md5(string.encode('utf-8')).hexdigest()
