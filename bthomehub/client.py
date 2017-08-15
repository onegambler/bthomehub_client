import hashlib
import json
import math
import random
import threading
from urllib.parse import quote

import requests

from bthomehub.exception import AuthenticationException, ResponseException


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
        self.lock = threading.RLock()

    def authenticate(self):
        headers = {
            "Cookie": "lang=en; session=" + quote(json.dumps(self.AUTH_COOKIE_OBJ).encode("utf-8"))
        }
        request = "req=" + quote(json.dumps(self.AUTH_REQUEST_OBJ, sort_keys=True).encode("utf-8"))

        response = requests.post(self.url, data=request, headers=headers, timeout=self.timeout)
        data = json.loads(response.text)
        if response.status_code != 200:
            raise AuthenticationException('Failed to authenticate. Status code: %s' % response.status_code)
        if not self._is_successful(data):
            raise AuthenticationException('Failed to authenticate. Error: %s' % data['reply']['error']['description'])

        server_nonce = data['reply']['actions'][0]['callbacks'][0]['parameters']['nonce']
        session_id = data['reply']['actions'][0]['callbacks'][0]['parameters']['id']
        self._authentication = Auth(nonce=server_nonce, session_id=session_id)

    def get_devices(self) -> dict:

        """
        Returns the list of connected devices
        :rtype: a dictionary containing all the devices connected to the bt home hub
        """
        if not self._authentication:
            self.lock.acquire()
            if not self._authentication:
                try:
                    self.authenticate()
                finally:
                    self.lock.release()

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
            self._authentication = None
            raise AuthenticationException('Failed to get list of devices. Session expired')
        elif response.status_code != 200:
            raise ResponseException('Failed to get list of devices. Got a %s' % response.status_code)

        data = json.loads(response.text)
        if not self._is_successful(data):
            self._authentication = None
            raise ResponseException('Failed to get list of devices: %s' % data['reply']['error']['code']['description'])

        if self._authentication.request_id >= 1000:
            self._authentication = None

        return self._parse_homehub_response(data)

    @staticmethod
    def _is_successful(data):
        return data['reply']['error']['code'] == 16777216

    @staticmethod
    def _parse_homehub_response(data):
        """Parse the BT Home Hub data format."""
        known_devices = data['reply']['actions'][0]['callbacks'][0]['parameters']['value']

        devices = {}

        for device in known_devices:
            mac = device['PhysAddress'].upper()
            name = device['HostName'] or mac.lower().replace('-', '')
            if device['Active']:
                devices[mac] = name

        return devices


class Auth:
    def __init__(self, nonce, session_id, request_id=0, user='guest',
                 password='d41d8cd98f00b204e9800998ecf8427e'):
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
