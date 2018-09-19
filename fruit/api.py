#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import os
import json
import copy
import re
import requests

DEFAULT_SERVER = 'https://fruit-testbed.org/api'
CONTAINER_NAME_RE = re.compile(r"^[a-zA-Z0-9_\-]+$")


def __debug_requests():
    import logging
    try:
        # Python 2
        import httplib
        httplib.HTTPConnection.debuglevel = 1
    except:
        # Python 3
        import http.client
        http.client.HTTPConnection.debuglevel = 1
    logging.basicConfig()
    logger = logging.getLogger('requests.packages.urllib3')
    logger.setLevel(logging.DEBUG)
    logger.propagate = True

if os.environ.get('FRUIT_API_DEBUG', ''):
    __debug_requests()


class FruitApiError(Exception):
    def __init__(self, response, message=None, **kwargs):
        if message is None:
            try:
                blob = response.json()
                message = blob['title']
            except:
                message = response.reason
        super().__init__(message, **kwargs)
        self.response = response


class FruitApiClientProblem(FruitApiError): pass
class FruitApiServerProblem(FruitApiError): pass


class FruitApi:
    def __init__(self, server=None, email=None, api_key=None):
        '''Construct with:
           - both email and api_key to be able to act as a user;
           - api_key alone to be able to act as a node/agent;
           - neither, for registration and verification'''
        self._server = server or DEFAULT_SERVER
        self._email = email
        self._api_key = api_key

    def _call(self, method, url, params={}, data=None, content_type=None, headers={}):
        headers = copy.copy(headers)
        headers['X-API-Key'] = self._api_key
        headers['Accept-Encoding'] = 'gzip'
        if content_type is not None:
            headers['Content-Type'] = content_type
        if isinstance(data, dict):
            data = json.dumps(data)
            if 'Content-Type' not in headers:
                headers['Content-Type'] = 'application/json'
        resp = requests.request(method,
                                self._server + url,
                                params=params,
                                data=data,
                                headers=headers)
        code = resp.status_code
        if code >= 200 and code <= 299:
            return resp
        if code >= 300 and code <= 399:
            # We do not yet handle redirections, since the API does not require them.
            raise FruitApiServerProblem(resp,
                                        message='Server redirection not supported by this client')
        if code >= 400 and code <= 499:
            raise FruitApiClientProblem(resp)
        if code >= 500:
            raise FruitApiServerProblem(resp)

    @property
    def email(self):
        return self._email

    def register(self, email):
        return self._call('POST', '/user/%s' % (email,))

    def resend_api_key(self, email):
        return self._call('GET', '/verify/%s/forget' % (email,))

    def list_nodes(self, group_name=None):
        params = {'email': self.email}
        if group_name is not None:
            params['hostname'] = group_name
        return self._call('GET', '/node', params).json()

    def node_config(self, node_id):
        return self._call('GET', '/node/%s/config' % (node_id,)).json()

    def post_monitoring_data(self, node_id, data):
        self._call('POST', '/monitor/%s' % (node_id,), data=data)
