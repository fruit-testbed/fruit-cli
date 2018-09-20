#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import os
import json
import copy
import re
import requests
import collections

DEFAULT_SERVER = 'https://fruit-testbed.org/api'


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
        headers['Accept-Encoding'] = 'gzip'
        if self._api_key is not None:
            headers['X-API-Key'] = self._api_key
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

    def _starting_params(self, group_name=None, node_id=None):
        params = { 'email': self.email }
        if group_name is not None: params['hostname'] = group_name
        if node_id is not None: params['id'] = node_id
        return params

    def register(self, email):
        return self._call('POST', '/user/%s' % (email,)).json()

    def resend_api_key(self, email):
        return self._call('GET', '/verify/%s/resend' % (email,)).json()

    def list_nodes(self, group_name=None):
        params = self._starting_params(group_name=group_name)
        return self._call('GET', '/node', params=params).json()

    def node_config(self, node_id):
        return self._call('GET', '/node/%s/config' % (node_id,)).json()

    def post_monitoring_data(self, node_id, data):
        self._call('POST', '/monitor/%s' % (node_id,), data=data)

    def get_monitoring_data(self, group_name=None, node_id=None):
        params = self._starting_params(group_name=group_name, node_id=node_id)
        return self._call('GET', '/monitor', params).json()

    def run_container(self, spec, group_name=None, node_id=None):
        params = self._starting_params(group_name=group_name, node_id=node_id)
        data = spec.to_json()
        return self._call('PUT', '/container', params=params, data=data).json()

    def list_containers(self, group_name=None, node_id=None):
        params = self._starting_params(group_name=group_name, node_id=node_id)
        return self._call('GET', '/container', params=params).json()

    def delete_container(self, container_name, group_name=None, node_id=None):
        params = self._starting_params(group_name=group_name, node_id=node_id)
        params['name'] = container_name
        return self._call('DELETE', '/container', params=params).json()

    def list_ssh_keys(self, group_name=None, node_id=None):
        ## TODO: split out retrieval of user keys from node keys entirely
        params = self._starting_params(group_name=group_name, node_id=node_id)
        result = self._call('GET', '/user/ssh-key', params=params).json()
        users = result.get('users', {})
        for (email, keys) in users.items():
            users[email] = map(json_to_ssh_key, keys)
        nodes = result.get('nodes', {})
        for (node_id, keys) in nodes.items():
            nodes[node_id] = map(json_to_ssh_key, keys)
        return result

    def add_ssh_key(self, key, group_name=None, node_id=None):
        params = self._starting_params(group_name=group_name, node_id=node_id)
        data = ssh_key_to_json(key)
        return self._call('PUT', '/user/ssh-key', params=params, data=data).json()

    def delete_ssh_key(self, key, group_name=None, node_id=None):
        params = self._starting_params(group_name=group_name, node_id=node_id)
        data = ssh_key_to_json(key)
        return self._call('DELETE', '/user/ssh-key', params=params, data=data).json()


class ContainerSpec:
    def __init__(self,
                 name,
                 image,
                 command=[], # array of strings
                 port=[], # array of strings - arguments to docker run -p
                 volume=[], # array of strings - 'hostpath:containerpath'
                 kernel_module=[], # array of strings - names of kernel modules to modprobe
                 device_tree=[], # array of strings - names of rpi device tree overlays
                 device=[]): # array of strings - e.g. 'ttyS0', 'sda' - names of devices to expose
        self.name = name
        self.image = image
        self.command = self._string_list('command', command)
        self.port = self._string_list('port', port)
        self.volume = self._string_list('volume', volume)
        self.kernel_module = self._string_list('kernel_module', kernel_module)
        self.device_tree = self._string_list('device_tree', device_tree)
        self.device = self._string_list('device', device)

    def _string_list(self, what, xs):
        if not all(isinstance(x, str) for x in xs):
            raise TypeError('%s must be a list of strings in ContainerSpec constructor' % (what,))
        return xs

    def to_json(self):
        blob = {}
        blob['name'] = self.name
        blob['image'] = self.image
        if self.command: blob['command'] = self.command
        if self.port: blob['port'] = self.port
        if self.volume: blob['volume'] = self.volume
        if self.kernel_module: blob['kernel_module'] = self.kernel_module
        if self.device_tree: blob['device_tree'] = self.device_tree
        if self.device: blob['device'] = self.device
        return blob

    @staticmethod
    def from_json(blob):
        return ContainerSpec(blob['name'],
                             blob['image'],
                             blob.get('command', []),
                             blob.get('port', []),
                             blob.get('volume', []),
                             blob.get('kernel_module', []),
                             blob.get('device_tree', []),
                             blob.get('device', []))


SshKey = collections.namedtuple('SshKey', 'key_type key_id key_comment')

# `ssh -Q key-plain`
# NB. For parsing only - distinct from the set of key types the
# management server is willing to accept.
KEY_TYPES = [
    'ssh-ed25519',
    'ssh-rsa',
    'ssh-dss',
    'ecdsa-sha2-nistp256',
    'ecdsa-sha2-nistp384',
    'ecdsa-sha2-nistp521',
]

def json_to_ssh_key(ssh_key):
    t = ssh_key['type']
    if t not in KEY_TYPES:
        raise TypeError('Invalid SSH key type %r' % (t,))
    return model.SshKey(ssh_key['type'], ssh_key['key'], ssh_key.get('comment', ''))

def ssh_key_to_json(k):
    j = { 'type': k.key_type, 'key': k.key_id }
    if k.key_comment: j['comment'] = k.key_comment
    return j


class SshKeyFile:
    COMMENT = re.compile(r"^\s*#")
    FIELDSEP = re.compile(r"\s+")

    def __init__(self):
        self.keys = []

    def load(self, fh):
        # Per sshd(8): "Each line of the file contains one key (empty
        # lines and lines starting with a '#' are ignored as
        # comments). Public keys consist of the following
        # space-separated fields: options, keytype, base64-encoded
        # key, comment. The options field is optional."
        #
        # It turns out that the comment is optional, too; or rather, a
        # missing comment and an empty comment are treated the same.
        #
        # Furthermore, "space-separated" means space *or tab*
        # separated (per openssh's sshkey.c).
        #
        # The parsing code in openssh can't just chop up each line,
        # because without knowledge of the valid key types and/or the
        # valid options, parsing is ambiguous. Given that the set of
        # available options is large, and the key types are simple and
        # flat, I've gone with using the key types to disambiguate. As
        # SSH grows new key types, we'll have to rerun `ssh -Q
        # key-plain` and update KEY_TYPES above.
        #
        # TODO: We DISCARD any key with options here, because it's
        # probably better to do so than to upload the key into some
        # authorized_keys position without restrictions! Perhaps a
        # future FRμIT version could support per-key options?
        #
        self.keys.clear()
        for line in fh:
            if SshKeyFile.COMMENT.match(line):
                pass
            else:
                fields = SshKeyFile.FIELDSEP.split(line, 2)
                if len(fields) in [2, 3] and fields[0] in KEY_TYPES:
                    # key type is first field -> no pesky options!
                    comment = fields[2] if len(fields) == 3 else ''
                    self.keys.append(SshKey(fields[0], fields[1], comment))
                else:
                    # either too short (i.e. invalid) or has something
                    # other than a key type as its first field (i.e.
                    # options present).
                    pass

    def save(self, fh):
        for k in self.keys:
            if k.key_comment:
                fh.write('%s %s %s\n' % (k.key_type, k.key_id, k.key_comment))
            else:
                fh.write('%s %s\n' % (k.key_type, k.key_id))
