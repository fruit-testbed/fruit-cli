#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import json
import copy
import re
import requests
import collections
import time

import fruit.auth

DEFAULT_SERVER = 'https://fruit-testbed.org/api'


def __debug_requests(): # pragma: no cover
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

if os.environ.get('FRUIT_API_DEBUG', ''): # pragma: no cover
    __debug_requests()


class FruitApiError(Exception):
    pass

class FruitApiRequestProblem(FruitApiError):
    def __init__(self, inner):
        self.inner = inner
        super(FruitApiRequestProblem, self).__init__(str(inner))

class FruitApiErrorResponse(FruitApiError):
    def __init__(self, response, **kwargs):
        try:
            blob = response.json()
            message = blob['title']
        except: # pragma: no cover
            message = response.reason
        super(FruitApiErrorResponse, self).__init__(message, **kwargs)
        self.response = response

class FruitApiClientProblem(FruitApiErrorResponse): pass
class FruitApiServerProblem(FruitApiErrorResponse): pass


class BaseFruitApi:
    def __init__(self, signer, server=None):
        '''Construct with the identity you wish to present.'''
        self._server = server or DEFAULT_SERVER
        self._signer = signer
        self._token = None
        self._token_timestamp = None

    def _inner_call(self, method, url,
                    params={},
                    data=None,
                    content_type=None,
                    headers={},
                    redirect_ok=False):
        headers = copy.copy(headers)
        headers['Accept-Encoding'] = 'gzip'
        if self._token is not None:
            headers['X-API-Key'] = self._token
        if content_type is not None:
            headers['Content-Type'] = content_type
        if isinstance(data, dict):
            data = json.dumps(data)
            if 'Content-Type' not in headers: # pragma: no branch
                headers['Content-Type'] = 'application/json'
        try:
            resp = requests.request(method,
                                    self._server + url,
                                    params=params,
                                    data=data,
                                    headers=headers,
                                    allow_redirects=False)
        except requests.exceptions.RequestException as exn:
            raise FruitApiRequestProblem(exn)
        code = resp.status_code
        if code >= 200 and code <= 299:
            return resp
        if code >= 300 and code <= 399: # pragma: no cover
            if redirect_ok:
                return resp
            else:
                # We do not yet follow redirections, since the API does not require them.
                raise FruitApiServerProblem(resp)
        if code >= 400 and code <= 499:
            raise FruitApiClientProblem(resp)
        if code >= 500: # pragma: no cover
            raise FruitApiServerProblem(resp)

    def _call(self, *args, **kwargs):
        self._freshen_token()
        try:
            return self._inner_call(*args, **kwargs)
        except FruitApiClientProblem as exn:
            if exn.response.status_code == 401:
                # Unauthorized; freshen token and try again
                self._freshen_token()
                return self._inner_call(*args, **kwargs)
            else:
                raise

    def _freshen_token(self):
        if self._signer is not None:
            now = time.time()
            if self._token is None or now - self._token_timestamp >= 30:
                self._token_timestamp = now
                self._token = fruit.auth.make_authenticated_identity(self._signer.identity, self._signer)

    def _starting_params(self, filter=None, node_id=None):
        params = {}
        if filter is not None: params['filter'] = json.dumps(filter)
        if node_id is not None: params['id'] = node_id
        return params

    def list_filter_paths(self):
        return self._call('GET', '/meta/filter_paths').json()


class FruitAdminApi(BaseFruitApi):
    def list_users(self):
        return self._call('GET', '/user').json()

    def user_info_by_email(self, email):
        return self._call('GET', '/user/%s' % (email,)).json()

    def delete_account(self, email):
        self._call('DELETE', '/user/%s' % (email,))

    def list_nodes(self, filter=None):
        params = self._starting_params(filter=filter)
        return self._call('GET', '/node', params=params).json()

    def delete_node(self, node_id):
        params = self._starting_params()
        try:
            self._call('DELETE', '/node/%s' % (node_id,), params=params)
            return True
        except FruitApiClientProblem as exn:
            if exn.response.status_code == 404:
                return False
            else:
                raise

    def get_monitoring_data(self, filter=None, node_id=None):
        params = self._starting_params(filter=filter, node_id=node_id)
        return self._call('GET', '/monitor', params).json()


class FruitUserApi(BaseFruitApi):
    def register(self, email):
        try:
            return self._call('POST', '/user/%s' % (email,)).json()
        except FruitApiClientProblem as exn:
            if exn.response.status_code == 409:
                # Conflict, i.e. already registered!
                # Check to see if we can authenticate as this user.
                try:
                    return self.account_info(email)
                except FruitApiClientProblem as exn2:
                    if exn2.response.status_code == 403:
                        # Forbidden, so there must be some real conflict.
                        raise exn # the ORIGINAL "conflict" exception
                    else:
                        raise exn2
            else:
                raise exn

    def account_info(self, email):
        return self._call('GET', '/user/%s' % (email,)).json()

    def delete_account(self, email):
        self._call('DELETE', '/user/%s' % (email,))

    def list_nodes(self, filter=None):
        params = self._starting_params(filter=filter)
        return self._call('GET', '/node', params=params).json()

    def get_monitoring_data(self, filter=None, node_id=None):
        params = self._starting_params(filter=filter, node_id=node_id)
        return self._call('GET', '/monitor', params).json()

    def run_container(self, spec, filter=None, node_id=None):
        params = self._starting_params(filter=filter, node_id=node_id)
        data = spec.to_json()
        return self._call('PUT', '/container', params=params, data=data).json()

    def list_containers(self, filter=None, node_id=None):
        params = self._starting_params(filter=filter, node_id=node_id)
        return self._call('GET', '/container', params=params).json()

    def delete_container(self, container_name, filter=None, node_id=None):
        if not isinstance(container_name, str):
            raise TypeError('delete_container: container_name must be string: got %r' %
                            (container_name,))
        params = self._starting_params(filter=filter, node_id=node_id)
        params['name'] = container_name
        return self._call('DELETE', '/container', params=params).json()

    def list_ssh_keys(self, filter=None, node_id=None, decode_json=True):
        ## TODO: split out retrieval of user keys from node keys entirely
        params = self._starting_params(filter=filter, node_id=node_id)
        result = self._call('GET', '/user/ssh-key', params=params).json()
        if decode_json:
            user_keys = result.get('user', [])
            for i in range(len(user_keys)):
                user_keys[i] = json_to_ssh_key(user_keys[i])
            nodes = result.get('nodes', {})
            for (node_id, keys) in nodes.items():
                nodes[node_id] = list(map(json_to_ssh_key, keys))
        return result

    def add_ssh_key(self, key, filter=None, node_id=None):
        params = self._starting_params(filter=filter, node_id=node_id)
        data = ssh_key_to_json(key)
        self._call('PUT', '/user/ssh-key', params=params, data=data)

    def delete_ssh_key(self, key, filter=None, node_id=None):
        params = self._starting_params(filter=filter, node_id=node_id)
        data = ssh_key_to_json(key)
        self._call('DELETE', '/user/ssh-key', params=params, data=data)

    def delete_node(self, node_id):
        params = self._starting_params()
        try:
            self._call('DELETE', '/node/%s' % (node_id,), params=params)
            return True
        except FruitApiClientProblem as exn:
            if exn.response.status_code == 404:
                return False
            else:
                raise


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
        if self.kernel_module: blob['kernel-module'] = self.kernel_module
        if self.device_tree: blob['device-tree'] = self.device_tree
        if self.device: blob['device'] = self.device
        return blob

    @staticmethod
    def from_json(blob):
        return ContainerSpec(blob['name'],
                             blob['image'],
                             blob.get('command', []),
                             blob.get('port', []),
                             blob.get('volume', []),
                             blob.get('kernel-module', []),
                             blob.get('device-tree', []),
                             blob.get('device', []))

    def __eq__(self, other):
        return isinstance(other, ContainerSpec) and self.to_json() == other.to_json()

    def __hash__(self):
        # This is vile
        return hash(json.dumps(self.to_json(), sort_keys=True))


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
    return SshKey(ssh_key['type'], ssh_key['key'], ssh_key.get('comment', ''))

def ssh_key_to_json(k):
    j = { 'type': k.key_type, 'key': k.key_id }
    if k.key_comment: j['comment'] = k.key_comment
    return j

def format_ssh_key(k):
    if k.key_comment:
        return '%s %s %s' % (k.key_type, k.key_id, k.key_comment)
    else:
        return '%s %s' % (k.key_type, k.key_id)

class SshKeyFile:
    COMMENT = re.compile(r"^\s*#")
    FIELDSEP = re.compile(r"\s+")

    def __init__(self):
        self.keys = []

    def load(self, fh, filename='???'):
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
        new_keys = []
        linenumber = 0
        for line in fh:
            linenumber = linenumber + 1
            line = line.rstrip('\n')
            if SshKeyFile.COMMENT.match(line):
                pass
            elif not line.strip():
                pass
            else:
                fields = SshKeyFile.FIELDSEP.split(line, 2)
                if len(fields) in [2, 3] and fields[0] in KEY_TYPES:
                    # key type is first field -> no pesky options!
                    comment = fields[2] if len(fields) == 3 else ''
                    new_keys.append(SshKey(fields[0], fields[1], comment))
                else:
                    # either too short (i.e. invalid) or has something
                    # other than a key type as its first field (i.e.
                    # options present).
                    raise FruitApiError('Unsupported SSH public key format at %s line %s: %s' % \
                                        (filename, linenumber, line))
        self.keys.extend(new_keys)

    def save(self, fh):
        for k in self.keys:
            fh.write(format_ssh_key(k) + '\n')
