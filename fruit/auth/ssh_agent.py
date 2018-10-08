# -*- coding: utf-8 -*-
# Do Ed25519 signature operations via ssh-agent

import os
import socket
import struct

import fruit.auth

from .bin_io import *

SSH_AGENTC_REQUEST_IDENTITIES = 11
SSH_AGENT_IDENTITIES_ANSWER = 12
SSH_AGENTC_SIGN_REQUEST = 13
SSH_AGENT_SIGN_RESPONSE = 14

class ProtocolError(Exception): pass

class Agent(object):
    def __init__(self, socket_path=None):
        if socket_path is None:
            socket_path = os.environ.get('SSH_AUTH_SOCK', None)

        self.socket_path = socket_path

        if socket_path:
            try:
                self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self._socket.connect(socket_path)
            except socket.error:
                if self._socket:
                    self._socket.close()
                self._socket = None
        else:
            self._socket = None

    def __del__(self):
        if self._socket:
            self._socket.close()
            self._socket = None

    def _send(self, packet):
        self._socket.sendall(format_str(packet))

    def _readbytes(self, count):
        bs = b''
        while count > 0:
            chunk = self._socket.recv(count)
            count = count - len(chunk)
            bs = bs + chunk
        return bs

    def _recv(self):
        (length,) = struct.unpack('>I', self._readbytes(4))
        bs = self._readbytes(length)
        return bs

    def list_identities(self):
        if not self._socket:
            return []
        self._send(format_byte(SSH_AGENTC_REQUEST_IDENTITIES))
        blob = self._recv()
        (replytype, blob) = parse_byte(blob)
        if replytype != SSH_AGENT_IDENTITIES_ANSWER: raise ProtocolError() # pragma: no cover
        (nkeys, blob) = parse_int(blob)
        result = []
        for i in range(nkeys):
            (keyblob, blob) = parse_str(blob)
            (comment, blob) = parse_str(blob)
            if keyblob.startswith(SSH_PUBLIC_KEY_BLOB_PREFIX):
                result.append((keyblob[len(SSH_PUBLIC_KEY_BLOB_PREFIX):], comment.decode('utf-8')))
        parse_end(blob)
        return result

    def sign_data(self, public_key, data):
        self._send(format_byte(SSH_AGENTC_SIGN_REQUEST) +
                   format_str(SSH_PUBLIC_KEY_BLOB_PREFIX + public_key) +
                   format_str(data) +
                   format_int(0))
        blob = self._recv()
        (replytype, blob) = parse_byte(blob)
        if replytype != SSH_AGENT_SIGN_RESPONSE: raise ProtocolError() # pragma: no cover
        (sig, blob) = parse_str(blob)
        parse_end(blob)
        sig = parse_expected(SSH_SIGNATURE_BLOB_PREFIX, sig)
        return sig

    def signer_for_identity(self, identity):
        for (pk, comment) in self.list_identities():
            if identity == pk:
                return AgentSigner(self, identity)
        return None

class AgentSigner(fruit.auth.Signer):
    def __init__(self, agent, identity):
        self.agent = agent
        self.identity = identity

    def _sign(self, msgbytes):
        return self.agent.sign_data(self.identity, msgbytes)
