#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
import rfc3339
import datetime
import paramiko
import nacl.signing, nacl.exceptions
import fruit.csexp as csexp

###########################################################################
## Deserialization from csexps

_reg = csexp.Registry()
_reg.record(b'rfc3339', datetime.datetime)(lambda e: rfc3339.parse_datetime(e.decode('us-ascii')))

def rfc3339_sexp(dt):
    return [b'rfc3339', dt.isoformat().encode('us-ascii')]

def _ensure_pk(sexp):
    if not (isinstance(sexp, bytes) and len(sexp) == 32): ## ed25519 public-key length
        raise ValueError('Invalid public-key format: %r' % (sexp,))

def _ensure_sig(sexp):
    if not (isinstance(sexp, bytes) and len(sexp) == 64): ## ed25519 signature length
        raise ValueError('Invalid signature format: %r' % (sexp,))

###########################################################################
## SignedItem

class SignedItem(object):
    def signing_identity(self):
        raise NotImplementedError('Subclass responsibility')

    def signed_message(self):
        raise NotImplementedError('Subclass responsibility')

    def attach_signature(self, signature):
        self.signature = signature
        if signature is not None:
            _ensure_sig(signature)
            self.check_signature()

    def check_signature(self):
        self.signing_identity().verify(self.signed_message(), self.signature)

    def sign_with(self, signer):
        self.signature = signer.sign(self.signing_identity(), self.signed_message())

    def ensure_signed(self):
        if self.signature is None:
            raise ValueError('Cannot serialize non-signed item')

###########################################################################
## Identity & Signer

SSH_PUBLIC_KEY_BLOB_PREFIX = b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 '
SSH_SIGNATURE_BLOB_PREFIX = b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00@'

class NotAuthorized(RuntimeError): pass

class Identity(object):
    def __init__(self, public_key):
        _ensure_pk(public_key)
        self.public_key = public_key ## bytes
        self.vk = nacl.signing.VerifyKey(public_key)

    def sexp(self):
        return self.public_key

    def unwrap(self, msgbytes, sigbytes):
        try:
            self.vk.verify(msgbytes, sigbytes)
        except nacl.exceptions.BadSignatureError:
            return None
        else:
            return msgbytes

    def verify(self, msgbytes, sigbytes):
        if self.unwrap(msgbytes, sigbytes) is None:
            raise NotAuthorized('Bad signature')

    def __eq__(self, other):
        return isinstance(other, Identity) and self.vk == other.vk

    def __ne__(self, other):
        return not (self == other)

    def as_ssh_blob(self):
        return SSH_PUBLIC_KEY_BLOB_PREFIX + self.public_key

    def as_base64(self):
        s = base64.b64encode(self.vk.encode()).decode('us-ascii')
        return s.replace('=', '')

    @staticmethod
    def from_base64(bs):
        if not isinstance(bs, bytes):
            bs = bs.encode('us-ascii')
        bs = bs + b'=' * (-len(bs) % 4)  ## re-pad
        bs = base64.b64decode(bs)
        return Identity(bs)

    def __repr__(self):
        return 'Identity(%s)' % (self.as_base64(),)

class Signer(object):
    @property
    def identity(self):
        return self._identity()

    def sign(self, on_behalf_of_identity, msgbytes):
        if self.identity != on_behalf_of_identity:
            raise ValueError('Cannot sign with signer not matching identity')
        return self._sign(msgbytes)

    def _identity(self):
        raise NotImplementedError('Subclass responsibility')

    def _sign(self, msgbytes):
        raise NotImplementedError('Subclass responsibility')

###########################################################################
## Requests and Contexts

class Context(object):
    def __init__(self, props, now=None):
        if now is None:
            now = rfc3339.now()
        self.now = now
        self.props = props

    def sexp(self):
        return [b'context',
                rfc3339_sexp(self.now),
                list((k.encode('utf-8'), v) for (k,v) in self.props.items())]

    @staticmethod
    def deserialize(ts, proplist):
        return Context(now=_reg.deserialize(ts, datetime.datetime),
                       props=dict((k.decode('utf-8'), v) for (k,v) in proplist))

    def prefix(self, key_prefix):
        new_props = {}
        for k in self.props:
            new_props[key_prefix + k] = self.props[k]
        return Context(now=self.now, props=new_props)

    def merge(self, other):
        result = dict(self.props)
        result.update(other.props)
        return Context(props=result)

_reg.record(b'context', Context)(Context.deserialize)

class Request(SignedItem):
    def __init__(self, agent, agent_context, signature=None):
        self.agent = agent
        self.agent_context = agent_context
        self.attach_signature(signature)

    def signing_identity(self):
        return self.agent

    def signed_message(self):
        return csexp.encode([self.agent.sexp(),
                             self.agent_context.sexp()])

    def sexp(self):
        self.ensure_signed()
        return [b'request',
                self.agent.sexp(),
                self.agent_context.sexp(),
                self.signature]

    def is_fresh(self,
                 backwards=datetime.timedelta(minutes=-10),
                 forwards=datetime.timedelta(minutes=5)):
        now = rfc3339.now()
        if self.agent_context.now < now + backwards:
            return False
        if self.agent_context.now >= now + forwards:
            return False
        return True

    @staticmethod
    def deserialize(agent, agent_context, signature):
        return Request(Identity(agent),
                       _reg.deserialize(agent_context, Context),
                       signature)

_reg.record(b'request', Request)(Request.deserialize)

###########################################################################
## Variations on Signer: Local SSH private key; SSH-agent based

class PasswordRequired(RuntimeError): pass

class LocalSigner(Signer):
    def __init__(self, secret_key=None):
        if secret_key is None:
            secret_key = nacl.signing.SigningKey.generate()._signing_key[:32]
        self.sk = nacl.signing.SigningKey(secret_key)

    def _identity(self):
        return Identity(self.sk.verify_key.encode())

    def _sign(self, msgbytes):
        return self.sk.sign(msgbytes).signature

    def secret_key_bytes(self):
        return self.sk._signing_key[:32]

    @staticmethod
    def from_ssh_private_key(filename, password=None, identity=None):
        try:
            k = paramiko.Ed25519Key(filename=filename, password=password)
        except paramiko.ssh_exception.PasswordRequiredException:
            raise PasswordRequired()
        except paramiko.ssh_exception.SSHException:
            return None
        else:
            if identity is None or k.asbytes() == identity.as_ssh_blob():
                return LocalSigner(k._signing_key._signing_key[:32])
            return None

class AgentSigner(Signer):
    def __init__(self, agent, agent_key):
        self.agent = agent
        self.agent_key = agent_key
        bs = agent_key.asbytes()
        if not bs.startswith(SSH_PUBLIC_KEY_BLOB_PREFIX):
            raise ValueError('Invalid public key')
        self.public_key = agent_key.asbytes()[len(SSH_PUBLIC_KEY_BLOB_PREFIX):]

    def _identity(self):
        return Identity(self.public_key)

    def _sign(self, msgbytes):
        blob = self.agent_key.sign_ssh_data(msgbytes)
        if not blob.startswith(SSH_SIGNATURE_BLOB_PREFIX):
            raise ValueError('Invalid signature from ssh-agent')
        return blob[len(SSH_SIGNATURE_BLOB_PREFIX):]

    @staticmethod
    def lookup(identity):
        expected_blob = identity.as_ssh_blob()
        agent = paramiko.Agent()
        for k in agent.get_keys():
            if k.asbytes() == expected_blob:
                return AgentSigner(agent, k)
        return None

###########################################################################

if __name__ == '__main__':
    import pprint
    import time

    def get_signer_for(identity, key_filename=None, key_password=None):
        k = AgentSigner.lookup(identity)
        if k:
            return k

        try:
            return LocalSigner.from_ssh_private_key(key_filename, None, identity=identity)
        except PasswordRequired:
            return LocalSigner.from_ssh_private_key(key_filename, key_password, identity=identity)

    s = get_signer_for(Identity.from_base64('CN94hrKIFDCF/DherJg4Et1ZB8dbG3766mAlVCgvp9Q'),
                       key_filename='testkey-ssob',
                       key_password=b'ssob')
    if not s:
        raise Exception('No key available')

    i = s.identity

    sig = s.sign(i, b'hello')
    print(i.unwrap(b'hello', sig))
    print(i.unwrap(b'hello2', sig))
    print(i.unwrap(b'hello', sig + b'x'))

    req = Request(i, Context({'v': b'A'}))
    req.sign_with(s)
    print(pprint.pformat(req.sexp(), indent=2))
    print(csexp.armor(req.sexp()))
    print(len(csexp.encode(req.sexp())))
    print(len(csexp.armor(req.sexp())))
    print(len(csexp.armor(req.sexp(), compress=False)))

    def judge():
        print("Fresh" if req.is_fresh(backwards=datetime.timedelta(seconds=0),
                                      forwards=datetime.timedelta(seconds=1)) else "Not fresh")

    judge()
    time.sleep(1)
    judge()
