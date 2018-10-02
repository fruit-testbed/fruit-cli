#!/usr/bin/env python
# -*- coding: utf-8 -*-

# [not-later-than(rfc3339("2018-10-01T17:56:33+01:00"))]
# [not-later-than(rfc3339("2018-10-01T16:56:33Z"))]

# Authority delegation.
#
# Authority is either
#  - primordial (intrinsic capability)
#  - a delegation, potentially attenuating
#
# <principal> = <32 bytes of ed25519 public-key>
#
# <grant> = (root <recipient:principal>)
#         | (grant <recipient:principal>
#                  <grant>
#                  <caveats:list-of(caveat)>
#                  <sig-val(grant.recipient, (recipient,grant,caveats))> )
#
# <caveat> = (not-later-than <rfc3339-datetime>)
#          | (== <context-variable-name> <literal-value>)

import rfc3339
import datetime
import nacl.signing, nacl.exceptions
import fruit.csexp as csexp

###########################################################################
## Deserialization from csexps

_reg = csexp.Registry()
_reg.record(b'rfc3339', datetime.datetime)(lambda e: rfc3339.parse_datetime(e.decode('us-ascii')))

def _ensure_pk(sexp):
    if not (isinstance(sexp, bytes) and len(sexp) == 32): ## ed25519 public-key length
        raise ValueError('Invalid public-key format: %r' % (sexp,))

def _ensure_sig(sexp):
    if not (isinstance(sexp, bytes) and len(sexp) == 64): ## ed25519 signature length
        raise ValueError('Invalid signature format: %r' % (sexp,))

###########################################################################
## Grants

class NotAuthorized(RuntimeError): pass

class Grant(object):
    def holder(self):
        raise NotImplementedError('Subclass responsibility')

    def check(self, agent, context):
        raise NotImplementedError('Subclass responsibility')

class RootGrant(Grant):
    def __init__(self, identity):
        self.identity = identity

    def holder(self):
        return self.identity

    def sexp(self):
        return [b'root', self.identity.sexp()]

    def check(self, agent, context):
        if agent != self.identity:
            raise NotAuthorized()

    @_reg.record(b'root', Grant)
    @staticmethod
    def deserialize(pk):
        return RootGrant(Identity(pk))

class DelegatedGrant(Grant):
    def __init__(self, recipient, base, caveats, signature=None):
        self.recipient = recipient
        self.base = base
        self.caveats = caveats
        self.signature = signature
        if signature is not None:
            _ensure_sig(signature)
            self.check_signature()

    def holder(self):
        return self.recipient

    def _message(self):
        return csexp.encode([self.recipient.sexp(),
                             self.base.sexp(),
                             [c.sexp() for c in self.caveats]])

    def check_signature(self):
        self.base.holder().verify(self._message(), self.signature)

    def sign_with(self, signer):
        if signer.identity != self.base.holder():
            raise ValueError('Cannot sign with signer not matching base holder identity')
        self.signature = signer.sign(self._message())

    def sexp(self):
        if self.signature is None:
            raise ValueError('Cannot serialize non-signed DelegatedGrant')
        return [b'grant',
                self.recipient.sexp(),
                self.base.sexp(),
                [c.sexp() for c in self.caveats],
                self.signature]

    def check(self, agent, context):
        if agent != self.recipient:
            raise NotAuthorized()
        self.base.check(self.base.holder(), context)
        for c in self.caveats:
            c.check(agent, context)

    @_reg.record(b'grant', Grant)
    @staticmethod
    def deserialize(recipient, base, caveats, sigval):
        return DelegatedGrant(Identity(recipient),
                              _reg.deserialize(base, Grant),
                              [_reg.deserialize(c, Caveat) for c in caveats],
                              sigval)

###########################################################################
## Identity & Signer

class Identity(object):
    def __init__(self, public_key):
        _ensure_pk(public_key)
        self.public_key = public_key ## bytes
        self.vk = nacl.signing.VerifyKey(public_key)

    def sexp(self):
        return self.public_key

    def verify(self, msgbytes, sigbytes):
        try:
            self.vk.verify(msgbytes, sigbytes)
        except nacl.exceptions.BadSignatureError:
            return None
        else:
            return msgbytes

    def __eq__(self, other):
        return isinstance(other, Identity) and self.vk == other.vk

    def __ne__(self, other):
        return not (self == other)

    def __repr__(self):
        import base64
        return 'Identity(%s)' % (base64.b64encode(self.vk.encode()),)

class Signer(object):
    def __init__(self, secret_key=None):
        if secret_key is None:
            secret_key = nacl.signing.SigningKey.generate()._signing_key[:32]
        self.sk = nacl.signing.SigningKey(secret_key)

    @property
    def identity(self):
        return Identity(self.sk.verify_key.encode())

    def sign(self, msgbytes):
        return self.sk.sign(msgbytes).signature

    def secret_key_bytes(self):
        return self.sk._signing_key[:32]

###########################################################################
## Caveats

class Caveat(object):
    def check(self, agent, context):
        raise NotImplementedError('Subclass responsibility')

class NotLaterThanCaveat(Caveat):
    def __init__(self, deadline=None, lifetime=None):
        if deadline is not None and lifetime is None:
            self.deadline = deadline
        elif deadline is None and lifetime is not None:
            self.deadline = rfc3339.now() + lifetime
        else:
            raise ValueError('Supply either (but not both) deadline or lifetime to NotLaterThanCaveat ctor')

    def sexp(self):
        return [b'not-later-than', [b'rfc3339', self.deadline.isoformat().encode('us-ascii')]]

    def check(self, agent, context):
        if context.now >= self.deadline:
            raise NotAuthorized()

    @_reg.record(b'not-later-than', Caveat)
    @staticmethod
    def deserialize(r):
        return NotLaterThanCaveat(deadline=_reg.deserialize(r, datetime.datetime))

class ContextEqualityCaveat(Caveat):
    def __init__(self, property_name, expected_value):
        self.property_name = property_name
        self.expected_value = expected_value

    def sexp(self):
        return [b'==', self.property_name.encode('utf-8'), self.expected_value]

    @_reg.record(b'==', Caveat)
    @staticmethod
    def deserialize(property_name, expected_value):
        return ContextEqualityCaveat(property_name.decode('utf-8'), expected_value)

###########################################################################
## Caveat context

class Context(object):
    def __init__(self, props):
        self.now = rfc3339.now()
        self.props = props

###########################################################################

import paramiko

# agent = paramiko.Agent()
# print([(k.name, k.asbytes()) for k in agent.get_keys() if k.name == 'ssh-ed25519'])
k = paramiko.Ed25519Key(filename="testkey-ssob", password=b'ssob')
# print(k.asbytes())
s = Signer(k._signing_key._signing_key[:32])
i = s.identity
sig = s.sign(b'hello')
r = RootGrant(i)
x = NotLaterThanCaveat(lifetime=datetime.timedelta(seconds = 1))
d = DelegatedGrant(i, r, [x])
d.sign_with(s)

v = csexp.encode(d.sexp())
print(v)
print(csexp.armor(d.sexp()))
import base64
print(len(v))
print(len(csexp.armor(d.sexp())))
print(len(csexp.armor(d.sexp(), compress=False)))
d2 = _reg.deserialize(csexp.decode(v), Grant)
print(d2)
print(_reg.deserialize(csexp.unarmor(csexp.armor(d.sexp())), Grant))
d2.check(i, Context({}))
import time
time.sleep(1)
d2.check(i, Context({}))

# tok = Token(i, lifetime = datetime.timedelta(seconds = 1))
# tok.sign_with(s)
# print(tok.signed_str)
# print(Token.from_signed_str(tok.signed_str))
# import time
# time.sleep(2)
# print(Token.from_signed_str(tok.signed_str))
