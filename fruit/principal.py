#!/usr/bin/env python
# -*- coding: utf-8 -*-

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
# <caveat> = (valid-between <rfc3339-datetime> <rfc3339-datetime>)
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

    def __repr__(self):
        return '<Root %r>' % (self.identity,)

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

    def __repr__(self):
        return '<Delegation of %r to %r subject to %r>' % (self.base, self.recipient, self.caveats)

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
        s = base64.b64encode(self.vk.encode()).decode('us-ascii')
        s = s.replace('=', '')
        return 'Identity(%s)' % (s,)

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

class ValidBetweenCaveat(Caveat):
    def __init__(self, notafter=None, lifetime=None, notbefore=None):
        if notbefore is None:
            notbefore = rfc3339.now()
        self.notbefore = notbefore
        if notafter is not None and lifetime is None:
            self.notafter = notafter
        elif notafter is None and lifetime is not None:
            self.notafter = notbefore + lifetime
        else:
            raise ValueError('Supply either notafter or lifetime (not both) to ValidBetweenCaveat')

    def sexp(self):
        return [b'valid-between',
                [b'rfc3339', self.notbefore.isoformat().encode('us-ascii')],
                [b'rfc3339', self.notafter.isoformat().encode('us-ascii')]]

    def check(self, agent, context):
        if context.now < self.notbefore:
            raise NotAuthorized()
        if context.now >= self.notafter:
            raise NotAuthorized()

    @_reg.record(b'valid-between', Caveat)
    @staticmethod
    def deserialize(nb, na):
        return ValidBetweenCaveat(notbefore=_reg.deserialize(nb, datetime.datetime),
                                  notafter=_reg.deserialize(na, datetime.datetime))

    def __repr__(self):
        return '<"%s < time <= %s">' % (self.notbefore, self.notafter)

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

if __name__ == '__main__':
    import paramiko

    # agent = paramiko.Agent()
    # print([(k.name, k.asbytes()) for k in agent.get_keys() if k.name == 'ssh-ed25519'])

    k = paramiko.Ed25519Key(filename="testkey-ssob", password=b'ssob')
    # print(k.asbytes())

    s = Signer(k._signing_key._signing_key[:32])
    i = s.identity
    s2 = Signer()
    i2 = s2.identity

    sig = s.sign(b'hello')
    print(i.verify(b'hello', sig))

    r = RootGrant(i)
    x = ValidBetweenCaveat(lifetime=datetime.timedelta(seconds = 1))
    d = DelegatedGrant(i2, r, [x])
    d.sign_with(s)

    v = csexp.encode(d.sexp())
    print(csexp.armor(d.sexp()))
    import pprint
    print(pprint.pformat(d.sexp(), indent=2))
    import base64
    print(len(v))
    print(len(csexp.armor(d.sexp())))
    print(len(csexp.armor(d.sexp(), compress=False)))
    d2 = _reg.deserialize(csexp.decode(v), Grant)
    print(d2)
    print(_reg.deserialize(csexp.unarmor(csexp.armor(d.sexp())), Grant))
    d2.check(i2, Context({}))
    import time
    time.sleep(1)
    d2.check(i2, Context({}))
