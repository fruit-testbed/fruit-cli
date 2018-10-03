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
            raise NotAuthorized('Expected agent to be %r, was %r' % (
                self.identity,
                agent))

    @_reg.record(b'root', Grant)
    @staticmethod
    def deserialize(pk):
        return RootGrant(Identity(pk))

    def __repr__(self):
        return '<Root %r>' % (self.identity,)

class DelegatedGrant(Grant, SignedItem):
    def __init__(self, recipient, base, caveats, signature=None):
        self.recipient = recipient
        self.base = base
        self.caveats = caveats
        self.attach_signature(signature)

    def holder(self):
        return self.recipient

    def signing_identity(self):
        return self.base.holder()

    def signed_message(self):
        return csexp.encode([self.recipient.sexp(),
                             self.base.sexp(),
                             [c.sexp() for c in self.caveats]])

    def sexp(self):
        self.ensure_signed()
        return [b'grant',
                self.recipient.sexp(),
                self.base.sexp(),
                [c.sexp() for c in self.caveats],
                self.signature]

    def check(self, agent, context):
        if agent != self.recipient:
            raise NotAuthorized('Expected agent to be %r, was %r' % (
                self.recipient,
                agent))
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

    def sign(self, on_behalf_of_identity, msgbytes):
        if self.identity != on_behalf_of_identity:
            raise ValueError('Cannot sign with signer not matching identity')
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
        return [b'valid-between', rfc3339_sexp(self.notbefore), rfc3339_sexp(self.notafter)]

    def check(self, agent, context):
        if context.now < self.notbefore:
            raise NotAuthorized('Not valid: too early')
        if context.now >= self.notafter:
            raise NotAuthorized('Not valid: expired')

    @_reg.record(b'valid-between', Caveat)
    @staticmethod
    def deserialize(nb, na):
        return ValidBetweenCaveat(notbefore=_reg.deserialize(nb, datetime.datetime),
                                  notafter=_reg.deserialize(na, datetime.datetime))

    def __repr__(self):
        return '<"%s <= time < %s">' % (self.notbefore, self.notafter)

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

    def check(self, agent, context):
        if self.property_name not in context.props:
            raise NotAuthorized('Expected context property %r to be %r, was missing' % (
                self.property_name,
                self.expected_value))
        if context.props[self.property_name] != self.expected_value:
            raise NotAuthorized('Expected context property %r to be %r, was %r' % (
                self.property_name,
                self.expected_value,
                context.props[self.property_name]))

###########################################################################
## Caveat/request context

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
    def __init__(self, agent, grant, agent_context, signature=None):
        self.agent = agent
        self.grant = grant
        self.agent_context = agent_context
        self.attach_signature(signature)

    def signing_identity(self):
        return self.agent

    def signed_message(self):
        return csexp.encode([self.agent.sexp(),
                             self.grant.sexp(),
                             self.agent_context.sexp()])

    def sexp(self):
        self.ensure_signed()
        return [b'request',
                self.agent.sexp(),
                self.grant.sexp(),
                self.agent_context.sexp(),
                self.signature]

    def check(self, service_context):
        context = service_context.prefix('service.').merge(self.agent_context.prefix('agent.'))
        if not context:
            raise NotAuthorized('Inconsistent agent and service contexts')
        self.grant.check(self.agent, context)

    @staticmethod
    def deserialize(agent, grant, agent_context, signature):
        return Request(Identity(agent),
                       _reg.deserialize(grant, Grant),
                       _reg.deserialize(agent_context, Context),
                       signature)

_reg.record(b'request', Request)(Request.deserialize)

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

    sig = s.sign(i, b'hello')
    print(i.unwrap(b'hello', sig))
    print(i.unwrap(b'hello2', sig))
    print(i.unwrap(b'hello', sig + b'x'))

    r = RootGrant(i)
    x = ValidBetweenCaveat(lifetime=datetime.timedelta(seconds = 1))
    d = DelegatedGrant(i2, r, [x,
                               ContextEqualityCaveat('agent.v', b'A'),
                               ContextEqualityCaveat('service.v', b'B')])
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
    d2.check(i2, Context({'agent.v': b'A', 'service.v': b'B'}))

    req = Request(i2, d2, Context({'v': b'A'}))
    req.sign_with(s2)
    print(pprint.pformat(req.sexp(), indent=2))
    print(csexp.armor(req.sexp()))

    req.check(Context({'v': b'B'}))
    print("Check passed!")

    import time
    time.sleep(1)
    d2.check(i2, Context({'agent_v': b'A', 'service_v': b'B'}))
