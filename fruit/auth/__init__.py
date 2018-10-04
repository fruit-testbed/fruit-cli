# -*- coding: utf-8 -*-

import base64
import rfc3339
import datetime
import paramiko
import ed25519
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

class NotAuthorized(RuntimeError): pass

class Identity(object):
    def __init__(self, public_key):
        _ensure_pk(public_key)
        self.public_key = public_key ## bytes

    def sexp(self):
        return self.public_key

    def unwrap(self, msgbytes, sigbytes):
        try:
            ed25519.keys.VerifyingKey(self.public_key).verify(sigbytes, msgbytes)
        except AssertionError:
            return None
        except ed25519.keys.BadSignatureError:
            return None
        else:
            return msgbytes

    def verify(self, msgbytes, sigbytes):
        if self.unwrap(msgbytes, sigbytes) is None:
            raise NotAuthorized('Bad signature')

    def __eq__(self, other):
        return isinstance(other, Identity) and self.public_key == other.public_key

    def __ne__(self, other):
        return not (self == other)

    def as_base64(self):
        return base64.b64encode(self.public_key).decode('us-ascii').rstrip('=')

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

class LocalSigner(Signer):
    def __init__(self, secret_key=None):
        if secret_key is None:
            secret_key = os.urandom(32)
        self.secret_key = secret_key
        (self.public_key, _sk) = ed25519._ed25519.publickey(secret_key)

    def _identity(self):
        return Identity(self.public_key)

    def _sign(self, msgbytes):
        return ed25519.keys.SigningKey(self.secret_key + self.public_key).sign(msgbytes)

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
