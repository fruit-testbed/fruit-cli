# -*- coding: utf-8 -*-

import base64
import datetime

import fruit.auth.pure_eddsa
import fruit.auth.rfc3339

def _ensure_pk(bs):
    if not (isinstance(bs, bytes) and len(bs) == 32): ## ed25519 public-key length
        raise ValueError('Invalid public-key format: %r' % (bs,))

def _ensure_sk(bs):
    if not (isinstance(bs, bytes) and len(bs) == 32): ## ed25519 secret-key length (!)
        raise ValueError('Invalid secret-key format: %r' % (bs,))

def _ensure_sig(bs):
    if not (isinstance(bs, bytes) and len(bs) == 64): ## ed25519 signature length
        raise ValueError('Invalid signature format: %r' % (bs,))

def _b64(bs):
    return base64.b64encode(bs).rstrip(b'=')

def _unb64(bs):
    if not isinstance(bs, bytes):
        bs = bs.encode('us-ascii')
    bs = bs + b'=' * (-len(bs) % 4)  ## re-pad
    return base64.b64decode(bs)

###########################################################################
## Identity & Signer

class NotAuthorized(RuntimeError): pass

class Identity(object):
    def __init__(self, public_key):
        _ensure_pk(public_key)
        self.public_key = public_key ## bytes

    def unwrap(self, msgbytes, sigbytes):
        try:
            pure_eddsa.verify(self.public_key, sigbytes, msgbytes)
        except:
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

    @staticmethod
    def from_base64(bs):
        return Identity(_unb64(bs))

    def __repr__(self):
        return 'Identity(%s)' % (_b64(self.public_key),)

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
        _ensure_sk(secret_key)
        self.secret_key = secret_key
        self.public_key = pure_eddsa.create_verifying_key(secret_key)

    def _identity(self):
        return Identity(self.public_key)

    def _sign(self, msgbytes):
        return pure_eddsa.signature(msgbytes, self.secret_key, self.public_key)

###########################################################################
## Authentication tokens and token freshness

def authenticated_identity(header_string,
                           backwards=datetime.timedelta(minutes=10),
                           forwards=datetime.timedelta(minutes=5)):
    pieces = header_string.split(';')
    if len(pieces) != 4 or pieces[0] != u'1':
        raise NotAuthorized('Bad authentication header format version')
    (_version, public_key_b64, timestamp_b64, signature_b64) = pieces
    identity = Identity(_unb64(public_key_b64))
    timestamp = _unb64(timestamp_b64)
    signature = _unb64(signature_b64)
    _ensure_sig(signature)
    identity.verify(timestamp, signature)
    now = rfc3339.now()
    timestamp = rfc3339.parse_datetime(timestamp.decode('us-ascii'))
    if timestamp < now - backwards:
        raise NotAuthorized('Expired')
    if timestamp >= now + forwards:
        raise NotAuthorized('Too far in future')
    return identity

def make_authenticated_identity(identity, signer):
    timestamp = rfc3339.now().isoformat().encode('us-ascii')
    signature = signer.sign(identity, timestamp)
    return b';'.join((b'1',
                      _b64(identity.public_key),
                      _b64(timestamp),
                      _b64(signature))).decode('us-ascii')
