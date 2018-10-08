# -*- coding: utf-8 -*-

import time
import base64
import datetime
import fruit.auth.pure_eddsa
import os

from .bin_io import BadPassword

class Signer(object):
    def sign(self, on_behalf_of_identity, msgbytes):
        if self.identity != on_behalf_of_identity:
            raise ValueError('Cannot sign with signer not matching identity')
        return self._sign(msgbytes)

    def identity_str(self):
        return _b64(self.identity)

    def _sign(self, msgbytes): # pragma: no cover
        raise NotImplementedError('Subclass responsibility')

class LocalSigner(Signer):
    def __init__(self, secret_key=None):
        if secret_key is None:
            secret_key = os.urandom(32)
        if not (isinstance(secret_key, bytes) and len(secret_key) == 32):
            raise ValueError('Invalid secret-key format: %r' % (secret_key,))
        self.secret_key = secret_key
        self.identity = fruit.auth.pure_eddsa.create_verifying_key(secret_key)

    def _sign(self, msgbytes):
        return fruit.auth.pure_eddsa.signature(msgbytes, self.secret_key, self.identity)

def _b64(bs):
    return base64.urlsafe_b64encode(bs).rstrip(b'=').decode('us-ascii')

def _unb64(bs):
    bs = bs.encode('us-ascii')
    bs = bs + b'=' * (-len(bs) % 4)  ## re-pad
    return base64.urlsafe_b64decode(bs)

class UTC(datetime.tzinfo):
    ZERO = datetime.timedelta(seconds = 0)
    def utcoffset(self, dt): return self.ZERO
    def dst(self, dt): return self.ZERO # pragma: no cover
    def tzname(self, dt): return 'Z' # pragma: no cover
utc = UTC()

def make_authenticated_identity(identity, signer):
    now = datetime.datetime(*time.gmtime(time.time())[:6] + (0, utc))
    timestamp = now.isoformat().encode('us-ascii')
    signature = signer.sign(identity, timestamp)
    return ';'.join(('1', _b64(identity), _b64(timestamp), _b64(signature)))
