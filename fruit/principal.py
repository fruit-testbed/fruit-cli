#!/usr/bin/env python
# -*- coding: utf-8 -*-

# [not-later-than(rfc3339("2018-10-01T17:56:33+01:00"))]
# [not-later-than(rfc3339("2018-10-01T16:56:33Z"))]

import os
import rfc3339
import datetime
import base64

class Token(object):
    '''For now, tokens are hard-coded to be simple expiring grants of
       anything the identified principal is allowed to do.'''
    def __init__(self, identity, expiry=None, lifetime=None):
        self.identity = identity
        if expiry is not None and lifetime is None:
            self.expiry = expiry
        elif expiry is None and lifetime is not None:
            self.expiry = rfc3339.now() + lifetime
        else:
            raise ValueError('Supply either (but not both) expiry or lifetime to Token ctor')

    def signed_str(self, signer):
        message = self.expiry.isoformat().encode('utf-8')
        return '%s %s %s' % (base64.b64encode(self.identity.public_key),
                             base64.b64encode(message),
                             base64.b64encode(signer.sign(message)))

    def is_valid(self):
        return rfc3339.now() < self.expiry

    @staticmethod
    def from_signed_str(self, signed_str):
        (id_enc, msg_enc, sig_enc) = signed_str.split()
        msg = base64.b64decode(msg_enc)
        identity = Identity(base64.b64decode(id_enc))
        try:
            identity.verify(msg, base64.b64decode(sig_enc))
        except:
            return None
        expiry = rfc3339.parse_datetime(msg.decode('utf-8'))
        token = Token(identity, expiry=expiry)
        return token if token.is_valid() else None

class Identity(object):
    def __init__(self, public_key):
        self.public_key = public_key ## bytes

    def verify(self, msgbytes, sigbytes):
        raise NotImplementedError()

class Signer(object):
    def __init__(self, secret_key):
        self.secret_key = secret_key ## bytes

    def sign(self, msgbytes):
        raise NotImplementedError()
