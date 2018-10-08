# -*- coding: utf-8 -*-
# Read OpenBSD Signify private keys
# https://www.openbsd.org/papers/bsdcan-signify.html
# https://man.openbsd.org/signify

import sys
import base64
import hashlib
# import bcrypt -- only imports when actually needed

import fruit.auth

from .bin_io import *

ID_BYTES = 8
PK_BYTES = 32
SK_BYTES = 64
SIG_BYTES = 64
SK_SALT_BYTES = 16
SK_CHECKSUM_BYTES = 8

if sys.version_info[0] == 2:
    def bytes_xor(a, b):
        c = b''
        for i in range(len(a)):
            c = c + chr(ord(a[i]) ^ ord(b[i]))
        return c
else:
    def bytes_xor(a, b):
        c = b''
        for i in range(len(a)):
            c = c + bytes((a[i] ^ b[i],))
        return c

class SignifyPrivateKey(object):
    def __init__(self, filename=None, contents=None):
        if contents is None:
            with open(filename, 'rt') as f:
                contents = f.read()

        lines = contents.rstrip().split('\n')
        if not lines[0].startswith("untrusted comment:"): raise SyntaxError()
        lines = lines[1:]
        blob = base64.b64decode('\n'.join(lines))

        blob = parse_expected(b'EdBK', blob) ## ed25519, bcrypt-kdf
        (self.kdfrounds, blob) = parse_int(blob)
        (self.salt, blob) = parse_chunk(SK_SALT_BYTES, blob)
        (self.checksum, blob) = parse_chunk(SK_CHECKSUM_BYTES, blob)
        (self.keyid, blob) = parse_chunk(ID_BYTES, blob)
        (self.enckey, blob) = parse_chunk(SK_BYTES, blob)
        parse_end(blob)
        self.public_key = None
        self.secret_key = None

    def password_needed(self):
        return True

    def unprotect(self, password):
        if self.secret_key is None:
            import bcrypt
            mask = bcrypt.kdf(password, self.salt, len(self.enckey), self.kdfrounds)
            result = bytes_xor(self.enckey, mask)
            if self.checksum != hashlib.sha512(result).digest()[:len(self.checksum)]:
                raise BadPassword()
            self.secret_key = result
            self.public_key = result[-PK_BYTES:]

    def signer_for_identity(self, identity):
        if identity == self.public_key:
            return fruit.auth.LocalSigner(self.secret_key[:32])
        else:
            return None
