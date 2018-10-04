# -*- coding: utf-8 -*-
# Read SSH Ed25519 private keys

import base64
import bcrypt

import fruit.auth

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from .bin_io import *

class BadPassword(ValueError):
    '''Invalid passphrase given when unprotecting a key'''
    pass

class SyntaxError(ValueError):
    '''A syntax error parsing an SSH data structure (e.g. key file, network message etc)'''
    pass

class SshPrivateKey(object):
    def __init__(self, filename):
        with open(filename, 'rt') as f:
            lines = f.readlines()

        if lines[0] != "-----BEGIN OPENSSH PRIVATE KEY-----\n": raise SyntaxError()
        if lines[-1] != "-----END OPENSSH PRIVATE KEY-----\n": raise SyntaxError()
        lines = lines[1:-1]
        blob = base64.b64decode(''.join(lines))

        blob = parse_expected(b'openssh-key-v1\0', blob)
        (self.ciphername, blob) = parse_str(blob)
        (self.kdfname, blob) = parse_str(blob)
        (self.kdfoptions, blob) = parse_str(blob)
        (nkeys, blob) = parse_int(blob)
        if nkeys != 1: raise SyntaxError()
        (publickey, blob) = parse_str(blob)
        self.public_key = parse_expected(SSH_PUBLIC_KEY_BLOB_PREFIX, publickey)
        (self.protected_privatekey, blob) = parse_str(blob)
        parse_end(blob)
        self.secret_key = None

    def password_needed(self):
        return self.ciphername != b'none' or self.kdfname != b'none'

    def unprotect(self, password):
        if self.secret_key is None:
            if self.ciphername == b'none' and self.kdfname == b'none':
                blob = self.protected_privatekey
            elif self.ciphername == b'aes256-ctr' and self.kdfname == b'bcrypt':
                (salt, kdfoptions) = parse_str(self.kdfoptions)
                (rounds, kdfoptions) = parse_int(kdfoptions)
                parse_end(kdfoptions)
                key_and_iv = bcrypt.kdf(password, salt, 32+16, rounds)
                c = Cipher(algorithms.AES(key_and_iv[:32]),
                           modes.CTR(key_and_iv[32:]),
                           backend=default_backend())
                d = c.decryptor()
                blob = d.update(self.protected_privatekey) + d.finalize()
            else:
                raise SyntaxError('Unsupported ciphername/kdfname')

            ## Oddly, this only partially lines up with the spec at
            ## https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.key?annotate=1.1
            ##
            ## Specifically, contra spec, after the checkints, we seem to have
            ## the public key again followed by the private key bytes and then
            ## a comment string.
            ##
            ## The code (sshkey.c) does this:
            ##  - retrieve a key type string
            ##  - dispatch on it
            ##  - for ed25519, read a string with the PK, then a string with the SK
            ##  - checks the sizes to ensure they are correct for ed25519
            ##
            ## This is what the PROTOCOL.key documentation says to do. It's
            ## not what actually needs to be done.
            ##
            ## [ (checkint1 :: bits 32) (= checkint1 :: bits 32) ## must be the same
            ##   (keys :: (ssh:repeat 1 (ssh:repeat 2 (ssh:string))))
            ##   (= 'padding-ok :: (ssh:padding)) ]
            ##
            (checkint1, blob) = parse_int(blob)
            (checkint2, blob) = parse_int(blob)
            if checkint1 != checkint2: raise BadPassword()
            (keytype, blob) = parse_str(blob)
            if keytype != b'ssh-ed25519': raise SyntaxError()
            (pkbytes, blob) = parse_str(blob)
            if pkbytes != self.public_key: raise BadPassword()
            (self.secret_key, blob) = parse_str(blob)
            (comment, blob) = parse_str(blob)
            self.comment = comment.decode('utf-8')

    def signer_for_identity(self, identity):
        if identity.public_key == self.public_key:
            return fruit.auth.LocalSigner(self.secret_key[:32])
        else:
            return None
