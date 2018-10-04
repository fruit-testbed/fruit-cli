# -*- coding: utf-8 -*-
# Binary parsing and formatting, plus SSH protocol & structure constants and formats

import struct

class BadPassword(ValueError):
    '''Invalid passphrase given when unprotecting a key'''
    pass

class SyntaxError(ValueError):
    '''A syntax error parsing a data structure (e.g. key file, network message etc)'''
    pass

SSH_PUBLIC_KEY_BLOB_PREFIX = b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 '
SSH_SIGNATURE_BLOB_PREFIX = b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00@'

def parse_chunk(length, bs):
    if len(bs) < length: raise SyntaxError()
    return (bs[:length], bs[length:])

def parse_expected(expected, bs):
    if not bs.startswith(expected): raise SyntaxError()
    return bs[len(expected):]

def parse_int(bs):
    if len(bs) < 4: raise SyntaxError()
    (val,) = struct.unpack('>I', bs[:4])
    return (val, bs[4:])

def parse_byte(bs):
    if len(bs) < 1: raise SyntaxError()
    (val,) = struct.unpack('>B', bs[:1])
    return (val, bs[1:])

def parse_str(bs):
    (length, bs) = parse_int(bs)
    if len(bs) < length: raise SyntaxError()
    return (bs[:length], bs[length:])

def parse_end(bs):
    if bs != b'': raise SyntaxError()

def format_int(i):
    return struct.pack('>I', i)

def format_byte(b):
    return struct.pack('>B', b)

def format_str(bs):
    return format_int(len(bs)) + bs
