# -*- coding: utf-8 -*-

import sys
import base64
import datetime
import fruit.auth.pure_eddsa
import fruit.auth.rfc3339

class NotAuthorized(RuntimeError): pass

def _unb64(bs):
    if not isinstance(bs, bytes):
        bs = bs.encode('us-ascii')
    bs = bs + b'=' * (-len(bs) % 4)  ## re-pad
    return base64.b64decode(bs)

def authenticated_identity(header_string,
                           backwards=datetime.timedelta(minutes=10),
                           forwards=datetime.timedelta(minutes=5)):
    pieces = header_string.strip().split(';')
    if len(pieces) != 4 or pieces[0] != '1':
        raise NotAuthorized('Bad authentication header format version')
    (_version, public_key_b64, timestamp_b64, signature_b64) = pieces
    try:
        identity = _unb64(public_key_b64)
        timestamp = _unb64(timestamp_b64)
        signature = _unb64(signature_b64)
    except TypeError:
        raise NotAuthorized('Invalid base64')
    try:
        fruit.auth.pure_eddsa.verify(identity, signature, timestamp)
    except:
        raise NotAuthorized('Bad signature')
    now = fruit.auth.rfc3339.now()
    timestamp = fruit.auth.rfc3339.parse_datetime(timestamp.decode('us-ascii'))
    if timestamp < now - backwards:
        raise NotAuthorized('Expired')
    if timestamp >= now + forwards:
        raise NotAuthorized('Too far in future')
    return identity

if __name__ == '__main__':
    token = sys.stdin.readline()
    try:
        print(base64.b64encode(authenticated_identity(token)).rstrip(b'=').decode('us-ascii'))
    except:
        sys.exit(1)
    sys.exit(0)
