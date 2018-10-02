# Simple Canonical S-Expression codec.
# https://people.csail.mit.edu/rivest/Sexp.txt

import base64
import zlib

try:
    unicode
except NameError:
    unicode = str

def decode(bs):
    (v,tail) = decodestream(bs)
    if tail != b'':
        raise ValueError('Trailing junk in canonical S-expression')
    return v

def decodestream(bs):
    if bs[0:1] == b'(':
        bs = bs[1:]
        acc = []
        while bs[0:1] != b')':
            (v,bs) = decodestream(bs)
            acc.append(v)
        bs = bs[1:]
        return (acc,bs)
    else:
        return _decodestr(bs)

def _decodestr(bs):
    count = 0
    while bs[count:count+1].isdigit():
        count = count + 1
    if bs[count:count+1] != b':':
        raise ValueError("Invalid canonical S-expression")
    strlen = int(bs[0:count])
    bs = bs[count+1:]
    return (bs[:strlen], bs[strlen:])

def encode(v):
    if isinstance(v, bytes):
        return str(len(v)).encode('us-ascii') + b':' + v
    elif isinstance(v, list) or isinstance(v, tuple):
        return b'(' + b''.join((encode(w) for w in v)) + b')'
    else:
        raise ValueError("Unsupported value encoding canonical S-expression")

def armor(sexp, compress=True):
    bs = encode(sexp)
    if compress: bs = b'gz' + zlib.compress(bs)
    bs = base64.b64encode(bs)
    return bs.replace(b'=', b'')

def unarmor(bs):
    bs = bs + b'=' * (-len(bs) % 4)  ## re-pad
    bs = base64.b64decode(bs)
    if bs[0:2] == b'gz': bs = zlib.decompress(bs[2:])
    return decode(bs)

class Registry(object):
    def __init__(self):
        self._labelmap = {}

    def record(self, label, baseclass):
        import inspect
        def add_decoder(fun):
            if isinstance(fun, staticmethod):
                fun = fun.__func__
            arity = len(inspect.getargspec(fun).args)
            self._labelmap[(label, baseclass, arity)] = fun
            return fun
        return add_decoder

    def deserialize(self, sexp, baseclass):
        if not isinstance(sexp, list) or len(sexp) == 0:
            raise ValueError('Cannot deserialize %r' % (sexp,))
        key = (sexp[0], baseclass, len(sexp) - 1)
        if key not in self._labelmap:
            raise ValueError('Cannot deserialize %r' % (sexp,))
        fun = self._labelmap[key]
        v = fun(*sexp[1:])
        if not isinstance(v, baseclass):
            raise ValueError('Expected %s; got %r' % (baseclass, v))
        return v
