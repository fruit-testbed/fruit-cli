# -*- coding: utf-8 -*-

import sys
import fruit.auth
import fruit.auth.ssh_key
import fruit.auth.signify_key

if __name__ == '__main__':
    filename = sys.argv[1]
    if hasattr(sys.stdin, 'buffer'):
        password = sys.stdin.buffer.readline().rstrip(b'\n')
    else:
        password = sys.stdin.readline().rstrip(b'\n')

    try:
        sk = fruit.auth.ssh_key.SshPrivateKey(filename)
        sk.unprotect(password)
    except:
        try:
            sk = fruit.auth.signify_key.SignifyPrivateKey(filename)
            sk.unprotect(password)
        except:
            sys.exit(1)
    identity = sk.public_key
    print(fruit.auth.make_authenticated_identity(identity, sk.signer_for_identity(identity)))
    sys.exit(0)
