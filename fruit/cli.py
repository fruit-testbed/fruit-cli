#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import argparse
import sys
import os
import stat
import yaml
import subprocess
import json
import re
import yaml
import io
import getpass
import pkg_resources

VERSION = repr(pkg_resources.require('fruit-cli')[0])

import fruit.api as fa
import fruit.auth as auth
import fruit.auth.ssh_agent as ssh_agent
import fruit.auth.ssh_key as ssh_key
import fruit.auth.signify_key as signify_key

FRUIT_CLI_CONFIG_VAR = 'FRUIT_CLI_CONFIG'
FRUIT_API_SERVER_VAR = 'FRUIT_API_SERVER'
DEFAULT_IDENTITY = 'default'


def _get_passphrase(source):
    return getpass.getpass('Enter passphrase to unlock %s: ' % (source,))


class Config:
    def __init__(self):
        self.server = os.environ.get(FRUIT_API_SERVER_VAR, fa.DEFAULT_SERVER)
        self.public_key = None
        self.secret_key = None
        self.email = None
        self.identities = None
        self.identityName = None
        self.default_identity = DEFAULT_IDENTITY
        self.apiClass = fa.FruitUserApi
        self._signer = None
        self._filename = None

    def load(self, filename):
        self._filename = filename
        if os.path.exists(filename):
            with open(filename) as f:
                blob = yaml.safe_load(f) or {}
        else:
            blob = {}

        self.default_identity = blob.get('default_identity', DEFAULT_IDENTITY)
        self.identities = blob.get('identities', None)

    def _load_identity(self, blob):
        self.server = blob.get('server', os.environ.get(FRUIT_API_SERVER_VAR, fa.DEFAULT_SERVER))
        self.public_key = blob.get('public-key', None)
        if self.public_key is not None:
            self.public_key = auth._unb64(self.public_key)
        self.secret_key_blob = blob.get('secret-key', None)
        self.secret_key_path = blob.get('secret-key-file', None)
        self.email = blob.get('email', None)
        self._signer = None

    def load_identity(self, newIdentity):
        self.identityName = newIdentity
        self._load_identity((self.identities or {}).get(self.identityName, {}))

    def _store_identity(self, blob):
        if self.identities is None:
            self.identities = {}
        if blob is None:
            if self.identityName in self.identities:
                del self.identities[self.identityName]
        else:
            self.identities[self.identityName] = blob
        if not self.identities:
            self.identities = None

    def store_identity(self):
        idblob = {}
        if self.email: idblob['email'] = self.email
        if self.public_key: idblob['public-key'] = auth._b64(self.public_key)
        if self.secret_key_blob: idblob['secret-key'] = self.secret_key_blob
        if self.secret_key_path: idblob['secret-key-file'] = self.secret_key_path
        if self.server != fa.DEFAULT_SERVER: idblob['server'] = self.server
        self._store_identity(idblob)

    def select_api(self, apiClass):
        self.apiClass = apiClass

    def to_json(self):
        blob = {}
        if self.default_identity != DEFAULT_IDENTITY:
            blob['default_identity'] = self.default_identity
        if self.identities:
            blob['identities'] = self.identities
        return blob

    def dump(self, filename):
        with open(filename, 'wt') as f:
            yaml.safe_dump(self.to_json(), stream=f, default_flow_style=False)
        os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)

    def __signer(self):
        blob = self.secret_key_blob
        source = 'secret key'
        if blob is None:
            if self.secret_key_path is None:
                raise fa.FruitApiError(
                    'No secret key is available for identity %r in config file %s' % (
                        self.identityName,
                        self._filename))
            with open(os.path.expanduser(self.secret_key_path), 'rt') as fh:
                blob = fh.read()
                source = 'secret key from file %r' % (self.secret_key_path,)

        agent = ssh_agent.Agent()
        s = agent.signer_for_identity(self.public_key)
        if s is not None:
            return s

        try:
            return auth.LocalSigner(auth._unb64(blob))
        except:
            pass

        sk = None
        try:
            sk = ssh_key.SshPrivateKey(contents=blob)
        except ssh_key.SyntaxError:
            try:
                sk = signify_key.SignifyPrivateKey(contents=blob)
            except signify_key.SyntaxError:
                pass

        if sk is None:
            raise fa.FruitApiError('Cannot open %s' % (source,))

        try:
            if sk.password_needed():
                sk.unprotect(_get_passphrase(source))
            else:
                sk.unprotect(None)
        except auth.BadPassword:
            raise fa.FruitApiError('Bad passphrase when opening %s' % (source,))

        return sk.signer_for_identity(sk.public_key)

    def signer(self):
        if self._signer is None:
            self._signer = self.__signer()
            if self.public_key is None:
                self.public_key = self._signer.identity
                self.store_identity()
                if self._filename:
                    self.dump(self._filename)
            elif self.public_key != self._signer.identity:
                raise fa.FruitApiError('Mismatch between public key and secret key')
        return self._signer

    def __enter__(self):
        return self.apiClass(signer=self.signer(), server=self.server)

    def __exit__(self, type, exn, tb):
        pass

    def print_pretty_summary(self, fh, exn):
        if isinstance(exn, fa.FruitApiErrorResponse):
            fh.write('-' * 75 + '\n' +
                     'ERROR: %s %s\n' % (exn.response.status_code, exn.response.reason))
            try:
                blob = exn.response.json()
                title = blob.get('title', None)
                detail = blob.get('detail', None)
                if title:
                    fh.write('       %s\n' % (title,))
                if detail:
                    fh.write('       %s\n' % (detail,))
                if os.environ.get('FRUIT_API_DEBUG', ''):
                    import json
                    fh.write(json.dumps(blob, indent=2))
            except:
                pass
            fh.write('-' * 75 + '\n')
        else:
            fh.write('ERROR: %s\n' % (str(exn),))


def config_filename():
    return \
        os.environ.get(FRUIT_CLI_CONFIG_VAR, None) or \
        os.path.join(os.path.expanduser("~"), ".fruit-cli")


def register(config, args):
    if args.email:
        if config.email is None:
            config.email = args.email
        if config.email != args.email:
            raise fa.FruitApiError('Configuration file already contains a different email address')

    if args.secret_key or args.secret_key_file:
        config.secret_key_blob = args.secret_key or None
        path = args.secret_key_file
        if path:
            if path[:1] != '~':
                path = os.path.abspath(path)
            config.secret_key_path = path
        else:
            config.secret_key_path = None
    else:
        # Register with existing configured secret key!
        pass

    if config.email is None:
        raise fa.FruitApiError('You must supply an email address for account registration.')
    if config.secret_key_blob is None and config.secret_key_path is None:
        raise fa.FruitApiError('You must supply a secret key for account registration.')

    with config as api:
        result = api.register(config.email)
        if result.get('created', False):
            print('A verification email has been sent to %s.' % (config.email,))
            print('Please check your mailbox and follow the instructions.')
        else:
            print('The provided secret key is authorized for this account.')
        config.store_identity()
        config.dump(args.config_filename)


def _pp_yaml(args, blob):
    if args.json:
        json.dump(blob, sys.stdout, indent=2)
        sys.stdout.write('\n')
    else:
        yaml.safe_dump(blob, stream=sys.stdout, indent=2, default_flow_style=False)


def print_config(config, args):
    _pp_yaml(args, config.to_json())


def user_account_info(config, args):
    with config as api:
        _pp_yaml(args, api.account_info(config.email))


def print_public_key(config, args):
    config.signer() ## load the key
    print(auth._b64(config.public_key))


def print_fresh_token(config, args):
    print(auth.make_authenticated_identity(config.signer().identity, config.signer()))


def delete_account(config, args):
    # Ugh, python3 renamed python2's `raw_input` to `input`, clashing
    # thereby with python2's `input`, which does something similar but
    # hideously misguided. Here we ask for `raw_input` if it's present
    # (i.e. python2), falling back to whatever `input` is bound to
    # otherwise.
    try:
        read_line_with_prompt = raw_input
    except NameError:
        read_line_with_prompt = input

    print()
    print('YOU ARE ABOUT TO DELETE YOUR FRμIT ACCOUNT.')
    print()
    print('This will destroy')
    print(' -- all your configuration data')
    print(' -- all your monitoring data')
    print(' -- all your node records')
    print(' -- all your uploaded SSH public keys')
    print()
    print('THIS IS PERMANENT. THERE IS NO WAY TO UNDO THIS.')
    print()
    entered_email = read_line_with_prompt("Type your account's email address to confirm deletion: ")
    if entered_email != config.email:
        print("Email address does not match.")
        sys.exit(1)

    print()
    if read_line_with_prompt("Last chance! Enter 'YES' to delete your account: ") != 'YES':
        print("Cancelling.")
        sys.exit(1)
    with config as api:
        api.delete_account(config.email)
        print()
        print("Account deleted.")
        config.email = None
        config.public_key = None
        config.secret_key_blob = None
        config.secret_key_path = None
        config.store_identity()
        config.dump(args.config_filename)


def _parse_filter(args):
    if args.filter is None:
        return None
    raw_filter = args.filter
    for triple in raw_filter:
        (_jsonpath, operator, _expectedvalue) = triple
        if operator not in ['=', '<', '>', 'glob']:
            raise fa.FruitApiError('Invalid filter clause operator: %r' % (operator,))
    def decode_json(p,v):
        try:
            return json.loads(v)
        except:
            raise fa.FruitApiError(
                'Invalid filter clause JSON comparison value %r for path %r' % (v, p))
    return [(p,o,v if o == 'glob' else decode_json(p,v)) for (p,o,v) in raw_filter]


def list_nodes(config, args):
    with config as api:
        _pp_yaml(args, api.list_nodes(filter=_parse_filter(args)))


def monitor(config, args):
    ## Previously, this subcommand supported a query language for
    ## extracting portions of the input. Instead, users could try
    ## tools like `jq` https://stedolan.github.io/jq/.
    with config as api:
        _pp_yaml(args, api.get_monitoring_data(filter=_parse_filter(args), node_id=args.node))


def reset_node(config, args):
    with config as api:
        api.delete_node(args.node)


def list_filter_paths(config, args):
    with config as api:
        _pp_yaml(args, api.list_filter_paths())


def run_container(config, args):
    with config as api:
        spec = fa.ContainerSpec(args.name,
                                args.image,
                                command=args.command,
                                port=args.publish or [],
                                volume=args.volume or [],
                                kernel_module=args.kernel_module or [],
                                device_tree=args.device_tree or [],
                                device=args.device or [])
        _pp_yaml(args, api.run_container(spec, filter=_parse_filter(args), node_id=args.node))


def list_container(config, args):
    with config as api:
        node_map = api.list_containers(filter=_parse_filter(args), node_id=args.node)

        # Modify `node_map` to add information on which nodes are
        # successfully running each container.
        all_data = api.get_monitoring_data(filter=_parse_filter(args), node_id=args.node)
        for (node_id, data) in all_data.items():
            if node_id in node_map:
                stub = node_map[node_id]
                if not isinstance(data, dict): continue
                docker = data.get('docker', {})
                if not isinstance(docker, dict): continue

                for name in stub:
                    stub[name]['state'] = 'absent'

                containers = docker.get('containers', [])
                if isinstance(containers, list):
                    for container in containers:
                        for name in container["Names"]: ## !! from the node itself
                            name, ext = os.path.splitext(name.lstrip('/'))
                            if ext == '.fruit':
                                if name in stub:
                                    stub[name]['state'] = container["State"] # !!
                                    stub[name]['status'] = container["Status"] # !!
                                break

        _pp_yaml(args, node_map)


def rm_container(config, args):
    with config as api:
        _pp_yaml(args, api.delete_container(args.name, filter=_parse_filter(args), node_id=args.node))


def list_ssh_keys(config, args):
    with config as api:
        ## TODO: split out retrieval of user keys from node keys entirely
        if args.ssh:
            keys = api.list_ssh_keys(filter=_parse_filter(args), node_id=args.node)
            for (category, keymap) in keys.items():
                print('#' + '-' * 71)
                print('# %s' % (category,))
                for (name, keys) in keymap.items():
                    print('# - %s' % (name,))
                    for k in keys:
                        print(fa.format_ssh_key(k))
        else:
            keys = api.list_ssh_keys(decode_json=False, filter=_parse_filter(args), node_id=args.node)
            _pp_yaml(args, keys)


def _collect_ssh_keys(args):
    keyfile = fa.SshKeyFile()
    for literal_key in args.key or []:
        keyfile.load(io.StringIO(literal_key))
    for filename in args.keyfile or []:
        try:
            with open(filename, 'rb') as fh:
                contents = fh.read().decode('utf-8')
        except:
            raise fa.FruitApiError('Cannot read keyfile %s', (filename,))
        else:
            keyfile.load(io.StringIO(contents), filename=filename)
    return keyfile.keys

def add_ssh_key(config, args):
    with config as api:
        keys = _collect_ssh_keys(args)
        for key in keys:
            ## TODO: make add_ssh_key actually send an array of keys to process!
            api.add_ssh_key(key, filter=_parse_filter(args), node_id=args.node)


def delete_ssh_key(config, args):
    with config as api:
        keys = _collect_ssh_keys(args)
        for key in keys:
            ## TODO: make delete_ssh_key actually send an array of keys to process!
            api.delete_ssh_key(key, filter=_parse_filter(args), node_id=args.node)


def admin_list_users(config, args):
    config.select_api(fa.FruitAdminApi)
    with config as api:
        _pp_yaml(args, api.list_users())


def admin_user_info_by_email(config, args):
    config.select_api(fa.FruitAdminApi)
    with config as api:
        _pp_yaml(args, api.user_info_by_email(args.email))


def admin_delete_account(config, args):
    config.select_api(fa.FruitAdminApi)
    with config as api:
        _pp_yaml(args, api.delete_account(args.email))


def admin_list_nodes(config, args):
    config.select_api(fa.FruitAdminApi)
    with config as api:
        _pp_yaml(args, api.list_nodes(filter=_parse_filter(args)))


def admin_monitor(config, args):
    config.select_api(fa.FruitAdminApi)
    with config as api:
        _pp_yaml(args, api.get_monitoring_data(filter=_parse_filter(args), node_id=args.node))


def admin_reset_node(config, args):
    config.select_api(fa.FruitAdminApi)
    with config as api:
        api.delete_node(args.node)


def _add_help_to(p, sp):
    h = sp.add_parser('help', help='Print help')
    h.set_defaults(handler=lambda config, args: p.print_help())

def _add_filter_argument(p):
    p.add_argument('--filter', metavar='STR', nargs=3, action='append',
                   help='Restrict operation by filtering nodes')


def _add_node_filter_arguments(p):
    g = p.add_argument_group('Node selection')
    _add_filter_argument(g)
    g.add_argument('--node', metavar='NODEID', type=str, default=None,
                   help='Restrict operation to the given node identifier key')
    return g


def _add_ssh_key_arguments(p):
    g = p.add_argument_group('Key specification')
    g.add_argument('--key', metavar='SSHPUBLICKEY', type=str, action='append',
                   help='Specify a literal SSH public key')
    g.add_argument('--keyfile', metavar='FILENAME', type=str, action='append',
                   help='Specify a path to a file containing SSH public keys')
    return g


def main(argv=sys.argv):
    app_name = os.path.basename(argv[0])
    argv = argv[1:]

    synopsis='''Interface to the FRμIT management server API. Your configuration
    file is %(config_file)s. Override its location with the
    %(config_file_var)s environment variable or the --config
    command-line option.''' % {
        'config_file': config_filename(),
        'config_file_var': FRUIT_CLI_CONFIG_VAR,
    }

    parser = argparse.ArgumentParser(prog=app_name,
                                     description=synopsis)
    parser.add_argument('--config', '-c', type=str, metavar='FILENAME',
                        dest='config_filename',
                        default=config_filename(),
                        help='Supply an alternate configuration file')
    parser.add_argument('--json', action='store_true',
                        default=False,
                        help='Produce output in JSON instead of YAML')
    parser.add_argument('--identity', type=str,
                        help='Select an alternate identity to use when authenticating with the server')
    parser.add_argument('--version', action='version', version=VERSION)
    parser.set_defaults(handler=lambda config, args: parser.print_help())

    sp = parser.add_subparsers()

    FILTER_HELP = ''' The --filter PATH OP VALUE command may be supplied multiple times.
    Each PATH is a JSON-pointer path. OP may be any of "=", "<", ">"
    or "glob". VALUE must be a string representation of a JSON value
    whenever OP is not "glob", or a shell-glob-style pattern when OP
    is "glob". Use `fruit-cli node filter-paths` to list the PATHs
    currently in the database and available to you.'''
    NODE_HELP = ''' If --node is supplied, includes only the node with the given
    identifier key (or nothing at all, if that node's attributes do
    not match selected `--filter`s).'''

    _add_help_to(parser, sp)

    #------------------------------------------------------------------------

    p = sp.add_parser('account', help='Account management')
    account_p = p
    p.set_defaults(handler=lambda config, args: account_p.print_help())
    ssp = p.add_subparsers()
    _add_help_to(p, ssp)

    p = ssp.add_parser('register', help='Register a new account',
                       description='''Interactive registration of a new
                       account. You must have access to the email
                       address supplied. The secret key you specify
                       will be used to authenticate you to the
                       management server. Registration is idempotent.
                       If omitted, a previously-configured email address
                       and/or secret key will be used.
                       ''')
    g = p.add_argument_group('Specifying a secret key to authenticate with')
    g = g.add_mutually_exclusive_group()
    g.add_argument('--secret-key', metavar='SECRETKEY', type=str,
                   help='Specify a literal SSH, signify, or base64-encoded Ed25519 secret key')
    g.add_argument('--secret-key-file', '-f', metavar='SECRETKEYPATH', type=str,
                   help='Specify a path to a SSH, signify, or base64-encoded Ed25519 secret key')
    p.add_argument('email', type=str, nargs='?',
                   help='Email address of the account to register')
    p.set_defaults(handler=register)

    p = ssp.add_parser('config', help='Print current configuration settings')
    p.set_defaults(handler=print_config)

    p = ssp.add_parser('info', help='Retrieve server-side account information')
    p.set_defaults(handler=user_account_info)

    p = ssp.add_parser('public-key', help='Print account public key')
    p.set_defaults(handler=print_public_key)

    p = ssp.add_parser('token', help='Print a fresh authentication token')
    p.set_defaults(handler=print_fresh_token)

    p = ssp.add_parser('delete', help='Delete account',
                       description='''Permanently deletes your
                       account, your nodes, and all your configuration
                       and settings.''')
    p.set_defaults(handler=delete_account)

    #------------------------------------------------------------------------

    p = sp.add_parser('node', help='Node management')
    node_p = p
    p.set_defaults(handler=lambda config, args: node_p.print_help())
    ssp = p.add_subparsers()
    _add_help_to(p, ssp)

    p = ssp.add_parser('list', help='List (all or some) nodes',
                      description='''Prints a YAML summary of accessible nodes to stdout.''' + FILTER_HELP)
    _add_filter_argument(p)
    p.set_defaults(handler=list_nodes)

    p = ssp.add_parser('monitor', help='Retrieve monitoring data from nodes',
                       description='''Prints a YAML summary of monitoring data from accessible nodes to
                       stdout.''' + FILTER_HELP + NODE_HELP)
    _add_node_filter_arguments(p)
    p.set_defaults(handler=monitor)

    p = ssp.add_parser('reset', help='Deregister and reset a specific node',
                       description='''Deletes all records associated with a specific node.''')
    p.add_argument('node', type=str, help="Specify the ID of the node to reset")
    p.set_defaults(handler=reset_node)

    p = ssp.add_parser('filter-paths', help='List currently-active filter JSON-pointer paths',
                       description='''For use in constructing `node list` and `monitor` filter clauses.''')
    p.set_defaults(handler=list_filter_paths)

    #------------------------------------------------------------------------

    p = sp.add_parser('container', help='Container management')
    _add_node_filter_arguments(p)
    container_p = p
    p.set_defaults(handler=lambda config, args: container_p.print_help())
    ssp = p.add_subparsers()
    _add_help_to(p, ssp)

    p = ssp.add_parser('run', help='Deploy containers to nodes')
    p.add_argument('--publish', '-p', metavar='[IP:][HOSTPORT:]CONTAINERPORT',
                   type=str, action='append',
                   help='Publish container port(s) to the host')
    p.add_argument('--volume', '-v', metavar='VOLUMESPEC', type=str, action='append',
                   help='Bind host volume(s) to the container')
    p.add_argument('--kernel-module', metavar='MODULENAME', type=str, action='append',
                   help='Kernel module to modprobe before starting container')
    p.add_argument('--device-tree', metavar='FILENAME', type=str, action='append',
                   help='Device-tree overlays to install before starting container')
    p.add_argument('--device', metavar='FILENAME', type=str, action='append',
                   help='Host device(s) to expose to the container')
    p.add_argument('--name', metavar='CONTAINERNAME', type=str, required=True,
                   help='Name for the container')
    p.add_argument('image', type=str,
                   help='Docker image for the container')
    p.add_argument('command', type=str, nargs=argparse.REMAINDER,
                   help='Command to run within container')
    p.set_defaults(handler=run_container)

    p = ssp.add_parser('list', help='List containers on nodes')
    p.set_defaults(handler=list_container)

    p = ssp.add_parser('remove', help='Remove containers from nodes')
    p.add_argument('--name', metavar='CONTAINERNAME', type=str, required=True,
                   help='Name of the container to remove')
    p.set_defaults(handler=rm_container)

    #------------------------------------------------------------------------

    p = sp.add_parser('key', help='SSH key management')
    ssh_p = p
    p.set_defaults(handler=lambda config, args: ssh_p.print_help())
    ssp = p.add_subparsers()
    _add_help_to(p, ssp)

    p = ssp.add_parser('add', help='Grant SSH key access to nodes')
    _add_node_filter_arguments(p)
    _add_ssh_key_arguments(p)
    p.set_defaults(handler=add_ssh_key)

    p = ssp.add_parser('list', help='List SSH keys with access to nodes')
    _add_node_filter_arguments(p)
    g = p.add_mutually_exclusive_group()
    g.add_argument('--ssh', action='store_true',
                   help='Produce output in SSH public-key/authorized_keys format')
    p.set_defaults(handler=list_ssh_keys)

    p = ssp.add_parser('remove', help='Delete SSH keys having access to nodes')
    _add_node_filter_arguments(p)
    g = _add_ssh_key_arguments(p)
    p.set_defaults(handler=delete_ssh_key)

    #------------------------------------------------------------------------

    p = sp.add_parser('admin', help='Actions for installation administrators')
    admin_p = p
    p.set_defaults(handler=lambda config, args: admin_p.print_help())
    ssp = p.add_subparsers()
    _add_help_to(p, ssp)

    p = ssp.add_parser('account', help='Installation-wide account management')
    admin_account_p = p
    p.set_defaults(handler=lambda config, args: admin_account_p.print_help())
    sssp = p.add_subparsers()
    _add_help_to(p, sssp)

    p = sssp.add_parser('list', help='List all user accounts')
    p.set_defaults(handler=admin_list_users)

    p = sssp.add_parser('info', help='Retrieve information on a specific user account')
    p.add_argument('email', type=str,
                   help='Specify the email address of the user account to retrieve')
    p.set_defaults(handler=admin_user_info_by_email)

    p = sssp.add_parser('delete', help='Delete a user account',
                        description='''Permanently deletes a specified
                        account, its nodes, and all its configuration
                        and settings.''')
    p.add_argument('email', type=str,
                   help='Specify the email address of the user account to delete')
    p.set_defaults(handler=admin_delete_account)

    p = ssp.add_parser('node', help='Installation-wide node management')
    admin_node_p = p
    p.set_defaults(handler=lambda config, args: admin_node_p.print_help())
    sssp = p.add_subparsers()
    _add_help_to(p, sssp)

    p = sssp.add_parser('list', help='List (all or some) nodes',
                        description='''Prints a YAML summary of nodes to stdout.''' + FILTER_HELP)
    _add_filter_argument(p)
    p.set_defaults(handler=admin_list_nodes)

    p = sssp.add_parser('monitor', help='Installation-wide monitoring data',
                        description='''Prints a YAML summary of monitoring data from nodes to
                        stdout.''' + FILTER_HELP + NODE_HELP)
    _add_node_filter_arguments(p)
    p.set_defaults(handler=admin_monitor)

    p = sssp.add_parser('reset', help='Deregister and reset a specific node',
                        description='''Deletes all records associated with a specific node.''')
    p.add_argument('node', type=str, help="Specify the ID of the node to reset")
    p.set_defaults(handler=admin_reset_node)

    #------------------------------------------------------------------------

    args = parser.parse_args(argv)

    config = Config()
    config.load(args.config_filename)

    # print()
    # for a in config.__dict__.items():
    #     print(a)
    # print()
    # for a in args.__dict__.items():
    #     print(a)

    try:
        config.load_identity(args.identity or config.default_identity)
        args.handler(config, args)
    except fa.FruitApiError as exn:
        config.print_pretty_summary(sys.stderr, exn)
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv)
