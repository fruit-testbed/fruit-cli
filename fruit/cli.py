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

import fruit.api as fa

FRUIT_CLI_CONFIG_VAR = 'FRUIT_CLI_CONFIG'
FRUIT_API_SERVER_VAR = 'FRUIT_API_SERVER'


class Config:
    def __init__(self):
        self.server = os.environ.get(FRUIT_API_SERVER_VAR, fa.DEFAULT_SERVER)
        self.api_key = None
        self.email = None

    def load(self, filename):
        if os.path.exists(filename):
            with open(filename) as f:
                blob = yaml.safe_load(f) or {}
        else:
            blob = {}
        if 'server' in blob: self.server = blob['server']
        self.api_key = blob.get('api-key', None)
        self.email = blob.get('email', None)

    def to_json(self):
        blob = {}
        if self.server != fa.DEFAULT_SERVER: blob['server'] = self.server
        if self.api_key: blob['api-key'] = self.api_key
        if self.email: blob['email'] = self.email
        return blob

    def dump(self, filename):
        with open(filename, 'wt') as f:
            yaml.safe_dump(self.to_json(), stream=f, default_flow_style=False)
        os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)

    def __enter__(self):
        return fa.FruitApi(self.server, self.email, self.api_key)

    def __exit__(self, type, exn, tb):
        if exn is not None:
            if isinstance(exn, fa.FruitApiError):
                self.print_pretty_summary(sys.stderr, exn)
                sys.exit(1)
            else:
                raise

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
    with config as api:
        api.register(args.email)

        print('A verification email has been sent to %s.' % (args.email,))
        print('Please check your mailbox and follow the instructions to get the API-Key.')
        print()

        while True:
            try:
                api_key = input("Please enter your API-Key: ")
            except EOFError:
                sys.exit(1)

            api_key = api_key.strip()
            if not api_key:
                continue

            config.email = args.email
            config.api_key = api_key
            config.dump(args.config_filename)
            break

        print()
        print('Your API-Key has been saved to your config file:', args.config_filename)
        print('You can now manage your nodes.')


def resend_api_key(config, args):
    with config as api:
        api.resend_api_key(args.email)
        print('An email with API key has been sent your mailbox:', args.email)


def _pp_yaml(args, blob):
    if args.json:
        json.dump(blob, sys.stdout, indent=2)
        sys.stdout.write('\n')
    else:
        yaml.safe_dump(blob, stream=sys.stdout, indent=2, default_flow_style=False)


def print_config(config, args):
    _pp_yaml(args, config.to_json())


def delete_account(config, args):
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
    entered_email = input("Type your account's email address to confirm deletion: ")
    if entered_email != config.email:
        print("Email address does not match.")
        sys.exit(1)

    print()
    if input("Last chance! Enter 'YES' to delete your account: ") != 'YES':
        print("Cancelling.")
        sys.exit(1)
    with config as api:
        api.delete_account()
        print()
        print("Account deleted.")


def list_nodes(config, args):
    with config as api:
        _pp_yaml(args, api.list_nodes(group_name=args.group))


def monitor(config, args):
    ## Previously, this subcommand supported a query language for
    ## extracting portions of the input. Instead, users could try
    ## tools like `jq` https://stedolan.github.io/jq/.
    with config as api:
        _pp_yaml(args, api.get_monitoring_data(group_name=args.group, node_id=args.node))


def reset_node(config, args):
    with config as api:
        api.delete_node(args.node)


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
        _pp_yaml(args, api.run_container(spec, group_name=args.group, node_id=args.node))


def list_container(config, args):
    with config as api:
        node_map = api.list_containers(group_name=args.group, node_id=args.node)

        # Modify `node_map` to add information on which nodes are
        # successfully running each container.
        all_data = api.get_monitoring_data(group_name=args.group, node_id=args.node)
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
        _pp_yaml(args, api.delete_container(args.name, group_name=args.group, node_id=args.node))


def list_ssh_keys(config, args):
    with config as api:
        ## TODO: split out retrieval of user keys from node keys entirely
        if args.ssh:
            keys = api.list_ssh_keys(group_name=args.group, node_id=args.node)
            for (category, keymap) in keys.items():
                print('#' + '-' * 71)
                print('# %s' % (category,))
                for (name, keys) in keymap.items():
                    print('# - %s' % (name,))
                    for k in keys:
                        print(fa.format_ssh_key(k))
        else:
            keys = api.list_ssh_keys(decode_json=False, group_name=args.group, node_id=args.node)
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
            api.add_ssh_key(key, group_name=args.group, node_id=args.node)


def delete_ssh_key(config, args):
    with config as api:
        keys = _collect_ssh_keys(args)
        for key in keys:
            ## TODO: make delete_ssh_key actually send an array of keys to process!
            api.delete_ssh_key(key, group_name=args.group, node_id=args.node)


def authorized_keys(config, args):
    with config as api:
        ## TODO: once we move to public-keys, this will have to change
        ## because we won't have the node's private key. Instead, a
        ## new API will be needed for a user to get *exactly* the set
        ## of SSH keys deployed to a particular node. One way to go
        ## about that would be to include global SSH keys in the
        ## list_ssh_keys output, alongside the user and node/group
        ## keys.
        sys.stdout.buffer.write(api.authorized_keys(args.node))


def _add_help_to(p, sp):
    h = sp.add_parser('help', help='Print help')
    h.set_defaults(handler=lambda config, args: p.print_help())

def _add_group_argument(p):
    p.add_argument('--group', metavar='NODEGROUP', type=str, default=None,
                   help='Restrict operation to the named node group')


def _add_node_group_filter_arguments(p):
    g = p.add_argument_group('Node selection')
    _add_group_argument(g)
    g.add_argument('--node', metavar='NODEID', type=str, default=None,
                   help='Restrict operation to the named node')
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
    parser.set_defaults(handler=lambda config, args: parser.print_help())

    sp = parser.add_subparsers()

    GROUP_HELP = ''' If --group is supplied, includes only nodes in the named group.'''
    NODE_HELP = ''' If --node is supplied, includes only the named node (or nothing at
    all, if that node is not in the selected --group).'''

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
                       address supplied.''')
    p.add_argument('email', type=str,
                   help='Email address of the account to register')
    p.set_defaults(handler=register)

    p = ssp.add_parser('resend-api-key', help='Request an email containing the API Key')
    p.add_argument('email', type=str,
                   help='Email address of the account')
    p.set_defaults(handler=resend_api_key)

    p = ssp.add_parser('config', help='Print current configuration settings')
    p.set_defaults(handler=print_config)

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
                      description='''Prints a YAML summary of accessible nodes to stdout.''' + GROUP_HELP)
    _add_group_argument(p)
    p.set_defaults(handler=list_nodes)

    p = ssp.add_parser('monitor', help='Retrieve monitoring data from nodes',
                       description='''Prints a YAML summary of monitoring data from accessible nodes to
                       stdout.''' + GROUP_HELP + NODE_HELP)
    _add_node_group_filter_arguments(p)
    p.set_defaults(handler=monitor)

    p = ssp.add_parser('reset', help='Deregister and reset a specific node',
                       description='''Deletes all records associated with a specific node.''')
    p.add_argument('node', type=str, help="Specify the ID of the node to reset")
    p.set_defaults(handler=reset_node)

    #------------------------------------------------------------------------

    p = sp.add_parser('container', help='Container management')
    _add_node_group_filter_arguments(p)
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
    _add_node_group_filter_arguments(p)
    _add_ssh_key_arguments(p)
    p.set_defaults(handler=add_ssh_key)

    p = ssp.add_parser('list', help='List SSH keys with access to nodes')
    _add_node_group_filter_arguments(p)
    g = p.add_mutually_exclusive_group()
    g.add_argument('--ssh', action='store_true',
                   help='Produce output in SSH public-key/authorized_keys format')
    p.set_defaults(handler=list_ssh_keys)

    p = ssp.add_parser('remove', help='Delete SSH keys having access to nodes')
    _add_node_group_filter_arguments(p)
    g = _add_ssh_key_arguments(p)
    p.set_defaults(handler=delete_ssh_key)

    p = ssp.add_parser('authorized_keys', help='Retrieve the authorized_keys file for a given node')
    p.add_argument('node', type=str,
                   help="Specify which node's authorized_keys file to retrieve by node ID")
    p.set_defaults(handler=authorized_keys)

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

    args.handler(config, args)


if __name__ == "__main__":
    main(sys.argv)
