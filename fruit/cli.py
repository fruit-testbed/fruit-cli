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

    def dump(self, filename):
        blob = {}
        if self.server != fa.DEFAULT_SERVER: blob['server'] = self.server
        if self.api_key: blob['api-key'] = self.api_key
        if self.email: blob['email'] = self.email
        with open(filename, 'wt') as f:
            yaml.safe_dump(blob, stream=f, default_flow_style=False)
        os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)

    def __enter__(self):
        return fa.FruitApi(self.server, self.email, self.api_key)

    def __exit__(self, type, exn, tb):
        if exn is not None:
            if isinstance(exn, fa.FruitApiError):
                sys.stderr.write('-' * 75 + '\n' +
                                 'ERROR: %s %s\n' % (exn.response.status_code,
                                                     exn.response.reason))
                try:
                    blob = exn.response.json()
                    title = blob.get('title', None)
                    detail = blob.get('detail', None)
                    if title:
                        sys.stderr.write('       %s\n' % (title,))
                    if detail:
                        sys.stderr.write('       %s\n' % (detail,))
                    if os.environ.get('FRUIT_API_DEBUG', ''):
                        import json
                        sys.stderr.write(json.dumps(blob, indent=2))
                except:
                    pass
                sys.stderr.write('-' * 75 + '\n')
                sys.exit(1)
            else:
                raise


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


def list_nodes(config, args):
    with config as api:
        _pp_yaml(args, api.list_nodes(group_name=args.group))


def monitor(config, args):
    ## Previously, this subcommand supported a query language for
    ## extracting portions of the input. Instead, users could try
    ## tools like `jq` https://stedolan.github.io/jq/.
    with config as api:
        _pp_yaml(args, api.get_monitoring_data(group_name=args.group, node_id=args.node))


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
        #
        # TODO: make more robust in traversing the `data` blobs
        all_data = api.get_monitoring_data(group_name=args.group, node_id=args.node)
        for (node_id, data) in all_data.items():
            if node_id in node_map:
                stub = node_map[node_id]
                if isinstance(data, dict) and 'docker' in data and 'containers' in data['docker']:
                    containers = data['docker']['containers']
                    if isinstance(containers, list):
                        for container in containers:
                            for name in container["Names"]: ## !! from the node itself
                                name, ext = os.path.splitext(name.lstrip('/'))
                                if ext == '.fruit':
                                    if name in stub:
                                        stub[name]['state'] = container["State"]
                                        stub[name]['status'] = container["Status"]
                                    break
                    for name in stub:
                        if 'state' not in stub[name]:
                            stub[name]['state'] = 'absent'

        _pp_yaml(args, node_map)


def rm_container(config, args):
    with config as api:
        _pp_yaml(args, api.delete_container(args.name, group_name=args.group, node_id=args.node))


def list_ssh_key(config, args):
    pass
#     parser = argparse.ArgumentParser()
#     parser.add_argument("--node", dest="node", type=str,
#                         help="Remove container from a specific node")
#     parser.add_argument("--name", dest="node_name", type=str,
#                         help="Node's name")
#     args = parser.parse_args()

#     headers = {
#         "X-API-Key": CONFIG["api-key"],
#         "Accept-Encoding": "gzip",
#         }
#     params = {
#         "hostname": args.node_name,
#         "id": args.node,
#         "email": CONFIG["email"],
#         }
#     url = "%s/user/ssh-key" % CONFIG["server"]
#     r = requests.get(url, headers=headers, params=params)
#     if r.status_code == 200:
#         yaml.safe_dump(r.json(), stream=sys.stdout, indent=2,
#                        default_flow_style=False)
#     elif r.status_code == 404:
#         sys.stderr.write("ERROR: Node is not found\n")
#         sys.exit(15)
#     else:
#         sys.stderr.write("ERROR: Listing SSH keys failed (status code: %d)\n"
#                          % r.status_code)
#         sys.exit(10)


def add_ssh_key(config, args):
    pass
#     parser = argparse.ArgumentParser()
#     parser.add_argument("--keyfile", dest="keyfile", type=str,
#                         help="File of public key to be added")
#     parser.add_argument("--key", dest="key", type=str,
#                         help="Public key to be added")
#     parser.add_argument("--node", dest="node", type=str,
#                         help="Remove container from a specific node")
#     parser.add_argument("--name", dest="node_name", type=str,
#                         help="Node's name")
#     args = parser.parse_args()

#     if args.keyfile is None and args.key is None:
#         return
#     if args.key is None and args.keyfile is not None:
#         with open(args.keyfile) as f:
#             args.key = f.read().strip()

#     parts = re.split(r"\s+", args.key)
#     if len(parts) < 2:
#         sys.stderr.write("Invalid key.")
#         sys.exit(1)
#     if parts[0] not in SSH_KEY_TYPES:
#         sys.stderr.write("Invalid key type: " + repr(parts[0]))
#         sys.exit(2)
#     ssh_key = {
#         "type": parts[0],
#         "key": parts[1],
#         "comment": None if len(parts) < 3 else parts[2],
#         }

#     headers = {
#         "Content-Type": "application/json",
#         "X-API-Key": CONFIG["api-key"],
#         "Accept-Encoding": "gzip",
#         }
#     params = {
#         "hostname": args.node_name,
#         "id": args.node,
#         "email": CONFIG["email"],
#         }
#     url = "%s/user/ssh-key" % CONFIG["server"]
#     r = requests.put(url, data=json.dumps(ssh_key), headers=headers,
#                      params=params)
#     if r.status_code == 200:
#         print("SSH Key has been stored. It takes several minutes to be \
# activated.")
#     elif r.status_code == 404:
#         sys.stderr.write("ERROR: Node is not found\n")
#         sys.exit(3)
#     else:
#         sys.stderr.write("ERROR: Failed storing the SSH key (status code: %d)\
# \n" % r.status_code)
#         sys.exit(4)


def rm_ssh_key(config, args):
    pass
#     parser = argparse.ArgumentParser()
#     parser.add_argument("--keyfile", dest="keyfile", type=str,
#                         help="File of public key to be removed")
#     parser.add_argument("--key", dest="key", type=str,
#                         help="Public key to be removed")
#     parser.add_argument("--index", dest="index", type=int,
#                         help="Index of public key")
#     parser.add_argument("--node", dest="node", type=str,
#                         help="Remove container from a specific node")
#     parser.add_argument("--name", dest="node_name", type=str,
#                         help="Node's name")
#     args = parser.parse_args()

#     if args.keyfile is None and args.key is None and args.index is None:
#         return
#     if args.key is None and args.keyfile is not None:
#         with open(args.keyfile) as f:
#             args.key = f.read().strip()

#     ssh_key = {"type": "", "key": "", "index": args.index}
#     if args.key is not None:
#         parts = re.split(r"\s+", args.key)
#         if len(parts) < 2:
#             sys.stderr.write("Invalid key.")
#             sys.exit(1)
#         if parts[0] not in SSH_KEY_TYPES:
#             sys.stderr.write("Invalid key type:", parts[0])
#             sys.exit(2)
#         ssh_key["type"] = parts[0]
#         ssh_key["key"] = parts[1]
#         if len(parts) >= 3:
#             ssh_key["comment"] = parts[2]

#     headers = {
#         "Content-Type": "application/json",
#         "X-API-Key": CONFIG["api-key"],
#         "Accept-Encoding": "gzip",
#         }
#     params = {
#         "hostname": args.node_name,
#         "id": args.node,
#         "email": CONFIG["email"],
#         }
#     url = "%s/user/ssh-key" % CONFIG["server"]
#     r = requests.delete(url, data=json.dumps(ssh_key), headers=headers,
#                         params=params)
#     if r.status_code == 200:
#         print("SSH Key has been deleted.")
#     elif r.status_code == 404:
#         sys.stderr.write("ERROR: Node is not found\n")
#         sys.exit(3)
#     else:
#         sys.stderr.write("ERROR: Failed deleting the SSH key (status code: %d)\
# \n" % r.status_code)
#         sys.exit(4)


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

    p = sp.add_parser('register', help='Register a new account',
                      description='''Interactive registration of a new
                      account. You must have access to the email
                      address supplied.''')
    p.add_argument('email', type=str,
                   help='Email address of the account to register')
    p.set_defaults(handler=register)

    p = sp.add_parser('resend-api-key', help='Request an email containing the API Key')
    p.add_argument('email', type=str,
                   help='Email address of the account')
    p.set_defaults(handler=resend_api_key)

    GROUP_HELP = ''' If --group is supplied, includes only nodes in the named group.'''
    NODE_HELP = ''' If --node is supplied, includes only the named node (or nothing at
    all, if that node is not in the selected --group).'''

    p = sp.add_parser('list-nodes', help='List (all or some) nodes',
                      description='''Prints a YAML summary of accessible nodes to stdout.''' + GROUP_HELP)
    _add_group_argument(p)
    p.set_defaults(handler=list_nodes)

    p = sp.add_parser('monitor', help='Retrieve monitoring data from nodes',
                      description='''Prints a YAML summary of monitoring data from accessible nodes to
                      stdout.''' + GROUP_HELP + NODE_HELP)
    _add_node_group_filter_arguments(p)
    p.set_defaults(handler=monitor)

    p = sp.add_parser('container', help='Container management')
    _add_node_group_filter_arguments(p)
    container_p = p
    p.set_defaults(handler=lambda config, args: container_p.print_help())
    ssp = p.add_subparsers()

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

    p = sp.add_parser('key', help='SSH key management')
    _add_node_group_filter_arguments(p)
    ssh_p = p
    p.set_defaults(handler=lambda config, args: ssh_p.print_help())
    ssp = p.add_subparsers()

    p = ssp.add_parser('add', help='Grant SSH key access to nodes')
    _add_ssh_key_arguments(p)
    p.set_defaults(handler=add_ssh_key)

    p = ssp.add_parser('list', help='List SSH keys with access to nodes')
    p.set_defaults(handler=list_ssh_key)

    p = ssp.add_parser('remove', help='Delete SSH keys having access to nodes')
    g = _add_ssh_key_arguments(p)
    g.add_argument('--index', type=str, action='append',
                   help='Specify key(s) by index in the output of "... key list"')
    p.set_defaults(handler=rm_ssh_key)

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
