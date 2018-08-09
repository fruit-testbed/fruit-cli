#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from builtins import input
import argparse
import sys
import requests
import os
from os import path, chmod
import stat
import yaml
import subprocess
import json
import re
import yaml

# def __debug_requests():
#     import logging
#     import httplib
#     httplib.HTTPConnection.debuglevel = 1
#     logging.basicConfig()
#     logger = logging.getLogger('requests.packages.urllib3')
#     logger.setLevel(logging.DEBUG)
#     logger.propagate = True
# __debug_requests()

CONFIG = None  # initialized by __load_config()
FRUIT_CLI_CONFIG_VAR = 'FRUIT_CLI_CONFIG'

SSH_KEY_TYPES = [
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-ed25519",
    "ssh-dss",
    "ssh-rsa",
]


def __config_file():
    return \
        os.environ.get(FRUIT_CLI_CONFIG_VAR, None) or \
        path.join(path.expanduser("~"), ".fruit-cli")


def __container_name_type(name, pattern=re.compile(r"^[a-zA-Z0-9_\-]+$")):
    if not isinstance(name, str) or not pattern.match(name):
        raise argparse.ArgumentTypeError
    return name


def __read_config():
    filename = __config_file()
    if path.exists(filename):
        with open(filename) as f:
            return yaml.safe_load(f)
    return None


def __write_config(cfg):
    filename = __config_file()
    with open(filename, "w") as f:
        yaml.safe_dump(cfg, stream=f, default_flow_style=False)
    chmod(filename, stat.S_IRUSR | stat.S_IWUSR)


def __load_config(create_if_missing=True):
    global CONFIG
    cfg = __read_config()
    if cfg is not None:
        CONFIG = {
            "server": "https://fruit-testbed.org/api",
            "editor": "nano",
        }
        CONFIG.update(cfg)
        return

    print("Config file %s does not exist." % filename)
    try:
        input("Press Enter to create one...")
    except EOFError:
        return

    __write_config({
        "email": "<your-email-address>",
        "api-key": "<your-api-key>",
    })
    __edit_config_interactively()
    sys.exit(0)


def __edit_config_interactively():
    subprocess.call([CONFIG["editor"], __config_file()])


def forget_api_key():
    parser = argparse.ArgumentParser()
    parser.add_argument("email", type=str)
    args = parser.parse_args()

    url = "%s/verify/%s/forget" % (CONFIG["server"], args.email)
    r = requests.get(url)
    if r.status_code in [200, 302]:
        print("An email with API key has been sent your mailbox:", args.email)
        return 0

    if r.status_code == 400:
        sys.stderr.write("Invalid email: %s\n" % args.email)
    if r.status_code == 403:
        sys.stderr.write("You have reached maximum number of requests within \
24-hour.\n")
    if r.status_code == 405:
        sys.stderr.write("You have reached maximum number of resending \
verification email.\n")
    sys.stderr.write("Error with code %d\n" % r.status_code)
    return r.status_code


def register():
    parser = argparse.ArgumentParser()
    parser.add_argument("email", type=str)
    args = parser.parse_args()

    url = "%s/user/%s" % (CONFIG["server"], args.email)

    r = requests.post(url)
    if r.status_code >= 200 and r.status_code <= 299:
        print("""Registration is successful and a verification email has been \
sent.
Please check your mailbox (%s) and follow the instructions to get the API-Key.
""" % args.email)
        return __setup(args.email)
    if r.status_code == 400:
        sys.stderr.write("Invalid email: %s\n" % args.email)
    if r.status_code == 403:
        sys.stderr.write("You have reached maximum number of requests within \
24-hour.\n")
    if r.status_code == 405:
        sys.stderr.write("You have reached maximum number of resending \
verification email.\n")
    if r.status_code == 409:
        sys.stderr.write("Email %s is already registered.\n" % args.email)
    sys.stderr.write("Registration failed with code: %d\n" % r.status_code)
    return r.status_code


def __setup(email):
    api_key = input("Please enter your API-Key: ")
    if api_key is None:
        return 901
    api_key = api_key.strip()
    if len(api_key.strip()) <= 0:
        return 902

    cfg = __read_config() or {}
    cfg.update({
        "email": email,
        "api-key": api_key,
    })
    __write_config(cfg)

    print("")
    print("Your API-Key has been saved to your config file:", __config_file())
    print("You can now manage your nodes.")
    return 0


def config():
    parser = argparse.ArgumentParser()
    parser.add_argument("--edit", action="store_const", const=True,
                        default=False, help="Edit config file")
    args = parser.parse_args()

    if args.edit:
        __edit_config_interactively()
        __load_config()
    print("# Your configs in %s" % __config_file())
    yaml.safe_dump(CONFIG, stream=sys.stdout, default_flow_style=False)
    sys.stdout.flush()


def list_node():
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", dest="node_name", type=str,
                        help="Node's name")
    args = parser.parse_args()

    headers = {
        "X-API-Key": CONFIG["api-key"],
        "Accept-Encoding": "gzip",
        }
    params = {
        "hostname": args.node_name,
        "email": CONFIG["email"],
        }
    url = url = "%s/node" % CONFIG["server"]

    r = requests.get(url, headers=headers, params=params)
    if r.status_code == 200:
        yaml.safe_dump(r.json(), stream=sys.stdout, indent=2,
                       default_flow_style=False)
    elif r.status_code == 404:
        sys.stderr.write("ERROR: Node is not found\n")
        sys.exit(15)
    else:
        sys.stderr.write("ERROR: Listing nodes failed (status code: %d)\n"
                         % r.status_code)
        sys.exit(10)


def __resolve(keys, data):
    for key in keys:
        if key == "":
            continue
        if not isinstance(data, dict) or key not in data:
            return None
        data = data[key]
    return data


def __path_to_array(p):
    sep = ":" if p[0] == ":" else "/"
    return list(filter(lambda s: len(s) > 0, p.split(sep)))


def __filter(condition, data):
    if condition is None:
        return data
    clauses = re.split(r",\s*", condition)
    for clause in map(lambda s: re.split(r"\s*=", s, maxsplit=1), clauses):
        if clause[0] == "":
            continue
        p = __path_to_array(clause[0])
        v = yaml.safe_load(clause[1]) if len(clause) >= 2 else None
        _data = {}
        for node in data:
            if __resolve(p, data[node]) == v:
                _data[node] = data[node]
        data = _data
    return data


def monitor():
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", dest="node", type=str)
    parser.add_argument("--name", dest="node_name", type=str,
                        help="Node's name")
    parser.add_argument("--where", dest="where", type=str,
                        help="""<path>=<value> clauses (',' separated) to
                             filter the node""")
    parser.add_argument("path", nargs="?", default="/", type=str,
                        help="Path of values (separated by /)")
    args = parser.parse_args()

    headers = {
        "X-API-Key": CONFIG["api-key"],
        "Accept-Encoding": "gzip",
        }
    params = {
        "hostname": args.node_name,
        "id": args.node,
        "email": CONFIG["email"],
        }
    url = "%s/monitor" % CONFIG["server"]

    r = requests.get(url, headers=headers, params=params)
    if r.status_code == 200:
        p = __path_to_array(args.path)
        data = __filter(args.where, r.json())
        if len(p) > 0:
            for node in data:
                data[node] = __resolve(p, data[node])
        yaml.safe_dump(data, stream=sys.stdout, indent=2,
                       default_flow_style=False)
    elif r.status_code == 404:
        sys.stderr.write("ERROR: Node is not found\n")
        sys.exit(16)
    else:
        sys.stderr.write(
            "ERROR: Failed getting monitoring data (status code: %d)\n"
            % r.status_code)
        sys.exit(11)


def run_container():
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", dest="node", type=str,
                        help="Target node")
    parser.add_argument("--name", dest="node_name", type=str,
                        help="Target node's name")
    parser.add_argument("-p", dest="ports", type=str,
                        help="Publish the container's port(s) to the host")
    parser.add_argument("-v", dest="volumes", type=str,
                        help="Bind host volume(s) to the container")
    parser.add_argument("-c", "--command", dest="command", type=str,
                        help="Command that will be run in the container")
    parser.add_argument("-k", "--kernel-module", dest="kernel_modules",
                        type=str, help="""Load kernel module(s) before
                        starting the container""")
    parser.add_argument("-dt", "--device-tree", dest="device_trees", type=str,
                        help="""Load host device-tree(s) before starting
                        the container""")
    parser.add_argument("-d", "--device", dest="devices", type=str,
                        help="Bind host device(s) to the container")
    parser.add_argument("container_name", type=__container_name_type,
                        help="Pattern [a-zA-Z0-9\\-_]+")
    parser.add_argument("container_image", type=str)
    args = parser.parse_args()

    headers = {
        "Content-Type": "application/json",
        "X-API-Key": CONFIG["api-key"],
        "Accept-Encoding": "gzip",
        }
    params = {
        "hostname": args.node_name,
        "id": args.node,
        "email": CONFIG["email"],
        }
    url = "%s/container" % CONFIG["server"]

    specification = {
        "name": args.container_name,
        "image": args.container_image,
        }
    if args.command is not None:
        try:
            specification["command"] = json.loads(args.command)
        except ValueError:
            specification["command"] = [args.command]
    if args.ports is not None:
        ports = list(filter(lambda s: len(s) > 0,
                     map(lambda p: p.strip(), args.ports.split(","))))
        if len(ports) > 0:
            specification['port'] = ports
    if args.volumes is not None:
        volumes = list(filter(lambda s: len(s) > 0,
                       map(lambda p: p.strip(), args.volumes.split(","))))
        if len(volumes) > 0:
            specification['volume'] = volumes
    if args.kernel_modules is not None:
        mods = list(filter(lambda m: len(m) > 0,
                    map(lambda s: s.strip(), args.kernel_modules.split(","))))
        if len(mods) > 0:
            specification['kernel-module'] = mods
    if args.device_trees is not None:
        dts = list(filter(lambda d: len(d) > 0,
                   map(lambda s: s.strip(), args.device_trees.split(","))))
        if len(dts) > 0:
            specification['device-tree'] = dts
    if args.devices is not None:
        devs = list(filter(lambda d: len(d) > 0,
                    map(lambda s: s.strip(), args.devices.split(","))))
        if len(devs) > 0:
            specification['device'] = devs

    r = requests.put(url, data=json.dumps(specification), headers=headers,
                     params=params)
    if r.status_code in [200, 201]:
        print("Created container '%s'." % (args.container_name))
    elif r.status_code == 202:
        print("Updated container '%s'." % (args.container_name))
    elif r.status_code == 206:
        print("Partial success on creating the containers")
        print(r.text)
    elif r.status_code == 404:
        sys.stderr.write("ERROR: Node is not found\n")
        sys.exit(15)
    else:
        sys.stderr.write(
            "ERROR: Failed creating container '%s' (status code: %d)\n" %
            (args.container_name, r.status_code))
        sys.stderr.write(r.text)
        sys.stderr.write("\n")
        sys.exit(12)


def list_container():
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", dest="node", type=str,
                        help="Containers only on a particular node")
    parser.add_argument("--name", dest="node_name", type=str,
                        help="Node's name")
    args = parser.parse_args()

    headers = {
        "X-API-Key": CONFIG["api-key"],
        "Accept-Encoding": "gzip",
        }
    params = {
        "hostname": args.node_name,
        "id": args.node,
        "email": CONFIG["email"],
        }
    url = "%s/container" % CONFIG["server"]

    r = requests.get(url, headers=headers, params=params)
    if r.status_code == 200:
        data = __inject_container_state(r.json(), headers, params)
        yaml.safe_dump(data, stream=sys.stdout, indent=2,
                       default_flow_style=False)
        sys.stdout.write("\n")
    elif r.status_code == 404:
        sys.stderr.write("ERROR: Node is not found\n")
        sys.exit(15)
    else:
        sys.stderr.write("Failed listing container(s) (status code: %d)\n" %
                         r.status_code)
        sys.stderr.write(r.text)
        sys.stderr.write("\n")
        sys.exit(13)


def __inject_container_state(data, headers, params):
    url = "%s/monitor" % CONFIG["server"]
    r = requests.get(url, headers=headers, params=params)
    if r.status_code != 200:
        sys.stderr.write("Warning: failed getting container(s)'s state\n")
        sys.stderr.flush()
        return

    # multiple nodes
    monitor = r.json()
    for piid in monitor:
        if piid not in data:
            continue
        node_monitor = monitor[piid]
        if isinstance(node_monitor, dict) and "docker" in node_monitor and \
                "containers" in node_monitor["docker"]:
            __inject_node_container_state(
                    data[piid],
                    node_monitor["docker"]["containers"])
    return data


def __inject_node_container_state(data, containers):
    if isinstance(containers, list):
        for container in containers:
            for name in container["Names"]:
                name = name.lstrip("/")
                name, ext = path.splitext(name)
                if ext == ".fruit":
                    if name in data:
                        data[name]["state"] = container["State"]
                        data[name]["status"] = container["Status"]
                    break
    for name in data:
        if "state" not in data[name]:
            data[name]["state"] = "absent"


def rm_container():
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", dest="node", type=str,
                        help="Remove container from a specific node")
    parser.add_argument("--name", dest="node_name", type=str,
                        help="Node's name")
    parser.add_argument("container_name", type=__container_name_type,
                        help="Container's name in pattern [a-zA-Z0-9\\-_]+")
    args = parser.parse_args()

    headers = {
        "X-API-Key": CONFIG["api-key"],
        "Accept-Encoding": "gzip",
        }
    params = {
        "name": args.container_name,
        "hostname": args.node_name,
        "id": args.node,
        "email": CONFIG["email"],
        }
    url = "%s/container" % CONFIG["server"]

    r = requests.delete(url, headers=headers, params=params)
    if r.status_code == 204:
        print("Container '%s' has been removed." % args.container_name)
    elif r.status_code == 206:
        print("Partial success on removing the containers")
        print(r.text)
    elif r.status_code == 404:
        sys.stderr.write("ERROR: Node is not found\n")
        sys.exit(15)
    else:
        sys.stderr.write("Failed removing container '%s' (status code: %d)\n"
                         % (args.container_name, r.status_code))
        sys.stderr.write(r.text)
        sys.stderr.write("\n")
        sys.exit(14)


def list_ssh_key():
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", dest="node", type=str,
                        help="Remove container from a specific node")
    parser.add_argument("--name", dest="node_name", type=str,
                        help="Node's name")
    args = parser.parse_args()

    headers = {
        "X-API-Key": CONFIG["api-key"],
        "Accept-Encoding": "gzip",
        }
    params = {
        "hostname": args.node_name,
        "id": args.node,
        "email": CONFIG["email"],
        }
    url = "%s/user/ssh-key" % CONFIG["server"]
    r = requests.get(url, headers=headers, params=params)
    if r.status_code == 200:
        yaml.safe_dump(r.json(), stream=sys.stdout, indent=2,
                       default_flow_style=False)
    elif r.status_code == 404:
        sys.stderr.write("ERROR: Node is not found\n")
        sys.exit(15)
    else:
        sys.stderr.write("ERROR: Listing SSH keys failed (status code: %d)\n"
                         % r.status_code)
        sys.exit(10)


def add_ssh_key():
    parser = argparse.ArgumentParser()
    parser.add_argument("--keyfile", dest="keyfile", type=str,
                        help="File of public key to be added")
    parser.add_argument("--key", dest="key", type=str,
                        help="Public key to be added")
    parser.add_argument("--node", dest="node", type=str,
                        help="Remove container from a specific node")
    parser.add_argument("--name", dest="node_name", type=str,
                        help="Node's name")
    args = parser.parse_args()

    if args.keyfile is None and args.key is None:
        return
    if args.key is None and args.keyfile is not None:
        with open(args.keyfile) as f:
            args.key = f.read().strip()

    parts = re.split(r"\s+", args.key)
    if len(parts) < 2:
        sys.stderr.write("Invalid key.")
        sys.exit(1)
    if parts[0] not in SSH_KEY_TYPES:
        sys.stderr.write("Invalid key type:", parts[0])
        sys.exit(2)
    ssh_key = {
        "type": parts[0],
        "key": parts[1],
        "comment": None if len(parts) < 3 else parts[2],
        }

    headers = {
        "Content-Type": "application/json",
        "X-API-Key": CONFIG["api-key"],
        "Accept-Encoding": "gzip",
        }
    params = {
        "hostname": args.node_name,
        "id": args.node,
        "email": CONFIG["email"],
        }
    url = "%s/user/ssh-key" % CONFIG["server"]
    r = requests.put(url, data=json.dumps(ssh_key), headers=headers,
                     params=params)
    if r.status_code == 200:
        print("SSH Key has been stored. It takes several minutes to be \
activated.")
    elif r.status_code == 404:
        sys.stderr.write("ERROR: Node is not found\n")
        sys.exit(3)
    else:
        sys.stderr.write("ERROR: Failed storing the SSH key (status code: %d)\
\n" % r.status_code)
        sys.exit(4)


def rm_ssh_key():
    parser = argparse.ArgumentParser()
    parser.add_argument("--keyfile", dest="keyfile", type=str,
                        help="File of public key to be added")
    parser.add_argument("--key", dest="key", type=str,
                        help="Public key to be added")
    parser.add_argument("--index", dest="index", type=int,
                        help="Index of public key")
    parser.add_argument("--node", dest="node", type=str,
                        help="Remove container from a specific node")
    parser.add_argument("--name", dest="node_name", type=str,
                        help="Node's name")
    args = parser.parse_args()

    if args.keyfile is None and args.key is None and args.index is None:
        return
    if args.key is None and args.keyfile is not None:
        with open(args.keyfile) as f:
            args.key = f.read().strip()

    ssh_key = {"type": "", "key": "", "index": args.index}
    if args.key is not None:
        parts = re.split(r"\s+", args.key)
        if len(parts) < 2:
            sys.stderr.write("Invalid key.")
            sys.exit(1)
        if parts[0] not in SSH_KEY_TYPES:
            sys.stderr.write("Invalid key type:", parts[0])
            sys.exit(2)
        ssh_key["type"] = parts[0]
        ssh_key["key"] = parts[1]
        if len(parts) >= 3:
            ssh_key["comment"] = parts[2]

    headers = {
        "Content-Type": "application/json",
        "X-API-Key": CONFIG["api-key"],
        "Accept-Encoding": "gzip",
        }
    params = {
        "hostname": args.node_name,
        "id": args.node,
        "email": CONFIG["email"],
        }
    url = "%s/user/ssh-key" % CONFIG["server"]
    r = requests.delete(url, data=json.dumps(ssh_key), headers=headers,
                        params=params)
    if r.status_code == 200:
        print("SSH Key has been deleted.")
    elif r.status_code == 404:
        sys.stderr.write("ERROR: Node is not found\n")
        sys.exit(3)
    else:
        sys.stderr.write("ERROR: Failed deleting the SSH key (status code: %d)\
\n" % r.status_code)
        sys.exit(4)


def print_usage(app_name):
    print("""Usage: %(app_name)s COMMAND

Your configuration file location: %(config_file)s
Override its location with the %(config_file_var)s environment variable.

Management Commands:
  config           Print/edit fruit-cli configuration file
  register         Register a user
  forget-api-key   Re-send user's API key to email
  list-node        List of nodes
  monitor          Print monitoring data
  run-container    Run a container on node(s)
  list-container   List container(s)
  rm-container     Remove a container
  list-ssh-key     List authorized SSH keys
  add-ssh-key      Add a new authorized SSH key
  rm-ssh-key       Remove an authorized SSH key
""" % {'app_name': app_name,
       'config_file': __config_file(),
       'config_file_var': FRUIT_CLI_CONFIG_VAR})


def main():
    app_name = sys.argv[0]
    if len(sys.argv) < 2:
        print_usage(app_name)
        sys.exit(1)
    sys.argv.pop(0)

    # Try loading the configuration at this point in order to allow
    # overriding of server api URL for e.g. register() and
    # forget_api_key().
    #
    __load_config(create_if_missing=False)

    if sys.argv[0] == "register":
        sys.exit(register())
    if sys.argv[0] == "forget-api-key":
        sys.exit(forget_api_key())

    __load_config()

    if sys.argv[0] == "config":
        config()
    elif sys.argv[0] == "list-node":
        list_node()
    elif sys.argv[0] == "monitor":
        monitor()
    elif sys.argv[0] == "run-container":
        run_container()
    elif sys.argv[0] == "list-container" or sys.argv[0] == "list-containers":
        list_container()
    elif sys.argv[0] == "rm-container":
        rm_container()
    elif sys.argv[0] == "list-ssh-key":
        list_ssh_key()
    elif sys.argv[0] == "add-ssh-key":
        add_ssh_key()
    elif sys.argv[0] == "rm-ssh-key":
        rm_ssh_key()
    else:
        print("Invalid command:", sys.argv[0], end="\n\n")
        print_usage(app_name)
        sys.exit(2)


if __name__ == "__main__":
    main()
