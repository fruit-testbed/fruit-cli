#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
import argparse
import sys
import requests
from os import path
import yaml
import subprocess
import json
import re


CONFIG_FILE = path.join(path.expanduser("~"), ".fruit-cli")
CONFIG = {
    "server": "https://fruit-testbed.org/api",
    "editor": "nano",
    }


def __container_name_type(name, pattern=re.compile(r"^[a-zA-Z0-9_\-]+$")):
    if not isinstance(name, str) or not pattern.match(name):
        raise argparse.ArgumentTypeError
    return name


def __load_config():
    if path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            cfg = yaml.safe_load(f)
            for key in cfg.keys():
                CONFIG[key] = cfg[key]
            return
    print("Config file %s does not exist." % CONFIG_FILE)
    try:
        input("Press Enter to create one...")
    except EOFError:
        return
    cfg = {
        "email": "<your-email-address>",
        "api-key": "<your-api-key>",
    }
    with open(CONFIG_FILE, "w") as f:
        yaml.safe_dump(cfg, stream=f, default_flow_style=False)
    subprocess.call(["nano", CONFIG_FILE])
    sys.exit(0)


def register():
    parser = argparse.ArgumentParser()
    parser.add_argument("email", type=str, nargs=1)
    args = parser.parse_args()

    url = "%s/user/%s" % (CONFIG["server"], args.email)

    r = requests.get(url)
    if r.status_code != 200:
        print("Registration failed (status code: %d)" % r.status_code)
        sys.exit(9)
    print("""Registration request has been submitted.
Please check your mailbox (%s) for further instructions.""" % args.email)


def config():
    parser = argparse.ArgumentParser()
    parser.add_argument("--edit", action="store_const", const=True,
                        default=False, help="Edit config file")
    args = parser.parse_args()

    if args.edit:
        subprocess.call([CONFIG["editor"], CONFIG_FILE])
        __load_config()
    print("--- Your configs in %s ---" % CONFIG_FILE)
    yaml.safe_dump(CONFIG, stream=sys.stdout, default_flow_style=False)
    sys.stdout.flush()


def __nodes(name=None):
    if CONFIG["email"] == "admin@fruit-testbed.org":
        url = "%s/node" % CONFIG["server"]
    else:
        url = "%s/user/%s/node" % (CONFIG["server"], CONFIG["email"])
    headers = {"X-API-Key": CONFIG["api-key"]}
    params = {'hostname': name}

    r = requests.get(url, headers=headers, params=params)
    if r.status_code == 200:
        return 200, json.loads(r.text)
    return r.status_code, None


def list_node():
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", dest="name", type=str,
                        help="Node's name")
    args = parser.parse_args()

    status, nodes = __nodes(name=args.name)
    if status == 200:
        json.dump(nodes, sys.stdout, sort_keys=True, indent="  ")
        sys.stdout.write("\n")
    elif status == 404:
        sys.stderr.write("Node '%s' is not found\n" % args.name)
        sys.exit(15)
    else:
        sys.stderr.write("ERROR: Listing nodes failed (status code: %d)\n" \
                         % status)
        sys.exit(10)


def monitor():
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", dest="node", type=str, nargs=1)
    parser.add_argument("--name", dest="name", type=str, help="Node's name")
    args = parser.parse_args()

    if args.name is not None and args.node is None:
        status, args.node = __nodes(name=args.name)
        if status == 404:
            sys.stderr.write("ERROR: Node '%s' is not found\n" % args.name)
            sys.exit(20)

    headers = {"X-API-Key": CONFIG["api-key"]}
    if CONFIG["email"] == "admin@fruit-testbed.org":
        url = "%s/monitor" % CONFIG["server"]
    else:
        url = "%s/user/%s/monitor" % (CONFIG["server"], CONFIG["email"])

    if args.node is None:
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            print(r.text)
            return
        else:
            sys.stderr.write("ERROR: Listing nodes failed (status code: %d)\n"
                             % r.status_code)
            sys.exit(11)

    res = {}
    for node in args.node:
        url_node = "%s/%s" % (url, node)
        r = requests.get(url_node, headers=headers)
        if r.status_code == 200:
            res[node] = json.loads(r.text)
        else:
            sys.stderr.write("""WARNING: Failed getting monitoring data of \
node '%s' (status code %d)\n""" % (node, r.status_code))
            sys.stderr.flush()
    json.dump(res, sys.stdout, sort_keys=True, indent="  ")
    sys.stdout.write("\n")


def run_container():
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", dest="node", type=str,
                        help="""Target node of container deployment.
                        If not specified then the container will be deployed
                        on all nodes owned by the user.""")
    parser.add_argument("--name", dest="name", type=str,
                        help="Name of target node")
    parser.add_argument("-p", dest="ports", type=str,
                        help="""Publish one or more container's ports to
                        the host""")
    parser.add_argument("-v", dest="volumes", type=str,
                        help="""Mount bind one or more host's volumes to
                        the container""")
    parser.add_argument("-c", "--command", dest="command", type=str,
                        help="Command that will be run in the container")
    parser.add_argument("-k", "--kernel-module", dest="kernel_modules",
                        type=str, help="""Load kernel modules before starting
                        the container""")
    parser.add_argument("-dt", "--device-tree", dest="device_tree", type=str,
                        help="""Load host device tree before starting
                        the container""")
    parser.add_argument("-d", "--device", dest="device", type=str,
                        help="Bind host device to the container")
    parser.add_argument("name", type=__container_name_type,
                        help="Container's name in pattern [a-zA-Z0-9\\-_]+")
    parser.add_argument("image", type=str, help="Container's image")
    args = parser.parse_args()

    if CONFIG["email"] == "admin@fruit-testbed.org":
        url = "%s/container" % CONFIG["server"]
    else:
        url = "%s/user/%s/container" % (CONFIG["server"], CONFIG["email"])

    if args.node is not None:
        url = "%s/%s" % (url, args.node)
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": CONFIG["api-key"],
        }
    data = {
        "name": args.name,
        "image": args.image,
        }
    if args.command is not None:
        try:
            data["command"] = json.loads(args.command)
        except ValueError:
            data["command"] = [args.command]
    if args.ports is not None:
        ports = list(filter(lambda s: len(s) > 0,
                     map(lambda p: p.strip(), args.ports.split(","))))
        if len(ports) > 0:
            data['port'] = ports
    if args.volumes is not None:
        volumes = list(filter(lambda s: len(s) > 0,
                       map(lambda p: p.strip(), args.volumes.split(","))))
        if len(volumes) > 0:
            data['volume'] = volumes
    if args.kernel_modules is not None:
        mods = list(filter(lambda m: len(m) > 0,
                    map(lambda s: s.strip(), args.kernel_modules.split(","))))
        if len(mods) > 0:
            data['kernel-module'] = mods
    if args.device_tree is not None:
        dts = list(filter(lambda d: len(d) > 0,
                   map(lambda s: s.strip(), args.device_tree.split(","))))
        if len(dts) > 0:
            data['device-tree'] = dts
    if args.device is not None:
        devs = list(filter(lambda d: len(d) > 0,
                    map(lambda s: s.strip(), args.device.split(","))))
        if len(devs) > 0:
            data['device'] = devs

    r = requests.put(url, data=json.dumps(data), headers=headers)
    if r.status_code == 200:
        print("Created new container '%s' on all nodes" % args.name)
    elif r.status_code == 201:
        print("Created new container '%s' on node %s" % (args.name, args.node))
    elif r.status_code == 202:
        print("Updated container '%s' on node %s" % (args.name, args.node))
    elif r.status_code == 206:
        print("Partial success on creating the containers")
        print(r.text)
    else:
        print("Created container '%s' failed (status code: %d)" %
              (args.name, r.status_code))
        print(r.text)
        sys.exit(12)


def list_container():
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", dest="node", type=str,
                        help="Containers only on a particular node")
    parser.add_argument("--name", dest="name", type=str, help="Node's name")
    args = parser.parse_args()

    headers = {"X-API-Key": CONFIG["api-key"]}
    params = {'hostname': args.name, 'id': args.node}

    if CONFIG["email"] == "admin@fruit-testbed.org":
        url = "%s/container" % CONFIG["server"]
    else:
        url = "%s/user/%s/container" % (CONFIG["server"], CONFIG["email"])

    r = requests.get(url, headers=headers, params=params)
    if r.status_code == 200:
        data = __inject_container_state(r.json())
        json.dump(data, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        sys.stderr.write("Failed listing container(s) (status code: %d)\n" % \
                         r.status_code)
        sys.stderr.write(r.text)
        sys.stderr.write("\n")
        sys.exit(13)


def __inject_container_state(data, node=None):
    if CONFIG["email"] == "admin@fruit-testbed.org":
        url = "%s/monitor" % CONFIG["server"]
    else:
        url = "%s/user/%s/monitor" % (CONFIG["server"], CONFIG["email"])

    headers = {"X-API-Key": CONFIG["api-key"]}
    if node is not None:
        url = "%s/%s" % (url, node)
    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        print("Warning: failed getting container(s)'s state", file=sys.stderr)
        print(r.text, file=sys.stderr)
    elif node is not None:
        # single node
        monitor = r.json()
        if "docker" in monitor and "containers" in monitor["docker"]:
            __inject_node_container_state(data,
                                          monitor["docker"]["containers"])
    else:
        # multiple nodes
        monitor = r.json()
        for piid in monitor:
            if piid not in data:
                continue
            node_monitor = monitor[piid]
            if "docker" in node_monitor and \
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

    headers = {"X-API-Key": CONFIG["api-key"]}
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
    else:
        sys.stderr.write("Failed removing container '%s' (status code: %d)\n" \
                         % (args.container_name, r.status_code))
        sys.stderr.write(r.text)
        sys.stderr.write("\n")
        sys.exit(14)


def print_usage(app_name):
        print("""Usage: %s COMMAND

Management Commands:
  config           Print/edit fruit-cli configuration file
  list-node        List of nodes
  monitor          Print monitoring data
  run-container    Run a container on node(s)
  list-container   List container(s)
  rm-container     Remove a container

""" % app_name)


def main():
    app_name = sys.argv[0]
    if len(sys.argv) < 2:
        print_usage(app_name)
        sys.exit(1)
    sys.argv.pop(0)

    if sys.argv[0] == "register":
        register()

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
    else:
        print("Invalid command:", sys.argv[0], end="\n\n")
        print_usage(app_name)
        sys.exit(2)


if __name__ == "__main__":
    main()
