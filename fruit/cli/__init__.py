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


def list_node():
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", dest="node_name", type=str,
                        help="Node's name")
    args = parser.parse_args()

    headers = {"X-API-Key": CONFIG["api-key"]}
    params = {
        "hostname": args.node_name,
        "email": CONFIG["email"],
        }
    url = url = "%s/node" % CONFIG["server"]

    r = requests.get(url, headers=headers, params=params)
    if r.status_code == 200:
        print(r.text)
    elif r.status_code == 404:
        sys.stderr.write("ERROR: Node is not found\n")
        sys.exit(15)
    else:
        sys.stderr.write("ERROR: Listing nodes failed (status code: %d)\n"
                         % r.status_code)
        sys.exit(10)


def monitor():
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", dest="node", type=str)
    parser.add_argument("--name", dest="node_name", type=str,
                        help="Node's name")
    args = parser.parse_args()

    headers = {"X-API-Key": CONFIG["api-key"]}
    params = {
        "hostname": args.node_name,
        "id": args.node,
        "email": CONFIG["email"],
        }
    url = "%s/monitor" % CONFIG["server"]

    r = requests.get(url, headers=headers, params=params)
    if r.status_code == 200:
        print(r.text)
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

    headers = {"X-API-Key": CONFIG["api-key"]}
    params = {
        "hostname": args.node_name,
        "id": args.node,
        "email": CONFIG["email"],
        }
    url = "%s/container" % CONFIG["server"]

    r = requests.get(url, headers=headers, params=params)
    if r.status_code == 200:
        data = __inject_container_state(r.json(), headers, params)
        json.dump(data, sys.stdout, indent=2, sort_keys=True)
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
    elif r.status_code == 404:
        sys.stderr.write("ERROR: Node is not found\n")
        sys.exit(15)
    else:
        sys.stderr.write("Failed removing container '%s' (status code: %d)\n"
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
