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


def container_name_type(name, pattern=re.compile(r"^[a-zA-Z0-9_\-]+$")):
    if not isinstance(name, str) or not pattern.match(name):
        raise argparse.ArgumentTypeError
    return name


def load_config():
    if path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            cfg = yaml.safe_load(f)
            for key in cfg.keys():
                CONFIG[key] = cfg[key]
            return
    print("Config file %s does not exist." % CONFIG_FILE)
    try:
        input("Press Enter to create one...")
    except:
        pass
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
        load_config()
    print("--- Your configs in %s ---" % CONFIG_FILE)
    yaml.safe_dump(CONFIG, stream=sys.stdout, default_flow_style=False)
    sys.stdout.flush()


def list_node():
    url = "%s/user/%s/node" % (CONFIG["server"], CONFIG["email"])
    headers = {"X-API-Key": CONFIG["api-key"]}

    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        print(r.text)
    else:
        print("Listing nodes failed (status code: %d)" % r.status_code)
        sys.exit(10)


def monitor():
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", dest="node", type=str)
    args = parser.parse_args()

    url = "%s/user/%s/monitor" % (CONFIG["server"], CONFIG["email"])
    if args.node is not None:
        url = "%s/%s" % (url, args.node)
    headers = {"X-API-Key": CONFIG["api-key"]}

    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        print(r.text)
    else:
        print("Listing nodes failed (status code: %d)" % r.status_code)
        sys.exit(11)


def run_container():
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", dest="node", type=str,
        help="""Target node which the container will be deployed.
                If not specified then the container will be deployed
                on all nodes owned by the user.""")
    parser.add_argument("--params", dest="params", type=str,
        help="Parameters to be passed to Docker run")
    parser.add_argument("--command", dest="command", type=str,
        help="Command that will be run in the container")
    parser.add_argument("name", type=container_name_type,
        help="Container's name in pattern [a-zA-Z0-9\\-_]+")
    parser.add_argument("image", type=str,
        help="Container's image")
    args = parser.parse_args()

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
        except:
            data["command"] = [args.command]
    if args.params is not None:
        try:
            data["parameters"] = json.loads(args.params)
        except:
            data["parameters"] = [args.params]

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
        print("Created container '%s' failed (status code: %d)" % \
                (args.name, r.status_code))
        print(r.text)
        sys.exit(12)


def list_container():
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", dest="node", type=str,
        help="""Target node which the container will be deployed.
                If not specified then the container will be deployed
                on all nodes owned by the user.""")
    args = parser.parse_args()

    url = "%s/user/%s/container" % (CONFIG["server"], CONFIG["email"])
    if args.node is not None:
        url = "%s/%s" % (url, args.node)
    headers = {
        "X-API-Key": CONFIG["api-key"],
        }
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        print(r.text)
    else:
        print("Failed listing container(s) (status code: %d)" % r.status_code)
        print(r.text)
        sys.exit(13)


def rm_container():
    parser = argparse.ArgumentParser()
    parser.add_argument("--node", dest="node", type=str,
        help="""Target node which the container will be deployed.
                If not specified then the container will be deployed
                on all nodes owned by the user.""")
    parser.add_argument("name", type=container_name_type,
        help="Container's name in pattern [a-zA-Z0-9\\-_]+")
    args = parser.parse_args()

    url = "%s/user/%s/container" % (CONFIG["server"], CONFIG["email"])
    if args.node is not None:
        url = "%s/%s" % (url, args.node)
    url = "%s/%s" % (url, args.name)
    headers = {
        "X-API-Key": CONFIG["api-key"],
        }
    r = requests.delete(url, headers=headers)
    if r.status_code == 204:
        if args.node is None:
            print("Stopped container '%s' on all nodes." % args.name)
        else:
            print("Stopped container '%s' on node %s" % (args.name, args.node))
    elif r.status_code == 206:
        print("Partial success on stopping the containers")
        print(r.text)
    else:
        print("Failed stopping container '%s' (status code: %d)" % \
                (args.name, r.status_code))
        print(r.text)
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

    load_config()

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
