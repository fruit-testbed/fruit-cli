fruit-cli
=========

[![PyPI version](https://badge.fury.io/py/fruit-cli.svg)](https://badge.fury.io/py/fruit-cli)

A command-line application to manage a FRμIT federated cluster.


## To Install

Requirements:

- Python (>= 2.7 or >= 3.3)
- Pip

**fruit-cli** can be installed using **pip** simply by invoking:

```sh
pip install fruit-cli
```

To upgrade to a newer version, you can invoke:

```shell
pip install -U fruit-cli
```

To install from source code:

```shell
git clone https://github.com/fruit-testbed/fruit-cli
cd fruit-cli
pip install requests PyYAML
python setup.py install
```


## Config

The default path for the `fruit-cli` configuration file is
`~/.fruit-cli`. It is a YAML file which holds the login information to
access the FRμIT management API. It has two mandatory fields:

- `email`, the user's email address (e.g. `foo@bar.com`).
- `api-key`, a 64-character string assigned to each user. You have to
  register an account (see
  [`fruit-cli account register` below](#account-commands)) to get this
  key.

There is one optional field:

- `server`, the management server's endpoint (default: `https://fruit-testbed.org/api`).

Example:

```yaml
email: foo@bar.com
api-key: 0123456789012345678901234567890123456789012345678901234567890123
```

## Examples

### Retrieving node monitor data

Use a tool like [`jq`](https://stedolan.github.io/jq/) to filter the
output from the `node monitor` subcommand. (You will need to supply
the `--json` global flag to `fruit-cli` to use it with `jq`.)

- `fruit-cli node monitor --node pi123456`
  shows monitoring data of node with ID=`pi123456`.
- `fruit-cli --json node monitor | jq '.[].os.hostname'`
  prints the hostname for each registered node.
- `fruit-cli node monitor --group foo` shows monitoring data of nodes
  with hostname `foo`.
- `fruit-cli --json node monitor | jq '.[] | select(.location.city == "Glasgow").os.hostname'`
  prints the hostname for each registered node located in Glasgow.

### Starting containers

#### ...on a specific node

```shell
fruit-cli container --node pi123 run -p 8080:80 --name nginx herry13/nginx:fruit
```

The above will run a container with name `nginx` and image
[`herry13/nginx:fruit`](https://hub.docker.com/r/herry13/nginx/), on
node `pi123`, where container's port `80` is mapped to host's port
`8080` so that the Nginx service can be accessed externally.

#### ...on all nodes

```shell
fruit-cli container run -p 8080:80 --name nginx herry13/nginx:fruit
```

As above, but on all registered nodes accessible to the active user.

#### ...that need specific kernel modules, device-trees, and device-files

```shell
fruit-cli container --node pi123 run -p 8000:80 \
    --kernel-module i2c-dev \
    --device-tree i2c_arm=on \
    --device /dev/i2c-1 \
    --name bme280 \
    herry13/fruit-bme280
```

The above will run a container with name `bme280` and image
`herry13/fruit-bme280` on node `pi123`. Before running the container,
`i2c-dev` kernel module must be loaded, `i2c_arm=on` device-tree
overlay parameter must be applied, and `/dev/i2c-1` device file must
be bound to the container. Port `80` of the container is bound to
host's port `8000`.

See also the
[list of permitted device prefixes](https://github.com/fruit-testbed/fruit-agent/blob/3f56ef1b890d8b9f14e2bfa509c7d9cbf654d2e7/fruit-container.in#L24-L29).

## Command Summary

```
usage: fruit-cli [-h] [--config FILENAME] [--json]
                 {help,account,node,container,key} ...

Interface to the FRμIT management server API. Your configuration file
is [...]. Override its location with the FRUIT_CLI_CONFIG environment
variable or the --config command-line option.

positional arguments:
  {help,account,node,container,key}
    help                Print help
    account             Account management
    node                Node management
    container           Container management
    key                 SSH key management

optional arguments:
  -h, --help            show this help message and exit
  --config FILENAME, -c FILENAME
                        Supply an alternate configuration file
  --json                Produce output in JSON instead of YAML
```

### Limiting commands to selected nodes or node groups

Many of the subcommands below accept `--group` and/or `--node`
arguments, which select a subset of the user's registered nodes.

If option `--group <hostname>` is given, the selected action will only
include nodes whose hostname is equal to `<hostname>`. Wildcard `*` is
available in `--group`; for example:

```shell
fruit-cli node list --name gms*
```

If option `--node <nodeid>` is given, the selected action will only
include the node with the given ID.

If both options are given, the logical AND of the two applies: only if
the named node ID is within the named group (or group pattern) will it
be selected.

### Account commands

```
usage: fruit-cli account [-h] {help,register,resend-api-key,config,delete} ...

positional arguments:
  {help,register,resend-api-key,config,delete}
    help                Print help
    register            Register a new account
    resend-api-key      Request an email containing the API Key
    config              Print current configuration settings
    delete              Delete account

optional arguments:
  -h, --help            show this help message and exit
```

### Node commands

```
usage: fruit-cli node [-h] {help,list,monitor,reset} ...

positional arguments:
  {help,list,monitor,reset}
    help                Print help
    list                List (all or some) nodes
    monitor             Retrieve monitoring data from nodes
    reset               Deregister and reset a specific node

optional arguments:
  -h, --help            show this help message and exit
```

### Container commands

Management of containers is performed *asynchronously*. It commonly
takes 5-10 minutes until a new container appears on or is removed from
a set of nodes.

```
usage: fruit-cli container [-h] [--group NODEGROUP] [--node NODEID]
                           {help,run,list,remove} ...

positional arguments:
  {help,run,list,remove}
    help                Print help
    run                 Deploy containers to nodes
    list                List containers on nodes
    remove              Remove containers from nodes

optional arguments:
  -h, --help            show this help message and exit

Node selection:
  --group NODEGROUP     Restrict operation to the named node group
  --node NODEID         Restrict operation to the named node
```

### Key commands

Nodes may be accessed via SSH. These commands manipulate SSH keys
allowed to access a user's nodes.

```
usage: fruit-cli key [-h] {help,add,list,remove,authorized_keys} ...

positional arguments:
  {help,add,list,remove,authorized_keys}
    help                Print help
    add                 Grant SSH key access to nodes
    list                List SSH keys with access to nodes
    remove              Delete SSH keys having access to nodes
    authorized_keys     Retrieve the authorized_keys file for a given node

optional arguments:
  -h, --help            show this help message and exit
```
