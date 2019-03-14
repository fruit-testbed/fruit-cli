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
pip install -r requirements.txt
python setup.py install
```

## Registering an account

The FRμIT management service uses
[the Ed25519 signature scheme](https://ed25519.cr.yp.to/) to
authenticate users and nodes with the management server.

To register an account, you will need an Ed25519 key.

Alternatively, you can [use an existing account](#using-an-existing-account).

### Step 1: Generate a key

You can use a new or existing Ed25519
[SSH key](https://wiki.archlinux.org/index.php/SSH_keys#Ed25519) or a
new or existing Ed25519 [OpenBSD signify][signify] key.

  [signify]: https://man.openbsd.org/signify

To generate a fresh SSH key:

    ssh-keygen -t ed25519 -f ssh-key-for-fruit

This will create files `ssh-key-for-fruit` and `ssh-key-for-fruit.pub`
in the current directory, holding your new secret key and its
corresponding public key, respectively. Supply a different path to the
`-f` option to alter this behaviour.

Alternatively, to generate a fresh signify key:

    signify -G -s signify-key-for-fruit.sec -p signify-key-for-fruit.pub

This will create files `signify-key-for-fruit.sec` and
`signify-key-for-fruit.pub` in the current directory, holding your new
secret key and its corresponding public key, respectively. Supply
different paths to the `-s` and `-p` options to alter this behaviour.
(The `signify` command-line tool may be called `signify-openbsd` on
systems such as Debian linux.)

### Step 1b (optional): Add your key to ssh-agent

If you chose to use an SSH key to authenticate with FRμIT, you may
choose to add the key to your
[`ssh-agent`](https://en.wikipedia.org/wiki/Ssh-agent).

This will allow you to use `fruit-cli` without having to enter your
passphrase for each command.

To do this, ensure your `SSH_AUTH_SOCK` environment variable is set
correctly per the
[`ssh-agent` documentation](https://man.openbsd.org/ssh-agent), and
then run

    ssh-add ssh-key-for-fruit

replacing the `ssh-key-for-fruit` filename with the correct path to
your SSH secret key file if necessary.

### Step 2: Register your account

Now that you have an Ed25519 key available, you may register your
account with the server.

Use the `fruit-cli account register` command, supplying the path to
your SSH or signify secret key using the `-f` option, and also
supplying an email address that you have access to, e.g. `fruit-cli account register user@test.org -f ssh-key-for-fruit`

### Step 3: Click the verification link

You will receive email at the address you specified in the previous
step. Click the link it contains. After you do so, your account is
ready to use.

Running

    fruit-cli node list

should successfully produce the empty list as output.

## Using an existing account

Instead of [registering an account](#registering-an-account), you can
configure `fruit-cli` to make use of a previously-registered email
address and Ed25519 key.

Create (or edit) your [configuration file](#config) to contain a
`default` identity containing the email address and Ed25519 key file
you used previously to register your account:

    identities:
      default:
        email: YOUR@EMAIL.ADDRESS
        secret-key-file: /PATH/TO/YOUR/ssh-ed25519-private-key-file

See below for more information on the possible contents of the
configuration file.

## Config

The default path for the `fruit-cli` configuration file is
`~/.fruit-cli`. It is a YAML file which holds the login information to
access the FRμIT management API.

It has two fields:

- `default_identity` names the identity that `fruit-cli` will use
  unless overridden with the `--identity` command-line argument. If
  this field is not defined, then it is implicitly set to `default`.

- `identities` is a dictionary, with each key naming an identity
  available to the user of `fruit-cli`. Each identity must itself be a
  dictionary, with two mandatory fields:

   - `email`, the account's email address (e.g. `foo@bar.com`).
   - `public-key`, a base64-encoded Ed25519 public key identifying the account.

  Each identity also must have one of two possible fields specifying
  the secret key corresponding to the account's public key, depending
  on the way the account was initially configured:

   - `secret-key` may contain either
       - an unprotected, base64-encoded, raw Ed25519 secret key; or
       - the contents of an SSH private key file; or
       - the contents of an
         [OpenBSD signify][signify]
         secret key file
   - `secret-key-file` may contain a path to
       - an SSH or private key file containing an Ed25519 key
       - an OpenBSD signify secret key file

  Finally, there is one optional identity field:

   - `server`, which overrides the management server API endpoint to
     use (default: `https://fruit-testbed.org/api`).

If an SSH private key is used and `SSH_AUTH_SOCK` is correctly set,
`fruit-cli` will use the SSH agent protocol to avoid needing to access
the decrypted SSH private key directly.

Example:

1. With SSH private key embedded in `.fruit-cli`:

   ```yaml
   identities:
     default:
       email: foo@bar.com
       public-key: Kr7zLRszjeJIFugU4emg3cRRkqwThzdWtdFgTNfWkwc=
       secret-key: |
         -----BEGIN OPENSSH PRIVATE KEY-----
         b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
         QyNTUxOQAAACAqvvMtGzON4kgW6BTh6aDdxFGSrBOHN1a10WBM19aTBwAAAJiF9PaZhfT2
         mQAAAAtzc2gtZWQyNTUxOQAAACAqvvMtGzON4kgW6BTh6aDdxFGSrBOHN1a10WBM19aTBw
         AAAEDXtEIQ3vT45HKCYAgdQsldEZCgd3LsKlGoaaWzAxLQCyq+8y0bM43iSBboFOHpoN3E
         UZKsE4c3VrXRYEzX1pMHAAAADnRlc3RrZXktbm9wYXNzAQIDBAUGBw==
         -----END OPENSSH PRIVATE KEY-----
   ```

1. With SSH private key in the user's `~/.ssh/id_ed25519` file:

   ```yaml
   identities:
     default:
       email: foo@bar.com
       public-key: Kr7zLRszjeJIFugU4emg3cRRkqwThzdWtdFgTNfWkwc=
       secret-key-file: ~/.ssh/id_ed25519
   ```

1. With signify secret key embedded in `.fruit-cli`:

   ```yaml
   identities:
     default:
       email: foo@bar.com
       public-key: Q0VY79+tjrd7liUgd+gNPIwgKjEj9htLoTCrKK2ticU=
       secret-key: |
         untrusted comment: signify secret key
         RWRCSwAAACr9As6kyntYZy64Ox6oyZxobHMbQBnRtZ+LuLux29x42u7NpUwzrJDA6Gq0PQOd6MaKPEzL0+RZWjao1EIXn6vKk1QoaMythTS6X2W0ZU21q4D6x/4d60JfbQr5VCU1GaU=
   ```

1. With signify secret key in `~/.signify.sec`:

   ```yaml
   identities:
     default:
       email: foo@bar.com
       public-key: Q0VY79+tjrd7liUgd+gNPIwgKjEj9htLoTCrKK2ticU=
       secret-key-file: ~/.signify.sec
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
usage: fruit-cli [-h] [--config FILENAME] [--json] [--identity IDENTITY]
                 {help,account,node,container,key,admin} ...

Interface to the FRμIT management server API. Your configuration file is
/home/tonyg/dev/fruit/public/fruit-cli/debug-config-file. Override its
location with the FRUIT_CLI_CONFIG environment variable or the --config
command-line option.

positional arguments:
  {help,account,node,container,key,admin}
    help                Print help
    account             Account management
    node                Node management
    container           Container management
    key                 SSH key management
    admin               Actions for installation administrators

optional arguments:
  -h, --help            show this help message and exit
  --config FILENAME, -c FILENAME
                        Supply an alternate configuration file
  --json                Produce output in JSON instead of YAML
  --identity IDENTITY   Select an alternate identity to use when
                        authenticating with the server
```

### Limiting commands to selected nodes or node groups

Many of the subcommands below accept `--filter` and/or `--node`
arguments, which select a subset of the user's registered nodes.

If option `--node <nodeid>` is given, the selected action will only
include the node with the given ID.

The option `--filter <jsonpointer> <operator> <value>` limits the
nodes selected to those matching the filter. The option can be
repeated to further narrow down the selection.

 - Every node has some JSON data associated with it. For example,
   uploaded monitoring statistics appear under key `"monitor"`. The
   `jsonpointer` (see
   [RFC 6901, "JavaScript Object Notation (JSON) Pointer"](https://tools.ietf.org/html/rfc6901))
   names a portion of this JSON data to examine. For example, the
   pointer `/monitor/os/hostname` retrieves the hostname uploaded by a
   node as part of its monitoring data.

 - The operator may be one of `=`, `<`, `>` or `glob`.

 - The `value` must be a JSON term, unless the operator is `glob`, in
   which case it is simple text with embedded `*` wildcards.

For example,

    fruit-cli node list --filter /monitor/os/hostname = '"pi4440302f"'

will list nodes who believe their hostname to be `pi4440302f`. Note
the use of single-quotes to protect the JSON string `"pi4440302f"`
from the shell.

As another example,

    fruit-cli node list --filter /monitor/os/hostname glob 'pi44*'

will list nodes who believe their hostname to be a string starting
with `pi44`. Note the use of single-quotes to protect the embedded
wildcard from the shell.

If a `--node` option and some `--filter` options are given, the
logical AND of them all applies: only if the named node ID is within
the filtered group will it be selected.

### Account commands

```
usage: fruit-cli account [-h]
                         {help,register,config,public-key,token,delete} ...

positional arguments:
  {help,register,config,info,public-key,token,delete}
    help                Print help
    register            Register a new account
    config              Print current configuration settings
    info                Retrieve server-side account information
    public-key          Print account public key
    token               Print a fresh authentication token
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
usage: fruit-cli key [-h] {help,add,list,remove} ...

positional arguments:
  {help,add,list,remove}
    help                Print help
    add                 Grant SSH key access to nodes
    list                List SSH keys with access to nodes
    remove              Delete SSH keys having access to nodes

optional arguments:
  -h, --help            show this help message and exit
```

### Admin commands

Administrators of the management system may access these functions.

```
usage: fruit-cli admin [-h] {help,account,node} ...

positional arguments:
  {help,account,node}
    help               Print help
    account            Installation-wide account management
    node               Installation-wide node management

optional arguments:
  -h, --help           show this help message and exit
```

