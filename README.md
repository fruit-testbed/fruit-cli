fruit-cli
=========

A command-line application to manage Fruit federated cluster.


## To Install

Requirements:

- Python (>= 2.7 or >= 3.3)
- Pip

**fruit-cli** can be installed using **pip** simply by invoking:

```sh
pip install fruit-cli
```

To upgrade to newer version, you can invoke:

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

Config file of **fruit-cli** is at path `~/.fruit-cli`. It is a **YAML** file which holds
the login information to access Fruit Management APIs. It has two mandatory fields:

- `email`, the user's  email address (e.g. `foo@bar.com`).
- `api-key`, a 64-character string assigned to each user. You have to register yourself
  to get this key.

There two optional fields:

* `editor`, the editor application used to edit the config file (default: `nano`).
* `server-url`, the management server's endpoint (default: `https://fruit-testbed.org/api`).

Example:

```yaml
email: foo@bar.com
api-key: 0123456789012345678901234567890123456789012345678901234567890123
editor: vi
```


## Commands

There are six commands: **config**, **list-node**, **monitor**, **list-container**,
**run-container**, and **rm-container**.


### config

`fruit-cli config [--edit]`

**config** prints **fruit-cli**'s configuration to the standard output.

If option `--edit` is given, then it opens the config file (`~/.fruit-cli`) with a text editor.


### list-node

`fruit-cli list-node [--name <hostname>]`

**list-node** prints a list of nodes (in JSON format) that belong to the user.

If option `--name <hostname>` is given, then it only includes nodes whose hostname is equal to `<hostname>`. You can use `*` for pattern matching, for example:

```shell
fruit-cli list-node --name gms*
```


### monitor

`fruit-cli monitor [--node <id>] [--name <hostname>]`

**monitor** prints monitoring data of all nodes belong to the user.

If option `--node <id>` is given, then it prints monitoring data of node with ID=`<id>`,
as long as the node belongs to the user.

If option `--name <hostname>` is given, then it only includes nodes whose hostname is equal to `<hostname>`. You can use `*` for pattern matching.


### list-container

`fruit-cli list-container [--node <id>] [--name <hostname>]`

**list-container** prints a list of containers that have been submitted to the management
server, that should be deployed on all nodes that belong to the user.

If option `--node <id>` is given, then it prints a list of containers of node with
ID=`<id>`, as long as the node belongs to the user.

If option `--name <hostname>` is given, then it only includes nodes whose hostname is equal to `<hostname>`. You can use `*` for pattern matching.


### run-container

`fruit-cli run-container [--node <id>] [--name <hostname>] [-p <list>] [-v <list>] [--command <command>] <name> <image>`

**run-container** submits a container specification to the management server,
that should be deployed on all nodes that belong to the user. When the container
with the same name is already exist, then it will be stopped and re-deployed again
if there is a difference on the image, parameters, or command.
Otherwise, no operation will be performed.

If option `--node <id>` is given, then the container will only be deployed on node
with ID=`<id>`, as long as the node belongs to the user.

If option `--name <hostname>` is given, then it only includes nodes whose hostname is equal to `<hostname>`. You can use `*` for pattern matching.

Arguments are:
- `<name>`, container's name.
- `<image>`, the container's image.

Other options are:
- `-p <list>`, publish a container's ports to the host. For example,
  `-p 8000:80` publishes container's port 80 to the host's port 8000.
  Multiple ports are separated with comma.
- `-v <list>`, mount bind the host's volume to the container. This is very useful
  to have a persistent file (_stateful container_) or sharing it with other containers. For example,
  `-v /foo:/bar` mounts the host's `/data/.container-data/foo`
  onto the container's `/bar`. Note that the host volume is always relative to `/data/.container-data`.
- `-c <command>`, commands (in JSON array format) that will be run inside the container.
- `-k <list>`, load kernel modules (comma separated) before starting the container.
- `-dt <list>`, apply device-tree parameters (comma separated) before starting the container.
- `-d <list>`, bind host devices (comma separated) to the container. [Here](https://github.com/fruit-testbed/fruit-agent/blob/1436ae0a99e784461a586feffea499841c39fe4c/fruit-container.in#L24) is the white-list of devices that can be bound to the container.

> Note that the deployment process is performed asynchronously. It commonly takes 5-10
> minutes until the container has been started on target node by **fruit-agent**.


#### Example: run a container on a specific node

```shell
fruit-cli run-container \
    --node pi123 --params '["-p", "8080:80"]' \
    nginx herry13/nginx:fruit
```

The above will run a container with name `nginx` and image `herry13/nginx:fruit`, on node `pi123`,
where container's port `80` is mapped to host's port `8080` so that the Nginx service can be
accessed from external.


#### Example: run a container on all nodes

```shell
fruit-cli run-container --params '["-p", "8080:80"]' \
    nginx herry13/nginx:fruit
```

The above will run a container with name `nginx` and image `herry13/nginx:fruit`, on all nodes
that belong to the user, where container's port `80` is mapped to host's port `8080` so that
the Nginx service can be accessed from external.


> The examples are using image `herry13/nginx:fruit` available in [Docker hub](https://hub.docker.com/r/herry13/nginx/).

#### Example: run a container that needs specific kernel module, device-tree, and device-file.

```shell
fruit-cli run-container --node pi123 -p 8000:80 \
    -k i2c-dev -dt i2c_arm=on -d /dev/i2c-1 \
    bme280 herry13/fruit-bme280
```

The above will run a container with name `bme280` and image `herry13/fruit-bme280`, on node `pi123`. Before running the container, `i2c-dev` kernel module must be loaded, `i2c_arm=on` device-tree overlay parameter must be applied, and `/dev/i2c-1` device file must be bound to the container. Port `80` of the container is bound to host's port `8000`.

A [permitted list of devices](https://github.com/fruit-testbed/fruit-agent/blob/1436ae0a99e784461a586feffea499841c39fe4c/fruit-container.in#L24) that can be bound are: `/dev/i2c*`, `/dev/spi*`, `/dev/ttyUSB*`.


### rm-container

`fruit-cli rm-container [--node <id>] [--node <hostname>] <name>`

**rm-container** removes container with name=`<name>` from all nodes that belong to the user.
For example:

```shell
fruit-cli rm-container nginx
```

If option `--node <id>` is given, then the container will only be removed from node with
ID=`<id>`, as long as the node belongs to the user. For example:

```shell
fruit-cli rm-container --node pi123 nginx
```

> Note that the deployment process is performed asynchronously. It commonly takes 5-10
> minutes until the container has been removed from target node by **fruit-agent**.

If option `--name <hostname>` is given, then it only includes nodes whose hostname is equal to `<hostname>`. You can use `*` for pattern matching.