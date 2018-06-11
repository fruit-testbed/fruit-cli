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

`fruit-cli list-node`

**list-node** prints a list of nodes (in JSON format) that belong to the user.


### monitor

`fruit-cli monitor [--node <id>]`

**monitor** prints monitoring data of all nodes belong to the user.

If option `--node <id>` is given, then it prints monitoring data of node with ID=`<id>`,
as long as the node belongs to the user.


### list-container

`fruit-cli list-container [--node <id>]`

**list-container** prints a list of containers that have been submitted to the management
server, that should be deployed on all nodes that belong to the user.

If option `--node <id>` is given, then it prints a list of containers of node with
ID=`<id>`, as long as the node belongs to the user.


### run-container

`fruit-cli run-container [--node <id>] [--params <params>] [--command <command>] <name> <image>`

**run-container** submits a container specification to the management server,
that should be deployed on all nodes that belong to the user. When the container
with the same name is already exist, then it will be stopped and re-deployed again
if there is a difference on the image, parameters, or command.
Otherwise, no operation will be performed.

If option `--node <id>` is given, then the container will only be deployed on node
with ID=`<id>`, as long as the node belongs to the user.

Arguments are:
- `<name>`, container's name.
- `<image>`, the container's image.

Other options are:
- `--params <params>`, parameters (in JSON array format) to be passed to `docker run` command.
  See [here](https://docs.docker.com/engine/reference/run/) to learn more about all available
  options.
- `--command <command>`, commands (in JSON array format) that will be run inside the container.

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


### rm-container

`fruit-cli rm-container [--node <id>] <name>`

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
