fruit-cli
=========

A command line app for Fruit clusters.

Usage: `fruit-cli <command>`

Config file:
- Path: `~/.fruit.json` (permission: 0600)
- Fields
  - User's email address
  - API key

Commands:
- `register <email-address>`
  - for a new user
    - server sends an activation link to user's email address
    - user activates the account by clicking the link
    - after activating the account, the server sends an API-Key to user's email address
  - for an existing user
    - server sends the API-Key to user's email address
- `edit-config`: open the config file with a text editor (e.g. nano, vi)
- `print-config`: print configuration to STDOUT
- `list-nodes`: list nodes belong to the user
- `get-monitoring-data [node-id]`
  - If `node-id` not given, returns all monitoring data of nodes belong to the user
  - If `node-id` given, returns monitoring data of the node if it’s belong to the user
- `run [--node-id <id>] [--tag <key>=<value>]* [--container-options <container-options>] <container-image> [container-command]`
  - `<container-image>`: the container image to be run
  - `<container-command>`: a command that will be run in the container
  - `<container-options>`: options that will be passed to Docker
  - If `--node-id` and `--tag` no given, run container on all nodes belong to the user
  - If `--node-id <id>` given, run container on node whose ID is `<id>`
  - if `--tag <key>=<value>` given, run container on nodes that has a tag `<key>` with value `<value>`

