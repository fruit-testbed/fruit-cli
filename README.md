fruit-cli
=========

A command line app for Fruit clusters.

Usage: `fruit-cli <command>`

Config file:
- Path: `~/.fruit-cli.json` (permission: 0600)
- Fields
  - Mandatory
    - `email`: user's email address
    - `api-key`: user's API key
  - Optional
    - `server-url`: server's URL (default: `https://fruit-testbed.org/api`)
    - `editor`: editor to edit the config file (default: `nano`)

Commands:
- `register <email-address>`
  - for a new user
    - server sends an activation link to user's email address
    - user activates the account by clicking the link
    - after activating the account, the server sends an API-Key to user's email address
  - for an existing user
    - server sends the API-Key to user's email address
- `config`
  - no-option given, then print configuration to STDOUT
  - option `--edit` given, open the config file with a text editor (e.g. nano, vi)
- `node`: list nodes belong to the user
- `monitor [--node <id>]`
  - If `--node` not given, returns all monitoring data of nodes belong to the user
  - If `--node <id>` given, returns monitoring data of node with ID=`<id>`,
    if the node is belong to the user
- `run [--node <id>] [--params <params>] [--command <command>] <name> <image>`
  - `<name>`: container's name
  - `<image>`: the container image to be run
  - `<command>`: a command that will be run in the container
  - `<params>`: parameters to be passed to Docker run
  - If `--node <id>` given, run container on node with ID=`<id>`