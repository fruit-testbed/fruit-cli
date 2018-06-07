fruit-cli
=========

A command line app for Fruit clusters.

Usage: `fruit-cli <command>`

Config file:
- Path: `~/.fruit-cli` (permission: 0600)
- Fields
  - Mandatory
    - `email`: user's email address
    - `api-key`: user's API key
  - Optional
    - `server-url`: server's URL (default: `https://fruit-testbed.org/api`)
    - `editor`: editor to edit the config file (default: `nano`)


Commands:
- `register <email-address>`
  - if `<email-address>` has not been registered (a new user), then:
    - the server sends an activation link to user's email address
    - the user activates the account by clicking the link
    - after activating the account, the server sends an API-Key to user's email address
  - if `<email-address>` has been registered, then:
    - the server sends the API-Key to user's email address
- `config [--edit]`
  - if no option given, then print configuration to the standard output
  - if option `--edit` given, open the config file with a text editor (e.g. nano, vi)
- `list-node`: list nodes belong to the user
- `monitor [--node <id>]`
  - if no option given, return all monitoring data of nodes owned by the user
  - if `--node <id>` given, return monitoring data of node with ID=`<id>` and owned by
    the user
- `run-container [--node <id>] [--params <params>] [--command <command>] <name> <image>`
  - if option `--node` not given, run a container on all nodes owned by the user
  - if option `--node <id>` given, run a container on node with ID=`<id>` and owned by
    the user
  - the arguments are:
    - `<name>`: container's name (containers with different name may use the same image)
    - `<image>`: the container's image (Docker is responsible to download the image)
    - `<command>`: a command that will be run in the container in the form of JSON array of 
                   strings
    - `<params>`: parameters to be passed to Docker run in the form of JSON array of strings
                  e.g. `-p 80:80` (publish container's port 80 to host's port 80)
- `list-container [--node <id>]`
  - if `--node` not given, return a list of containers on all nodes owned by the user
  - if `--node <id>` given, return a list of containers on node with ID=`<id>`
    and owned by the user
- `rm-container [--node <id>] <name>`
  - if `--node` not given, remove container `<name>` from all nodes owned by the user
  - if `--node <id>` given, remove container `<name>` from node with ID=`<id>` and owned
    by the user