# Ansible setup

This folder contains an ansible setup for `irma_api_server`, along with an example configuration for a vagrant virtual machine in `inventories/dev/`.

## Structure

The `inventories` directory contains all host-specific configuration and data. Each inventory is contained in its own subdirectory of the `inventories` directory, along with any group or host variables and files and possibly a vault (see below). (All such subdirs of the `inventories` directory -- except for the example vagrant setup, see `inventories/dev` -- are .gitignore'd, so that you can put these in your own separate git repos.)

## The play script

Run the ansible playbook using

    ./play [host] [tags]

from the `ansible` directory; for example, `./play dev all`. This would run all roles on the vagrant VM using the inventory file at `inventories/dev/inventory`.

## Inventory contents

The nginx reverse proxy is optional; if you do not need it then (using the vagrant VM) you can run `./play dev setup` (instead of using `all` as the third argument). If you do need it, then defining the `proxy_vhost_name`, `proxy_key` and `proxy_certificate` variables (see for example `inventories/dev/host_vars/vagrant/main.yml`) is mandatory, otherwise the nginx setup will fail. You can also optionally override the variables that have defaults in `roles/apiserver/defaults/main.yml`.

## Vaults

If your inventory is at `inventories/myinv`, then the `play` script will use the vaultkey at `inventories/myinv/vaultkey`, if such a file exists. Note that if this file is executable, then instead of being used directly as the secret key it will be executed, and its output will be used. See [the documentation][1] for more information.

## Setting up the Vagrant VM

Assuming you have Vagrant, Ansible and Virtualbox installed, cd into the `ansible` directory and run `vagrant up`. This will create a new virtual machine, that you can ssh into using `vagrant ssh`. At that point `./play dev all` should work.

[1]: https://docs.ansible.com/ansible/playbooks_vault.html#running-a-playbook-with-vault
