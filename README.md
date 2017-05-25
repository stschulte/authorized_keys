# lookup-ssh-pubkey

## Background

If you are using ssh you probably already know of public key
authentication. For this to work you normally have a file
`$HOME/.ssh/authorized_keys` in each users homedirectory.

While this works pretty well it can be hard to ship these
public keys. This gets even more hard when user home
directories are not guranteed to even exist.

Imagine you have 20 LDAP users. The homedirectory will only
be created after the first login. So you cannot deploy the
`authorized_keys` file beforehand (or your deployment
mechanism needs to create all homedirectories first).

For this scenario you can now deploy all keys to a common
directory and use a custom command to retrieve the keys.

## How to use

The `lookup-ssh-pubkey` executable can be used as a local
lookup method to retrieve public authorized ssh keys.

It is intended to be used by openssh. In `sshd_config` just
specify

    AuthorizedKeysCommand /path/to/lookup-ssh-pubkey
    AuthorizedKeysCommandUser nobody

The command will check if there is a file

    /etc/ssh-public-keys.d/<username>.pub

present that should have the same format as a
normale `.ssh/authorized_keys` file.

## Security considerations

The public keys should be **readable** for everyone as the
`lookup-ssh-pubkey` should normally run as user nobody.
The keyfiles itself should only be writeable by the owner and
should be owned by either root or the corresponding user the
keyfile belongs to. This is important so no user can write
its own public key to the `authorized_keys` file of a different
user.

The `lookup-ssh-pubkey` will raise an error if this condition is
not met. The same goes for each parent directory. If a parent
directory would be writeable by someone else, an attacker would
be able to remove a key (or a part of the directory tree) and
replace it with a new keyfile (or directory tree). This
condition will also be tested.

## How to build

you can build and install the package locally with the following
commands

    mkdir build
    cd build
    cmake ..
    make
    make install

