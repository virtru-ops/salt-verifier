salt-verifier
=============

A library that provides both a client and server that can be used to verify a
salt minion's public key before it is accepted by the master. The server is
meant to run on the minion and listen on port 4533. In order to verify the
public key of the minion, the client generates random challenge messages that
the minion must sign.

Installation
------------

::
    
    $ pip install salt-verifier

Usage
-----

Run the server::
    
    $ salt-verifier-server

It will load the private key of the current minion from
``/etc/salt/pki/minion/minion.pem``.

From the master, verify the minion by using the client library like so::
    
    from saltverifier.client import is_valid_server_public_key

    if is_valid_server_public_key('tcp://minion-ip:4533', 'SOME_PUBLIC_KEY_STR'):
        do-something-when-the-public-is-valid
    else:
        do-something-when-the-public-is-invalid


Install an Upstart Script
-------------------------

For convenience this package provides a command
