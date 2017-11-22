
PyWallet
===========

.. image:: https://img.shields.io/pypi/pyversions/pywallet.svg?maxAge=60
    :target: https://pypi.python.org/pypi/pywallet
    :alt: Python version

.. image:: https://img.shields.io/pypi/v/pywallet.svg?maxAge=60
    :target: https://pypi.python.org/pypi/pywallet
    :alt: PyPi version

.. image:: https://img.shields.io/pypi/status/pywallet.svg?maxAge=60
    :target: https://pypi.python.org/pypi/pywallet
    :alt: PyPi status

\

**Simple BIP32 (HD) wallet creation for: BTC, BTG, BCH, LTC, DASH, DOGE**

BIP32 (or HD for "hierarchical deterministic") wallets allow you to create
child wallets which can only generate public keys and don't expose a
private key to an insecure server.

This library simplify the process of creating new wallets for the
BTC, BTG, BCH, LTC, DASH and DOGE cryptocurrencies.

Most of the code here is forked from:

- Steven Buss's `Bitmerchant <https://github.com/sbuss/bitmerchant>`_ (original)
- BlockIo's `multimerchant-python <https://github.com/BlockIo/multimerchant-python>`_ (fork of Bitmerchant)
- Michail Brynard's `Ethereum BIP44 Python <https://github.com/michailbrynard/ethereum-bip44-python>`_

I simply added support for a few more cryptocurrencies (BCH, BTG, DASH), as well as created
methods to simplify the creation of HD wallets and child wallets.

Enjoy!

--------------

Installation
-------------

Install via PiP:

.. code:: bash

   $ sudo pip install pywallet


Example code:
=============

Create HD Wallet
----------------

The following code creates a new Bitcoin HD wallet:

.. code:: python

    # create_btc_wallet.py

    from pywallet import wallet

    # generate 12 word mnemonic seed
    seed = wallet.generate_mnemonic()

    # create bitcoin wallet
    w = wallet.create_wallet(network="BTC", seed=seed)

    print(w)

Output looks like this:

.. code:: bash

    $ python create_btc_wallet.py

    {
     'coin': 'BTC',
     'seed': 'tool innocent picnic fluid silent ask minute scheme rural crumble decrease rescue',
     'address': '1CPG2MU2fbXKfqi3pdBF3WaiodE28uB6ns',
     'xprivate_key': 'xprv9s21ZrQH143K4WwrikXgmThRVAXko6oSNKcG5AUyRhYQCmmUX18eZUpcB98T3DP73jqgq7JrLEaXLkUs5cQ4HnCmtVuNVTbfRx9GRB1duuX',
     'xpublic_key': 'xpub661MyMwAqRbcH12Kpn4h8beA3CNFCZXHjYXrsYtaz35P5a6d4YSu7H962Rt1nzo6q5rhHmTCTcxSaNFG2UtAQdy4pAuLqaz5gAmSx76t5Ab',
     'wif': 'KzkcdtrAPY3CctyzLJARA3rC8gUHEdrk1V8hN3GGE2UHJvaFEhA2'
    }

Similarly, you can do the same for an Ethereum wallet:

.. code:: python

    # create_eth_wallet.py

    from pywallet import wallet

    seed = wallet.generate_mnemonic()
    w = wallet.create_wallet(network="ETH", seed=seed)

    print(w)

Output looks like this (no WIF for Ethereum):

.. code:: bash

    $ python create_eth_wallet.py

    {
     'coin': 'ETH',
     'seed': 'cactus father lecture ahead strategy parrot genre kind crew lock merit unfair',
     'address': '0x6497148e392fc5703db95be03cc5cbb81009d3b2',
     'xprivate_key': 'xprv9zJtR6McPYXYpQGeUgAy219NSPBiHXmP8kzwsMJVRjGd86r4cDgZotQJaXH1TAZ2MSFKoPE6pYUe3cTEgRAdwXKt9enhoc7PnF7opkwdBqP',
     'xpublic_key': 'xpub6DJEpbtWDv5r2tM7ahhyP966zR2CgzVEVyvYfji6z4obzuBD9kzpMginRnczVeuxXjvQFEGDEgdKzTB4r8Q2aUUa5GAZxDfogChbrZxj3Cj',
     'wif': ''
    }

\* Valid options for `network` are: BTC, BTG, BCH, LTC, DASH, DOGE

Create Child Wallet
-------------------

You can create child-wallets (BIP32 wallets) from the HD wallet's
**Extended Public Key** to generate new public addresses without
revealing your private key.

Example:

.. code-block:: python

    # create_child_wallet.py

    from pywallet import wallet

    WALLET_PUBKEY = 'YOUR WALLET XPUB'

    # generate address for specific user (id = 10)
    user_addr = wallet.create_address(network="BTC", xpub=WALLET_PUBKEY, child=10)

    # or generate a random address, based on timestamp
    rand_addr = wallet.create_address(network="BTC", xpub=WALLET_PUBKEY)

    print("User Address\n", user_addr)
    print("Random Address\n", rand_addr)

Output looks like this:

.. code:: bash

    $ python create_child_wallet.py

    User Address
     1FxgaPRGHcY7JGg5jqdwx4kYgiP3xB1aX7
    Random Address
     1KpS2wC5J8bDsGShXDHD7qdGvnic1h27Db

-----

IMPORTANT
=========

I **highly** recommend that you familiarize yourself with the Blockchain technology and
be aware of security issues.
Reading `Mastering Bitcoin <https://github.com/bitcoinbook/bitcoinbook>`_ and going over
Steven Buss's security notes on the `Bitmerchant repository <https://github.com/sbuss/bitmerchant>`_
is a good start.

Enjoy!
