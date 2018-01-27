
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

**Simple BIP32 (HD) wallet creation for: BTC, BTG, BCH, ETH, LTC, DASH, DOGE**

BIP32 (or HD for "hierarchical deterministic") wallets allow you to create
child wallets which can only generate public keys and don't expose a
private key to an insecure server.

This library simplify the process of creating new wallets for the
BTC, BTG, BCH, ETH, LTC, DASH and DOGE cryptocurrencies.

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
    w = wallet.create_wallet(network="BTC", seed=seed, children=1)

    print(w)

Output looks like this:

.. code:: bash

    $ python create_btc_wallet.py

    {
      "coin": "BTC",
      "seed": "guess tiny intact poet process segment pelican bright assume avocado view lazy",
      "address": "1HwPm2tcdakwkTTWU286crWQqTnbEkD7av",
      "xprivate_key": "xprv9s21ZrQH143K2Dizn667UCo9oYPdTPSMWq7D5t929aXf1kfnmW79CryavzBxqbWfrYzw8jbyTKvsiuFNwr1JL2qfrUy2Kbwq4WbBPfxYGbg",
      "xpublic_key": "xpub661MyMwAqRbcEhoTt7d7qLjtMaE7rrACt42otGYdhv4dtYzwK3RPkfJ4nEjpFQDdT8JjT3VwQ3ZKjJaeuEdpWmyw16sY9SsoY68PoXaJvfU",
      "wif": "L1EnVJviG6jR2oovFbfxZoMp1JknTACKLzsTKqDNUwATCWpY1Fp4",
      "children": [{
         "address": "1E3btRwsoJx2jUcMnATyx7poHhV2tomL8g",
         "path": "m/0",
         "xpublic_key": "xpub69Fho5TtAbdoXyWzgUV1ZYst9K4bVfoGNLZxQ9u5js4Rb1jEyUjDtoATXbWvAcV8cERCMMnH8wYRVVUsRDSfaMjLqaY3TvD7Am9ALjq5PsG",
         "wif": "KysRDiwJNkS9VPzy1UH76DrCDizsWKtEooSzikich792RVzcUaJP"
     }]
    }

Similarly, you can do the same for an Ethereum wallet:

.. code:: python

    # create_eth_wallet.py

    from pywallet import wallet

    seed = wallet.generate_mnemonic()
    w = wallet.create_wallet(network="ETH", seed=seed, children=1)

    print(w)

Output looks like this (no WIF for Ethereum):

.. code:: bash

    $ python create_eth_wallet.py

    {
      "coin": "ETH",
      "seed": "traffic happy world clog clump cattle great toy game absurd alarm auction",
      "address": "0x3b777f60eb04fcb13e6b27e468532e491409722e",
      "xprivate_key": "xprv9yTuSjwb95QZznV6epMWpb4Kpc2S8ZRaQuAf5B697YXtQD2tDmmJ5KvwJWVjtbVrdJ1WBKNnuodrpTKGfHfiPSEgrAxUjL5RP1gQwwT3fFx",
      "xpublic_key": "xpub6GhhMtkVjoPi5DKtqapKzMzrzdGjo1EPc7Ka6KdeoXYdCrTBH1Hu1wKysm8boWSy8VeTKVJi6gQJ2qJ4YG2ZhvFDcUUgMJrFCJWN1PGtBry",
      "wif": "",
      "children": [{
        "address": "0x87eb82d43fa7316df0a989c0d951a9037ed02f9b",
        "path": "m/0",
        "xpublic_key": "xpub6LnpVXD73jNuAYXxzQCnEY6wXQspwkiAEkZWoX4BW9Tzx6KbUrMUYAU1Yvw4kebPHSPiEJPo8irHWHSwQR6WuVwUj85xURsugPWeJVH6sau",
        "wif": ""
      }]
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
    {
      "address": "13myudz3WhpBezoZue6cwRUoHrzWs4vCrb",
      "path": "m/0/395371597"
    }
    Random Address
    {
      "address": "1KpS2wC5J8bDsGShXDHD7qdGvnic1h27Db",
      "path": "m/0/394997119"
    }

-----

IMPORTANT
=========

I **highly** recommend that you familiarize yourself with the Blockchain technology and
be aware of security issues.
Reading `Mastering Bitcoin <https://github.com/bitcoinbook/bitcoinbook>`_ and going over
Steven Buss's security notes on the `Bitmerchant repository <https://github.com/sbuss/bitmerchant>`_
is a good start.

Enjoy!
