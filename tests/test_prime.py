#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pywallet import wallet

seed = 'horror please embark security repair unfair stock stone engage taxi diesel silent'

for net in ["BTC", "DOGE", "LTC", "BCH", "BTG", "DASH", "ETH"]:
    my_wallet = wallet.create_wallet(net, seed)
    print("----------------------------")
    print(net)
    print(my_wallet['xpublic_key'])
    print(wallet.create_address(net, my_wallet['xpublic_key'], child=0, is_prime=True))

print("----------------------------")