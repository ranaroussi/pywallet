from multimerchant.wallet import Wallet
import time
from block_io import BlockIo
import six
import os
import sys

try:
    os.environ["HD_PRIVKEY"]
except KeyError:
    print("Please generate an HD wallet first. See README.rst on https://github.com/blockio/multimerchant-python")
    print("Or do this:")
    print("\t $ python")
    print("\t >> from multimerchant.wallet import Wallet")
    print("\t >> print \"My HD Private Key:\", Wallet.new_generate_wallet(network=\"DOGETEST\")")
    print("\t >> quit()")
    print("\t $ HD_PRIVKEY=STRING_FROM_ABOVE python sweeper.py")
    print("... where sweeper.py is this file.")
    sys.exit(1)

# Please use the Dogecoin Testnet here -- you have free coins on sign up at Block.io
# Dogecoin Testnet because of the static demo amount for withdrawals/sweeps below
block_io = BlockIo('Your Dogecoin Testnet API Key', 'Your Secret PIN', 2)

network = block_io.get_balance()['data']['network'] # extract the network of our API Key

# create a wallet using a master secret -- this one is super insecure, but it's an example
# don't have an HD privkey yet? Create one by using:
#
#    $ python
#    >> from multimerchant.wallet import Wallet
#    >> hd_privkey = Wallet.new_random_wallet(network="DOGETEST").serialize()
#    >> print "My Super Secret HD Wallet:", hd_privkey
#
# The 'network' value above can be: BTC, BTCTEST, DOGE, DOGETEST, LTC, LTCTEST
# Get the relevant network's API Key at Block.io for use in this example

w = Wallet.deserialize(os.environ['HD_PRIVKEY'], network=network)

# or generate an insecure version like this:
# w = Wallet.from_master_secret("correct horse battery staple", network=network)

# BIP32 wallets are children derived from a single master seed (you generated this with the instructions above)
# You can specify a child by an ID. For instance, for child_id=1:

# let's generate 5 wallets

addresses = []
children = [] # the payment addresses we'll generate from the seed

for child_id in range(1,6):
    child = w.get_child(child_id, is_prime=True, as_private=True)
    addresses.insert(len(addresses), child.to_address())
    children.insert(len(children), child)

    six.print_("Child No.", child_id, ". Address="+child.to_address(), "PrivKey="+child.export_to_wif())

# check the balance for these addresses using Block.io
all_addresses = ','.join(str(x) for x in addresses)

response = block_io.get_address_balance(addresses=all_addresses) # the addresses parameter can be a comma-separated list of addresses here

# NOTE: Amounts deposited into addresses through Block.io green addresses will be immediately available
# even with 0 confirmations
six.print_(">> Total Balance in All Addresses:", response['data']['available_balance'], network)

for addrinfo in response['data']['balances']:
    six.print_(" >> Balances in", addrinfo['address'])
    six.print_(" >>> Available:", addrinfo['available_balance'], network) # either confirmed or from a green address
    six.print_(" >>> Pending:", addrinfo['pending_received_balance'], network) # is neither from a green address, nor is it confirmed

# let's transfer some testnet coins into the first child address
amounts = "500.0" # DOGETEST
response = block_io.withdraw(to_addresses=children[0].to_address(), amounts=amounts)

six.print_("* Depositing", amounts, network, "into", children[0].to_address())
six.print_(">> Deposit Proof Transaction ID:", response['data']['txid']) # you can view this on https://chain.so immediately

time.sleep(2) # let the transaction propagate on the network for a bit

# so far so good. Let's sweep the coins out of the first child, and into the second child
# NOTE: While you can specify the number of confirmations required for coins to be swept, 
# please beware that deposits from green addresses will show as available in get_address_balance calls.
# This might cause confusion when the sweep_from_address call returns an error when sweeping amounts with
# confirmations > 0

six.print_("* Sweeping all funds (confirmed and unconfirmed) from", children[0].to_address(), "to", children[1].to_address())
response = block_io.sweep_from_address(from_address=children[0].to_address(), private_key=children[0].export_to_wif(), to_address=children[1].to_address())


six.print_(">> Amount swept from", children[0].to_address(), "into", children[1].to_address(), "=", response['data']['amount_sent'], network)
six.print_(">> Transaction ID:", response['data']['txid'])

# Note: the swept amount does not need to be confirmed. In the above case, the amount was not confirmed
# but was swept into the destination address immediately
# You can sweep only confirmed amounts if you wish by adding "confirmations=X" to the sweep_from_address call,
# where X is the number of confirmations

