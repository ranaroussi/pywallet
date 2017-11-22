"""Generate a JSON dump of keys for validating multimerchant.wallet.keys.

First install bitcoind and run

$ touch fakewallet.dat
$ bitcoind --rpcuser=bitcoinrpc --rpcpassword=multimerchanttest --server --wallet=fakewallet.dat
$ python generate_test_keys.py -o test_keys.json
"""
import argparse
import json
import pyjsonrpc

client = pyjsonrpc.HttpClient(
    'http://localhost:8332',
    username='bitcoinrpc',
    password='multimerchanttest')


def get_new_address():
    address = client.getnewaddress()
    private_key = client.dumpprivkey(address)
    address_info = client.validateaddress(address)
    assert address_info['isvalid']
    data = {
        'private_key': private_key,
        'iscompressed': address_info['iscompressed'],
        'address': address,
        'pubkey': address_info['pubkey'],
    }
    return data


def generate_address_vector(outfile, num_addresses):
    with open(outfile, 'w') as f:
        f.write("[\n")
        for i in range(num_addresses):
            f.write(json.dumps(get_new_address()))
            if i < (num_addresses - 1):
                f.write(",")
            f.write("\n")
        f.write("]")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate test vectors for pub/private key validation")
    parser.add_argument("-o", "--output", help="output file path",
                        default="tests/keys_test_vector.json")
    parser.add_argument("-n", "--num-keys", type=int, default=1000,
                        help="Number of keys to generate")
    args = parser.parse_args()
    generate_address_vector(outfile=args.output, num_addresses=args.num_keys)
