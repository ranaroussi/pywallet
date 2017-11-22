"""Generate BIP32 wallet test vectors from pycoin"""
import argparse
from binascii import hexlify
from hashlib import sha256
import json
import random

from pycoin.wallet import Wallet


def dump_node(node):
    return {
        'private_key': node.wallet_key(True),
        'wif': node.wif(),
        'public_key': node.wallet_key(False),
        'chain_code': hexlify(node.chain_code),
        'fingerprint': hexlify(node.fingerprint()),
        'depth': node.depth,
        'secret_exponent': node.secret_exponent,
    }


def get_new_address(wallet_num):
    passphrase = sha256(b"%s" % random.randint(0, 2**30)).hexdigest()
    wallet = Wallet.from_master_secret(passphrase)
    ret = dump_node(wallet)
    children = []
    # Now build up some random paths
    # Just go five deep
    path = "m"
    for depth in range(5):
        child_number = random.randint(0, 0x80000000)
        path = "%s/%s" % (path, child_number)
        prime = random.choice([True, False])
        if prime:
            path += "'"
        children.append(
            {"path": path,
             "child": dump_node(wallet.subkey_for_path(path[2:]))})
    ret['children'] = children
    return ret


def generate_address_vector(outfile, num_addresses, seed):
    if args.seed:
        random.seed(args.seed)
    with open(outfile, 'w') as f:
        f.write("[\n")
        for i in range(num_addresses):
            f.write(json.dumps(get_new_address(i)))
            if i < (num_addresses - 1):
                f.write(",")
            f.write("\n")
        f.write("]")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate test vectors for pub/private key validation")
    parser.add_argument("-o", "--output", help="output file path",
                        default="tests/bip32_test_vector.json")
    parser.add_argument("-n", "--num-keys", type=int, default=100,
                        help="Number of keys to generate")
    parser.add_argument("-s", "--seed", type=int, default=1234,
                        help="The random seed for random wallets. Optional.")
    args = parser.parse_args()
    generate_address_vector(
        outfile=args.output, num_addresses=args.num_keys, seed=args.seed)
