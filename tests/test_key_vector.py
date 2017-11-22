import json

from unittest import TestCase

from multimerchant.network import BitcoinMainNet
from multimerchant.wallet.keys import PrivateKey
from multimerchant.wallet.keys import PublicKey


class TestKeys(TestCase):
    def test_keys(self):
        with open("tests/keys_test_vector.json", 'r') as f:
            vectors = json.loads(f.read())
        for vector in vectors:
            private_key = PrivateKey.from_wif(
                vector['private_key'], network=BitcoinMainNet)
            public_key = PublicKey.from_hex_key(
                vector['pubkey'], network=BitcoinMainNet)
            self.assertEqual(private_key.get_public_key(), public_key)
            self.assertEqual(public_key.to_address(), vector['address'])
