class BitcoinGoldMainNet(object):
    """Bitcoin Gold MainNet version bytes. """
    NAME = "Bitcoin Gold Main Net"
    COIN = "BTG"
    SCRIPT_ADDRESS = 0x17  # int(0x17) = 23
    PUBKEY_ADDRESS = 0x26  # int(0x26) = 38  # Used to create payment addresses
    SECRET_KEY = 0x80      # int(0x80) = 128  # Used for WIF format
    EXT_PUBLIC_KEY = 0x0488b21E  # Used to serialize public BIP32 addresses
    EXT_SECRET_KEY = 0x0488ADE4  # Used to serialize private BIP32 addresses
    BIP32_PATH = "m/44'/0'/0'/"


class BitcoinCashMainNet(object):
    """Bitcoin Cash MainNet version bytes."""
    NAME = "Bitcoin Cash Main Net"
    COIN = "BCH"
    SCRIPT_ADDRESS = 0x28  # int(0x28) = 40
    PUBKEY_ADDRESS = 0x1C  # int(0x00) = 28  # Used to create payment addresses
    SECRET_KEY = 0x80      # int(0x80) = 128  # Used for WIF format
    EXT_PUBLIC_KEY = 0x0488b21E  # Used to serialize public BIP32 addresses
    EXT_SECRET_KEY = 0x0488ADE4  # Used to serialize private BIP32 addresses
    BIP32_PATH = "m/44'/145'/0'/"


class DashMainNet(object):
    """Dash MainNet version bytes."""
    NAME = "Dash Main Net"
    COIN = "DASH"
    SCRIPT_ADDRESS = 0x10  # int(0x10) = 16
    PUBKEY_ADDRESS = 0x4C  # int(0x4C) = 76  # Used to create payment addresses
    SECRET_KEY = 0xCC      # int(0xCC) = 204  # Used for WIF format
    EXT_PUBLIC_KEY = 0X0488B21E  # Used to serialize public BIP32 addresses
    EXT_SECRET_KEY = 0X0488ADE4  # Used to serialize private BIP32 addresses
    BIP32_PATH = "m/44'/5'/0'/"


class DashTestNet(object):
    """Dash TestNet version bytes."""
    NAME = "Dash Test Net"
    COIN = "DASH"
    SCRIPT_ADDRESS = 0x13  # int(0x13) = 19
    PUBKEY_ADDRESS = 0x8C  # int(0x8C) = 140  # Used to create payment addresses
    SECRET_KEY = 0xEF      # int(0xEF) = 239  # Used for WIF format
    EXT_PUBLIC_KEY = 0x043587CF  # Used to serialize public BIP32 addresses
    EXT_SECRET_KEY = 0x04358394  # Used to serialize private BIP32 addresses
    BIP32_PATH = "m/44'/1'/0'/"

class OmniMainNet(object):
    """Bitcoin MainNet version bytes.
    From https://github.com/OmniLayer/omnicore/blob/develop/src/chainparams.cpp
    """
    NAME = "Omni Main Net"
    COIN = "USDT"
    SCRIPT_ADDRESS = 0x00  # int(0x00) = 0
    PUBKEY_ADDRESS = 0x05  # int(0x05) = 5  # Used to create payment addresses
    SECRET_KEY = 0x80      # int(0x80) = 128  # Used for WIF format
    EXT_PUBLIC_KEY = 0x0488B21E  # Used to serialize public BIP32 addresses
    EXT_SECRET_KEY = 0x0488ADE4  # Used to serialize private BIP32 addresses
    BIP32_PATH = "m/44'/0'/0'/"

class OmniTestNet(object):
    """Bitcoin MainNet version bytes.
    From https://github.com/OmniLayer/omnicore/blob/develop/src/chainparams.cpp
    """
    NAME = "Omni Test Net"
    COIN = "USDT"
    SCRIPT_ADDRESS = 0x6f  # int(0x6f) = 111
    PUBKEY_ADDRESS = 0xc4  # int(0xc4) = 196  # Used to create payment addresses
    SECRET_KEY = 0xef      # int(0xef) = 239  # Used for WIF format
    EXT_PUBLIC_KEY = 0x043587CF  # Used to serialize public BIP32 addresses
    EXT_SECRET_KEY = 0x04358394  # Used to serialize private BIP32 addresses
    BIP32_PATH = "m/44'/0'/0'/"

class BitcoinMainNet(object):
    """Bitcoin MainNet version bytes.
    From https://github.com/bitcoin/bitcoin/blob/v0.9.0rc1/src/chainparams.cpp
    """
    NAME = "Bitcoin Main Net"
    COIN = "BTC"
    SCRIPT_ADDRESS = 0x05  # int(0x05) = 5
    PUBKEY_ADDRESS = 0x00  # int(0x00) = 0  # Used to create payment addresses
    SECRET_KEY = 0x80      # int(0x80) = 128  # Used for WIF format
    EXT_PUBLIC_KEY = 0x0488B21E  # Used to serialize public BIP32 addresses
    EXT_SECRET_KEY = 0x0488ADE4  # Used to serialize private BIP32 addresses
    BIP32_PATH = "m/44'/0'/0'/"

class FeathercoinMainNet(object):
    """Feathercoin MainNet version bytes.
    From https://github.com/FeatherCoin/Feathercoin/blob/master-0.13/src/chainparams.cpp
    """
    NAME = "Feathercoin Main Net"
    COIN = "FTC"
    SCRIPT_ADDRESS = 0x05  # int(0x05) = 5
    PUBKEY_ADDRESS = 0x0E  # int(0x0E) = 14  # Used to create payment addresses
    SECRET_KEY = 0x8E      # int(0x8E) = 142  # Used for WIF format
    EXT_PUBLIC_KEY = 0x0488BC26  # Used to serialize public BIP32 addresses
    EXT_SECRET_KEY = 0x0488DAEE  # Used to serialize private BIP32 addresses
    BIP32_PATH = "m/44'/4'/0'/"

class BitcoinTestNet(object):
    """Bitcoin TestNet version bytes.
    From https://github.com/bitcoin/bitcoin/blob/v0.9.0rc1/src/chainparams.cpp
    """
    NAME = "Bitcoin Test Net"
    COIN = "BTC"
    SCRIPT_ADDRESS = 0xc4  # int(0xc4) = 196
    PUBKEY_ADDRESS = 0x6f  # int(0x6f) = 111
    SECRET_KEY = 0xEF      # int(0xef) = 239
    EXT_PUBLIC_KEY = 0x043587CF
    EXT_SECRET_KEY = 0x04358394
    BIP32_PATH = "m/44'/1'/0'/"


class LitecoinMainNet(object):
    """Litecoin MainNet version bytes

    Primary version bytes from:
    https://github.com/litecoin-project/litecoin/blob/master-0.8/src/base58.h

    Unofficial extended version bytes from
    https://bitcointalk.org/index.php?topic=453395.0
    """
    NAME = "Litecoin Main Net"
    COIN = "LTC"
    SCRIPT_ADDRESS = 0x05  # int(0x05) = 5
    PUBKEY_ADDRESS = 0x30  # int(0x30) = 48
    SECRET_KEY = PUBKEY_ADDRESS + 128  # = int(0xb0) = 176

    # Unofficial extended version bytes taken from
    # https://bitcointalk.org/index.php?topic=453395.0
    # EXT_PUBLIC_KEY = 0x019da462
    # EXT_SECRET_KEY = 0x019d9cfe

    # same as Bitcoin's
    # https://github.com/ranaroussi/pywallet/issues/6
    EXT_PUBLIC_KEY = 0x0488B21E
    EXT_SECRET_KEY = 0x0488ADE4

    BIP32_PATH = "m/44'/2'/0'/"

class LitecoinTestNet(object):
    """Litecoin TestNet version bytes

    Primary version bytes from:
    https://github.com/litecoin-project/litecoin/blob/master-0.8/src/base58.h

    Unofficial extended version bytes from
    https://bitcointalk.org/index.php?topic=453395.0
    """
    NAME = "Litecoin Test Net"
    COIN = "LTC"
    SCRIPT_ADDRESS = 0xc4  # int(0xc4) = 196
    PUBKEY_ADDRESS = 0x6f  # int(0x6f) = 111
    SECRET_KEY = PUBKEY_ADDRESS + 128  # = int(0xef) = 239

    # Unofficial extended version bytes taken from
    # https://bitcointalk.org/index.php?topic=453395.0
    # EXT_PUBLIC_KEY = 0x0436f6e1
    # EXT_SECRET_KEY = 0x0436ef7d

    # same as Bitcoin's
    # https://github.com/ranaroussi/pywallet/issues/6
    EXT_PUBLIC_KEY = 0x043587CF
    EXT_SECRET_KEY = 0x04358394

    BIP32_PATH = "m/44'/1'/0'/"


class DogecoinMainNet(object):
    """Dogecoin MainNet version bytes

    Primary version bytes from:
    https://github.com/dogecoin/dogecoin/blob/1.5.2/src/base58.h

    Unofficial extended version bytes from
    https://bitcointalk.org/index.php?topic=409731
    """
    NAME = "Dogecoin Main Net"
    COIN = "DOGE"
    SCRIPT_ADDRESS = 0x16  # int(0x16) = 22
    PUBKEY_ADDRESS = 0x1e  # int(0x1e) = 30
    SECRET_KEY = PUBKEY_ADDRESS + 128  # int(0x9e) = 158

    # Unofficial extended version bytes taken from
    # https://bitcointalk.org/index.php?topic=409731
    EXT_PUBLIC_KEY = 0x02facafd
    EXT_SECRET_KEY = 0x02fac398
    BIP32_PATH = "m/44'/3'/0'/"


class DogecoinTestNet(object):
    """Dogecoin TestNet version bytes

    Primary version bytes from:
    https://github.com/dogecoin/dogecoin/blob/1.5.2/src/base58.h

    Unofficial extended version bytes from
    https://bitcointalk.org/index.php?topic=409731
    """
    NAME = "Dogecoin Test Net"
    COIN = "DOGE"
    SCRIPT_ADDRESS = 0xc4  # int(0xc4) = 196
    PUBKEY_ADDRESS = 0x71  # int(0x71) = 113
    SECRET_KEY = PUBKEY_ADDRESS + 128  # int(0xf1) = 241

    # Unofficial extended version bytes taken from
    # https://bitcointalk.org/index.php?topic=409731
    EXT_PUBLIC_KEY = 0x0432a9a8
    EXT_SECRET_KEY = 0x0432a243
    BIP32_PATH = "m/44'/1'/0'/"


class BlockCypherTestNet(object):
    """BlockCypher TestNet version bytes.
    From http://dev.blockcypher.com/#testing
    """
    NAME = "BlockCypher Test Net"
    COIN = "BlockCypher"
    SCRIPT_ADDRESS = 0x1f  # int(0x1f) = 31
    PUBKEY_ADDRESS = 0x1b  # int(0x1b) = 27  # Used to create payment addresses
    SECRET_KEY = 0x49      # int(0x49) = 73  # Used for WIF format
    EXT_PUBLIC_KEY = 0x2d413ff  # Used to serialize public BIP32 addresses
    EXT_SECRET_KEY = 0x2d40fc3  # Used to serialize private BIP32 addresses
    BIP32_PATH = "m/44'/1'/0'/"


class QtumMainNet(object):
    """Qtum MainNet version bytes

    Primary version bytes from:
    https://github.com/qtumproject/qtum/blob/master/src/chainparams.cpp
    """
    NAME = "Qtum Main Net"
    COIN = "QTUM"
    SCRIPT_ADDRESS = 0x32  # int(0x32) = 50
    PUBKEY_ADDRESS = 0x3A  # int(0x3A) = 58  # Used to create payment addresses
    SECRET_KEY = 0x80      # int(0x80) = 128  # Used for WIF format
    EXT_PUBLIC_KEY = 0x0488B21E  # Used to serialize public BIP32 addresses
    EXT_SECRET_KEY = 0x0488ADE4  # Used to serialize private BIP32 addresses
    BIP32_PATH = "m/44'/88'/0'/"


class QtumTestNet(object):
    """Qtum TestNet version bytes

    Primary version bytes from:
    https://github.com/qtumproject/qtum/blob/master/src/chainparams.cpp
    """
    NAME = "Qtum Test Net"
    COIN = "QTUM"
    SCRIPT_ADDRESS = 0x6E  # int(0x6e) = 110
    PUBKEY_ADDRESS = 0x78  # int(0x78) = 120
    SECRET_KEY = 0xEF      # int(0xef) = 239
    EXT_PUBLIC_KEY = 0x043587CF
    EXT_SECRET_KEY = 0x04358394
    BIP32_PATH = "m/44'/88'/0'/"
 

 class BitcoreMainNet(object):
    """BitCore MainNet version bytes.
    From https://github.com/LIMXTEC/BitCore/blob/0.15/src/chainparams.cpp
    """
    NAME = "BitCore Main Net"
    COIN = "BTX"
    SCRIPT_ADDRESS = 0x7D  # int(0x7D) = 125
    PUBKEY_ADDRESS = 0x03  # int(0x03) = 3  # Used to create payment addresses
    SECRET_KEY = 0x80      # int(0x80) = 128  # Used for WIF format
    EXT_PUBLIC_KEY = 0x0488B21E # Used to serialize public BIP32 addresses
    EXT_SECRET_KEY = 0x0488ADE4  # Used to serialize private BIP32 addresses
    BIP32_PATH = "m/44'/160'/0'/"
    
class BitcoreTestNet(object):
    """BitCore TestNet version bytes.
    From https://github.com/LIMXTEC/BitCore/blob/0.15/src/chainparams.cpp
    """
    NAME = "BitCore Test Net"
    COIN = "BTX"
    SCRIPT_ADDRESS = 0xC4  # int(0xC4) = 196
    PUBKEY_ADDRESS = 0x6F  # int(0x6F) = 111  # Used to create payment addresses
    SECRET_KEY = 0xEF      # int(0xEF) = 239  # Used for WIF format
    EXT_PUBLIC_KEY = 0x043587CF # Used to serialize public BIP32 addresses
    EXT_SECRET_KEY = 0x04358394  # Used to serialize private BIP32 addresses
    BIP32_PATH = "m/44'/1'/0'/"
    
