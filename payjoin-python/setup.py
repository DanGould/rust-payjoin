#!/usr/bin/env python

from setuptools import setup

LONG_DESCRIPTION = """# payjoinpython
The Python language bindings for the [Bitcoin Dev Kit](https://github.com/bitcoindevkit).

## Install the package
```shell
pip install payjoinpython
```

## Simple example
```python
import payjoinpython as payjoin


descriptor = payjoin.Descriptor("wpkh(tprv8ZgxMBicQKsPcx5nBGsR63Pe8KnRUqmbJNENAfGftF3yuXoMMoVJJcYeUw5eVkm9WBPjWYt6HMWYJNesB5HaNVBaFc1M6dRjWSYnmewUMYy/84h/0h/0h/0/*)", payjoin.Network.TESTNET) 
db_config = payjoin.DatabaseConfig.MEMORY()
blockchain_config = payjoin.BlockchainConfig.ELECTRUM(
    payjoin.ElectrumConfig(
        "ssl://electrum.blockstream.info:60002",
        None,
        5,
        None,
        100,
        True,
    )
)
blockchain = payjoin.Blockchain(blockchain_config)

wallet = payjoin.Wallet(
             descriptor=descriptor,
             change_descriptor=None,
             network=payjoin.Network.TESTNET,
             database_config=db_config,
         )

# print new receive address
address_info = wallet.get_address(payjoin.AddressIndex.LAST_UNUSED())
address = address_info.address
index = address_info.index
print(f"New BIP84 testnet address: {address} at index {index}")


# print wallet balance
wallet.sync(blockchain, None)
balance = wallet.get_balance()
print(f"Wallet balance is: {balance.total}")
"""

setup(
    name="payjoinpython",
    version="0.29.0.dev0",
    description="The Python language bindings for the Bitcoin Development Kit",
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    include_package_data = True,
    zip_safe=False,
    packages=["payjoinpython"],
    package_dir={"payjoinpython": "./src/payjoinpython"},
    url="https://github.com/bitcoindevkit/payjoin-ffi",
    author="Alekos Filini <alekos.filini@gmail.com>, Steve Myers <steve@notmandatory.org>",
    license="MIT or Apache 2.0",
    # This is required to ensure the library name includes the python version, abi, and platform tags
    # See issue #350 for more information
    has_ext_modules=lambda: True,
)
