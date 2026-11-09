# txparser

A from-scratch Bitcoin raw transaction parser (Lab 01, blockchain course).

Features:
- CompactSize (VarInt) decoding for all four length classes
- Legacy and SegWit transactions, with byte offsets
- Witness stacks, txid / wtxid, size, stripped size, weight, vsize
- Script disassembly and output classification (p2pk, p2pkh, p2sh, p2wpkh, p2wsh, p2tr, nulldata)
- Addresses (Base58Check, Bech32 / Bech32m), regtest by default

## Usage

    uv sync
    uv run python -m txparser <TX_HEX>
    uv run python -m txparser --mainnet <TX_HEX>

The hex can also be piped in on standard input.

## Tests

    uv run pytest -v
