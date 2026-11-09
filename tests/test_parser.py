import pytest
from txparser.parser import parse_transaction, serialize

GENESIS = ("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000")

PARTB = ("02000000000101bc739ec884ed994366dec38fe1947b091e63ab1a1f03964e65088d271da4b4fe0000000000fdffffff0200ca9a3b00000000160014945a773b2d3fd4c7a114b1359aa0fa7e584514f8f0006bee00000000160014cb444832ccae1872e25227ffa797ecfb27022f6d0247304402201006ed65fa06c4673ed6679f8cf873a21c6d6065010d1553090a0bda78d0a636022062c64e9cc93c120802d714f7421086fb6529cdbb6f343fb7298241565a9032160121024fe202e0cca6d6987cf1e74f29865af1d3e633a8044fd69071763894ea54522400000000")


def test_genesis_legacy():
    tx = parse_transaction(GENESIS)
    assert not tx.segwit
    assert tx.inputs[0].offset == 5
    assert tx.txid == "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    assert tx.wtxid == tx.txid
    assert tx.outputs[0].value == 5_000_000_000
    assert serialize(tx, True) == bytes.fromhex(GENESIS)


def test_partb_segwit():
    tx = parse_transaction(PARTB)
    assert tx.segwit
    assert tx.inputs[0].offset == 7
    assert len(tx.inputs[0].witness) == 2
    assert tx.inputs[0].sequence == 0xFFFFFFFD
    assert tx.txid == "aabee579c7bce6dadc83ba85d98aedb8f9ac583e91cda90ad025835f382c50ce"
    assert tx.wtxid == "cdb09d924076dd053bebf317220a3a7f8a5e28e898f6c32f690018ca6e27ef80"
    assert (tx.size, tx.stripped_size, tx.weight, tx.vsize) == (222, 113, 561, 141)
    assert [o.value for o in tx.outputs] == [1_000_000_000, 3_999_990_000]
    assert serialize(tx, True) == bytes.fromhex(PARTB)


def test_robustesse():
    with pytest.raises(ValueError):
        parse_transaction(PARTB[:-10])
    with pytest.raises(ValueError):
        parse_transaction(PARTB + "00")
    with pytest.raises(ValueError):
        parse_transaction("zzzz")
    with pytest.raises(ValueError):
        parse_transaction("")
