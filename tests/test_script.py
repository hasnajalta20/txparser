from txparser.script import address, classify, disassemble

H20 = bytes.fromhex("62e907b15cbf27d5425399ebf6f0fb50ebb88f18")


def test_p2pkh():
    s = b"\x76\xa9\x14" + H20 + b"\x88\xac"
    assert classify(s) == "p2pkh"
    assert disassemble(s) == f"OP_DUP OP_HASH160 <{H20.hex()}> OP_EQUALVERIFY OP_CHECKSIG"
    assert address(s, "mainnet") == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"


def test_p2sh():
    s = b"\xa9\x14" + H20 + b"\x87"
    assert classify(s) == "p2sh"
    assert disassemble(s) == f"OP_HASH160 <{H20.hex()}> OP_EQUAL"
    assert address(s, "mainnet").startswith("3")


def test_p2wpkh():
    s = bytes.fromhex("0014945a773b2d3fd4c7a114b1359aa0fa7e584514f8")
    assert classify(s) == "p2wpkh"
    assert disassemble(s).startswith("OP_0 <945a")
    assert address(s) == "bcrt1qj3d8wwed8l2v0gg5ky6e4g860evy298c9dp2ne"


def test_p2wsh():
    s = b"\x00\x20" + bytes(32)
    assert classify(s) == "p2wsh"
    assert address(s, "mainnet").startswith("bc1q")


def test_p2tr():
    s = b"\x51\x20" + bytes(32)
    assert classify(s) == "p2tr"
    assert disassemble(s).startswith("OP_1 <")
    assert address(s, "mainnet").startswith("bc1p")


def test_p2pk_genesis():
    key = bytes.fromhex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f")
    s = b"\x41" + key + b"\xac"
    assert classify(s) == "p2pk"
    assert disassemble(s).endswith("OP_CHECKSIG")
    assert address(s) is None


def test_nulldata():
    s = b"\x6a\x04test"
    assert classify(s) == "nulldata"
    assert disassemble(s) == "OP_RETURN <74657374>"
    assert address(s) is None
