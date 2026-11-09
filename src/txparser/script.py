import hashlib

OPCODES = {
    0x00: "OP_0", 0x4F: "OP_1NEGATE", 0x6A: "OP_RETURN",
    0x76: "OP_DUP", 0x87: "OP_EQUAL", 0x88: "OP_EQUALVERIFY",
    0xA9: "OP_HASH160", 0xAC: "OP_CHECKSIG", 0xAE: "OP_CHECKMULTISIG",
}
for _n in range(1, 17):
    OPCODES[0x50 + _n] = f"OP_{_n}"


def disassemble(script: bytes) -> str:
    """Transforme un script en suite d'opcodes lisibles."""
    parts = []
    i = 0
    while i < len(script):
        op = script[i]
        i += 1
        if 0x01 <= op <= 0x4E:
            if op <= 0x4B:
                n = op
            else:
                width = {0x4C: 1, 0x4D: 2, 0x4E: 4}[op]
                if i + width > len(script):
                    parts.append("[erreur : push tronque]")
                    break
                n = int.from_bytes(script[i:i + width], "little")
                i += width
            data = script[i:i + n]
            if len(data) < n:
                parts.append("[erreur : push tronque]")
                break
            parts.append(f"<{data.hex()}>")
            i += n
        else:
            parts.append(OPCODES.get(op, f"OP_UNKNOWN_{op:#04x}"))
    return " ".join(parts)


def classify(s: bytes) -> str:
    """Reconnait le type standard d'un scriptPubKey."""
    if len(s) == 25 and s[:3] == b"\x76\xa9\x14" and s[23:] == b"\x88\xac":
        return "p2pkh"
    if len(s) == 23 and s[:2] == b"\xa9\x14" and s[22] == 0x87:
        return "p2sh"
    if len(s) == 22 and s[:2] == b"\x00\x14":
        return "p2wpkh"
    if len(s) == 34 and s[:2] == b"\x00\x20":
        return "p2wsh"
    if len(s) == 34 and s[:2] == b"\x51\x20":
        return "p2tr"
    if (len(s) == 35 and s[0] == 0x21 and s[34] == 0xAC) or \
       (len(s) == 67 and s[0] == 0x41 and s[66] == 0xAC):
        return "p2pk"
    if len(s) >= 1 and s[0] == 0x6A:
        return "nulldata"
    return "nonstandard"


# ---------- adresses ----------
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
NETWORKS = {
    "mainnet": {"hrp": "bc", "p2pkh": 0x00, "p2sh": 0x05},
    "regtest": {"hrp": "bcrt", "p2pkh": 0x6F, "p2sh": 0xC4},
}


def _base58check(version: int, payload: bytes) -> str:
    data = bytes([version]) + payload
    data += hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    num = int.from_bytes(data, "big")
    out = ""
    while num:
        num, rem = divmod(num, 58)
        out = _B58[rem] + out
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= gen[i]
    return chk


def _bech32(hrp: str, witver: int, program: bytes) -> str:
    # conversion 8 bits -> 5 bits
    acc, bits, data = 0, 0, [witver]
    for byte in program:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits:
        data.append((acc << (5 - bits)) & 31)
    const = 1 if witver == 0 else 0x2BC830A3  # bech32 / bech32m
    values = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + data
    pm = _polymod(values + [0] * 6) ^ const
    checksum = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_B32[d] for d in data + checksum)


def address(script: bytes, network: str = "regtest"):
    """Adresse correspondant au script, ou None (p2pk, nulldata...)."""
    net = NETWORKS[network]
    kind = classify(script)
    if kind == "p2pkh":
        return _base58check(net["p2pkh"], script[3:23])
    if kind == "p2sh":
        return _base58check(net["p2sh"], script[2:22])
    if kind in ("p2wpkh", "p2wsh"):
        return _bech32(net["hrp"], 0, script[2:])
    if kind == "p2tr":
        return _bech32(net["hrp"], 1, script[2:])
    return None
