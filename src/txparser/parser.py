import hashlib
from dataclasses import dataclass, field

from .compactsize import read_compact_size, write_compact_size


@dataclass
class TxInput:
    offset: int
    prev_txid: str  # ordre d'affichage (big-endian)
    vout: int
    script_sig: bytes
    sequence: int
    witness: list = field(default_factory=list)


@dataclass
class TxOutput:
    offset: int
    value: int  # en satoshis
    script_pubkey: bytes


@dataclass
class Transaction:
    version: int
    segwit: bool
    inputs: list
    outputs: list
    locktime: int
    size: int
    stripped_size: int
    weight: int
    vsize: int
    txid: str
    wtxid: str


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ValueError(f"donnees tronquees a l'offset {self.pos}")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def compact(self) -> int:
        value, self.pos = read_compact_size(self.data, self.pos)
        return value

    def uint(self, n: int) -> int:
        return int.from_bytes(self.take(n), "little")


def _sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def serialize(tx: Transaction, with_witness: bool) -> bytes:
    """Re-serialise la transaction (avec ou sans donnees temoin)."""
    witness = with_witness and tx.segwit
    out = tx.version.to_bytes(4, "little", signed=True)
    if witness:
        out += b"\x00\x01"
    out += write_compact_size(len(tx.inputs))
    for i in tx.inputs:
        out += bytes.fromhex(i.prev_txid)[::-1]
        out += i.vout.to_bytes(4, "little")
        out += write_compact_size(len(i.script_sig)) + i.script_sig
        out += i.sequence.to_bytes(4, "little")
    out += write_compact_size(len(tx.outputs))
    for o in tx.outputs:
        out += o.value.to_bytes(8, "little")
        out += write_compact_size(len(o.script_pubkey)) + o.script_pubkey
    if witness:
        for i in tx.inputs:
            out += write_compact_size(len(i.witness))
            for item in i.witness:
                out += write_compact_size(len(item)) + item
    out += tx.locktime.to_bytes(4, "little")
    return out


def parse_transaction(raw) -> Transaction:
    if isinstance(raw, str):
        try:
            raw = bytes.fromhex("".join(raw.split()))
        except ValueError:
            raise ValueError("entree non hexadecimale") from None
    if len(raw) == 0:
        raise ValueError("transaction vide")

    r = _Reader(raw)
    version = int.from_bytes(r.take(4), "little", signed=True)

    segwit = len(raw) >= 6 and raw[4] == 0x00 and raw[5] == 0x01
    if segwit:
        r.take(2)  # marqueur 0x00 + drapeau 0x01

    inputs = []
    for _ in range(r.compact()):
        offset = r.pos
        prev_txid = r.take(32)[::-1].hex()  # stocke a l'envers
        vout = r.uint(4)
        script_sig = r.take(r.compact())
        sequence = r.uint(4)
        inputs.append(TxInput(offset, prev_txid, vout, script_sig, sequence))

    outputs = []
    for _ in range(r.compact()):
        offset = r.pos
        value = r.uint(8)
        script_pubkey = r.take(r.compact())
        outputs.append(TxOutput(offset, value, script_pubkey))

    if segwit:
        for i in inputs:
            i.witness = [r.take(r.compact()) for _ in range(r.compact())]

    locktime = r.uint(4)
    if r.pos != len(raw):
        raise ValueError(f"{len(raw) - r.pos} octet(s) en trop a la fin")

    tx = Transaction(version, segwit, inputs, outputs, locktime,
                     size=len(raw), stripped_size=0, weight=0, vsize=0,
                     txid="", wtxid="")
    legacy = serialize(tx, with_witness=False)
    tx.stripped_size = len(legacy)
    tx.weight = 3 * tx.stripped_size + tx.size
    tx.vsize = (tx.weight + 3) // 4
    tx.txid = _sha256d(legacy)[::-1].hex()
    tx.wtxid = _sha256d(raw)[::-1].hex() if segwit else tx.txid
    return tx
