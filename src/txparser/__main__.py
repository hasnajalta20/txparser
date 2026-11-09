import sys

from .parser import parse_transaction
from .script import address, classify, disassemble


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    network = "mainnet" if "--mainnet" in sys.argv else "regtest"
    raw = args[0] if args else sys.stdin.read()
    try:
        tx = parse_transaction(raw)
    except ValueError as e:
        print(f"Erreur : {e}", file=sys.stderr)
        return 1

    print(f"version   : {tx.version}")
    print(f"segwit    : {tx.segwit}")
    print(f"locktime  : {tx.locktime}")
    print(f"size {tx.size}, stripped size {tx.stripped_size}, "
          f"weight {tx.weight}, vsize {tx.vsize}")
    print(f"txid      : {tx.txid}")
    print(f"wtxid     : {tx.wtxid}")
    for n, i in enumerate(tx.inputs):
        print(f"input [{n}] (offset {i.offset})")
        print(f"  prev txid : {i.prev_txid}")
        print(f"  vout      : {i.vout}")
        print(f"  scriptSig : {i.script_sig.hex()}")
        if i.script_sig:
            print(f"  scriptSig (opcodes) : {disassemble(i.script_sig)}")
        print(f"  sequence  : {i.sequence:#010x}")
        for k, item in enumerate(i.witness):
            print(f"  witness[{k}] ({len(item)} octets) : {item.hex()}")
    for n, o in enumerate(tx.outputs):
        spk = o.script_pubkey
        print(f"output [{n}] (offset {o.offset})")
        print(f"  value        : {o.value} sat ({o.value / 1e8:.8f} BTC)")
        print(f"  scriptPubKey : {spk.hex()}")
        print(f"  opcodes      : {disassemble(spk)}")
        print(f"  type         : {classify(spk)}")
        print(f"  address      : {address(spk, network) or '(aucune)'}")
    print("fee       : non calculable ici (il faut connaitre la valeur des sorties depensees)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
