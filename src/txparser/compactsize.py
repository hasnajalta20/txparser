def read_compact_size(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Lit un CompactSize a partir de `offset`.
    Retourne (valeur, nouvel_offset)."""
    if offset >= len(data):
        raise ValueError(f"donnees tronquees : rien a lire a l'offset {offset}")
    first = data[offset]
    if first < 0xFD:
        return first, offset + 1
    size = {0xFD: 2, 0xFE: 4, 0xFF: 8}[first]
    start = offset + 1
    end = start + size
    if end > len(data):
        raise ValueError(f"donnees tronquees : {size} octets attendus apres le prefixe")
    return int.from_bytes(data[start:end], "little"), end


def write_compact_size(n: int) -> bytes:
    """Encode un entier en CompactSize (sert aux tests aller-retour)."""
    if n < 0:
        raise ValueError("un CompactSize ne peut pas etre negatif")
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    if n <= 0xFFFFFFFFFFFFFFFF:
        return b"\xff" + n.to_bytes(8, "little")
    raise ValueError("nombre trop grand")
