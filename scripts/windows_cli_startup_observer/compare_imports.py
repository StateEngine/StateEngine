"""Compare the loader-bound imports of two Windows PE executables."""
import collections
import json
import struct
import sys
from pathlib import Path


def imports(path):
    data = Path(path).read_bytes()
    u16 = lambda at: struct.unpack_from('<H', data, at)[0]
    u32 = lambda at: struct.unpack_from('<I', data, at)[0]
    pe = u32(0x3c)
    if data[:2] != b'MZ' or data[pe:pe + 4] != b'PE\0\0':
        raise ValueError('Not a PE executable')
    opt = pe + 24
    magic = u16(opt)
    if magic not in (0x10b, 0x20b):
        raise ValueError('Unknown optional header')
    wide = magic == 0x20b
    directories = opt + (112 if wide else 96)
    start = opt + u16(pe + 20)
    sections = []
    for index in range(u16(pe + 6)):
        at = start + 40 * index
        sections.append((u32(at + 12), u32(at + 16), u32(at + 20)))

    def offset(rva):
        matches = [raw + rva - address for address, size, raw in sections
                   if address <= rva < address + size]
        if len(matches) != 1 or matches[0] >= len(data):
            raise ValueError(f'Unmapped or ambiguous RVA {rva}')
        return matches[0]

    def string(at):
        end = data.index(b'\0', at)
        return data[at:end].decode('ascii')

    result = collections.defaultdict(set)

    def table(module, lookup):
        base = offset(lookup)
        stride = 8 if wide else 4
        ordinal_mask = 1 << (63 if wide else 31)
        read = '<Q' if wide else '<I'
        for index in range(1_000_000):
            value = struct.unpack_from(read, data, base + index * stride)[0]
            if not value:
                return
            symbol = f'ordinal:{value & 0xffff}' if value & ordinal_mask else string(offset(value) + 2)
            result[module.casefold()].add(symbol)
        raise ValueError('Unterminated import table')

    normal = u32(directories + 8)
    if normal:
        cursor = offset(normal)
        while True:
            lookup, _, _, name, iat = struct.unpack_from('<IIIII', data, cursor)
            if not any((lookup, name, iat)):
                break
            table(string(offset(name)), lookup or iat)
            cursor += 20
    delay = u32(directories + 13 * 8)
    if delay:
        cursor = offset(delay)
        while True:
            flags, name, _, iat, lookup, _, _, _ = struct.unpack_from('<IIIIIIII', data, cursor)
            if not any((name, lookup, iat)):
                break
            if not flags & 1:
                raise ValueError('Delay import descriptor is not RVA-based')
            table(string(offset(name)), lookup or iat)
            cursor += 32
    return result


baseline, candidate = map(imports, sys.argv[1:3])
missing = {dll: sorted(symbols - candidate.get(dll, set()))
           for dll, symbols in baseline.items() if symbols - candidate.get(dll, set())}
report = {'baseline_symbols': {dll: len(symbols) for dll, symbols in sorted(baseline.items())},
          'candidate_symbols': {dll: len(symbols) for dll, symbols in sorted(candidate.items())},
          'missing_from_candidate': missing}
print(json.dumps(report, indent=2))
if missing:
    sys.exit(1)
