# Parsing for other substructures (PcDescriptors, CodeSourceMap, etc.)

import io

from .read import readint, read_uleb128


def parse_pc_descriptors(data):
    f = io.BytesIO(data)
    def elem():
        x = {}
        merged_kind = readuleb128(f) # FIXME: should be signed
        x['kind'] = kPcDescriptorKindBits[merged_kind & 0b111][0]
        x['try_index'] = merged_kind >> 3
        x['pc_offset'] = readuleb128(f)
        if kind == kkKind['kFullAOT']: # FIXME: check meaning of FLAG_precompiled_mode
            x['deopt_id'] = readuleb128(f)
            x['token_pos'] = readuleb128(f)
        return x
    els = []
    while f.tell() < len(data): els.append(elem())
    return els

# runtime/vm/dwarf.cc and runtime/vm/code_descriptors.cc
kCodeSourceMapOpCodes = ['kChangePosition', 'kAdvancePC', 'kPushFunction', 'kPopFunction', 'kNullCheck']
kkCodeSourceMapOpCodes = {k: v for v, k in enumerate(kCodeSourceMapOpCodes)}

def parse_code_source_map(data):
    f = io.BytesIO(data)
    ops = []
    while f.tell() < len(data):
        opcode = readint(f, 9)  # <- FIXME: should be uint and 8...
        op = kCodeSourceMapOpCodes[opcode] if opcode < len(kCodeSourceMapOpCodes) else None
        if opcode == kkCodeSourceMapOpCodes['kChangePosition']:
            ops.append((op, readint(f, 32)))
        elif opcode == kkCodeSourceMapOpCodes['kAdvancePC']:
            ops.append((op, readint(f, 32)))
        elif opcode == kkCodeSourceMapOpCodes['kPushFunction']:
            ops.append((op, readint(f, 32)))
        elif opcode == kkCodeSourceMapOpCodes['kPopFunction']:
            ops.append((op, ))
        elif opcode == kkCodeSourceMapOpCodes['kNullCheck']:
            ops.append((op, readint(f,32)))
        else: raise Exception('Unknown opcode {}'.format(opcode))
    return ops
