#!/usr/bin/python3
# Generates R2 metadata for an ELF snapshot, saves it at .meta.r2
# Usage: generate_metadata.py <snapshot.so>

import sys
from os.path import dirname
sys.path.append(dirname(dirname(__file__)))
from darter.file import parse_elf_snapshot
from darter.asm.base import populate_native_references
from collections import defaultdict
from base64 import b64encode

snapshot_file = sys.argv[1]
metadata_out = snapshot_file + '.meta.r2'

print('[Loading snapshot]')
s = parse_elf_snapshot(snapshot_file)

print('[Analyzing code]')
populate_native_references(s)

print('[Generating metadata]')

do_b64 = lambda x: 'base64:' + b64encode(x.encode('utf-8')).decode('ascii')

def produce_metadata(f, snapshot):
    comments = defaultdict(lambda: [])
    print('fs functions', file=f)
    for code in snapshot.getrefs('Code'):
        instr = code.x['instructions']
        name = 'c_{}'.format(code.ref)
        comment = ' '.join(map(str, code.locate()))
        print('f {name} {len} {addr} {c}'.format( name=name, len=len(instr['data']), addr=instr['data_addr'], c=do_b64(comment) ), file=f)
        for target, pc, kind, *args in code.x.get('nrefs', []):
            if kind == 'load':
                comments[pc].append( 'load: {reg} = {tg}'.format(tg=target.describe(), reg=args[0]) )
    for addr, lines in comments.items():
        print('CCu {} @ {}'.format( do_b64("\n".join(lines)), addr ), file=f)

with open(metadata_out, 'w') as f: produce_metadata(f, s)

