# FILE: Stores top level logic to unwrap blobs from a snapshot file and parse them

from struct import unpack
import r2pipe   # FIXME: use something more portable

from .constants import kAppAOTSymbols, kAppJITMagic, kAppSnapshotPageSize
from .core import Snapshot

# FIXME: verify that kind, version and features is the same for both snapshots
# FIXME: verify that archs match

def parse_elf_snapshot(fname, report_virtual=True, **kwargs):
    ''' Open and parse an ELF (executable) AppAOT snapshot. Note that by default the reported
        offsets are virtual addresses, not physical ones. Returns isolate snapshot. '''
    f = open(fname, 'rb')

    # Obtain file info (sections, symbols)
    r2 = r2pipe.open(fname)
    sections = r2.cmdj('iSj')
    symbol_list = r2.cmdj('isj')
    symbols = { s['name']: s for s in symbol_list }

    # Extract blobs
    blobs, offsets = [], []
    for s in kAppAOTSymbols:
        s = symbols[s]
        section = next(S for S in sections if 0 <= s['paddr'] - S['paddr'] < S['size'])
        section_end = section['paddr'] + section['size']
        f.seek(s['paddr'])
        blobs.append(f.read(section_end - s['paddr']))
        offsets.append(s['vaddr' if report_virtual else 'paddr'])

    # Parse VM snapshot, then isolate snapshot
    print('------- PARSING VM SNAPSHOT --------\n')
    base = Snapshot(data=blobs[0], data_offset=offsets[0],
                    instructions=blobs[1], instructions_offset=offsets[1],
                    vm=True, **kwargs).parse()
    print('\n------- PARSING ISOLATE SNAPSHOT --------\n')
    return Snapshot(data=blobs[2], data_offset=offsets[2],
                    instructions=blobs[3], instructions_offset=offsets[3],
                    base=base, **kwargs).parse()

def parse_appjit_snapshot(fname, base=None, **kwargs):
    ''' Open and parse an AppJIT snapshot file. Returns isolate snapshot. '''
    # Read header, check magic
    f = open(fname, 'rb')
    magic = unpack('<Q', f.read(8))[0]
    if magic != kAppJITMagic:
        print("WARN: Magic not matching, got 0x{:016x}".format(magic))
    lengths = unpack('<qqqq', f.read(4 * 8))
    print('Blob lengths:', lengths)

    # Extract blobs
    blobs, offsets = [], []
    for length in lengths:
        f.seek( ((f.tell() - 1) // kAppSnapshotPageSize + 1) * kAppSnapshotPageSize )
        offsets.append(f.tell())
        blobs.append(f.read(length))

    # Parse VM snapshot if present, then isolate snapshot
    if blobs[0]:
        print('\n------- PARSING VM SNAPSHOT --------\n')
        base = Snapshot(data=blobs[0], data_offset=offsets[0],
                        instructions=blobs[1], instructions_offset=offsets[1],
                        vm=True, **kwargs).parse()
    else:
        print('No base snapshot, skipping base snasphot parsing...')
        assert not lengths[1]

    print('\n------- PARSING ISOLATE SNAPSHOT --------\n')
    return Snapshot(data=blobs[2], data_offset=offsets[2],
                    instructions=blobs[3], instructions_offset=offsets[3],
                    base=base, **kwargs).parse()
