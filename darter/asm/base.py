# ASM/BASE: Common API to disassemble compiled instructions and analyze them

import time

from ..constants import kEntryType
from . import _arm, _arm64, _ia32, _x64


ARCH_MODULES = _arm, _arm64, _ia32, _x64

def _find_arch_module(snapshot):
    '''
    Create and return the appropriate arch-specific module,
    according to the architecture and other settings of a given snapshot.
    Raises if the architecture / settings are not supported.
    '''
    arch = snapshot.arch.split('-')[0]
    for m in ARCH_MODULES:
        if m.supports(snapshot, arch): return m
    raise Exception('Unknown / unsupported arch')

def make_engine(snapshot):
    '''
    Create and return an instance of the Capstone engine
    for the architecture/settings of the passed snapshot.
    '''
    return _find_arch_module(snapshot).make_engine(snapshot)

def disasm_code(md, code, lite=False, detail=False):
    '''
    Convenience method to disassemble the `instructions` of a Code object.
    It is preferable to use this function when possible (i.e. for thumb mode).
    '''
    instr = code.x['instructions']
    data, addr = instr['data'], instr['data_addr']
    md.detail = detail
    ops = list((md.disasm_lite if lite else md.disasm)(data, addr))
    get_end = lambda x: (x[0]+x[1] if lite else x.address+x.size)
    if (get_end(ops[-1])-addr if ops else 0) != len(data):
        raise Exception('Not all instructions were disassembled')
    return ops        

def analyze_native_references(snapshot):
    '''
    Analyzes all Code objects of a snapshot that have native instructions:
    the instructions are disassembled and searched for references to VM
    objects. Currently only ARM and ARM64 support this.

    This is a low-level function, most people should use
    `populate_native_references` instead.
    
    The returned object is a dictionary that associates Code objects with
    their results. The results are a list of (address, <fields>) tuples;
    the fields depend on the kind of native reference:

     - "load", n, reg: object from global object pool entry `n` was loaded
       into register named `reg` (special value `call` means that next
       entry was also loaded and called).
    - "call", address: function call to `address`
    '''
    arch = _find_arch_module(snapshot)
    if not hasattr(arch, 'match_nref'):
        raise Exception('Native reference analysis is not yet implemented for this architecture')
    md = arch.make_engine(snapshot)
    result = {}
    for code in snapshot.getrefs('Code'):
        if 'instructions' not in code.x: continue
        ops = disasm_code(md, code, lite=True)
        result[code] = nrefs = []
        i = 0
        while i < len(ops):
            res = arch.match_nref(ops, i)
            if res:
                ii, *nref = res
                nrefs.append((ops[i][0], *nref))
                assert ii > i
                i = ii
            else:
                i += 1
    return result

def populate_native_references(snapshot):
    '''
    High-level method that uses analyze_native_references, then associates
    the results to objects, and saves the results into the snapshot data,
    storing back-references on the pointed objects too:

     1. Each analyzed Code object gets an `nrefs` entry on its data
        dictionary, which is a list of `(target, address, <fields>)` items,
        where `target` is the object (Ref) that was loaded, called, etc.

     2. This also creates back-references on the pointed objects; every
        snapshot object (the object itself, not the data dictionary)
        will have an `nsrc` field containing a list of `(code, address, <fields>)`
        items, where `code` is the Code object the native reference was found at.
        
    `address` is the address of the instruction(s) which referenced the object,
    and the rest of the fields depend on the kind of native reference:

     - `"load", reg`: the object was loaded (through the global pool) into register
       named `reg` (special value `call` means that next entry was also loaded and
       called).
     - `"call", offset`: function call to the object, at offset `offset`.
    '''
    print('Starting analysis...')
    start = time.time()
    results = analyze_native_references(snapshot)
    print('Done in {:.2f}s, processing results'.format(time.time() - start))

    entries = snapshot.refs['root'].x['global_object_pool'].x['entries']
    # initialize nsrc to an empty list on every object
    for i in range(1, snapshot.refs['next']):
        snapshot.refs[i].nsrc = []

    for code, nrefs in results.items():
        out_nrefs = code.x['nrefs'] = []
        for address, kind, x, *rest in nrefs:
            if kind == 'call':
                match = snapshot.search_address(x)
                if match is None:
                    print('Call address not found: 0x{:x}'.format(x))
                    continue
                target, offset = match
                rest = (offset, *rest)
            elif kind == 'load':
                if not (0 <= x < len(entries)):
                    print('Entry index outside range: {}'.format(x))
                    continue
                if 'raw_obj' not in entries[x]:
                    # print('Entry {} not an object: type={}'.format(x, kEntryType[entries[x]['type']])) # FIXME: proper logging
                    continue
                # FIXME: take 'patchable' into account
                target = entries[x]['raw_obj']
            else:
                continue
            out_nrefs.append(( target, address, kind, *rest ))
            target.nsrc.append(( code, address, kind, *rest ))
