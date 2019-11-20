# CORE: Logic to fully parse an individual snapshot, given its two blobs

from io import BytesIO
from struct import unpack
import re

from .read import *
from .constants import *
from .clusters import make_cluster_handlers
from .data.type_data import make_type_data
from .data.base_objects import make_base_objects


class ParseError(Exception):
    def __init__(self, data_offset, message):
        self.data_offset = data_offset
        self.message = message


def parse_features(features):
    # FIXME: handle quotes correctly
    result = {}
    for token in features.split(' '):
        token = re.fullmatch(r'(no-)?"?(.+)"?', token)
        if token.group(2) in result:
            raise Exception('Duplicate features')
        result[token.group(2)] = not token.group(1)
    return result

format_cid = lambda cid: \
    kClassId[cid] if type(cid) is int and 0 <= cid < kNumPredefinedCids else repr(cid)

unob_string = lambda str: str.x['unob'] if 'unob' in str.x else str.x['value']

# FIXME: throw parseerror if:
# if instructions / rodata is needed and not present,
# if Bytecode and KernelProgramInfo appear if precompiled
# if utf-16 decoding fails
# if read methods fail

class Ref:
    def __init__(self, s, ref, cluster, x):
        self.ref = ref
        self.x = x
        self.cluster = cluster
        self.src = []
        self.s = s
    def is_base(self):
        return type(self.ref) is int and self.ref < self.s.num_base_objects+1
    def is_own(self):
        return type(self.ref) is int and self.ref >= self.s.num_base_objects+1
    def __str__(self):
        if self.cluster['cid'] == 'BaseObject':
            return '<base {}>{}'.format(self.x['type'], self.x['value'])
        cid = self.cluster['cid']
        x = self.x
        fields = ['url' if 'url' in x else 'name']
        fields = [(f, unob_string(x[f])) for f in fields if f in x]
        content = format_cid(cid) + ''.join(' {}={}'.format(f, repr(v)) for f, v in fields if v)
        if cid in {kkClassId['OneByteString'], kkClassId['TwoByteString']}:
            content = repr(x['value'])
            if 'unob' in x: content += '({})'.format(repr(x['unob']))
        if cid in {kkClassId['Array'], kkClassId['ImmutableArray']}:
            content += '[{}]'.format(len(x['value'])) #repr(x['value'])
        return '{base}{1}->{0}'.format(self.ref, content, base="<base>" if self.is_base() else "")
    def __repr__(self):
        return self.__str__()


class Snapshot:
    """
    This is the core snapshot parser. It can only parse one snapshot,
    that is, a 'data' blob with an optional 'instructions' blob.
    
        - If the snapshot is a VM snapshot, you should pass `vm=True`
        - Otherwise, you should provide the parsed VM snapshot as `base=<Snapshot object>`
    
    Typical usage is constructing an instance and then calling the `parse`
    method to perform the actual parsing. Most of the parsed information is
    in `refs` and `clusters`.
    """

    def __init__(self, data, instructions=None, vm=False, base=None,
        data_offset=0, instructions_offset=0, print_level=3,
        strict=True, parse_rodata=True, parse_csm=True, build_tables=True):
        """ Initialize a parser.
        
        Main arguments
        --------------

        data -- The data blob.
        instructions -- The instructions blob (if present).
        vm -- True if this is a VM snapshot; False if isolate snapshot (default).
        base -- Base snapshot, which should always be passed if vm=False. If not passed, the core base objects are used.

        Parsing behaviour
        -----------------

        strict -- If strict mode is enabled (default True); in strict mode, inconsistency warnings become errors.
        parse_rodata -- Enables / disables parsing of memory structures. The layout of memory structures is decided
            by the compiler, can also vary between archs, so if parsing fails you can try disabling it. This causes
            the following dictionaries:

                - CodeSourceMap, PcDescriptors and StackMap objects, if present
                - OneByteString / TwoByteString objects (for AppJIT and AppAOT snapshots)
                - instructions / active_instructions field of Code objects, if present
            
            To be empty except for an `offset` field pointing where they are located.
        parse_csm -- Enables / disabling parsing code source maps using parse_code_source_map().
            If disabled, code source maps will contain a 'data' field with the encoded bytecode, instead of 'ops'.
            This option has no effect if parse_rodata is False.
        build_tables -- Calls build_tables() at the end of the parsing, which populates some convenience data
            about the snapshot. Disable this if it fails for some reason.

        Reporting parameters
        --------------------

        data_offset -- When reporting an offset into the data blob, this value will be added to it.
        instructions_offset -- When reporting an offset into the instructions blob, this value will be added to it.
        print_level -- Maximum message level to print: -1 nothing, 0 error, 1 warning, 2 notice, 3 info (default), 4 debug
        """
        self.data = BytesIO(data)
        self.data_offset = data_offset
        self.instructions = None if instructions is None else BytesIO(instructions)
        self.instructions_offset = instructions_offset
        self.vm = vm
        self.base = base

        self.print_level = print_level
        self.show_debug = print_level >= 4
        self.strict = strict
        self.parse_rodata = parse_rodata
        self.parse_csm = parse_csm
        self.do_build_tables = build_tables
    
    def parse(self):
        ''' Parse the snapshot. '''
        self.parse_header()
        self.initialize_settings()
        self.initialize_clusters()
        self.initialize_references()
        
        self.info('Reading allocation clusters...')
        self.clusters = [ self.read_cluster() for _ in range(self.num_clusters) ]
        if self.refs['next']-1 != self.num_objects:
            self.warning('Expected {} total objects, produced {}'.format(self.num_objects, self.refs['next']-1))

        self.info('Reading fill clusters...')
        for cluster in self.clusters:
            self.read_fill_cluster(cluster)

        self.info('Reading roots...')
        root = self.refs['root'] = Ref(self, 'root', {'handler': 'ObjectStore', 'cid': 'ObjectStore'}, {})
        if self.vm:
            self.storeref(self.data, root.x, 'symbol_table', root)
            if self.includes_code:
                root.x['_stubs'] = [ self.readref(self.data, (root, '_stubs', n)) for n in kStubCodeList ]
            self.enforce_section_marker()
        else:
            self.read_fill_cluster(root.cluster, [root])

        self.info('Snasphot parsed.')
        if self.data.tell() != self.length + 4:
            self.warning('Snapshot should end at 0x{:x} but we are at 0x{:x}'.format(self.length + 4, self.data.tell()))

        if self.do_build_tables:
            self.build_tables()
        return self

    
    # REPORTING #

    def p(self, level, message, show_offset=True, offset=None):
        if self.print_level < level:
            return
        if show_offset:
            offset = self.data.tell() if offset is None else offset
            message = '[{:08x}]: {}'.format(self.data_offset + offset, message)
        print(message)
    
    def debug(self, message):
        self.p(4, 'DEBUG: {}'.format(message))

    def info(self, message):
        self.p(3, 'INFO: {}'.format(message))
    
    def notice(self, message):
        self.p(2, 'NOTICE: {}'.format(message))

    def warning(self, message):
        if self.strict:
            self.p(1, 'WARN: An inconsistency was found; failing. Pass strict=False to treat inconsistencies as warnings and continue parsing.')
            raise ParseError(self.data_offset + self.data.tell(), message)
        self.p(1, 'WARN: {}'.format(message))


    # HEADER PARSING & INITIALIZATION #

    def parse_header(self):
        ''' This method parses the header of a snapshot, checks the magic and does
        some extra steps to prepare for actual parsing:
        1. If the snapshot contains a 'rodata section', then `self.rodata` is populated
           with a BytesIO for this extra data.
        2. Checks that `self.data` matches or exceeds the length in the snapshot header,
           and then truncates `self.data` to that length.
        '''
        f = self.data

        self.magic_value, self.length, self.kind = unpack('<Iqq', f.read(4+8+8))
        if self.magic_value != MAGIC_VALUE:
            self.warning('Invalid magic value: {:08x}'.format(self.magic_value))
        self.p(1, "[Header]\n  length = {}\n  kind = {} {}\n".format(self.length, self.kind, kKind[self.kind]), show_offset=False)

        self.includes_code = self.kind in {kkKind['kFullJIT'], kkKind['kFullAOT']}
        self.includes_bytecode = self.kind in {kkKind['kFull'], kkKind['kFullJIT']}

        # Check length, set rodata if needed, truncate
        data_end = 4 + self.length
        if len(f.getbuffer()) < data_end:
            self.warning('Data blob should be at least {} bytes, got {}'.format(data_end, len(f.getbuffer())))
        if self.includes_code:
            rodata_offset = ((data_end - 1) // kMaxPreferredCodeAlignment + 1) * kMaxPreferredCodeAlignment
            if len(f.getbuffer()) < rodata_offset:
                self.warning('The rodata section is not present')
            self.rodata_offset = self.data_offset + rodata_offset
            self.rodata = BytesIO(f.getbuffer()[rodata_offset:])
        elif len(f.getbuffer()) > data_end:
            self.notice('There are {} excess bytes at the end of the data blob'.format(len(f.getbuffer()) - data_end), offset=data_end)
        f.truncate(data_end)

        # Parse rest of header
        self.version = f.read(32).decode('ascii')
        if self.version != EXPECTED_VERSION:
            self.warning('Version ({}) doesn\'t match with the one this parser was made for'.format(self.version))
        self.features = parse_features(readcstr(f).decode('ascii'))
        self.p(1, "[Snapshot header]\n  version = {}\n  features = {}\n".format(repr(self.version), repr(self.features)), show_offset=False)

        self.num_base_objects, self.num_objects, self.num_clusters, self.code_order_length = (readuint(f) for _ in range(4))
        self.p(1, "  base objects: {}\n  objects: {}\n  clusters: {}\n  code order length = {}\n".format(
            self.num_base_objects, self.num_objects, self.num_clusters, self.code_order_length), show_offset=False)

    # FIXME: let user override settings, too
    def initialize_settings(self):
        ''' Detect settings / flags from parsed header '''
        # detect arch
        archs = { 'x64': True, 'ia32': False, 'arm64': True, 'arm': False }
        names = ( x.split('-')[0] for x in self.features )
        self.is_64 = next( archs[x] for x in names if x in archs )

        # detect mode
        self.is_debug = self.features.get('debug', False)
        self.is_product = self.features.get('product', False)
        self.is_precompiled = self.kind == kkKind['kFullAOT'] and self.is_product  # FIXME

        # other settings and constants (FIXME)
        kObjectAlignment = 2 * (8 if self.is_64 else 4)
        self.kObjectAlignmentLog2 = kObjectAlignment.bit_length()-1
        self.raw_instance_size_in_words = 1

    def initialize_clusters(self):
        ''' Initialize cluster type data and handlers '''
        types, mappings = make_type_data(self.is_precompiled, self.is_product)

        def remove_fields(fields, to_remove):
            assert to_remove.issubset(set(f[1] for f in fields))
            return [f for f in fields if f[1] not in to_remove]
        
        for name, fields in types.items():
            mapping = mappings.get(name)
            if not (mapping is None or type(mapping) is bool):
                last_field = mapping[{ kkKind[n]: i for i, n in enumerate(['kFull', 'kFullJIT', 'kFullAOT']) }[self.kind]]
                idx = next(filter(lambda x: x[1][1] == last_field, enumerate(fields)))[0]
                fields = fields[:idx+1]
            
            if name == 'ClosureData' and self.kind == kkKind['kFullAOT']:
                fields = remove_fields(fields, {'context_scope'})
            if name == 'Code':
                if not self.is_precompiled and self.kind != kkKind['kFullJIT']:
                    fields = remove_fields(fields, {'deopt_info_array', 'static_calls_target_table'})
            
            types[name] = fields
        self.types = types

        # Initialize clusters
        self.handlers = make_cluster_handlers(self)


    # REFS HANDLING #

    def initialize_references(self):
        # refs is a dict from int to Ref,
        # except for 'next' key which just stores next ID to be assigned
        self.refs = { 'next': 1 } # ref 0 is illegal

        # check that base objects match
        base = self.base.refs if self.base else make_base_objects(self.includes_code)
        exp_base_objects = self.num_base_objects
        base_objects = base['next']-1
        if base_objects != exp_base_objects:
            self.notice('Snapshot expected {} base objects, but the provided base has {}'.format(exp_base_objects, base_objects))
        base_objects = min(base_objects, exp_base_objects)
        # fill base objects
        for r in range(1, 1 + base_objects):
            self.refs[r] = Ref(self, base[r].ref, base[r].cluster, base[r].x)
        self.refs['next'] = 1 + base_objects
        # fill any missing refs
        tmp_cluster = { 'handler': 'UnknownBase', 'cid': 'unknown' }
        while self.refs['next']-1 < exp_base_objects: self.allocref(tmp_cluster, {})

    def allocref(self, cluster, x):
        if 'refs' not in cluster:
            cluster['refs'] = []
        ref = Ref(self, self.refs['next'], cluster, x)
        self.refs[ref.ref] = ref
        self.refs['next'] += 1
        cluster['refs'].append(ref)

    def readref(self, f, source):
        r = readuint(f)
        if r not in self.refs:
            self.warning('Code referenced a non-existent ref, a broken ref is returned')
            return { 'broken': r }
        self.refs[r].src.append(source)
        return self.refs[r]

    def storeref(self, f, x, name, src):
        if not (type(src) is tuple): src = (src,)
        x[name] = self.readref(f, src + (name,))


    # MAIN PARSING LOGIC #

    def read_cluster(self):
        ''' Reads the alloc section of a new cluster '''
        cid = readcid(self.data)
        self.debug('reading cluster with cid={}'.format(format_cid(cid)))
        if cid >= kNumPredefinedCids:
            handler = 'Instance'
        elif isTypedData(cid) or isExternalTypedData(cid):
            handler = 'TypedData'
        elif isTypedDataView(cid):
            handler = 'TypedDataView'
        elif cid == kkClassId['ImmutableArray']:
            handler = 'Array'
        else:
            handler = kClassId[cid]
        cluster = { 'handler': handler, 'cid': cid }
        if not hasattr(self.handlers, handler):
            raise ParseError(self.data_offset + self.data.tell(), 'Cluster "{}" still not implemented'.format(handler))
        getattr(self.handlers, handler)(cid).alloc(self.data, cluster)
        
        if self.is_debug:
            serializers_next_ref_index = readint(f, 32)
            self.warning('next_ref doesn\'t match, expected {} but got {}'.format(serializers_next_ref_index, refs['next']))
        return cluster

    def read_fill_cluster(self, cluster, refs=None):
        ''' Reads the fill section of the passed cluster '''
        f = self.data
        cid, name = cluster['cid'], cluster['handler']
        self.debug('reading cluster with cid={}'.format(format_cid))
        handler = getattr(self.handlers, name)(cid)
        if refs is None: refs = cluster['refs']
        for ref in refs:
            if self.show_debug: self.debug('  reading ref {}'.format(ref.ref))
            assert ref.cluster == cluster
            if handler.do_read_from:
                if name in {'Closure', 'GrowableObjectArray'}:
                    ref.x['canonical'] = read1(f)
                if name == 'Code':
                    ref.x['instructions'] = self.read_instructions()
                    if not self.is_precompiled and self.kind == kkKind['kFullJIT']:
                        ref.x['active_instructions'] = self.read_instructions()
                for _, fname, _ in self.types[cluster['handler']]:
                    if self.show_debug: self.debug('    reading field {}'.format(fname))
                    self.storeref(f, ref.x, fname, ref)
            if self.show_debug: self.debug('    reading fill')
            handler.fill(f, ref.x, ref)
        self.enforce_section_marker()

    def read_instructions(self):
        ''' Reads RawInstructions object '''
        offset = readint(self.data, 32)
        if offset < 0:
            offset = -offset # FIXME: implement
            self.notice('Base instructions not implemented yet, returning empty object')
            return None
        if not self.parse_rodata:
            return { 'offset': self.instructions_offset + offset }
        f = self.instructions
        f.seek(offset)

        if self.is_64:
            tags, _, size_and_flags, unchecked_entrypoint_pc_offset = unpack('<LLLL', f.read(16))
            f.read(16) # 16 0xCC bytes observed on x64, looks like a sentinel or something?
        else:
            tags, size_and_flags, unchecked_entrypoint_pc_offset, _ = unpack('<LLLL', f.read(16))
        size, flags = size_and_flags & ((1 << 31) - 1), size_and_flags >> 31
        data_addr = self.instructions_offset + f.tell() # for disassembling in another program
        data = f.read(size)
        return {
            'tags': tags,
            'flags': { 'single_entry': flags & 1 },
            'unchecked_entrypoint_pc_offset': unchecked_entrypoint_pc_offset,
            'data': data,
            'data_addr': data_addr,
        }

    def enforce_section_marker(self):
        if not self.is_debug: return
        offset = self.data.tell()
        section_marker = readint(self.data, 32)
        if section_marker != kSectionMarker:
            raise ParseError(self.data_offset + offset, 'Section marker doesn\'t match')

   # CONVENIENCE API #

    getrefs = lambda self, name: self.clrefs.get(name, [])

    def build_tables(self):
        self.cl = {}
        self.clrefs = {}
        for c in self.clusters:
            if c['cid'] in self.cl:
                self.notice('Cluster {} is duplicated'.format(format_cid(c['cid'])))
            self.cl[c['cid']] = c
            n = format_cid(c['cid'])
            if n not in self.clrefs: self.clrefs[n] = []
            self.clrefs[n] += c['refs']

        self.strings_refs = self.getrefs('OneByteString') + self.getrefs('TwoByteString')
        self.strings = { ref.x['value']: ref for ref in self.strings_refs }
        if len(self.strings) != len(self.strings_refs):
            self.notice('There are {} duplicate strings.'.format(len(self.strings_refs) - len(self.strings)))

        self.scripts_lib = {}
        for l in self.getrefs('Library'):
            for r in l.x['owned_scripts'].x['data'].x['value']:
                if r.ref == 1: continue
                if r.ref in self.scripts_lib:
                    self.notice('Script {} owned by multiple libraries, this should not happen'.format(l))
                self.scripts_lib[r.ref] = l

        # Consistency checks
        if len(self.scripts_lib) != len(self.getrefs('Script')):
            self.notice('There are {} scripts but only {} are associated to a library'.format(len(self.getrefs('Script')), len(self.scripts_lib)))
        for c in self.getrefs('Class'):
            if c.x['library'] != self.scripts_lib[c.x['script'].ref]:
                self.notice('Class {} does not have matching script / library'.format(c))

        # TODO: function table, class table
