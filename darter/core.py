# CORE: Logic to fully parse a snapshot

from struct import unpack
import re

from .settings import *
from .read import *
from .constants import *
from .data.type_data import make_type_data
from .data.base_objects import make_base_objects


# It's always a good idea to try with disableRoData=True first, and if that succeeds, then enable

# FIXME: is product a flag, or a compile flag?
# FIXME: return header, verify that kind, version and features is the same for both snapshots
# FIXME: check that Bytecode and KernelProgramInfo do not appear if precompiled

def parse_snapshot(app, BASE_ADDRESS, INSTR_ADDRESS, vm=False, base=None, disableRoData=False):
    app.seek(BASE_ADDRESS)

    magic_value, length, kind = unpack('<Iqq', app.read(4+8+8))
    assert magic_value == MAGIC_VALUE
    print("[Header]\n  length = {}\n  kind = {} {}\n".format(length, kind, kKind[kind]))

    includes_code = kind in {kkKind['kFullJIT'], kkKind['kFullAOT']}
    includes_bytecode = kind in {kkKind['kFull'], kkKind['kFullJIT']}
    snapshot_end = BASE_ADDRESS + 4 + length
    data_start = ((snapshot_end - 1) // kMaxPreferredCodeAlignment + 1) * kMaxPreferredCodeAlignment

    version = app.read(32).decode('ascii')
    features = readcstr(app).decode('ascii')
    print("[Snapshot header]\n  version = {}\n  features = {}\n".format(repr(version), repr(features)))

    if version != EXPECTED_VERSION:
        print('WARN: Version doesn\'t match with the one this parser was made for ({}). Continuing anyway...'.format(EXPECTED_VERSION))

    num_base_objects, num_objects, num_clusters, code_order_length = (readuint(app) for _ in range(4))
    print("  base objects: {}\n  objects: {}\n  clusters: {}\n  code order length = {}\n  data starts at 0x{:x}\n".format(num_base_objects, num_objects, num_clusters, code_order_length, data_start))


    # REFS HANDLING

    # refs is a dict from int to Ref,
    # except for 'next' key which just stores next ID to be assigned
    refs = { 'next': 1 } # ref 0 is illegal

    class Ref:
        def __init__(self, ref, cluster, x, prop):
            self.ref = ref
            self.x = x
            self.cluster = cluster
            self.prop = prop
            self.src = []
        def is_base(self):
            return type(self.ref) is int and self.ref < num_base_objects+1
        def is_own(self):
            return type(self.ref) is int and self.ref >= num_base_objects+1
        def __str__(self):
            if self.cluster['cid'] == 'BaseObject':
                return '<base {}>{}'.format(self.x['type'], self.x['value'])
            cid = self.cluster['cid']
            x = self.x
            content = re.fullmatch('k(.+)Cid', kClassId[cid]).group(1) if type(cid) is int and 0 <= cid < len(kClassId) else cid
            if cid in {kkClassId['kOneByteStringCid'], kkClassId['kTwoByteStringCid']}:
                content = repr(x['value'])
            if cid in {kkClassId['kArrayCid']}:
                content = 'Array[{}]'.format(len(x['items'])) #repr(x['items'])
            return '{base}{1}->{0}'.format(self.ref, content, base="<base>" if self.is_base() else "")
        def __repr__(self):
            return self.__str__()

    def allocRef(cluster, x, prop='refs'):
        if prop not in cluster:
            cluster[prop] = []
        idx = len(cluster[prop])
        cluster[prop].append(x)
        refs[refs['next']] = Ref(refs['next'], cluster, x, prop)
        refs['next'] += 1

    def readref(f, source):
        r = readuint(f)
        if r not in refs:
            print('WARN: Code referenced a non-existent ref -- will return a broken ref')
            return { 'broken': r }
        refs[r].src.append(source)
        return refs[r]

    def storeref(f, x, name, src):
        if not (type(src) is tuple): src = (src,)
        x[name] = readref(f, src + (name,))


    # CLUSTER DESERIALIZATION LOGIC

    def simpleAlloc(f, cluster):
        for _ in range(readuint(f)): allocRef(cluster, {})

    def lengthAlloc(f, cluster):
        for _ in range(readuint(f)): allocRef(cluster, { 'length': readuint(f) })

    def RODataAlloc(elem=lambda f: {}):
        def parseElemAt(offset):
            saved = f.tell()
            try:
                f.seek(data_start + running_offset)
                return elem(f)
            finally:
                f.seek(saved)
        if disableRoData: parseElemAt = lambda offset: { 'offset': offset }
        def alloc(f, cluster):
            for _ in range(readuint(f)):
                allocRef(cluster, { 'offset': readuint(f) }, 'refs_shared') # FIXME implement
            running_offset = 0
            for _ in range(readuint(f)):
                running_offset += readuint(f) << kObjectAlignmentLog2
                allocRef(cluster, parseElemAt(running_offset), 'refs_object')
        return alloc

    class AllocParsers:
        def kClassCid(f, cluster):
            for _ in range(readuint(f)):
                allocRef(cluster, { 'cid': readcid(f) }, 'refs_class_table')
            for _ in range(readuint(f)):
                allocRef(cluster, {})
        
        def kInstanceCid(f, cluster):
            count = readuint(f)
            cluster['next_field_offset_in_words'] = readint(f, 32)
            cluster['instance_size_in_words'] = readint(f, 32)
            for _ in range(count): allocRef(cluster, {})

        def kTypeCid(f, cluster):
            canonical_items = readuint(f)
            for i in range(canonical_items + readuint(f)):
                allocRef(cluster, { 'canonical': i < canonical_items })

        def kMintCid(f, cluster):
            for _ in range(readuint(f)):
                allocRef(cluster, { 'canonical': read1(f), 'value': readint(f, 64) })
        
        ROData = RODataAlloc() # FIXME: remove
        
        # standard stuff
        kPatchClassCid = simpleAlloc
        kFunctionCid = simpleAlloc
        kClosureDataCid = simpleAlloc
        kSignatureDataCid = simpleAlloc
        kFieldCid = simpleAlloc
        kScriptCid = simpleAlloc
        kLibraryCid = simpleAlloc
        kCodeCid = simpleAlloc
        kObjectPoolCid = lengthAlloc
        kExceptionHandlersCid = lengthAlloc
        kUnlinkedCallCid = simpleAlloc
        kMegamorphicCacheCid = simpleAlloc
        kSubtypeTestCacheCid = simpleAlloc
        kUnhandledExceptionCid = simpleAlloc
        kTypeArgumentsCid = lengthAlloc
        kTypeRefCid = simpleAlloc
        kTypeParameterCid = simpleAlloc
        kClosureCid = simpleAlloc
        kDoubleCid = simpleAlloc
        kGrowableObjectArrayCid = simpleAlloc
        kStackTraceCid = simpleAlloc
        kArrayCid = lengthAlloc
        kNamespaceCid = simpleAlloc
        kKernelProgramInfoCid = simpleAlloc
        kContextScopeCid = lengthAlloc
        kICDataCid = simpleAlloc
        kLibraryPrefixCid = simpleAlloc
        kRegExpCid = simpleAlloc
        kWeakPropertyCid = simpleAlloc
        
        kTypedDataViewCid = simpleAlloc
        kExternalTypedDataCid = simpleAlloc
        kTypedDataCid = lengthAlloc
        
        def _parseOneByteString(f):
            tags, length, hash_ = unpack('<LLI', f.read(12))
            return { 'tags': tags, 'hash': hash_, 'value': "".join(chr(x) for x in f.read(length//2)) }
        kOneByteStringCid = RODataAlloc(_parseOneByteString) if includes_code else lengthAlloc
        def _parseTwoByteString(f):
            tags, length, hash_ = unpack('<LLI', f.read(12))
            return { 'tags': tags, 'hash': hash_, 'value': f.read(length).decode('utf16') }
        kTwoByteStringCid = RODataAlloc(_parseTwoByteString) if includes_code else lengthAlloc
        def _parsePcDescriptors(f):
            tags, length = unpack('<II', f.read(8))
            data = f.read(length)
            return { 'tags': tags, 'data': data } # TODO: parse that data
        kPcDescriptorsCid = RODataAlloc(_parsePcDescriptors)
        def _parseCodeSourceMap(f):
            tags, length = unpack('<II', f.read(8))
            return { 'tags': tags, 'data': f.read(length) } # TODO: parse that data
        kCodeSourceMapCid = RODataAlloc(_parseCodeSourceMap)
        def _parseStackMap(f):
            tags, pc_offset, length, slow_path_bit_count = unpack('<IIHH', f.read(12))
            bits = []
            while length > 0:
                c = f.read(1)[0]
                for i in range(8):
                    if length == 0: break
                    bits.append(bool((c >> i) & 1))
                    length -= 1
            return { 'tags': tags, 'pc_offset': pc_offset, 'bits': bits, 'slow_path_bit_count': slow_path_bit_count }
        kStackMapCid = RODataAlloc(_parseStackMap)

    def read_cluster(f):
        ''' Reads a cluster and its alloc section '''
        cid = readcid(f)
        if cid >= kNumPredefinedCids:
            handler = 'kInstanceCid'
        elif isTypedDataView(cid):
            handler = 'kTypedDataViewCid'
        elif isExternalTypedData(cid):
            handler = 'kExternalTypedDataCid'
        elif isTypedData(cid):
            handler = 'kTypedDataCid'
        elif cid == kkClassId['kImmutableArrayCid']:
            handler = 'kArrayCid'
        else:
            if cid >= 0 and hasattr(AllocParsers, kClassId[cid]):
                handler = kClassId[cid]
            else:
                raise Exception('Unknown CID: {}'.format(cid))
        cluster = { 'handler': handler, 'cid': cid }
        cluster['ref_start'] = refs['next']
        getattr(AllocParsers, handler)(f, cluster)
        cluster['ref_end'] = refs['next']
        
        if DEBUG:
            serializers_next_ref_index = readint(f, 32)
            print('WARN: next_ref doesn\'t match, expected {} but got {}'.format(serializers_next_ref_index, refs['next']))
        return cluster

    class FillParsers:
        def kOneByteStringCid(f, x, ref): pass
        def kTwoByteStringCid(f, x, ref): pass
        def kPcDescriptorsCid(f, x, ref): pass
        def kStackMapCid(f, x, ref): pass
        def kCodeSourceMapCid(f, x, ref): pass
        def kNamespaceCid(f, x, ref): pass

        def kKernelProgramInfoCid(f, x, ref):
            x['kernel_binary_version'] = readuint(f, 32)

        def kContextScopeCid(f, x, ref):
            length = readuint(f)
            x['implicit'] = read1(f)
            def read_variable_desc(src):
                x = {}
                x['declaration_token_pos'] = readuint(f)
                x['token_pos'] = readuint(f)
                storeref(f, x, 'name', src)
                storeref(f, x, 'is_final', src)
                storeref(f, x, 'is_const', src)
                storeref(f, x, 'value_or_type', src)
                x['context_index'] = readuint(f)
                x['context_level'] = readuint(f)
                return x
            x['variables'] = [ read_variable_desc((ref, 'variables', i)) for i in range(length) ]

        def kICDataCid(f, x, ref):
            if not PRECOMPILED_RUNTIME:
                x['deopt_id'] = readint(f, 32)
            x['state_bits'] = readint(f, 32)

        def kLibraryPrefixCid(f, x, ref):
            x['num_imports'] = readuint(f, 16)
            x['deferred_load'] = read1(f)

        def kRegExpCid(f, x, ref):
            x['num_one_byte_registers'] = readint(f, 32)
            x['num_two_byte_registers'] = readint(f, 32)
            x['type_flags'] = readint(f, 8)

        def kWeakPropertyCid(f, x, ref): pass
        
        def kClassCid(f, x, ref):
            x['cid'] = readcid(f)
            # regular: assert that cid >= kNumPredefinedCids
            
            if (not PRECOMPILED_RUNTIME) and (kind != kkKind['kFullAOT']):
                x['binary_declaration'] = readuint(f, 32)
            
            # FIXME not store these two (just discard) if (predefined and IsInternalVMdefinedClassId)
            x['instance_size_in_words'] = readint(f, 32)
            x['next_field_offset_in_words'] = readint(f, 32)

            x['type_arguments_field_offset_in_words'] = readint(f, 32)
            x['num_type_arguments'] = readint(f, 16)
            x['num_native_fields'] = readuint(f, 16)
            x['token_pos'] = readtokenposition(f)
            x['end_token_pos'] = readtokenposition(f)
            x['state_bits'] = readuint(f, 32)
            
            # regular: store at class table

        def kPatchClassCid(f, x, ref):
            if (not PRECOMPILED_RUNTIME) and (kind != kkKind['kFullAOT']):
                x['library_kernel_offset'] = readint(f, 32)

        def kFunctionCid(f, x, ref):
            if not PRECOMPILED_RUNTIME:
                if kind == kkKind['kFullJIT']:
                    storeref(f, x, 'unoptimized_code', ref)
                if includes_bytecode:
                    storeref(f, x, 'bytecode', ref)
            if includes_code:
                storeref(f, x, 'code', ref)
            if kind == kkKind['kFullJIT']:
                storeref(f, x, 'ic_data_array', ref)
            
            if (not PRECOMPILED_RUNTIME) and (kind != kkKind['kFullAOT']):
                x['token_pos'] = readtokenposition(f)
                x['end_token_pos'] = readtokenposition(f)
                x['binary_declaration'] = readuint(f, 32)
            x['packed_fields'] = readuint(f, 32)
            x['kind_tag'] = readuint(f, 64) # FIXME it should be 32

        def kClosureDataCid(f, x, ref): pass
        def kSignatureDataCid(f, x, ref): pass
        
        def kFieldCid(f, x, ref):
            if kind != kkKind['kFullAOT']:
                x['token_pos'] = readtokenposition(f)
                x['end_token_pos'] = readtokenposition(f)
                x['guarded_cid'] = readcid(f)
                x['is_nullable'] = readcid(f)
                x['static_type_exactness_state'] = readint(f,8)
                if not PRECOMPILED_RUNTIME:
                    x['binary_declaration'] = readuint(f,32)
            x['kind_bits'] = readuint(f,16)
        
        def kScriptCid(f, x, ref):
            x['line_offset'] = readint(f,32)
            x['col_offset'] = readint(f,32)
            x['kind'] = readint(f,8)
            x['kernel_script_index'] = readint(f,32)

        def kLibraryCid(f, x, ref):
            x['index'] = readint(f,32)
            x['num_imports'] = readuint(f,16)
            x['load_state'] = readint(f,8)
            x['is_dart_scheme'] = read1(f)
            x['debuggable'] = read1(f)
            if not PRECOMPILED_RUNTIME:
                x['binary_declaration'] = readuint(f,32)

        def kCodeCid(f, x, ref):
            x['state_bits'] = readint(f, 32)
        
        def kObjectPoolCid(f, x, ref):
            def read_entry(n):
                e = decodeObjectEntryTypeBits(readuint(f,8))
                if e['entry_type'] in {kkEntryType['kNativeEntryData'], kkEntryType['kTaggedObject']}:
                    e['raw_obj'] = readref(f, (ref, 'entries', n, 'raw_obj'))
                elif e['entry_type'] in {kkEntryType['kImmediate']}:
                    e['raw_value'] = readint(f)
                elif e['entry_type'] in {kkEntryType['kNativeFunction'], kkEntryType['kNativeFunctionWrapper']}:
                    pass
                else:
                    print('WARN: Unknown entry type {}... continuing anyway'.format(e['entry_type']))
                return e
            x['entries'] = [read_entry(n) for n in range(readuint(f))]
        
        def ROData(f, x, ref): pass
        
        def kExceptionHandlersCid(f, x, ref):
            count = readuint(f)
            storeref(f, x, 'handled_types_data', ref)
            def read_info():
                i = {}
                i['handler_pc_offset'] = readuint(f,32)
                i['outer_try_index'] = readint(f,16)
                i['needs_stacktrace'] = readint(f,8)
                i['has_catch_all'] = readint(f,8)
                i['is_generated'] = readint(f,8)
                return i
            x['entries'] = [read_info() for _ in range(count)]

        def kUnlinkedCallCid(f, x, ref): pass
        
        def kMegamorphicCacheCid(f, x, ref):
            x['filled_entry_count'] = readint(f, 32)
        
        def kSubtypeTestCacheCid(f, x, ref): pass
        
        def kUnhandledExceptionCid(f, x, ref): pass
        
        def kInstanceCid(f, x, ref):
            x['canonical'] = read1(f)
            count = ref.cluster['next_field_offset_in_words'] - RAW_INSTANCE_SIZE_IN_WORDS
            x['fields'] = [ readref(f, (ref, 'fields', n)) for n in range(count) ]
        
        def kTypeArgumentsCid(f, x, ref):
            count = readuint(f)
            x['canonical'] = read1(f)
            x['hash'] = readint(f, 32)
            storeref(f, x, 'instantiations', ref)
            x['types'] = [ readref(f, (ref, 'types', n)) for n in range(count) ]
        
        def kTypeCid(f, x, ref):
            x['token_pos'] = readtokenposition(f)
            x['type_state'] = readint(f, 8)
        
        def kTypeRefCid(f, x, ref): pass
        
        def kTypeParameterCid(f, x, ref):
            x['parameterized_class_id'] = readint(f, 32)
            x['token_pos'] = readtokenposition(f)
            x['index'] = readint(f, 16)
            x['flags'] = readuint(f, 8)
        
        def kClosureCid(f, x, ref): pass
        
        def kMintCid(f, x, ref): pass
        
        def kDoubleCid(f, x, ref):
            x['canonical'] = read1(f)
            x['value'] = readdouble(f)

        def kGrowableObjectArrayCid(f, x, ref): pass
        
        def kStackTraceCid(f, x, ref): pass
        
        def kArrayCid(f, x, ref):
            count = readuint(f)
            x['canonical'] = read1(f)
            storeref(f, x, 'type_arguments', ref)
            x['items'] = [ readref(f, (ref, 'items', n)) for n in range(count) ]
        
        def _typedData(f, x, ref, external):
            count = readuint(f)
            if external:
                while f.tell() % kDataSerializationAlignment != 0: f.read(1)
            else:
                x['canonical'] = read1(f)
            cid = kClassId[ref.cluster['cid']]
            type_name = re.fullmatch('k' + ('External' if external else '') + 'TypedData(.+)ArrayCid', cid).group(1)
            element_size, parse_char = {
                'Int8': (1, 'b'),
                'Uint8': (1, 'B'),
                'Int16': (2, 'h'),
                'Uint16': (2, 'H'),
                'Int32': (4, 'i'),
                'Uint32': (4, 'I'),
                'Int64': (8, 'q'),
                'Uint64': (8, 'Q'),
            }[type_name]
            parse_func = lambda: unpack('<' + parse_char, f.read(element_size))[0]
            x['items'] = [ parse_func() for _ in range(count) ]
        kTypedDataCid = lambda f, x, ref: FillParsers._typedData(f, x, ref, False)
        kExternalTypedDataCid = lambda f, x, ref: FillParsers._typedData(f, x, ref, True)


    FIELDS, MAPPINGS = make_type_data()

    def remove_fields(fields, to_remove):
        assert to_remove.issubset(set(f[1] for f in fields))
        return [f for f in fields if f[1] not in to_remove]

    def read_from_to(f, x, ref):
        handler = ref.cluster['handler']
        if handler in {'kObjectPoolCid', 'ROData', 'kExceptionHandlersCid', 'kInstanceCid', 'kTypeArgumentsCid', 'kMintCid', 'kDoubleCid', 'kArrayCid', 'kTypedDataCid', 'kExternalTypedDataCid', 'kOneByteStringCid', 'kTwoByteStringCid', 'kPcDescriptorsCid', 'kCodeSourceMapCid', 'kStackMapCid', 'kContextScopeCid'}: return
        kname = re.fullmatch('k(.+)Cid', handler).group(1)
        fields, mapping = FIELDS[kname], MAPPINGS.get(kname)
        if not (mapping is None or type(mapping) is bool):
            last_field = mapping[{ kkKind[n]: i for i, n in enumerate(['kFull', 'kFullJIT', 'kFullAOT']) }[kind]]
            idx = next(filter(lambda x: x[1][1] == last_field, enumerate(fields)))[0]
            fields = fields[:idx+1]

        if kname in {'Closure', 'GrowableObjectArray'}:
            x['canonical'] = read1(f)
        if kname == 'ClosureData' and kind == kkKind['kFullAOT']:
            fields = remove_fields(fields, {'context_scope'})
        if kname == 'Code':
            x['instructions'] = read_instructions(f)
            if not PRECOMPILED_RUNTIME and kind == kkKind['kFullJIT']:
                    x['active_instructions'] = read_instructions(f)
            if not PRECOMPILED_RUNTIME and kind != kkKind['kFullJIT']:
                fields = remove_fields(fields, {'deopt_info_array', 'static_calls_target_table'})

        for t, name, c in fields:
            storeref(f, x, name, ref)

    def read_fill_cluster(f, cluster):
        cid = cluster['cid']
        #print('cluster cid', kClassId[cid] if 0 <= cid < kNumPredefinedCids else cid)
        for ref in range(cluster['ref_start'], cluster['ref_end']):
            ref = refs[ref]
            assert ref.cluster == cluster
            read_from_to(f, ref.x, ref)
            getattr(FillParsers, cluster['handler'])(f, ref.x, ref)

    def read_instructions(f):
        roffset = readint(f, 32)
        offset = roffset
        if offset < 0:
            offset = -offset
            # TODO: get from base
            raise Exception('Not implemented')
        else:
            offset += INSTR_ADDRESS
        if disableRoData:
            return { 'offset': offset }
        saved = f.tell()
        try:
            f.seek(offset)
            tags, size_and_flags, unchecked_entrypoint_pc_offset, stats_ptr = unpack('<LLLI', f.read(16))
            size = size_and_flags & ((1 << 31) - 1)
            flags = size_and_flags >> 31
            data_addr = f.tell() # for disassembling in another program
            data = f.read(size)
            instr = {
                'tags': tags,
                'flags': { 'single_entry': flags & 1 },
                'unchecked_entrypoint_pc_offset': unchecked_entrypoint_pc_offset,
                'stats_ptr': stats_ptr,
                'data': data,
                'data_addr': data_addr,
            }
            if False: # not instructions or not marked
                print('WARN: Invalid instructions at offset {}'.format(roffset))
            return instr
        finally:
            f.seek(saved)

    def enforce_section_marker(f):
        if not DEBUG: return
        section_marker = readint(f, 32)
        if section_marker != kSectionMarker:
            print('ERR: Section marker doesn\'t match')
            exit(1)


    # check that base objects match
    if base is None: base = make_base_objects(includes_code)
    base_objects = base['next']-1
    if base_objects != num_base_objects:
        print('WARN: Snapshot expected {} base objects, but the provided base has {}'.format(num_base_objects, base_objects))
    base_objects = min(base_objects, num_base_objects)
    # fill base objects
    for r in range(1, 1 + base_objects):
        refs[r] = Ref(base[r].ref, base[r].cluster, base[r].x, base[r].prop)
    refs['next'] = 1 + base_objects
    # fill any missing refs
    tmp_cluster = { 'handler': 'UnknownBase', 'cid': 'unknown' }
    while refs['next']-1 < num_base_objects: allocRef(tmp_cluster, {})

    # read allocation clusters
    print("INFO: [%08x]: Reading allocation clusters..." % app.tell())
    clusters = [ read_cluster(app) for _ in range(num_clusters) ]
    if refs['next']-1 != num_objects:
        print('WARN: Expected {} total objects, produced {}'.format(num_objects, refs['next']-1))

    # read fill clusters
    print("INFO: [%08x]: Reading fill clusters..." % app.tell())
    for cluster in clusters:
        read_fill_cluster(app, cluster)
        enforce_section_marker(app)

    # read roots (for isolate snapshots, the ObjectStore)
    print("INFO: [%08x]: Reading roots..." % app.tell())
    refs['root'] = Ref('root', {'handler': 'kObjectStoreCid', 'cid': 'ObjectStore'}, {}, 'refs')
    if vm:
        storeref(app, refs['root'].x, 'symbol_table', refs['root'])
        if includes_code:
            refs['root'].x['_stubs'] = [ readref(app, (refs['root'], '_stubs', n)) for n in kStubCodeList ]        
    else:
        read_from_to(app, refs['root'].x, refs['root'])
    enforce_section_marker(app)

    # verify end of snapshot
    print('INFO: [%08x]: Snasphot parsed.' % app.tell())
    if app.tell() != snapshot_end:
        print('WARN: Snapshot should end at 0x{:x} but we are at 0x{:x}'.format(snapshot_end, app.tell()))

    # FIXME: do we need to reproduce postLoad (fixups)?
    # FIXME: analyze orphan references/graphs (which could indicate parsing errors)?
    
    return clusters, refs
