# CONSTANTS

import json
import os.path


EXPECTED_VERSION = 'c8562f0ee0ebc38ba217c7955956d1cb'

MAGIC_VALUE = 0xdcdcf5f5

kSectionMarker = 0xABAB

kMaxPreferredCodeAlignment = 32

# as an exception, kClassId names are stripped of k- and -Cid (except items 2 and 3: kFreeListElement, kForwardingCorpse)
with open(os.path.join(os.path.dirname(__file__), 'data', 'classIds.json')) as f:
    kClassId = json.load(f)
kkClassId = { k: v for (v, k) in enumerate(kClassId) }
assert len(kClassId) == len(kkClassId)
# kNumPredefinedCids is not included in kClassIds
kNumPredefinedCids = len(kClassId)
kTypedDataInt8ArrayCid = kkClassId['TypedDataInt8Array']
kByteDataViewCid = kkClassId['ByteDataView']

kTypedDataCidRemainderInternal = 0
kTypedDataCidRemainderView = 1
kTypedDataCidRemainderExternal = 2

kDataSerializationAlignment = 8

kEntryType = [ 'kTaggedObject', 'kImmediate', 'kNativeFunction', 'kNativeFunctionWrapper', 'kNativeEntryData' ]
kkEntryType = { k: v for (v, k) in enumerate(kEntryType) }
decode_object_entry_type_bits = lambda x: { "patchable": not (x >> 7), "type": x & 0x7F }

__isBase = lambda x, r: \
    (kTypedDataInt8ArrayCid <= x < kByteDataViewCid) and (x - kTypedDataInt8ArrayCid) % 3 == r
isTypedData = lambda x: __isBase(x, kTypedDataCidRemainderInternal)
isTypedDataView = lambda x: __isBase(x, kTypedDataCidRemainderView) or x == kByteDataViewCid
isExternalTypedData = lambda x: __isBase(x, kTypedDataCidRemainderExternal)

kKind = [
    ('kFull', "Full snapshot of core libraries or an application"),
    ('kFullJIT', "Full + JIT code"),
    ('kFullAOT', "Full + AOT code"),
    ('kMessage', "A partial snapshot used only for isolate messaging"),
    ('kNone', "gen_snapshot"),
    ('kInvalid', None),
]
kkKind = { k[0]: v for (v, k) in enumerate(kKind) }

kPcDescriptorKindBits = [
    ('deopt', 'Deoptimization continuation point.'),
    ('icCall', 'IC call.'),
    ('unoptStaticCall', 'Call to a known target via stub.'),
    ('runtimeCall', 'Runtime call.'),
    ('osrEntry', 'OSR entry point in unopt. code.'),
    ('rewind', 'Call rewind target address.'),
    ('other', None),
]
kkPcDescriptorKindBits = { k[0]: v for (v, k) in enumerate(kPcDescriptorKindBits) }

with open(os.path.join(os.path.dirname(__file__), 'data', 'stub_code_list.json')) as f:
    kStubCodeList = json.load(f)

with open(os.path.join(os.path.dirname(__file__), 'data', 'runtime_offsets.json')) as f:
    kRuntimeOffsets = json.load(f)

# runtime/vm/dart_entry.h
kCachedDescriptorCount = 32
# runtime/vm/object.h
kCachedICDataArrayCount = 4


### Entry points

# tuples are (kMonomorphicEntryOffset<x>, kPolymorphicEntryOffset<x>)
kEntryOffsets = {
    'ia32': (
        (6, 34), # JIT
        (0, 0),  # AOT
    ),
    'x64': (
        (8, 40), # JIT
        (8, 32), # AOT
    ),
    'arm': (
        (0, 40), # JIT
        (0, 20), # AOT
    ),
    'arm64': (
        (8, 48), # JIT
        (8, 28), # AOT
    ),
    'dbc': (
        (0, 0),  # JIT
        (0, 0),  # AOT
    ),
}

### AppJIT blob wrapping

kAppJITMagic = 0xf6f6dcdc
kAppSnapshotPageSize = 4 * 1024

### AppAOT blob wrapping

kAppAOTSymbols = [
    '_kDartVmSnapshotData',
    '_kDartVmSnapshotInstructions',
    '_kDartIsolateSnapshotData',
    '_kDartIsolateSnapshotInstructions'
]
